// Copyright 2026 Keith Marshall
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dns

import (
	"context"
	"fmt"
	"net"
	"os"
	"simulacrum/internal/core/inspect"
	"simulacrum/internal/core/logger"
	"simulacrum/internal/services/dns/dnat"
	"simulacrum/internal/services/dns/ippool"
	"simulacrum/internal/services/responder"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Server struct {
	bindAddress              string
	analysisIP               net.IP
	dnsServer                *dns.Server
	checkLiveness            bool
	upstreamDNS              string
	SpoofNetwork             bool
	tunnelDetection          bool
	tunnelDetectionThreshold float64
	responderManager         *responder.Manager
	ipPool                   *ippool.Pool
	dnatManager              *dnat.Manager
	dnatMap                  map[string]string // domain -> spoofed IP
	dnatLock                 sync.RWMutex
}

type Config struct {
	Enabled                  bool
	BindAddress              string
	AnalysisIP               string
	CheckLiveness            bool
	UpstreamDNS              string
	SpoofNetwork             bool
	DefaultSubnet            string
	TunnelDetection          bool
	TunnelDetectionThreshold float64
	ResponseManager          *responder.Manager
}

func New(cfg Config) (*Server, error) {
	ip := net.ParseIP(cfg.AnalysisIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid analysis IP address: %s", cfg.AnalysisIP)
	}

	var pool *ippool.Pool

	if cfg.SpoofNetwork {
		var err error
		pool, err = ippool.New(cfg.DefaultSubnet)
		if err != nil {
			return nil, fmt.Errorf("invalid default subnet: %w", err)
		}
	}

	server := &Server{
		bindAddress:              cfg.BindAddress,
		analysisIP:               ip,
		checkLiveness:            cfg.CheckLiveness,
		upstreamDNS:              cfg.UpstreamDNS,
		SpoofNetwork:             cfg.SpoofNetwork,
		tunnelDetection:          cfg.TunnelDetection,
		tunnelDetectionThreshold: cfg.TunnelDetectionThreshold,
		responderManager:         cfg.ResponseManager,
		ipPool:                   pool,
		dnatManager:              dnat.New(cfg.AnalysisIP),
		dnatMap:                  make(map[string]string),
	}

	// validate upstream DNS if liveness check is enabled
	if server.checkLiveness && server.upstreamDNS == "" {
		return nil, fmt.Errorf("upstream DNS required for liveness check")
	}

	return server, nil
}

func (s *Server) Start() error {
	dns.HandleFunc(".", s.handleDNSRequest)

	s.dnsServer = &dns.Server{Addr: s.bindAddress, Net: "udp"}

	fmt.Fprintf(os.Stdout, "[dns] listening on: %s\n", s.bindAddress)

	if err := s.dnsServer.ListenAndServe(); err != nil {
		return fmt.Errorf("failed to open listener: %w", err)
	}
	return nil
}

func (s *Server) Stop() error {
	if s.dnsServer != nil {
		fmt.Println("[dns] stopping server")

		// Clean up all DNAT rules
		s.dnatLock.Lock()
		fmt.Println("[dns] removing DNAT rules")

		for domain, spoofedIP := range s.dnatMap {
			if err := s.dnatManager.RemoveDNAT(spoofedIP); err != nil {
				logger.Error("[dns] failed to remove DNAT", "domain", domain, "error", err)
			}
		}
		s.dnatLock.Unlock()

		// Clear IP pool
		if s.ipPool != nil {
			s.ipPool.Clear()
		}

		return s.dnsServer.Shutdown()
	}
	return nil
}

func (s *Server) resolveUpstream(domain string, qtype uint16) (bool, net.IP) {
	if !s.checkLiveness {
		return true, nil // always return success if upstream checking is disabled
	}

	c := new(dns.Client)
	c.Timeout = 2 * time.Second

	m := new(dns.Msg)
	m.SetQuestion(domain, qtype)
	m.RecursionDesired = true

	r, _, err := c.Exchange(m, s.upstreamDNS)
	if err != nil {
		logger.Warn("[dns] upstream DNS check failed",
			"domain", domain,
			"error", err,
			"type", dns.TypeToString[qtype])
		return true, nil // fail open if upstream check fails
	}

	// check response code
	switch r.Rcode {
	case dns.RcodeSuccess:
		var upstreamIP net.IP
		if qtype == dns.TypeA {
			for _, ans := range r.Answer {
				if a, ok := ans.(*dns.A); ok {
					upstreamIP = a.A
					break
				}
			}
		}
		logger.Info("[dns] upstream DNS check succeeded",
			"domain", domain,
			"type", dns.TypeToString[qtype],
			"upstream_ip", upstreamIP,
		)
		return true, upstreamIP
	case dns.RcodeNameError: // NXDOMAIN
		logger.Info("[dns] upstream DNS check failed",
			"domain", domain,
			"error", "NXDOMAIN",
		)
		return false, nil
	default:
		logger.Warn("[dns] upstream DNS check failed",
			"domain", domain,
			"rcode", dns.RcodeToString[r.Rcode],
		)
		return true, nil // fail open
	}
}

func (s *Server) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	var err error
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	clientAddr := w.RemoteAddr().String()
	clientIP, _, _ := net.SplitHostPort(clientAddr)

	for _, question := range r.Question {
		domain := strings.TrimSuffix(question.Name, ".")

		logger.Info("[dns] query",
			"domain", domain,
			"type", dns.TypeToString[question.Qtype],
			"client", clientAddr,
		)

		// attempt to detect tunneling by testing domain entropy
		if s.tunnelDetection {
			labels := strings.Split(strings.TrimSuffix(question.Name, "."), ".")
			suspicious := labels[0]

			entropy := inspect.Shannon([]byte(suspicious))
			if entropy > s.tunnelDetectionThreshold {
				logger.Warn("[dns] detected possible tunneling attempt", "domain", domain)
				msg.SetRcode(r, dns.RcodeSuccess)
				continue
			}
		}

		// check upstream DNS for domain if liveness check is enabled
		exists, upstreamIP := s.resolveUpstream(question.Name, question.Qtype)

		if !exists {
			// return NXDOMAIN if upstream check fails
			msg.SetRcode(r, dns.RcodeNameError)
			logger.Info("[dns] returning NXDOMAIN for non-existent domain", "domain", domain)

			continue
		}

		var responseIP net.IP

		if s.SpoofNetwork && question.Qtype == dns.TypeA {
			if upstreamIP != nil {
				// spoof network if upstream IP is available
				responseIP = upstreamIP
			} else {
				// use default subnet if upstream IP is not available
				responseIP, err = s.ipPool.Allocate()
				if err != nil {
					logger.Error("[dns] failed to allocate IP from pool", "error", err)
					responseIP = s.analysisIP
				}
			}

			// add DNAT rule
			if err = s.dnatManager.AddDNAT(responseIP.String()); err != nil {
				logger.Error("[dns] failed to add DNAT", "error", err)
				// Fall back to analysis IP
				responseIP = s.analysisIP
			} else {
				// Track mapping for cleanup
				s.dnatLock.Lock()
				s.dnatMap[domain] = responseIP.String()
				s.dnatLock.Unlock()
			}
		} else {
			// return analysis IP as fallback
			responseIP = s.analysisIP
		}

		switch question.Qtype {
		case dns.TypeA:
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    1,
				},
				A: responseIP,
			})

			logger.Info("[dns] response",
				"domain", domain,
				"returned_ip", responseIP.String(),
				"spoofed", s.SpoofNetwork,
			)

			// run request through responder
			if s.responderManager != nil {
				var result responder.Result
				logger.Info("[dns] sending responder request")
				req := responder.RequestContext{
					Key:    responder.Key(clientIP),
					Kind:   responder.KindDNS,
					Source: clientIP,
					Target: domain,
					Meta:   map[string]string{"qtype": dns.TypeToString[question.Qtype]},
					Now:    time.Now(),
				}
				if result, err = s.responderManager.Handle(context.Background(), req); err != nil {
					logger.Warn("[dns] responder handle error", "error", err)
				}

				fmt.Printf("[dns] responder result: %s\n", result.Decision)
			}
		case dns.TypeAAAA:
			logger.Info("[dns] returning NODATA for AAAA query", "domain", question.Name)
			continue // sending NODATA for AAAA queries to attempt to force IPv4 fallback
		case dns.TypeMX, dns.TypeNS, dns.TypeCNAME, dns.TypeTXT:
			logger.Info("[dns] ignoring unsupported query", "type", dns.TypeToString[question.Qtype])
			// TODO add capture support for these types
			continue // sending NODATA for unsupported types
		default:
			logger.Info("[dns] unknown query type", "type", question.Qtype)
			msg.SetRcode(r, dns.RcodeNameError)
		}
	}

	if err = w.WriteMsg(msg); err != nil {
		fmt.Fprintf(os.Stderr, "[dns] failed to write response: %v\n", err)
	}
}
