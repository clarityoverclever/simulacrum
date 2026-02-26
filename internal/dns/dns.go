package dns

import (
	"fmt"
	"net"
	"os"
	"simulcrum/internal/logger"
	"strings"

	"github.com/miekg/dns"
)

type Server struct {
	addr      string
	defaultIP net.IP
	dnsServer *dns.Server
}

type Config struct {
	ListenAddr string
	DefaultIP  string // IP returned for all queries
}

func New(cfg Config) (*Server, error) {
	ip := net.ParseIP(cfg.DefaultIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid default IP address: %s", cfg.DefaultIP)
	}
	return &Server{
		addr:      cfg.ListenAddr,
		defaultIP: ip,
	}, nil
}

func (s *Server) Start() error {
	dns.HandleFunc(".", s.handleDNSRequest)

	s.dnsServer = &dns.Server{Addr: s.addr, Net: "udp"}

	fmt.Fprintf(os.Stdout, "Starting DNS server on %s\n", s.addr)

	if err := s.dnsServer.ListenAndServe(); err != nil {
		return fmt.Errorf("failed to start DNS server: %w", err)
	}
	return nil
}

func (s *Server) Stop() error {
	if s.dnsServer != nil {
		fmt.Println("stopping DNS server")
		return s.dnsServer.Shutdown()
	}
	return nil
}

func (s *Server) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	for _, question := range r.Question {
		logger.Info("dns query",
			"domain", strings.TrimSuffix(question.Name, "."),
			"type", dns.TypeToString[question.Qtype],
			"client", w.RemoteAddr().String(),
		)

		switch question.Qtype {
		case dns.TypeA:
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    30,
				},
				A: s.defaultIP,
			})
		case dns.TypeAAAA:
			logger.Info("ignoring AAAA query", "domain", question.Name)
		case dns.TypeMX, dns.TypeNS, dns.TypeCNAME, dns.TypeTXT:
			logger.Info("ignoring unsupported query", "type", dns.TypeToString[question.Qtype])
		default:
			logger.Info("unknown query type", "type", question.Qtype)
		}
	}

	if err := w.WriteMsg(msg); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write DNS response: %v\n", err)
	}
}
