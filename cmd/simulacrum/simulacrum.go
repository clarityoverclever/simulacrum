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

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"simulacrum/internal/core"
	"simulacrum/internal/core/config"
	"simulacrum/internal/core/logger"
	"simulacrum/internal/core/socket"
	"simulacrum/internal/core/tlscert"
	"simulacrum/internal/services/ca"
	"simulacrum/internal/services/dns"
	"simulacrum/internal/services/http"
	"simulacrum/internal/services/https"
	"simulacrum/internal/services/ntp"
	"simulacrum/internal/services/responder"
	"simulacrum/internal/services/web"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"
)

// main entry point for Simulacrum and initializes core components
func main() {
	// initialize configuration
	cfg, err := config.LoadOrCreate("./config/config.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "--- CONFIG LOAD FAILURE --- : %v\n", err)
		os.Exit(1)
	}

	// initialize logger
	if err = logger.Init(slog.LevelInfo, "./logs/simulacrum.log"); err != nil {
		fmt.Fprintf(os.Stderr, "--- LOGGER INIT FAILURE --- : %v\n", err)
		os.Exit(1)
	}

	fmt.Println("starting Simulacrum version: 0.4.2")

	// capture and process terminating signals
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	// abstract main into run to maintain logging while processing termination signals
	if err := run(cfg, quit); err != nil {
		fmt.Fprintf(os.Stderr, "--- MAIN FAILURE --- : %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nSimulacrum stopped\n")
}

// run initializes core services and runs the main loop
func run(cfg *config.Config, quit <-chan os.Signal) error {
	var err error

	// initialize core services: ipc, tls, responder
	fmt.Println("[core] initializing core services")

	// initialize socket manager for interprocess communication
	socketManager, err := socket.NewManager("/tmp/simulacrum")
	if err != nil {
		return fmt.Errorf("failed to initialize socket manager: %w", err)
	}

	defer socketManager.Close("/tmp/simulacrum")

	// initialize TLS provider and certificate authority
	tlsManager, err := tlscert.NewManager(tlscert.TLSConfig{
		Mode: cfg.TLS.Mode,
		Cert: cfg.TLS.Cert,
		Key:  cfg.TLS.Key,
	}, ca.Config{
		CertFile:         cfg.CA.CertFile,
		KeyFile:          cfg.CA.KeyFile,
		CommonName:       cfg.CA.CommonName,
		Organization:     cfg.CA.Organization,
		RootValidityDays: time.Duration(cfg.CA.RootValidityDays),
		LeafValidityDays: time.Duration(cfg.CA.LeafValidityDays),
	})

	if err != nil {
		return fmt.Errorf("failed to initialize TLS provider: %w", err)
	}

	// initialize response manager
	var responseManager *responder.Manager
	pool := responder.NewPool(cfg.Responder.PoolSize)
	store := responder.NewMemoryStore()
	resolver, err := responder.NewResolver(cfg.Responder.RulesPath)
	if err != nil {
		return fmt.Errorf("failed to initialize responder service: %w", err)
	}

	responseManager = responder.NewManager(pool, store, resolver)

	// initialize listener services: dns, http, https, ntp
	fmt.Println("[core] starting listeners")

	services := []core.Service{
		dns.Init(dns.Config{
			Enabled:                  cfg.DNS.Enabled,
			BindAddress:              cfg.DNS.BindAddress,
			AnalysisIP:               cfg.DNS.AnalysisIP,
			VerifyUpstream:           cfg.DNS.VerifyUpstream,
			UpstreamDNS:              cfg.DNS.UpstreamDNS,
			DefaultSubnet:            cfg.DNS.DefaultSubnet,
			TunnelDetectionThreshold: cfg.DNS.TunnelDetectionThreshold,
			ResponseManager:          responseManager,
		}),

		http.Init(http.Config{
			Enabled:     cfg.HTTP.Enabled,
			BindAddress: cfg.HTTP.BindAddress,
			Handler: web.HandlerConfig{
				ServiceName:  "http",
				LogHeaders:   cfg.CommonWeb.LogHeaders,
				SpoofPayload: cfg.CommonWeb.SpoofPayload,
				MaxBodyKb:    cfg.CommonWeb.MaxBodyKb,
			},
		}),

		https.Init(https.Config{
			Enabled:     cfg.HTTPS.Enabled,
			BindAddress: cfg.HTTPS.BindAddress,
			Handler: web.HandlerConfig{
				ServiceName:  "https",
				LogHeaders:   cfg.CommonWeb.LogHeaders,
				SpoofPayload: cfg.CommonWeb.SpoofPayload,
				MaxBodyKb:    cfg.CommonWeb.MaxBodyKb,
			},
			CertProvider: tlsManager.Provider(),
		}),

		ntp.Init(ntp.Config{
			Enabled:     cfg.NTP.Enabled,
			BindAddress: cfg.NTP.BindAddress,
			Multiplier:  cfg.NTP.Multiplier,
		}),
	}

	// add context for managing listener services
	ctx := context.Background()
	group, ctx := errgroup.WithContext(ctx)

	// track listeners so they can be closed on shutdown
	listeners := make([]net.Listener, 0, len(services))

	for _, service := range services {
		// capture service shadow for use per goroutine
		service := service

		listener, err := socketManager.Create(service.Name())
		if err != nil {
			return err
		}

		listeners = append(listeners, listener)

		group.Go(func() error {
			exeErr := service.Run(listener)
			if exeErr != nil {
				if errors.Is(exeErr, net.ErrClosed) {
					return nil
				}
				return fmt.Errorf("service %s failed: %w", service.Name(), err)
			}
			return nil
		})
	}

	// wait for terminating signals and close listeners
	group.Go(func() error {
		<-quit
		fmt.Printf("\nterminating services\n")

		for _, listener := range listeners {
			_ = listener.Close()
		}

		for _, service := range services {
			if stopErr := service.Stop(); err != nil {
				if errors.Is(stopErr, net.ErrClosed) {
					return nil
				}
				fmt.Printf("[%s] service stop error: %v\n", service.Name(), err)
			}
		}

		return nil
	})

	return group.Wait()
}
