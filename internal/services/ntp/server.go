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

package ntp

import (
	"context"
	"fmt"
	"net"
	"simulacrum/internal/services/logger"
	"sync"
	"time"
)

type Server struct {
	cfg    Config
	conn   *net.UDPConn
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type Config struct {
	Enabled     bool
	BindAddress string
	Mode        string
	UpstreamNTP string
	Multiplier  float64
}

func New(cfg Config) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		cfg:    cfg,
		ctx:    ctx,
		cancel: cancel,
	}
}

func (s *Server) Start() error {
	addr, err := net.ResolveUDPAddr("udp", s.cfg.BindAddress)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	s.conn, err = net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to start NTP server: %w", err)
	}

	fmt.Println("[ntp] listening on:", s.cfg.BindAddress)

	s.wg.Add(1)
	go s.serve()

	<-s.ctx.Done()
	return nil
}

func (s *Server) serve() {
	defer s.wg.Done()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			// Set read deadline so ReadFromUDP doesn't block forever
			s.conn.SetReadDeadline(time.Now().Add(1 * time.Second))

			buf := make([]byte, 48)
			_, remoteAddr, err := s.conn.ReadFromUDP(buf)
			if err != nil {
				// Check if it's a timeout (expected during shutdown)
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				logger.Error("[ntp] Error reading from NTP server", "error", err)
				continue
			}

			originTimestamp := buf[40:48]
			fmt.Printf("[ntp] packet received from: %s\n", remoteAddr.String())

			response := make([]byte, 48)
			response[0] = 0x24
			response[1] = 0x02
			response[2] = 0x06
			response[3] = 0xec
			response[4] = 0x00
			response[5] = 0x00
			response[6] = 0x00
			response[7] = 0x0f
			response[8] = 0x00
			response[9] = 0x00
			response[10] = 0x00
			response[11] = 0x0f
			copy(response[12:22], "ntp.sim.org")
			copy(response[24:32], originTimestamp)

			now := time.Now().Unix() + 2208988800 // Unix epoch to go epoch conversion
			response[40] = byte(now >> 24)
			response[41] = byte(now >> 16)
			response[42] = byte(now >> 8)
			response[43] = byte(now)

			_, err = s.conn.WriteToUDP(response, remoteAddr)
			if err != nil {
				logger.Error("[ntp] Error writing to server", "error", err)
				continue
			}

			logger.Info("[ntp] packet processed", "read", string(buf), "wrote", string(response))
			fmt.Printf("[ntp] packet sent to %s\n", remoteAddr.String())
		}
	}
}

func (s *Server) Stop() error {
	fmt.Println("[ntp] stopping server")

	// Signal shutdown
	s.cancel()

	// Close the connection
	if s.conn != nil {
		if err := s.conn.Close(); err != nil {
			return fmt.Errorf("error closing NTP connection: %w", err)
		}
	}

	// Wait for goroutine to finish
	s.wg.Wait()

	return nil
}
