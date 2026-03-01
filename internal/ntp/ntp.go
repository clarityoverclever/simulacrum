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
	"fmt"
	"net"
	"simulacrum/internal/logger"
	"time"
)

type Server struct {
	cfg Config
}

type Config struct {
	Enabled     bool
	BindAddress string
}

func New(cfg Config) *Server {
	return &Server{cfg: cfg}
}

func (s *Server) Start() error {
	addr, err := net.ResolveUDPAddr("udp", s.cfg.BindAddress)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to start NTP server: %w", err)
	}

	defer func(conn *net.UDPConn) {
		err = conn.Close()
		if err != nil {
			fmt.Println("Error closing NTP server:", err)
		}
	}(conn)

	fmt.Println("NTP listening on: ", s.cfg.BindAddress)

	for {
		buf := make([]byte, 48)
		_, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			logger.Error("Error reading from NTP server", "error", err)
			continue
		}

		// strip out requestor timestamp
		originTimestamp := buf[40:48]

		fmt.Printf("NTP packet received from: %s\n", remoteAddr.String())

		response := make([]byte, 48)
		// 0x24 = 00 100 100 (No warning, NTP v4, Server Mode)
		response[0] = 0x24

		// Byte 1: Stratum (secondary server)
		response[1] = 0x02

		// Byte 2: Polling interval (6 = 64 seconds)
		response[2] = 0x06

		// Byte 3: Precision (typical for system clocks)
		response[3] = 0xec

		// Bytes 4-7: Root Delay (Fixed point small value)
		response[4] = 0x00
		response[5] = 0x00
		response[6] = 0x00
		response[7] = 0x0f

		// Bytes 8-11: Root Dispersion
		response[8] = 0x00
		response[9] = 0x00
		response[10] = 0x00
		response[11] = 0x0f

		// Bytes 12-23: Reference ID (The "source")
		copy(response[12:21], "Simulacrum")

		// Bytes 24-31: Requestor timestamp
		copy(response[24:32], originTimestamp)

		// Bytes 40-47: Reference Timestamp
		now := time.Now().Unix() + 2208988800
		response[40] = byte(now >> 24)
		response[41] = byte(now >> 16)
		response[42] = byte(now >> 8)
		response[43] = byte(now)

		_, err = conn.WriteToUDP(response, remoteAddr)
		if err != nil {
			logger.Error("Error writing to NTP server", "error", err)
			continue
		}

		logger.Info("NTP packet processed", "read", string(buf), "wrote", string(response))
		fmt.Printf("NTP packet sent to %s\n", remoteAddr.String())
	}
}
