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
	"encoding/json"
	"fmt"
	"io"
	"net"
	"simulacrum/internal/core"
	"strconv"
	"sync"
)

type Service struct {
	mu     sync.Mutex
	state  core.Status
	server *Server
	config Config
}

func Init(cfg Config) *Service {
	return &Service{
		state:  core.StatusStopped,
		config: cfg,
	}
}

func (s *Service) Name() string {
	return "ntp"
}

func (s *Service) Run(l net.Listener) error {
	if s.config.Enabled {
		if err := s.start(); err != nil {
			fmt.Printf("[ntp] failed to start server: %v\n", err)
		}
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}

		go s.handleConnection(conn)
	}
}

func (s *Service) handleConnection(conn net.Conn) {
	defer conn.Close()

	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)

	var msg core.ControlMessage
	if err := dec.Decode(&msg); err != nil {
		if err != io.EOF {
			fmt.Printf("[ntp] control message decode error: %v\n", err)
		}
		return
	}

	var resp core.ControlResponse

	switch msg.Action {
	case core.ActionStart:
		if err := s.start(); err != nil {
			resp = core.ControlResponse{Status: "error", Message: fmt.Sprintf("[ntp] %v", err.Error())}
		} else {
			resp = core.ControlResponse{Status: "ok", Message: "[ntp] server started"}
		}
	case core.ActionStop:
		if err := s.stop(); err != nil {
			resp = core.ControlResponse{Status: "error", Message: fmt.Sprintf("[ntp] %v", err.Error())}
		} else {
			resp = core.ControlResponse{Status: "ok", Message: "[ntp] server stopped"}
		}
	case core.ActionStatus:
		resp = core.ControlResponse{Status: "ok", Message: string("[ntp] server " + s.getState())}
	case core.ActionRestart:
		if err := s.restart(); err != nil {
			resp = core.ControlResponse{Status: "error", Message: fmt.Sprintf("[ntp] %v", err.Error())}
		} else {
			resp = core.ControlResponse{Status: "ok", Message: "[ntp] server restarted"}
		}
	case core.ActionUpdate:
		var key, value string
		for k, v := range msg.Params {
			key = k
			switch val := v.(type) {
			case string:
				value = val
			case int:
				value = strconv.Itoa(val)
			case float64:
				value = fmt.Sprintf("%g", v)
			case bool:
				value = strconv.FormatBool(val)
			default:
				fmt.Printf("unknown type for key %s: %v\n", k, v)
			}

			fmt.Printf("key: %s, value: %s\n", key, value)
		}

		switch key {
		case "multiplier":
			multiplier, err := strconv.ParseFloat(value, 64)
			if err != nil {
				resp = core.ControlResponse{Status: "error", Message: fmt.Sprintf("[ntp] failed to set multiplier: %v", err)}
			} else {
				s.server.SetMultiplier(multiplier)
				resp = core.ControlResponse{Status: "ok", Message: fmt.Sprintf("[ntp] multiplier set to %s", value)}
			}
		default:
			resp = core.ControlResponse{Status: "error", Message: fmt.Sprintf("[ntp] unknown update action %s %s", key, value)}
		}
	default:
		resp = core.ControlResponse{Status: "error", Message: "[ntp] unknown action"}
	}

	_ = enc.Encode(resp)
}

func (s *Service) start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == core.StatusRunning {
		return fmt.Errorf("server already running")
	}

	var err error
	s.server = New(s.config)
	if err != nil {
		s.state = core.StatusError
		return fmt.Errorf("failed to create server: %w", err)
	}

	go func() {
		if err := s.server.Start(); err != nil {
			s.setState(core.StatusError)
			fmt.Printf("[ntp] server error: %v\n", err)
		}
	}()

	s.state = core.StatusRunning
	return nil
}

func (s *Service) stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != core.StatusRunning {
		return fmt.Errorf("server not running")
	}

	if s.server != nil {
		if err := s.server.Stop(); err != nil {
			s.state = core.StatusError
			return fmt.Errorf("failed to stop server: %w", err)
		}
	}

	s.state = core.StatusStopped
	return nil
}

func (s *Service) restart() error {
	if err := s.stop(); err != nil && s.getState() != core.StatusStopped {
		return err
	}
	return s.start()
}

func (s *Service) setState(state core.Status) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = state
}

func (s *Service) getState() core.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}
