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

package tlscert

import (
	"crypto/tls"
	"fmt"
)

type TLSConfig struct {
	Mode string
	Cert string
	Key  string
}

type Manager struct {
	cfg      TLSConfig
	provider CertificateProvider
}

func NewManager(cfg TLSConfig) (*Manager, error) {
	provider, err := newProvider(cfg)
	if err != nil {
		return nil, err
	}

	return &Manager{cfg: cfg, provider: provider}, nil
}

func (m *Manager) Provider() CertificateProvider {
	return m.provider
}

func (m *Manager) Mode() string {
	return m.cfg.Mode
}

func newProvider(cfg TLSConfig) (CertificateProvider, error) {
	err := cfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("[tls] invalid configuration: %w", err)
	}

	switch cfg.Mode {
	case "static":
		cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
		if err != nil {
			return nil, fmt.Errorf("[tls] failed to load certificate: %w", err)
		}
		return &StaticProvider{Certificate: &cert}, nil
	default:
		return nil, fmt.Errorf("[tls] unsupported mode: %s", cfg.Mode)
	}
}

func (c *TLSConfig) Validate() error {
	if c.Mode == "" {
		return fmt.Errorf("mode cannot be empty")
	}

	switch c.Mode {
	case "static":
		if c.Cert == "" || c.Key == "" {
			return fmt.Errorf("static mode requires both cert and key")
		}
	case "dynamic":
		return fmt.Errorf("dynamic mode is not implemented")
	default:
		return fmt.Errorf("unsupported mode: %s", c.Mode)
	}

	return nil
}
