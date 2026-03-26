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
	"simulacrum/internal/services/ca"
)

type Manager struct {
	cfg      TLSConfig
	provider CertificateProvider
}

// NewManager creates a new TLS certificate manager
func NewManager(tlsCfg TLSConfig, caCfg ca.Config) (*Manager, error) {
	provider, err := newProvider(tlsCfg, caCfg)
	if err != nil {
		return nil, err
	}

	return &Manager{cfg: tlsCfg, provider: provider}, nil
}

// Provider returns the configured certificate provider
func (m *Manager) Provider() CertificateProvider {
	return m.provider
}

// Mode returns the TLS mode configuration
func (m *Manager) Mode() string {
	return m.cfg.Mode
}

// newProvider creates a new certificate provider based on the TLS configuration
func newProvider(tlsCfg TLSConfig, caCfg ca.Config) (CertificateProvider, error) {
	err := tlsCfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("[tls] invalid configuration: %w", err)
	}

	switch tlsCfg.Mode {
	case "static":
		cert, err := tls.LoadX509KeyPair(tlsCfg.Cert, tlsCfg.Key)
		if err != nil {
			return nil, fmt.Errorf("[tls] failed to load certificate: %w", err)
		}
		return &StaticProvider{Certificate: &cert}, nil
	case "dynamic":
		caManager, err := ca.NewManager(caCfg)
		if err != nil {
			return nil, fmt.Errorf("[tls] failed to initialize CA issuer: %w", err)
		}

		return NewCachingProvider(caManager), nil
	default:
		return nil, fmt.Errorf("[tls] unsupported mode: %s", tlsCfg.Mode)
	}
}
