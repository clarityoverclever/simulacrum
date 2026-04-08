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

package config

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

//go:embed static/default.yaml
var defaultConfig []byte

type DnsConfig struct {
	Enabled                  bool    `yaml:"enabled"`
	BindAddress              string  `yaml:"bind_addr"`
	AnalysisIP               string  `yaml:"analysis_ip"`
	VerifyUpstream           bool    `yaml:"verify_upstream"`
	UpstreamDNS              string  `yaml:"upstream_dns"`
	DefaultSubnet            string  `yaml:"default_subnet"`
	TunnelDetectionThreshold float64 `yaml:"tunnel_detection_threshold"`
}

type NtpConfig struct {
	Enabled     bool    `yaml:"enabled"`
	BindAddress string  `yaml:"bind_addr"`
	Multiplier  float64 `yaml:"multiplier"`
}

type HttpConfig struct {
	Enabled     bool   `yaml:"enabled"`
	BindAddress string `yaml:"bind_addr"`
}

type HttpsConfig struct {
	Enabled     bool   `yaml:"enabled"`
	BindAddress string `yaml:"bind_addr"`
}

type CommonWebConfig struct {
	SpoofPayload bool  `yaml:"spoof_payload"`
	LogHeaders   bool  `yaml:"log_headers"`
	MaxBodyKb    int64 `yaml:"max_body_kb"`
}

type TlsConfig struct {
	Mode string `yaml:"cert_mode"`
	Cert string `yaml:"cert_file"`
	Key  string `yaml:"key_file"`
}

type CAConfig struct {
	CertFile         string `yaml:"cert_file"`
	KeyFile          string `yaml:"key_file"`
	CommonName       string `yaml:"common_name"`
	Organization     string `yaml:"organization"`
	RootValidityDays int    `yaml:"root_validity_days"`
	LeafValidityDays int    `yaml:"leaf_validity_days"`
}

type ResponderConfig struct {
	RulesPath string `yaml:"rules_path"`
	PoolSize  int    `yaml:"pool_size"`
}

type Config struct {
	DNS       DnsConfig       `yaml:"dns"`
	NTP       NtpConfig       `yaml:"ntp"`
	HTTP      HttpConfig      `yaml:"http"`
	HTTPS     HttpsConfig     `yaml:"https"`
	CommonWeb CommonWebConfig `yaml:"common_web"`
	TLS       TlsConfig       `yaml:"tls"`
	CA        CAConfig        `yaml:"ca"`
	Responder ResponderConfig `yaml:"responder"`
}

// LoadOrCreate loads a config file from disk, or creates a new one if it doesn't exist'
func LoadOrCreate(path string) (*Config, error) {
	var err error
	cfg := &Config{}

	err = ensureConfig(path)
	if err != nil {
		return nil, fmt.Errorf("failed to create default config: %w", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	err = yaml.Unmarshal(data, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return cfg, nil
}

// CreateConfig creates a new config file from the embedded default
func ensureConfig(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err = os.WriteFile(path, defaultConfig, 0644); err != nil {
			return fmt.Errorf("failed to write default config: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to stat default config: %w", err)
	}

	return nil
}
