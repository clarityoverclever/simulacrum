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

package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type Manager struct {
	cfg      Config
	rootCert *x509.Certificate
	rootKey  crypto.PrivateKey
}

type Config struct {
	CertFile         string
	KeyFile          string
	CommonName       string
	Organization     string
	RootValidityDays time.Duration
	LeafValidityDays time.Duration
}

// NewManager creates a new CA manager.
func NewManager(cfg Config) (*Manager, error) {
	m := &Manager{cfg: cfg}

	if err := m.loadOrCreateRootCert(); err != nil {
		return nil, err
	}
	return m, nil
}

// loadOrCreateRootCert loads or creates the CA root certificate and key.
func (m *Manager) loadOrCreateRootCert() error {
	certDir := filepath.Dir(m.cfg.CertFile)

	if err := os.MkdirAll(certDir, 0700); err != nil {
		return fmt.Errorf("failed to create cert directory: %w", err)
	}

	_, certErr := os.Stat(m.cfg.CertFile)
	_, keyErr := os.Stat(m.cfg.KeyFile)

	if certErr == nil && keyErr == nil {
		return m.loadRoot()
	}

	if os.IsNotExist(certErr) && os.IsNotExist(keyErr) {
		if err := m.createRootCert(); err != nil {
			return fmt.Errorf("failed to create root certificate: %w", err)
		}

		return m.loadRoot()
	}

	if certErr != nil {
		return fmt.Errorf("failed to load root certificate: %w", certErr)
	}

	if keyErr != nil {
		return fmt.Errorf("failed to load root key: %w", keyErr)
	}

	return nil
}

// createRootCert generates a new CA root certificate and key.
func (m *Manager) createRootCert() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate root key: %w", err)
	}

	serialNumber, err := randomSerialNumber()
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now().UTC()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   m.cfg.CommonName,
			Organization: []string{m.cfg.Organization},
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(m.cfg.RootValidityDays * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create root certificate: %w", err)
	}

	if err = writeCertPEM(m.cfg.CertFile, derBytes); err != nil {
		return fmt.Errorf("failed to write root certificate: %w", err)
	}

	if err = writeKeyPEM(m.cfg.KeyFile, privateKey); err != nil {
		return fmt.Errorf("failed to write root key: %w", err)
	}

	return nil
}

// loadRoot loads the CA root certificate and key from disk.
func (m *Manager) loadRoot() error {
	certPEM, err := os.ReadFile(m.cfg.CertFile)
	if err != nil {
		return fmt.Errorf("failed to read root certificate: %w", err)
	}

	keyPEM, err := os.ReadFile(m.cfg.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to read root key: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse root certificate: %w", err)
	}

	if len(tlsCert.Certificate) == 0 {
		return fmt.Errorf("root certificate chain is empty: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fmt.Errorf("failed to decode root certificate PEM: %w", err)
	}

	rootCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse root certificate: %w", err)
	}
	m.rootCert = rootCert
	m.rootKey = tlsCert.PrivateKey

	return nil
}

// IssueServerCertificate generates a new server leaf certificate signed by the CA root certificate.
func (m *Manager) IssueServerCertificate(serverName string) (*tls.Certificate, error) {
	if m.rootCert == nil || m.rootKey == nil {
		return nil, fmt.Errorf("root certificate or key not loaded")
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	serialNumber, err := randomSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now().UTC()

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: serverName,
		},
		NotBefore: now,
		NotAfter:  now.Add(m.cfg.LeafValidityDays * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		IsCA:         false,
		DNSNames:     []string{serverName},
		SubjectKeyId: []byte{1, 2, 3, 4},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, m.rootCert, &privateKey.PublicKey, m.rootKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create leaf certificate: %w", err)
	}

	rootPEM, err := os.ReadFile(m.cfg.CertFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read root certificate: %w", err)
	}

	leafPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	var certPEM []byte

	if rootPEM != nil {
		certPEM = append(leafPEM, rootPEM...)
	} else {
		certPEM = leafPEM
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse leaf certificate: %w", err)
	}

	if len(tlsCert.Certificate) == 0 {
		return nil, fmt.Errorf("leaf certificate chain is empty: %w", err)
	}

	return &tlsCert, nil
}

// randomSerialNumber generates a random serial number.
func randomSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}
	return serialNumber, nil
}

// writeCertPEM writes a certificate to disk in PEM format.
func writeCertPEM(path string, der []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0644)
	if err != nil {
		return fmt.Errorf("failed to open cert file: %w", err)
	}
	defer f.Close()

	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}

	if err := pem.Encode(f, block); err != nil {
		return fmt.Errorf("failed to write cert PEM: %w", err)
	}

	return nil
}

// writeKeyPEM writes a private key to disk in PEM format.
func writeKeyPEM(path string, key *rsa.PrivateKey) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("failed to open key file: %w", err)
	}
	defer f.Close()

	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	if err := pem.Encode(f, block); err != nil {
		return fmt.Errorf("failed to write key PEM: %w", err)
	}

	return nil
}
