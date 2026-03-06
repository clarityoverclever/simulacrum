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

package http

import (
	"context"
	"embed"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"simulacrum/internal/services/logger"
	"time"
)

//go:embed static/*
var staticDir embed.FS

type Server struct {
	cfg    Config
	Server *http.Server
}

type Config struct {
	Enabled      bool
	BindAddress  string
	LogHeaders   bool
	SpoofPayload bool
	MaxBodyBytes int64
}

var mimes = map[string]string{
	".exe": "application/x-msdownload",
	".dll": "application/x-msdownload",
	".ps1": "text/plain",
	".dat": "application/octet-stream",
}

func New(cfg Config) (*Server, error) {
	return &Server{cfg: cfg}, nil
}

func (s *Server) Start() error {
	if !s.cfg.Enabled {
		return nil
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/{path...}", s.handleRequest)

	s.Server = &http.Server{
		Addr:         s.cfg.BindAddress,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	fmt.Println("[http] listening on", s.cfg.BindAddress)
	if err := s.Server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("failed to start server: %w", err)
	}

	return nil
}

func (s *Server) Stop() error {
	if s.Server != nil {
		fmt.Println("[http] Stopping server")

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := s.Server.Shutdown(ctx); err != nil {
			fmt.Println("server shutdown failed:", err)
		}
	}

	return nil
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	s.logRequest(r)

	switch r.Method {
	case "GET":
		s.handleGet(w, r)
	case "POST":
		s.handlePost(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}

}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	if s.cfg.SpoofPayload {
		leaf := r.PathValue("path")
		ext := filepath.Ext(leaf) // extracts extension from the leaf path

		val, ok := mimes[ext]
		if ok {
			s.serveFile(w, leaf, ext, val)
			return
		}
	}

	// default serve a 200
	w.Header().Set("Content-Type", "text/html")

	w.Write([]byte("<!DOCTYPE html><html><head><title>simulacrum</title></head><body><center><h1>OK</h1></center></body></html>"))
}

func (s Server) handlePost(w http.ResponseWriter, r *http.Request) {
	fmt.Println("[http] POST received")

	var capture []byte
	var truncated bool
	var maxBodyBytes = s.cfg.MaxBodyBytes * 1024

	limitReader := io.LimitReader(r.Body, maxBodyBytes)
	data, _ := io.ReadAll(limitReader)

	if int64(len(data)) > maxBodyBytes {
		truncated = true
		data = data[:maxBodyBytes]
	}

	capture = []byte(base64.StdEncoding.EncodeToString(data))
	captureHead := string(capture[:8])
	preview := ""
	if len(capture) > 0 {
		preview = captureHead
	}

	logger.Info("[http] POST data captured",
		"client", r.RemoteAddr,
		"host", r.Host,
		"path", r.URL.Path,
		"truncated", truncated,
		"bytes", len(capture),
		"preview", preview,
	)

	if len(capture) > 0 {
		err := s.capturePostBody(captureHead, capture)
		if err != nil {
			logger.Error("[http] failed to write capture to file", "error", err)
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (s *Server) serveFile(w http.ResponseWriter, fileName string, fileType string, contentType string) {
	logger.Info("[http] Serving agent payload", "file_type", fileType)

	switch fileType {
	case ".exe":
		fmt.Println("[http] serving x64 payload")
		w.Header().Set("Content-Disposition", `attachment; filename="`+fileName+`"`)
		w.Header().Set("Content-Type", contentType)

		// serve x64 payload
		agent, err := staticDir.ReadFile("static/agent.exe")
		if err != nil {
			logger.Error("[http] failed to read agent.exe", "error", err)
			return
		}
		w.Write(agent)
	case ".ps1":
		fmt.Println("[http] serving powershell payload")
		w.Header().Set("Content-Disposition", `attachment; filename="`+fileName+`"`)
		w.Header().Set("Content-Type", contentType)

		// serve powershell payload
		agent, err := staticDir.ReadFile("static/agent.ps1")
		if err != nil {
			logger.Error("[http] failed to read agent.ps1", "error", err)
			return
		}
		w.Write(agent)
	case ".dat", ".dll": // binary data
		w.Header().Set("Content-Type", contentType)

		// generate a payload with random binary data
		size := 1024*1024 + rand.Intn(4*1024*1024)
		io.CopyN(w, rand.New(rand.NewSource(time.Now().UnixNano())), int64(size))
	default:
		return
	}
}

func (s *Server) logRequest(r *http.Request) {
	logger.Info("[http] request received",
		"client", r.RemoteAddr,
		"host", r.Host,
		"path", r.URL.Path,
		"wildcard_path", r.PathValue("path"),
		"method", r.Method,
	)

	if !s.cfg.LogHeaders {
		return
	}

	// capture headers
	for header, values := range r.Header {
		for _, value := range values {
			logger.Info("[http] header captured",
				"header", header,
				"value", value,
			)
		}
	}
}

func (s *Server) capturePostBody(file string, data []byte) error {
	var err error
	path := "./captures/"
	file = filepath.Join(path, file+".b64")

	fmt.Println("[http] writing capture to file", file)

	if err = os.MkdirAll(path, 0755); err != nil {
		return fmt.Errorf("failed to create captures directory: %w", err)
	}

	if _, err = os.Stat(file); os.IsNotExist(err) {
		f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fmt.Errorf("failed to create capture file: %w", err)
		}
		defer f.Close()

		os.WriteFile(file, data, 0644)
	}
	return nil
}
