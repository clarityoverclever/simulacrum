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
	"log/slog"
	"os"
	"os/signal"
	"simulcrum/internal/logger"
	"syscall"
)

func init() {}

func main() {
	// init logger
	logger.Init(slog.LevelInfo, "json")

	logger.Info("starting simulcrum", "version", "0.0.1")

	// abstract main into run to maintain logging while processing termination signals
	if err := run(); err != nil {
		logger.Error("---MAIN FAILURE---", "error", err)
		os.Exit(1)
	}

	// capture and process terminating signals
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	<-quit
	logger.Info("shutting down application")
}

// main application logic
func run() error {
	logger.Info("running")

	return nil
}
