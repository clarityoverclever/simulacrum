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

package logger

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/natefinch/lumberjack"
)

type requestIDKey struct{}

// Init initializes the logger
func Init(level slog.Level, logFilePath string) error {
	logDir := filepath.Dir(logFilePath)

	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	logWriter := &lumberjack.Logger{
		Filename:   logFilePath,
		MaxSize:    100, // megabytes
		MaxAge:     30,  //days
		MaxBackups: 5,
		LocalTime:  true,
	}

	handler := slog.NewJSONHandler(logWriter, &slog.HandlerOptions{
		Level: level,
	})

	logger := slog.New(handler)
	slog.SetDefault(logger)

	return nil
}

// Info logs a message
func Info(msg string, args ...any) {
	slog.Info(msg, args...)
}

// Error logs an error
func Error(msg string, args ...any) {
	slog.Error(msg, args...)
}

// Debug logs a debug message
func Debug(msg string, args ...any) {
	slog.Debug(msg, args...)
}

// Warn logs a warning
func Warn(msg string, args ...any) {
	slog.Warn(msg, args...)
}

// WithReqID attaches a request ID to the context used for logging.
func WithReqID(ctx context.Context, reqID string) context.Context {
	if reqID == "" {
		return ctx
	}
	return context.WithValue(ctx, requestIDKey{}, reqID)
}

func fromContext(ctx context.Context) *slog.Logger {
	if ctx == nil {
		return slog.Default()
	}
	if reqID, ok := ctx.Value(requestIDKey{}).(string); ok && reqID != "" {
		return slog.Default().With("req_id", reqID)
	}
	return slog.Default()
}

func InfoContext(ctx context.Context, msg string, args ...any) {
	fromContext(ctx).Info(msg, args...)
}

func WarnContext(ctx context.Context, msg string, args ...any) {
	fromContext(ctx).Warn(msg, args...)
}

func ErrorContext(ctx context.Context, msg string, args ...any) {
	fromContext(ctx).Error(msg, args...)
}

func DebugContext(ctx context.Context, msg string, args ...any) {
	fromContext(ctx).Debug(msg, args...)
}
