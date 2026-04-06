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

package responder

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

//go:embed static/default.lua
var defaultRules []byte

type Resolver struct {
	RulesPath string
	Rules     map[string]string
}

func NewResolver(rulesPath string) (*Resolver, error) {
	resolver := Resolver{
		RulesPath: rulesPath,
		Rules:     make(map[string]string),
	}

	if err := EnsureDefaultRules(rulesPath); err != nil {
		return nil, fmt.Errorf("resolver failed to ensure rules directory: %w", err)
	}

	if err := resolver.LoadScripts(); err != nil {
		return nil, fmt.Errorf("resolver failed to load scripts: %w", err)
	}
	return &resolver, nil
}

func (r *Resolver) LoadScripts() error {
	entries, err := os.ReadDir(r.RulesPath)
	if err != nil {
		return fmt.Errorf("failed to read scripts directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) != ".lua" {
			continue
		}

		name := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		name = strings.ToLower(strings.TrimSpace(name))

		r.Rules[name] = filepath.Join(r.RulesPath, entry.Name())
	}

	return nil
}

func (r *Resolver) GetRule(name string) (string, bool) {
	name = normalizeRuleName(name)

	for _, candidate := range ruleCandidates(name) {
		if rule, ok := r.Rules[candidate]; ok {
			return rule, true
		}
	}

	return "", false
}

func normalizeRuleName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.TrimSuffix(name, ".")
	return name
}

func ruleCandidates(name string) []string {
	if name == "" {
		return []string{"default"}
	}

	parts := strings.Split(name, ".")
	candidates := make([]string, 0, len(parts)+1)

	for i := 0; i < len(parts); i++ {
		candidates = append(candidates, strings.Join(parts[i:], "."))
	}

	candidates = append(candidates, "default")
	return candidates
}

// EnsureDefaultRules creates a default.lua file from the embedded default
func EnsureDefaultRules(path string) error {
	err := os.MkdirAll(path, 0755)
	if err != nil {
		return fmt.Errorf("failed to create rules directory: %w", err)
	}

	ruleFile := filepath.Join(path, "default.lua")

	_, err = os.Stat(ruleFile)
	if os.IsNotExist(err) {
		err = os.WriteFile(ruleFile, defaultRules, 0644)
		if err != nil {
			return fmt.Errorf("failed to write default.lua: %w", err)
		}
	}

	return nil
}
