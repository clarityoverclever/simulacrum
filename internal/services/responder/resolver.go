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
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Resolver struct {
	RulesPath string
	Rules     map[string]string
}

func NewResolver(rulesPath string) (*Resolver, error) {
	resolver := Resolver{
		RulesPath: rulesPath,
		Rules:     make(map[string]string),
	}
	err := resolver.LoadScripts()
	if err != nil {
		return nil, fmt.Errorf("resolver failed to load scripts: %w", err)
	}

	return &resolver, nil
}

func (r *Resolver) LoadScripts() error {
	scripts, err := os.ReadDir(r.RulesPath)
	if err != nil {
		return fmt.Errorf("failed to read scripts directory: %w", err)
	}

	for _, script := range scripts {
		if script.IsDir() {
			continue
		}

		if filepath.Ext(script.Name()) != ".lua" {
			continue
		}

		// normalize lookup key
		name := filepath.Base(script.Name())
		key := strings.TrimSuffix(strings.TrimSpace(name), filepath.Ext(name))
		key = strings.ToLower(key)

		fullPath := filepath.Join(r.RulesPath, script.Name())
		r.Rules[key] = fullPath
	}

	return nil
}

func (r *Resolver) GetRule(name string) (string, bool) {
	// normalize lookup key
	key := strings.ToLower(name)

	rule, ok := r.Rules[key]
	if !ok {
		rule, ok = r.Rules["default"]
	}

	return rule, ok
}
