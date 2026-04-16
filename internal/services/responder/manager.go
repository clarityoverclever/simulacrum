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
	"context"
	"fmt"
	"time"

	lua "github.com/yuin/gopher-lua"
)

type Manager struct {
	pool     *Pool
	store    Store
	resolver *Resolver
}

type Config struct {
	PoolSize  int
	RulesPath string
}

type RequestContext struct {
	Key    Key
	Kind   Kind
	Source string
	Target string
	Inputs Inputs
	Meta   map[string]string
	Now    time.Time
}

type Inputs struct {
	IsSuspectedTunnel bool
	Entropy           float64
	TestedUpstream    bool
	IsAlive           bool
}

func NewManager(pool *Pool, store Store, resolver *Resolver) *Manager {
	return &Manager{pool: pool, store: store, resolver: resolver}
}

func (m *Manager) Handle(ctx context.Context, req RequestContext) (Result, error) {
	rule, ok := m.resolver.GetRule(req.Target)
	if !ok {
		return Result{}, fmt.Errorf("no rule found for target: %s", req.Target)
	}

	vm, err := m.pool.CheckOut()
	if err != nil {
		return Result{}, fmt.Errorf("failed to checkout VM: %w", err)
	}

	// capture any errors from the VM and pass them to the check-in function for handling
	defer func() {
		// execute vm lifecycle tombstone
		if vm.RequestCount > vm.MaxRequests {
			err = fmt.Errorf("VM request count exceeded: %d", vm.RequestCount)
		}

		m.pool.CheckIn(vm, err)
	}()

	bridge := m.newBridge(vm.State, ctx, req, rule)

	if err = bridge.InjectContext(req); err != nil {
		return Result{}, fmt.Errorf("failed to inject context: %w", err)
	}

	bridge.RegisterFunctions()

	if err = bridge.Run(); err != nil {
		return Result{}, err
	}

	response, err := bridge.Result()
	if err != nil {
		return Result{}, err
	}

	return response, nil
}

func (m *Manager) newBridge(vm *lua.LState, ctx context.Context, req RequestContext, scriptPath string) *Bridge {
	return &Bridge{
		vm:         vm,
		store:      m.store,
		ctx:        ctx,
		req:        req,
		scriptPath: scriptPath,
	}
}
