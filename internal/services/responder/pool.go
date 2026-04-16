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
	"math/rand"
	"simulacrum/internal/core/logger"

	lua "github.com/yuin/gopher-lua"
)

type Worker struct {
	State        *lua.LState
	RequestCount uint64
	MaxRequests  uint64
}

type Pool struct {
	pool chan *Worker
}

func NewPool(size int) *Pool {
	rp := &Pool{
		pool: make(chan *Worker, size),
	}

	for i := 0; i < size; i++ {
		worker := rp.createWorker()
		rp.pool <- &Worker{worker.State, 0, worker.MaxRequests}
	}

	return rp
}

// createWorker creates a new worker vm
func (rp *Pool) createWorker() *Worker {
	base := 125000                                       // ~9 min @ 250 req/s
	jitter := 25000                                      // +- 20%
	top := uint64(base + (rand.Intn(jitter*2) - jitter)) // 1-2 minute stagger for vm lifecycle

	return &Worker{
		State:       lua.NewState(),
		MaxRequests: top,
	}
}

// CheckOut checks out a worker from the pool
func (rp *Pool) CheckOut() (*Worker, error) {
	return <-rp.pool, nil
}

// CheckIn checks in a worker to the pool, recycling it if necessary
func (rp *Pool) CheckIn(worker *Worker, err error) {
	if err != nil {
		logger.Error("vm health update: ", "error", err)

		worker.State.Close()

		newWorker := rp.createWorker()
		rp.pool <- &Worker{newWorker.State, 0, newWorker.MaxRequests}
		return
	}

	// reset the lua stack before returning the worker
	worker.State.SetTop(0)

	worker.RequestCount++
	rp.pool <- worker
}
