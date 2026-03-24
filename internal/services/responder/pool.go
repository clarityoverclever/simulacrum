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

import lua "github.com/yuin/gopher-lua"

type Pool struct {
	pool chan *lua.LState
}

func NewPool(size int) *Pool {
	rp := &Pool{
		pool: make(chan *lua.LState, size),
	}

	for i := 0; i < size; i++ {
		worker := lua.NewState()
		rp.pool <- worker
	}

	return rp
}

func (rp *Pool) CheckOut() (*lua.LState, error) {
	return <-rp.pool, nil
}

func (rp *Pool) CheckIn(worker *lua.LState) {
	rp.pool <- worker
}
