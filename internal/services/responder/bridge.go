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
	"errors"
	"time"

	lua "github.com/yuin/gopher-lua"
)

type Bridge struct {
	vm         *lua.LState
	store      Store
	ctx        context.Context
	req        RequestContext
	scriptPath string
}

func (b *Bridge) InjectContext(req RequestContext) error {
	b.req = req

	tbl := b.vm.NewTable()
	b.vm.SetField(tbl, "key", lua.LString(req.Key))
	b.vm.SetField(tbl, "kind", lua.LString(req.Kind))
	b.vm.SetField(tbl, "source", lua.LString(req.Source))
	b.vm.SetField(tbl, "target", lua.LString(req.Target))

	meta := b.vm.NewTable()
	for k, v := range req.Meta {
		b.vm.SetField(meta, k, lua.LString(v))
	}
	b.vm.SetField(tbl, "meta", meta)
	b.vm.SetField(tbl, "now", lua.LString(req.Now.Format(time.RFC3339Nano)))

	b.vm.SetGlobal("request", tbl)
	return nil
}

func (b *Bridge) Run() error {
	return b.vm.DoFile(b.scriptPath)
}

func (b *Bridge) Result() (Result, error) {
	tbl, ok := b.vm.Get(-1).(*lua.LTable)
	if !ok {
		return Result{}, errors.New("script did not return a table")
	}

	out := Result{
		Meta: map[string]string{},
	}

	if v := tbl.RawGetString("decision"); v != lua.LNil {
		out.Decision = lua.LVAsString(v)
	}

	if metaTbl, ok := tbl.RawGetString("meta").(*lua.LTable); ok {
		metaTbl.ForEach(func(k, v lua.LValue) {
			key := lua.LVAsString(k)
			val := lua.LVAsString(v)
			out.Meta[key] = val
		})
	}

	return out, nil
}

func (b *Bridge) RegisterFunctions() {
	b.vm.SetGlobal("Observe", b.vm.NewFunction(b.observe))
	b.vm.SetGlobal("Get", b.vm.NewFunction(b.get))

}

func (b *Bridge) observe(L *lua.LState) int {
	if L.GetTop() < 3 {
		L.Push(lua.LBool(false))
		L.Push(lua.LString("observe requires: kind, source, and target"))
		return 2
	}

	if b.store == nil {
		L.Push(lua.LBool(false))
		L.Push(lua.LString("no store configured"))
		return 2
	}

	kind := Kind(L.CheckString(1))
	source := L.CheckString(2)
	target := L.CheckString(3)

	meta := map[string]string{}
	if tbl, ok := L.Get(4).(*lua.LTable); ok {
		tbl.ForEach(func(k, v lua.LValue) {
			key := lua.LVAsString(k)
			val := lua.LVAsString(v)
			meta[key] = val
		})
	}

	obs := Observation{
		Kind:      kind,
		Timestamp: b.req.Now,
		Source:    source,
		Target:    target,
		Meta:      meta,
	}

	_, err := b.store.Observe(b.ctx, b.req.Key, obs)
	if err != nil {
		L.Push(lua.LBool(false))
		L.Push(lua.LString(err.Error()))
		return 2
	}

	L.Push(lua.LBool(true))

	return 1
}

func (b *Bridge) get(L *lua.LState) int {
	if L.GetTop() < 1 {
		L.Push(lua.LString("get requires: key"))
		return 2
	}

	if b.store == nil {
		L.Push(lua.LBool(false))
		L.Push(lua.LString("no store configured"))
		return 2
	}

	record, ok := b.store.Get(b.ctx, Key(L.CheckString(1)))
	if !ok {
		L.Push(lua.LNil)
		return 1
	}

	tbl := b.recordToTable(L, record)
	L.Push(tbl)

	return 1
}

func (b *Bridge) recordToTable(L *lua.LState, record Record) *lua.LTable {
	tbl := L.NewTable()

	L.SetField(tbl, "key", lua.LString(record.Key))
	L.SetField(tbl, "first_seen", lua.LString(record.FirstSeen.Format(time.RFC3339Nano)))
	L.SetField(tbl, "last_seen", lua.LString(record.LastSeen.Format(time.RFC3339Nano)))
	L.SetField(tbl, "dns_queries", lua.LNumber(record.DNSQueries))
	L.SetField(tbl, "http_requests", lua.LNumber(record.HTTPRequests))
	L.SetField(tbl, "tls_handshakes", lua.LNumber(record.TLSHandshakes))

	tags := L.NewTable()
	i := 1
	for tag := range record.Tags {
		L.RawSetInt(tags, i, lua.LString(tag))
		i++
	}
	L.SetField(tbl, "tags", tags)

	meta := L.NewTable()
	for k, v := range record.Meta {
		L.SetField(meta, k, lua.LString(v))
	}
	L.SetField(tbl, "meta", meta)

	return tbl
}
