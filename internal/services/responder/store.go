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
	"time"
)

type Key string
type Kind string

const (
	KindDNS  Kind = "dns"
	KindHTTP Kind = "http"
	KindTLS  Kind = "tls"
)

type Observation struct {
	Kind      Kind
	Timestamp time.Time
	Source    string
	Target    string
	Meta      map[string]string
}

type Record struct {
	Key       Key
	FirstSeen time.Time
	LastSeen  time.Time

	DNSQueries    uint64
	HTTPRequests  uint64
	TLSHandshakes uint64

	Tags map[string]struct{}
	Meta map[string]string
}

type Store interface {
	Get(ctx context.Context, key Key) (Record, bool)
	GetOrCreate(ctx context.Context, key Key) (Record, error)
	Observe(ctx context.Context, key Key, obs Observation) (Record, error)
	UpdateMeta(ctx context.Context, key Key, values map[string]string) (Record, error)
	AddTag(ctx context.Context, key Key, tag string) (Record, error)
	RemoveTag(ctx context.Context, key Key, tag string) (Record, error)
	MarkSeen(ctx context.Context, key Key, at time.Time) (Record, error)
	Delete(ctx context.Context, key Key) error
	PruneExpired(ctx context.Context, olderThan time.Time) (int, error)
}
