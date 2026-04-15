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

package dns

import "sync"

type ignore struct {
	list       map[string]struct{} // domain -> response
	ignoreLock sync.RWMutex
}

func newIgnoreList() *ignore {
	return &ignore{
		list: make(map[string]struct{}),
	}
}

func (i *ignore) add(domain string) bool {
	i.ignoreLock.Lock()
	defer i.ignoreLock.Unlock()

	_, ok := i.list[domain]
	if ok {
		return ok
	}

	i.list[domain] = struct{}{}
	return ok
}

func (i *ignore) remove(domain string) bool {
	i.ignoreLock.Lock()
	defer i.ignoreLock.Unlock()

	_, ok := i.list[domain]
	if ok {
		delete(i.list, domain)
	}

	return ok
}

func (i *ignore) checkIsIgnored(domain string) bool {
	i.ignoreLock.RLock()
	defer i.ignoreLock.RUnlock()

	_, ok := i.list[domain]
	return ok
}
