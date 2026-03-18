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

package inspect

import "math"

// Shannon calculates the entropy of a byte slice, returning a value of increasing randomness 0-8
func Shannon(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	countsByByte := make(map[byte]int)

	for _, b := range data {
		countsByByte[b]++
	}
	var entropy float64

	for _, count := range countsByByte {
		p := float64(count) / float64(len(data))
		entropy -= p * math.Log2(p)
	}

	return entropy
}
