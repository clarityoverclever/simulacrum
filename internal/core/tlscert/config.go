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

package tlscert

import "fmt"

type TLSConfig struct {
	Mode string
	Cert string
	Key  string
}

func (c *TLSConfig) Validate() error {
	if c.Mode == "" {
		return fmt.Errorf("mode cannot be empty")
	}

	switch c.Mode {
	case "static":
		if c.Cert == "" || c.Key == "" {
			return fmt.Errorf("static mode requires both cert and key")
		}
	case "dynamic":
		return fmt.Errorf("dynamic mode is not implemented")
	default:
		return fmt.Errorf("unsupported mode: %s", c.Mode)
	}

	return nil
}
