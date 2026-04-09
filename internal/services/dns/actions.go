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

import (
	"context"
	"fmt"
	"simulacrum/internal/core/logger"
	"simulacrum/internal/services/responder"
	"sort"
	"strings"
)

func (s *Server) actionHandler(ctx context.Context, actions []responder.Action) error {
	for _, action := range actions {
		switch action.Type {
		case "log":
			// extract and sort map keys
			keys := make([]string, 0, len(action.Args)*2)
			for k := range action.Args {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			// build log message in a fixed order
			message := make([]any, 0, len(action.Args)*2)
			for _, k := range keys {
				message = append(message, k, action.Args[k])
			}

			logger.InfoContext(ctx, "[action_log]", message...)
		case "print":
			var message strings.Builder

			// extract and sort map keys
			keys := make([]string, 0, len(action.Args)*2)
			for k := range action.Args {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			// build print output in a fixed order
			for i, k := range keys {
				if i > 0 {
					message.WriteString(",")
				}
				fmt.Fprintf(&message, "\"%s\":\"%v\"", k, action.Args[k])
			}

			fmt.Println(message.String())
		}
	}

	return nil
}
