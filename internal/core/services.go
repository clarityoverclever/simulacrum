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

package core

import "net"

type Status string

const (
	StatusRunning Status = "running"
	StatusStopped Status = "stopped"
	StatusError   Status = "error"
)

type ControlAction string

const (
	ActionStart   ControlAction = "start"
	ActionStop    ControlAction = "stop"
	ActionRestart ControlAction = "restart"
	ActionStatus  ControlAction = "status"
	ActionUpdate  ControlAction = "update"
)

type ControlMessage struct {
	Action  ControlAction  `json:"action"`
	Service string         `json:"service"`
	Params  map[string]any `json:"params,omitempty"`
}

type ControlResponse struct {
	Status  Status `json:"status"`
	Message string `json:"message"`
}

type Service interface {
	Name() string
	Run(listener net.Listener) error
}
