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

type Mode string

const (
	ModeSpoof  Mode = "spoof"
	ModeProxy  Mode = "proxy"
	ModeIgnore Mode = "ignore"
	ModeError  Mode = "error"
)

type Response struct {
	ResponseCode ResponseCode `json:"rcode"`
	RecordType   ResponseType `json:"rtype"`
	Value        string       `json:"value,omitempty"`
	Provisioning Provisioning `json:"provisioning"`
}

type ResponseCode string

const (
	ResponseCodeNoError  ResponseCode = "NOERROR"
	ResponseCodeNXDomain ResponseCode = "NXDOMAIN"
	ResponseCodeServFail ResponseCode = "SERVFAIL"
	ResponseCodeRefused  ResponseCode = "REFUSED"
)

type ResponseType string

const (
	// todo - add more types
	ResponseTypeA    ResponseType = "A"
	ResponseTypeAAAA ResponseType = "AAAA"
	ResponseTypeTXT  ResponseType = "TXT"
)

type Provisioning string

const (
	ProvisioningNone    Provisioning = "none"
	ProvisioningStatic  Provisioning = "static"
	ProvisioningDynamic Provisioning = "dynamic"
	ProvisioningProxy   Provisioning = "proxy"
)

type ActionType string

const (
	ActionPrint ActionType = "print"
	ActionLog   ActionType = "log"
)

type Action struct {
	Type ActionType
	Args map[string]string
}

type Result struct {
	Mode     Mode
	Response Response
	Actions  []Action
	Meta     map[string]string
}

func (r ResponseCode) Valid() bool {
	switch r {
	case ResponseCodeNoError, ResponseCodeNXDomain, ResponseCodeServFail, ResponseCodeRefused:
		return true
	default:
		return false
	}
}

func (t ResponseType) Valid() bool {
	switch t {
	case ResponseTypeA, ResponseTypeAAAA, ResponseTypeTXT:
		return true
	default:
		return false
	}
}

func (t Provisioning) Valid() bool {
	switch t {
	case ProvisioningNone, ProvisioningStatic, ProvisioningDynamic, ProvisioningProxy:
		return true
	default:
		return false
	}
}

func (m Mode) Valid() bool {
	switch m {
	case ModeSpoof, ModeProxy, ModeIgnore, ModeError:
		return true
	default:
		return false
	}
}

func (a ActionType) Valid() bool {
	switch a {
	case ActionPrint, ActionLog:
		return true
	default:
		return false
	}
}
