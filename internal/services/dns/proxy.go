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
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

func (s *Server) handleProxyRequest(w dns.ResponseWriter, r *dns.Msg) (*dns.Msg, error) {
	fmt.Printf("Proxying DNS request to %s\n", s.upstreamDNS)
	isTCP := false
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		isTCP = true
	}

	client := new(dns.Client)
	client.Timeout = 2 * time.Second

	if isTCP {
		client.Net = "tcp"
	} else {
		client.Net = "udp"
	}

	response, _, err := client.Exchange(r, s.upstreamDNS)
	if err != nil {
		fmt.Println("Error proxying DNS request:", err)
		return nil, err
	}

	err = captureProxyResponse(response)

	return response, nil
}

func captureProxyResponse(response *dns.Msg) error {
	// todo implement response capture logic
	return nil
}
