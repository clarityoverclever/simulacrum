
---
# simulacrum

## Overview
Simulacrum aims to provide deterministic network behavior for analysis and testing in controlled environments.

---

## Open Beta
### This project is in open beta, under active development, and the documentation is incomplete. 
### Read more about the Open Beta [here](https://github.com/clarityoverclever/simulacrum/blob/main/OPEN-BETA.md).

---

### Objectives
Tools like INetSim laid the groundwork for network simulation in malware analysis and have been the backbone of network simulation for years; however, as malware has evolved, the tool is starting to show its age.
Simulacrum aims to bridge the gap by providing a modern network simulator with an extensible, forward-looking design built for today’s threat landscape.

## Features
- supplies configurable servers on a data plane (DNS, HTTP(S), NTP)
- smart DNS that uses upstream checks to keep the malware's view of the world realistic
- dynamic TLS minting with a pre-installed trusted root to prevent broken handshakes and capture encrypted traffic
- time manipulation via an NTP multiplier
- structured logging for analysis

### DNS
- Serves DNS on configurable port
- Dynamic and scriptable DNS response construction
- Custom response modes to allow static and dynamic spoofing with local DNAT, or transparent proxy behavior
- Optional upstream checks against upstream DNS server
- DNS spoofing using a configurable CIDR subnet
- DNS tunneling detection with a configurable threshold

### HTTP(S)
- Serves HTTP with file service on  configurable port
- Capture POST data into Base64 files for later analysis
- Optional logging of HTTP request headers
- Optional spoofed HTTP request payload delivery with a canary file (ps1, exe)

### TLS with Dynamic Certificate Management
- Manages TLS certificates for HTTPS
- intercepts outbound TLS connections and mints a leaf certificate for the requested SNI
- caches leaf certificates in memory for reuse

### NTP
- Serves NTP
- Supports adding a time multiplier to NTP datagram

---

## How to Use
```bash
git clone https://github.com/simulacrum/simulacrum.git

cd simulacrum

# build data plane
go build ./cmd/simulacrum/simulacrum.go

# build control plane
go build ./cmd/simctl/simctl.go
````

## How It Works
1. simulacrum listens on a specified IP and port for DNS queries.
2. Each query is intercepted and passed to a virtual response environment where the analyst defines the response behavior.
3. Logs provide visibility into query flow and behavior.

## Installation
1. git clone https://github.com/simulacrum/simulacrum.git
2. cd simulacrum
3. go build ./cmd/simulacrum/simulacrum.go
4. sudo ./simulacrum

the first time you run simulacrum, default config, rules, and certs will be generated
5. Add ./certs/ca.crt to the trusted root certificates on the target system.

---

## Configuration
file: ./config/config.yaml

### dns
- **enabled:** `true | false`  
  Controls whether the DNS server starts at launch.

- **bind_addr:** `IP:PORT`  
  Address and port simulacrum binds to for snooping DNS traffic.

- **analysis_ip:** `IP`  
  The IP returned for all DNS queries when spoofing is disabled.

- **verify_upstream:** `true | false`  
  Enables upstream DNS health checks.

- **upstream_dns:** `IP:PORT`  
  Required when `check_liveness` is enabled.

- **default_subnet:** `CIDR`  
  Subnet used to generate spoofed IPs.

- **tunnel_detection_threshold:** `float`  
  Threshold for tunneling detection. 4.0 is recommended

### ntp
- **enabled:** `true | false`  
  Controls whether the NTP server starts at launch.

- **bind_addr:** `IP:PORT`  
  Address and port serving NTP.

- **multiplier:** `float`  
  Multiplier applied to NTP timestamps.

### http
- **enabled:** `true | false`  
  Controls whether the HTTP server starts at launch.

- **bind_addr:** `IP:PORT`  
  Address and port simulacrum binds to for serving HTTP traffic.

### https
- **enabled:** `true | false`  
  Controls whether the HTTP server starts at launch.

- **bind_addr:** `IP:PORT`  
  Address and port simulacrum binds to for serving HTTP traffic.

### common_web:
- **max_body_kb:** `int`  
  Maximum capture size of HTTP POST request bodies in kilobytes.

- **log_headers:** `true | false`  
  Enables logging of HTTP request headers.

- **spoof_payload:** `true | false`  
  Enables spoofing of HTTP request payloads (ps1, exe, binary.

### tls
- **cert_mode:** `static` || `dynamic` 
  Controls how TLS certificates are managed.

- **cert_file:** `PATH`
  Path to TLS certificate file for static mode.

- **key_file:** `PATH`
  Path to TLS key file for static mode.

### ca
- **cert_file:** `PATH`
  Path to CA root certificate file. This needs to be installed on the target system Local Machine Trusted Root Certification Authorities.

- **key_file:** `PATH`
  Path to CA root key file.
- 
- **common_name:** `string`
  Common name for the CA root certificate.

- **organization:** `string`
  Organization for the CA root certificate.

- **root_validity_days:** `int`
  Validity period for the CA root certificate in days.

- **leaf_validity_days:** `int`
  Validity period for the leaf certificate in days.

### responder
- **rules_path:** `PATH`  
  Path to responder rules directory.
- **pool_size:** `int`  
  Maximum number of concurrent virtual machine connections.

### Example
```yaml
dns:
  enabled: true
  bind_addr: 0.0.0.0:53
  analysis_ip: 192.168.117.128
  verify_upstream: true
  upstream_dns: 9.9.9.9:53
  default_subnet: 10.0.1.0/8
  tunnel_detection_threshold: 4.0
ntp:
  enabled: true
  bind_addr: 0.0.0.0:123
  multiplier: 1.0
http:
  enabled: true
  bind_addr: 0.0.0.0:80
https:
  enabled: true
  bind_addr: 0.0.0.0:443
common_web:
  log_headers: false
  spoof_payload: true
  max_body_kb: 64
tls:
  cert_mode: dynamic
  cert_file: ./certs/https.crt
  key_file: ./certs/https.key
ca:
  cert_file: ./certs/ca.crt
  key_file: ./certs/ca.key
  common_name: "Simulacrum Root CA"
  organization: "Simulacrum"
  root_validity_days: 3650
  leaf_validity_days: 7
responder:
  rules_path: ./rules
  pool_size: 4
```

### Usage
1. Edit the configuration file with your desired settings.
2. Ensure the listening port (typically 53) is available.
3. Start simulacrum (root/sudo required for privileged ports and DNAT).

### Notes
#### Enable IP forwarding on host for spoofing
```bash
sudo sysctl -w net.ipv4.ip_forward=1

# add persistent IP forwarding if needed
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
```

#### Inspect the PREROUTING NAT table
```bash
sudo iptables -t nat -L PREROUTING -n -v
```

#### Build exe agent
```bash
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o agent.exe ./cmd/agent/agent.go

mv ./agent.exe ./internal/services/web/static/
```

### What's Next
- [ ] SMTP/s sinkhole, credential, and payload collection
- [ ] Capture support for proxied requests
- [ ] Whitelist to bypass apex resolution safety on suspected DNS tunnels
- [ ] DNS over HTTPS support
- [ ] Scriptable HTTP/s responder support
- [ ] Bidirectional communication support for canary files
- [ ] Enhanced canary file capabilities for environmental analysis
- [ ] Persistent memory store with snapshotting
- [ ] expand control plane integration
- [ ] improve first run experience with --init