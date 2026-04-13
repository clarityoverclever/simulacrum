## Simulacrum Open Beta: Modern Malware Simulation & Interception
This project is a modern re-imagination of inetsim, built in Go for speed, isolation, and scriptability. After months of internal development, it is ready for real-world stress testing.

### The Philosophy
I’ve prioritized clarity and simplicity over "clever" features. The goal is to provide a reliable instrument for researchers that stays out of the way until it's needed.

### The "First Run" & Transparency
Sane Defaults: The binary contains embedded defaults. It will run out of the box with no config.

The Scaffold: On the first run, it will generate a config.yaml and a unique Root CA.

HTTPS Support: To enable dynamic TLS minting, you must add the generated rootCA.crt to your guest VM's trusted store and restart the tool.

### Programmable Analysis (Lua API)
The core of this project is the Lua-to-Go bridge. Each request is evaluated by a stateless Lua VM, allowing you to separate the wire response from your own log logic.

Stateful Memory: Use Get() and Observe() to track malware progression over time.

Response Modes: Control the engine with spoof, proxy, ignore, or error modes.

Weighted Routing: (Beta Feature) I am implementing a weight-based priority in the metadata. If multiple scripts match a domain, the highest weight wins.

### What I Need From You
I am looking for "workflow friction" and identification of missing QoL features:

The API Surface: Does the Lua bridge feel expressive enough for the C2 traffic you're seeing?

The "First Run" Experience: Was the transition from "no certs" to "TLS intercepting" clear?

Stability: Does the memory store hold up under high-concurrency requests?

### Community & Future
I am architecting a separate repository for Community Patterns. If you write a script for a specific threat actor, I’d love for you to contribute it once the structure is finalized.
