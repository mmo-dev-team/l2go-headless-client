# L2 Headless Client

[![Go Report Card](https://goreportcard.com/badge/github.com/mmo-dev-team/l2go-headless-client)](https://goreportcard.com/report/github.com/mmo-dev-team/l2go-headless-client)
[![Go Version](https://img.shields.io/github/go-mod/go-version/mmo-dev-team/l2go-headless-client?style=flat-square&logo=go)](https://go.dev/)
[![Release](https://img.shields.io/github/v/release/mmo-dev-team/l2go-headless-client?style=flat-square&logo=github)](https://github.com/mmo-dev-team/l2go-headless-client/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/mmo-dev-team/l2go-headless-client.svg)](https://pkg.go.dev/github.com/mmo-dev-team/l2go-headless-client)
[![License](https://img.shields.io/github/license/mmo-dev-team/l2go-headless-client?style=flat-square)](LICENSE)

A high-performance, **zero-allocation** Go-based headless client for Lineage 2, specifically optimized for `l2go` server environments. Designed for extreme load testing and automated behavioral simulation.

## Core Pillars

- **Absolute Performance:** Engineered with `zero-alloc` in mind. Uses reusable buffers, manual string formatting, and a custom lightweight logger to ensure minimal GC pressure even with thousands of concurrent connections.
- **Full World Entry:** Automates the entire process from Login Server handshake to entering the Game World, including automatic character creation if none exist.
- **Bot Simulation:** Features a sophisticated game loop that simulates player behavior, including movement, combat (physical/magic), social actions, and chat spamming to stress-test server broadcasts.
- **Graceful Lifecycle:** Handles interrupts safely, performing a clean logout for all connected bots to avoid ghost sessions.

## Features

- **Concurrent Load Testing:** Launch N clients simultaneously with auto-generated credential suffixes.
- **Thundering Herd Prevention:** Use `-ramp` to spread connection bursts over time, preventing Login Server congestion.
- **High Five & l2go Support:** Implements the modern packet structure and is synchronized with `l2go-auth` and `l2go-game` protocol specifics.
- **Advanced Crypto:** Supports Rolling XOR (Rolling Key) for Game Server traffic and RSA/Blowfish for Login Server authentication.
- **Custom Logging:** Descriptive (`-detail`) mode shows human-readable packet names for protocol tracing.

## Building

```bash
go build -o l2go-headless-client ./cmd/main.go
```

## Usage

### 1. Automated Pipeline
Provide credentials via flags to automate the full login-to-world flow:
```bash
./l2go-headless-client -ip 127.0.0.1 -login mylogin -password mypass -server 1
```

### 2. Stress Testing (Concurrent Bots)
Spawn multiple concurrent bots. Logins and passwords will be automatically suffixed (e.g., `bot0`, `bot1`, ...):
```bash
./l2go-headless-client -ip 127.0.0.1 -login bot -password pass -thread 500 -ramp 60s
```

### 3. Combat Mode
Keep bots in place but fighting nearby targets to stress test broadcast logic in a specific area:
```bash
./l2go-headless-client -ip 127.0.0.1 -login fighter -password pass -thread 100 -stationary
```

## Command Line Flags

| Flag          | Description | Default |
|:--------------| :--- | :--- |
| `-ip`         | Login Server IP address | `localhost` |
| `-port`       | Login Server Port number | `2106` |
| `-login`      | Login account name (or prefix for `-thread` mode) | (Required) |
| `-password`   | Account password (or prefix for `-thread` mode) | (Required) |
| `-server`     | Order of the game server to select (1-based index) | `1` |
| `-thread`     | Number of concurrent clients for stress testing | `1` |
| `-ramp`       | Spread bot logins evenly across this window (e.g. `30s`) | `0s` |
| `-stationary` | Keep bots in place (disable roaming) while fighting | `false` |
| `-blowfish`   | Static Blowfish key in HEX format | `6B60CB5B82CE90B1CC2B6C556C6C6C6C` |
| `-detail`     | **Descriptive mode**: show human-readable packet names in logs | `false` |

## Project Structure

- `cmd/main.go`: High-performance entry point and CLI logic.
- `internal/client`: Full authentication pipeline and game loop logic.
- `internal/crypto`: High-performance Rolling XOR, RSA, and Blowfish implementations.
- `internal/net`: Optimized length-prefixed packet IO and protocol definitions.
- `internal/logger`: Thread-safe, zero-allocation custom console logger.

## License

This project is open-source and available under the [Mozilla Public License 2.0 (MPL 2.0)](LICENSE).
