# L2 Headless Client

[![Go Report Card](https://goreportcard.com/badge/github.com/mmo-dev-team/l2go-headless-client)](https://goreportcard.com/report/github.com/mmo-dev-team/l2go-headless-client)
[![Go Version](https://img.shields.io/github/go-mod/go-version/mmo-dev-team/l2go-headless-client?style=flat-square&logo=go)](https://go.dev/)
[![Release](https://img.shields.io/github/v/release/mmo-dev-team/l2go-headless-client?style=flat-square&logo=github)](https://github.com/mmo-dev-team/l2go-headless-client/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/mmo-dev-team/l2go-headless-client.svg)](https://pkg.go.dev/github.com/mmo-dev-team/l2go-headless-client)
[![License](https://img.shields.io/github/license/mmo-dev-team/l2go-headless-client?style=flat-square)](LICENSE)

A high-performance, **zero-allocation** Go-based headless client for Lineage 2, specifically optimized for `l2go` server environments. Designed for extreme load testing and automated pipeline verification.

## Core Pillars

- **Absolute Performance:** Engineered with `zero-alloc` in mind. Uses reusable buffers, manual string formatting, and a custom lightweight logger to ensure minimal GC pressure even with thousands of concurrent connections.
- **Full Pipeline:** Automates the entire process from initial Login Server handshake to entering the Game Server character selection lobby.
- **Interactive & Automated:** Launches in interactive mode by default for ease of use, with powerful CLI flags for automated stress testing.

## Features

- **Concurrent Load Testing:** Launch N clients simultaneously with auto-generated credential suffixes.
- **High Five & l2go Support:** Implements the modern packet structure and is synchronized with `l2go-auth` and `l2go-game` protocol specifics.
- **Advanced Crypto:** Supports Rolling XOR (Rolling Key) for Game Server traffic and RSA/Blowfish for Login Server authentication.
- **Custom Logging:** Descriptive (`-d`) mode shows human-readable packet names for protocol tracing without the overhead of heavy logging libraries.

## Building

```bash
go build -o l2go-headless-client ./cmd/main.go
```

## Usage

### 1. Interactive Mode (Default)
Simply run the client and follow the prompts:
```bash
./l2go-headless-client
```

### 2. Automated Pipeline
Provide credentials via flags to skip prompts and automate the login-to-lobby flow:
```bash
./l2go-headless-client -ip 127.0.0.1 -l mylogin -p mypass -s 1
```

### 3. Stress Testing (Concurrent Connections)
Use the `-t` flag to spawn multiple concurrent bots. Logins and passwords will be automatically suffixed (e.g., `bot0`, `bot1`, ...):
```bash
./l2go-headless-client -ip 127.0.0.1 -l bot -p pass -t 500 -s 1
```

## Command Line Flags

| Flag | Description | Default |
| :--- | :--- | :--- |
| `-ip` | Login Server IP address | `localhost` |
| `-port` | Login Server Port number | `2106` |
| `-l` | Login account name (or prefix for `-t` mode) | (Interactive) |
| `-p` | Account password (or prefix for `-t` mode) | (Interactive) |
| `-s` | Order of the game server to select (1-based index) | `1` |
| `-t` | Number of concurrent clients for stress testing | `1` |
| `-bf` | Static Blowfish key in HEX format | `6B60CB5B82CE90B1CC2B6C556C6C6C6C` |
| `-d` | **Descriptive mode**: show human-readable packet names in logs | `false` |

## Project Structure

- `cmd/main.go`: High-performance entry point and CLI logic.
- `internal/client`: Full authentication pipeline management (Login $\rightarrow$ GS Lobby).
- `internal/crypto`: High-performance Rolling XOR, RSA, and Blowfish implementations.
- `internal/net`: Optimized length-prefixed packet IO and protocol definitions.
- `internal/logger`: Thread-safe, zero-allocation custom console logger.

## License

This project is open-source and available under the [Mozilla Public License 2.0 (MPL 2.0)](LICENSE).
