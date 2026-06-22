// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"flag"
	"math/rand/v2"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/mmo-dev-team/l2go-headless-client/internal/client"
	"github.com/mmo-dev-team/l2go-headless-client/internal/logger"
)

type creds struct {
	user string
	pass string
}

type botConfig struct {
	log        *logger.Logger
	addr       string
	scenario   string
	creds      []creds
	staticKey  []byte
	ramp       time.Duration
	serverIdx  int
	count      int
	stationary bool
}

func main() {
	os.Exit(run())
}

func run() int {
	// Connection Flags
	ipFlag := flag.String("ip", "", "Login server IP address")
	portFlag := flag.Int("port", 2106, "Login server port number")
	userFlag := flag.String("login", "", "Login account name (prefix for test mode)")
	passFlag := flag.String("password", "", "Account password (prefix for test mode)")

	// Customization Flags
	bfKeyHex := flag.String("blowfish", "6B60CB5B82CE90B1CC2B6C556C6C6C6C", "Static Blowfish key in HEX format")
	serverIdx := flag.Int("server", 1, "Order of the game server to select (1-based)")
	threads := flag.Int("thread", 1, "Number of concurrent clients for stress testing")
	ramp := flag.Duration("ramp", 0, "Spread bot logins evenly across this window (e.g. 30s) instead of all at once; avoids a thundering-herd connection burst")
	detailed := flag.Bool("detail", false, "Enable descriptive packet logging")
	stationary := flag.Bool("stationary", false, "Enable keep bots in place and fighting")
	scenario := flag.String("scenario", "", "Run a functional test scenario (e.g. A) instead of the load loop; with -thread N each client takes a different base class")

	flag.Parse()

	// Initialize the high-performance zero-allocation logger.
	log := logger.NewLogger(*detailed)
	defer log.Flush()

	stdin := bufio.NewReader(os.Stdin)
	addr := resolveAddr(stdin, *ipFlag, *portFlag)
	accountBase, passwordBase := promptCredentials(stdin, *threads, *userFlag, *passFlag)

	if accountBase == "" || passwordBase == "" {
		log.Log("", "ERROR: Login and Password are required")
		return 1
	}

	staticKey, err := hex.DecodeString(*bfKeyHex)
	if err != nil {
		log.Log("", "ERROR: Invalid Blowfish key")
		return 1
	}

	// Create context to handle graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Log("", "Received interrupt signal. Shutting down gracefully...")
		cancel()
	}()

	count := *threads
	log.Log("", "Starting "+strconv.Itoa(count)+" concurrent clients...")

	runFleet(ctx, &botConfig{
		creds:      buildCreds(accountBase, passwordBase, count),
		staticKey:  staticKey,
		addr:       addr,
		scenario:   *scenario,
		log:        log,
		ramp:       *ramp,
		serverIdx:  *serverIdx,
		count:      count,
		stationary: *stationary,
	})

	log.Log("", "Stress test completed. All clients finished.")
	return 0
}

// resolveAddr returns the server address from the flag, or prompts for it interactively.
func resolveAddr(stdin *bufio.Reader, ipFlag string, portFlag int) string {
	if ipFlag != "" {
		return strings.TrimSpace(ipFlag) + ":" + strconv.Itoa(portFlag)
	}
	os.Stdout.WriteString("Enter Server Address (localhost:2106): ")
	line, _ := stdin.ReadString('\n')
	addr := strings.TrimSpace(line)
	if addr == "" {
		return "localhost:2106"
	}
	return addr
}

// promptCredentials returns the account/password bases, prompting interactively only in
// single-client mode when they were not supplied via flags.
func promptCredentials(stdin *bufio.Reader, threads int, userFlag, passFlag string) (string, string) {
	account, password := userFlag, passFlag
	if threads > 1 {
		return account, password
	}
	if account == "" {
		os.Stdout.WriteString("Enter Login: ")
		line, _ := stdin.ReadString('\n')
		account = strings.TrimSpace(line)
	}
	if password == "" {
		os.Stdout.WriteString("Enter Password: ")
		line, _ := stdin.ReadString('\n')
		password = strings.TrimSpace(line)
	}
	return account, password
}

// buildCreds pre-allocates per-client account/password strings to keep the hot loops zero-alloc.
func buildCreds(accountBase, passwordBase string, count int) []creds {
	all := make([]creds, count)
	for i := range count {
		if count > 1 {
			suffix := strconv.Itoa(i)
			all[i] = creds{user: accountBase + suffix, pass: passwordBase + suffix}
		} else {
			all[i] = creds{user: accountBase, pass: passwordBase}
		}
	}
	return all
}

// runFleet spawns one goroutine per simulated client and waits for them all to finish.
func runFleet(ctx context.Context, cfg *botConfig) {
	var wg sync.WaitGroup
	for i := range cfg.count {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			runBot(ctx, id, cfg)
		}(i)
	}
	wg.Wait()
}

// runBot executes the full authentication pipeline for one simulated client and then
// either runs the requested functional scenario or the load loop.
func runBot(ctx context.Context, id int, cfg *botConfig) {
	log := cfg.log

	if cfg.ramp > 0 && cfg.count > 1 {
		slot := time.Duration(int64(cfg.ramp) / int64(cfg.count))
		delay := time.Duration(id) * slot
		if slot > 0 {
			delay += time.Duration(rand.Int64N(int64(slot)))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}

	account := cfg.creds[id].user
	c := client.NewClient(cfg.addr, account, cfg.creds[id].pass, cfg.staticKey, log)
	defer c.Close()

	if !loginPipeline(c, account, log) {
		return
	}

	if len(c.Servers) == 0 {
		log.Log(account, "ERROR: No servers available in list")
		return
	}

	targetIdx := cfg.serverIdx - 1
	if targetIdx < 0 || targetIdx >= len(c.Servers) {
		targetIdx = 0
	}
	s := c.Servers[targetIdx]

	if err := c.SelectServer(s.ID); err != nil {
		log.LogErr(account, "Server selection failed", err)
		return
	}
	if err := c.ConnectToGameServer(s.IP, s.Port); err != nil {
		log.LogErr(account, "Connection to Game Server failed", err)
		return
	}

	// Functional scenario mode: drive the lobby/world explicitly and assert, instead of the load loop.
	if cfg.scenario != "" {
		class := client.StarterClasses[id%len(client.StarterClasses)]
		if sErr := c.RunScenario(cfg.scenario, class); sErr != nil {
			log.LogErr(account, "SCENARIO FAILED", sErr)
		} else {
			log.Log(account, "SCENARIO PASS")
		}
		return
	}

	if err := c.AuthGameServer(); err != nil {
		log.LogErr(account, "Game Server authentication failed", err)
		return
	}

	log.Log(account, "SUCCESS: Entered game world")
	c.RunGameLoop(ctx, cfg.stationary)
}

// loginPipeline runs the Login Server handshake up to fetching the server list.
// It returns false (after logging) on the first failure.
func loginPipeline(c *client.Client, account string, log *logger.Logger) bool {
	if err := c.Connect(); err != nil {
		log.LogErr(account, "Connection to Login Server failed", err)
		return false
	}
	if err := c.HandleInit(); err != nil {
		log.LogErr(account, "Login Server handshake failed", err)
		return false
	}
	if err := c.SendAuthGG(); err != nil {
		log.LogErr(account, "GameGuard verification failed", err)
		return false
	}
	if err := c.Login(); err != nil {
		log.Log(account, "LOGIN FAILED: "+err.Error())
		return false
	}
	log.Log(account, "Login successful")

	if err := c.FetchServerList(); err != nil {
		log.LogErr(account, "Failed to retrieve server list", err)
		return false
	}
	return true
}
