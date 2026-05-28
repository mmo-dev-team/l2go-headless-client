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

func main() {
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

	var addr string
	// Interactive logic for server address if not provided via flags.
	if *ipFlag != "" {
		addr = strings.TrimSpace(*ipFlag) + ":" + strconv.Itoa(*portFlag)
	} else {
		os.Stdout.WriteString("Enter Server Address (localhost:2106): ")
		line, _ := stdin.ReadString('\n')
		addr = strings.TrimSpace(line)
		if addr == "" {
			addr = "localhost:2106"
		}
	}

	accountBase := *userFlag
	passwordBase := *passFlag

	// Prompt for credentials if not in bulk test mode.
	if *threads <= 1 {
		if accountBase == "" {
			os.Stdout.WriteString("Enter Login: ")
			line, _ := stdin.ReadString('\n')
			accountBase = strings.TrimSpace(line)
		}
		if passwordBase == "" {
			os.Stdout.WriteString("Enter Password: ")
			line, _ := stdin.ReadString('\n')
			passwordBase = strings.TrimSpace(line)
		}
	}

	if accountBase == "" || passwordBase == "" {
		log.Log("", "ERROR: Login and Password are required")
		os.Exit(1)
	}

	staticKey, err := hex.DecodeString(*bfKeyHex)
	if err != nil {
		log.Log("", "ERROR: Invalid Blowfish key")
		os.Exit(1)
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

	var wg sync.WaitGroup
	count := *threads

	log.Log("", "Starting "+strconv.Itoa(count)+" concurrent clients...")

	// Pre-allocate account and password strings to reach Zero-Alloc in hot loops.
	type creds struct {
		user string
		pass string
	}
	allCreds := make([]creds, count)
	for i := 0; i < count; i++ {
		if count > 1 {
			suffix := strconv.Itoa(i)
			allCreds[i] = creds{
				user: accountBase + suffix,
				pass: passwordBase + suffix,
			}
		} else {
			allCreds[i] = creds{user: accountBase, pass: passwordBase}
		}
	}

	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			if *ramp > 0 && count > 1 {
				slot := time.Duration(int64(*ramp) / int64(count))
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

			currentAccount := allCreds[id].user
			c := client.NewClient(addr, currentAccount, allCreds[id].pass, staticKey, log)
			defer c.Close()

			// Execute the full authentication pipeline.
			if err = c.Connect(); err != nil {
				log.LogErr(currentAccount, "Connection to Login Server failed", err)
				return
			}

			if err = c.HandleInit(); err != nil {
				log.LogErr(currentAccount, "Login Server handshake failed", err)
				return
			}

			if err = c.SendAuthGG(); err != nil {
				log.LogErr(currentAccount, "GameGuard verification failed", err)
				return
			}

			if err = c.Login(); err != nil {
				log.Log(currentAccount, "LOGIN FAILED: "+err.Error())
				return
			}
			log.Log(currentAccount, "Login successful")

			if err = c.FetchServerList(); err != nil {
				log.LogErr(currentAccount, "Failed to retrieve server list", err)
				return
			}

			serverCount := len(c.Servers)
			if serverCount > 0 {
				targetIdx := *serverIdx - 1
				if targetIdx < 0 || targetIdx >= serverCount {
					targetIdx = 0
				}
				s := c.Servers[targetIdx]

				if err = c.SelectServer(s.ID); err != nil {
					log.LogErr(currentAccount, "Server selection failed", err)
					return
				}

				if err = c.ConnectToGameServer(s.IP, s.Port); err != nil {
					log.LogErr(currentAccount, "Connection to Game Server failed", err)
					return
				}

				// Functional scenario mode: drive the lobby/world explicitly and assert, instead of the load loop.
				if *scenario != "" {
					class := client.StarterClasses[id%len(client.StarterClasses)]
					if sErr := c.RunScenario(*scenario, class); sErr != nil {
						log.LogErr(currentAccount, "SCENARIO FAILED", sErr)
					} else {
						log.Log(currentAccount, "SCENARIO PASS")
					}
					return
				}

				if err = c.AuthGameServer(); err != nil {
					log.LogErr(currentAccount, "Game Server authentication failed", err)
					return
				}

				log.Log(currentAccount, "SUCCESS: Entered game world")
				c.RunGameLoop(ctx, *stationary)
			} else {
				log.Log(currentAccount, "ERROR: No servers available in list")
			}
		}(i)
	}

	wg.Wait()
	log.Log("", "Stress test completed. All clients finished.")
}
