// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/mmo-dev-team/l2go-headless-client/internal/client"
	"github.com/mmo-dev-team/l2go-headless-client/internal/logger"
)

func main() {
	// Connection Flags
	ipFlag := flag.String("ip", "", "Login server IP address")
	portFlag := flag.Int("port", 2106, "Login server port number")
	userFlag := flag.String("l", "", "Login account name (prefix for test mode)")
	passFlag := flag.String("p", "", "Account password (prefix for test mode)")

	// Customization Flags
	bfKeyHex := flag.String("bf", "6B60CB5B82CE90B1CC2B6C556C6C6C6C", "Static Blowfish key in HEX format")
	serverIdx := flag.Int("s", 1, "Order of the game server to select (1-based)")
	threads := flag.Int("t", 1, "Number of concurrent clients for stress testing")
	detailed := flag.Bool("d", false, "Enable descriptive packet logging")

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

				if err = c.AuthGameServer(); err != nil {
					log.LogErr(currentAccount, "Game Server authentication failed", err)
					return
				}

				log.Log(currentAccount, "SUCCESS: Entered character selection lobby")
			} else {
				log.Log(currentAccount, "ERROR: No servers available in list")
			}
		}(i)
	}

	wg.Wait()
	log.Log("", "Stress test completed. All clients finished.")
}
