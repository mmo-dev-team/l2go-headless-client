// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package client

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mmo-dev-team/l2go-headless-client/internal/crypto"
	"github.com/mmo-dev-team/l2go-headless-client/internal/logger"
	l2net "github.com/mmo-dev-team/l2go-headless-client/internal/net"
)

// State represents the current connection state of the client.
type State int

const (
	StateDisconnected State = iota
	StateConnected
	StateInitialized
	StateGGAuth
	StateLoggedIn
	StateGSConnected
	StateGSHandshake
	StateGSLoggedIn
)

// Client is a high-performance headless Lineage 2 client.
type Client struct {
	staticKey     []byte
	Servers       []l2net.GameServer
	inventory     []uint32
	npcs          []uint32
	conn          net.Conn
	gsConn        net.Conn
	reader        *l2net.Reader
	writer        *l2net.Writer
	crypt         *crypto.Crypt
	rsa           *crypto.RSA
	log           *logger.Logger
	attackChan    chan struct{}
	gsReader      *l2net.Reader
	gsWriter      *l2net.Writer
	State         State
	addr          string
	account       string
	password      string
	sessionID     uint32
	loginKey1     uint32
	loginKey2     uint32
	playKey1      uint32
	playKey2      uint32
	objectId      uint32
	classId       uint32
	x             int32
	y             int32
	z             int32
	pendingAppear atomic.Bool
	converged     atomic.Bool
	dead          atomic.Bool
	mp            atomic.Int32
	maxMp         atomic.Int32
	skillReady    sync.Map
	gsCrypt       crypto.GameCrypt
}

// NewClient creates a new headless client instance.
func NewClient(addr, account, password string, staticKey []byte, logger *logger.Logger) *Client {
	return &Client{
		addr:       addr,
		account:    account,
		password:   password,
		staticKey:  staticKey,
		State:      StateDisconnected,
		log:        logger,
		attackChan: make(chan struct{}, 1),
	}
}

// Connect establishes a TCP connection to the Login Server.
func (c *Client) Connect() error {
	conn, err := net.Dial("tcp", c.addr)
	if err != nil {
		return err
	}
	c.conn = conn
	c.reader = l2net.NewReader(conn)
	c.writer = l2net.NewWriter(conn)
	c.State = StateConnected
	return nil
}

// HandleInit processes the initial greeting packet from the Login Server.
func (c *Client) HandleInit() error {
	if c.State != StateConnected {
		return errors.New("invalid state for init")
	}

	data, err := c.reader.Read()
	if err != nil {
		return err
	}

	c.crypt = crypto.NewCrypt(c.staticKey)
	c.crypt.DecryptInit(data)
	c.logPacket("S2C", "Init", data)

	init, err := l2net.DecodeInit(data)
	if err != nil {
		return err
	}

	c.sessionID = init.SessionID
	c.rsa = crypto.NewRSA(init.RSAModulus)

	if len(init.BlowfishKey) > 0 {
		c.crypt.UpdateKey(init.BlowfishKey)
	}

	c.State = StateInitialized
	return nil
}

// SendAuthGG sends a GameGuard authentication request to the Login Server.
func (c *Client) SendAuthGG() error {
	if c.State != StateInitialized {
		return errors.New("invalid state for AuthGG")
	}

	payload := c.writer.Prepare(25)
	l2net.EncodeAuthGGRequestTo(c.sessionID, payload)
	c.logPacket("C2S", "AuthGGRequest", payload)

	encrypted := c.crypt.Encrypt(payload)
	if err := c.writer.Send(len(encrypted)); err != nil {
		return err
	}

	data, err := c.reader.Read()
	if err != nil {
		return err
	}

	if !c.crypt.Decrypt(data) {
		return errors.New("failed to decrypt AuthGG response")
	}
	c.logPacket("S2C", "GGAuthResponse", data)

	if data[0] != l2net.OpGGAuthResponse {
		return errors.New("unexpected AuthGG response opcode")
	}

	c.State = StateGGAuth
	return nil
}

// Login performs credential authentication with the Login Server.
func (c *Client) Login() error {
	if c.State != StateGGAuth && c.State != StateInitialized {
		return errors.New("invalid state for login")
	}

	req := &l2net.LoginRequest{
		Account:   c.account,
		Password:  c.password,
		SessionID: c.sessionID,
	}

	payload, err := l2net.EncodeLoginRequest(req, c.rsa)
	if err != nil {
		return err
	}
	c.logPacket("C2S", "LoginRequest", payload)

	const cryptoOverhead = 16
	buf := c.writer.Prepare(len(payload) + cryptoOverhead)
	copy(buf, payload)
	encrypted := c.crypt.Encrypt(buf[:len(payload)])

	if err = c.writer.Send(len(encrypted)); err != nil {
		return err
	}

	data, err := c.reader.Read()
	if err != nil {
		return err
	}

	if !c.crypt.Decrypt(data) {
		return errors.New("failed to decrypt login response")
	}
	c.logPacket("S2C", "LoginResponse", data)

	opcode := data[0]
	switch opcode {
	case l2net.OpLoginSuccess:
		ok, cErr := l2net.DecodeLoginOk(data)
		if cErr != nil {
			return cErr
		}
		c.loginKey1 = ok.LoginKey1
		c.loginKey2 = ok.LoginKey2
		c.State = StateLoggedIn
	case l2net.OpLoginFail:
		return errors.New(l2net.GetLoginFailReason(data))
	default:
		return errors.New("unexpected login response opcode")
	}

	return nil
}

// FetchServerList retrieves the list of available game servers.
func (c *Client) FetchServerList() error {
	if c.State != StateLoggedIn {
		return errors.New("must be logged in to fetch server list")
	}

	payload := c.writer.Prepare(9)
	l2net.EncodeRequestServerListTo(c.loginKey1, c.loginKey2, payload)
	c.logPacket("C2S", "RequestServerList", payload)

	encrypted := c.crypt.Encrypt(payload)
	if err := c.writer.Send(len(encrypted)); err != nil {
		return err
	}

	data, err := c.reader.Read()
	if err != nil {
		return err
	}

	if !c.crypt.Decrypt(data) {
		return errors.New("failed to decrypt server list")
	}
	c.logPacket("S2C", "ServerList", data)

	if data[0] != l2net.OpServerList {
		return errors.New("unexpected server list opcode")
	}

	sl, err := l2net.DecodeServerList(data)
	if err != nil {
		return err
	}

	c.Servers = sl.Servers
	return nil
}

// SelectServer selects a specific game world and obtains the final session keys.
func (c *Client) SelectServer(serverID uint8) error {
	if c.State != StateLoggedIn {
		return errors.New("must be logged in to select server")
	}

	payload := c.writer.Prepare(10)
	l2net.EncodeRequestServerLoginTo(c.loginKey1, c.loginKey2, serverID, payload)
	c.logPacket("C2S", "RequestServerLogin", payload)

	encrypted := c.crypt.Encrypt(payload)
	if err := c.writer.Send(len(encrypted)); err != nil {
		return err
	}

	data, err := c.reader.Read()
	if err != nil {
		return err
	}

	if !c.crypt.Decrypt(data) {
		return errors.New("failed to decrypt play response")
	}
	c.logPacket("S2C", "PlayOk", data)

	switch data[0] {
	case l2net.OpPlaySuccess:
		ok, cErr := l2net.DecodePlayOk(data)
		if cErr != nil {
			return cErr
		}
		c.playKey1 = ok.PlayKey1
		c.playKey2 = ok.PlayKey2
	case l2net.OpPlayFail:
		return errors.New("server selection failed")
	default:
		return errors.New("unexpected play response opcode")
	}

	return nil
}

// ConnectToGameServer establishes a connection to the selected Game Server.
func (c *Client) ConnectToGameServer(ip [4]byte, port uint16) error {
	// Zero-alloc manual address formatting
	var buf [32]byte
	pos := 0
	for i, b := range ip {
		s := strconv.Itoa(int(b))
		copy(buf[pos:], s)
		pos += len(s)
		if i < 3 {
			buf[pos] = '.'
			pos++
		}
	}
	buf[pos] = ':'
	pos++
	sPort := strconv.Itoa(int(port))
	copy(buf[pos:], sPort)
	pos += len(sPort)

	conn, err := net.Dial("tcp", string(buf[:pos]))
	if err != nil {
		return err
	}
	c.gsConn = conn
	c.gsReader = l2net.NewReader(conn)
	c.gsWriter = l2net.NewWriter(conn)
	c.State = StateGSConnected

	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
	return nil
}

// sendGS encrypts the first n bytes of payload (prepared via gsWriter.Prepare) and
// writes the packet to the Game Server.
func (c *Client) sendGS(payload []byte, n int) error {
	c.gsCrypt.Encrypt(payload[:n])
	return c.gsWriter.Send(n)
}

// recvGS reads and decrypts the next Game Server packet.
func (c *Client) recvGS() ([]byte, error) {
	data, err := c.gsReader.Read()
	if err != nil {
		return nil, err
	}
	c.gsCrypt.Decrypt(data)
	return data, nil
}

// HandshakeToLobby performs the GS handshake and returns the decoded character-selection info,
// leaving the client at the lobby — WITHOUT auto-creating, selecting, or entering the world.
// Used by the functional scenarios that drive create/select/delete/restore explicitly.
func (c *Client) HandshakeToLobby() (*l2net.CharSelectionInfo, error) {
	if c.State != StateGSConnected {
		return nil, errors.New("must be connected to GS")
	}

	// Step 1: Protocol Version (plaintext)
	payload := c.gsWriter.Prepare(5)
	const gsProtocolVersion = 140
	l2net.EncodeProtocolVersionTo(gsProtocolVersion, payload)
	c.logPacket("C2S", "GS:ProtocolVersion", payload)
	if err := c.gsWriter.Send(5); err != nil {
		return nil, err
	}

	// Step 2: Key Exchange (plaintext)
	data, err := c.gsReader.Read()
	if err != nil {
		return nil, err
	}
	c.logPacket("S2C", "GS:KeyPacket", data)
	key, err := l2net.DecodeGSKeyPacket(data)
	if err != nil {
		return nil, err
	}
	c.gsCrypt.Init(key)
	c.State = StateGSHandshake

	// Step 3: Game Auth Login
	size := 1 + len(c.account)*2 + 2 + 16
	payload = c.gsWriter.Prepare(size)
	actualSize := l2net.EncodeAuthLoginTo(c.account, c.playKey1, c.playKey2, c.loginKey1, c.loginKey2, payload)
	c.logPacket("C2S", "GS:AuthLogin", payload[:actualSize])
	if err = c.sendGS(payload, actualSize); err != nil {
		return nil, err
	}

	// Step 4: Login Result
	if data, err = c.recvGS(); err != nil {
		return nil, err
	}
	c.logPacket("S2C", "GS:LoginResult", data)
	if data[0] != l2net.OpGSLoginResult {
		return nil, errors.New("unexpected login result opcode 0x" +
			strconv.FormatInt(int64(data[0]), 16) + " (len " + strconv.Itoa(len(data)) + ")")
	}

	// Step 5: Character Selection Info
	if data, err = c.recvGS(); err != nil {
		return nil, err
	}
	c.logPacket("S2C", "GS:CharSelectionInfo", data)
	if data[0] != l2net.OpGSCharSelectionInfo {
		return nil, errors.New("failed to enter lobby: got opcode 0x" +
			strconv.FormatInt(int64(data[0]), 16))
	}
	return l2net.DecodeCharSelectionInfo(data)
}

// AuthGameServer performs the full handshake then enters the world with a character
// at slot 0 (auto-creating one if the account has none). This is the load-test path.
func (c *Client) AuthGameServer() error {
	charInfo, err := c.HandshakeToLobby()
	if err != nil {
		return err
	}
	var data, payload []byte

	if charInfo.CharacterCount == 0 {
		c.log.Log(c.account, "No characters found, creating a new one...")

		// Clean up account name to use as character name (must be alphanumeric)
		var validName []byte
		for i := 0; i < len(c.account); i++ {
			b := c.account[i]
			if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') {
				validName = append(validName, b)
			}
		}
		if len(validName) == 0 || len(validName) > 16 {
			validName = []byte("BotTestPlayer")
		}

		classId := int32(0) // Human Fighter
		if rand.New(rand.NewSource(time.Now().UnixNano())).Intn(2) == 1 {
			classId = 10 // Human Mystic
		}

		payload = c.gsWriter.Prepare(100)
		createSize := l2net.EncodeGSCharacterCreateTo(string(validName), 0, false, classId, 0, 0, 0, payload)
		c.logPacket("C2S", "GS:CharacterCreate", payload[:createSize])

		c.gsCrypt.Encrypt(payload[:createSize])
		if err = c.gsWriter.Send(createSize); err != nil {
			return err
		}

		// Wait for CharCreateSuccess or Fail
		data, err = c.gsReader.Read()
		if err != nil {
			return err
		}
		c.gsCrypt.Decrypt(data)
		c.logPacket("S2C", "GS:CharCreateResponse", data)

		if data[0] == l2net.OpGSCharCreateFail {
			return errors.New("character creation failed")
		} else if data[0] == l2net.OpGSCharCreateSuccess {
			c.log.Log(c.account, "Character created successfully.")
		} else {
			return errors.New("unexpected character create response opcode")
		}
	}

	// Step 6: Select Character (slot 0)
	c.log.Log(c.account, "Selecting character at slot 0...")
	payload = c.gsWriter.Prepare(30)
	selectSize := l2net.EncodeGSCharacterSelectTo(0, payload)
	c.logPacket("C2S", "GS:CharacterSelect", payload[:selectSize])

	c.gsCrypt.Encrypt(payload[:selectSize])
	if err = c.gsWriter.Send(selectSize); err != nil {
		return err
	}

	// Wait for CharSelected (0x0b)
	for {
		data, err = c.gsReader.Read()
		if err != nil {
			return err
		}
		c.gsCrypt.Decrypt(data)
		c.logPacket("S2C", "GS:ResponseAfterSelect", data)

		if data[0] == l2net.OpGSCharSelected {
			c.log.Log(c.account, "SUCCESS: Entered game with character.")
			objId, classId, x, y, z, iErr := l2net.DecodeCharSelected(data)
			if iErr == nil {
				c.objectId = objId
				c.classId = classId
				c.x, c.y, c.z = x, y, z
			}
			break
		}
	}

	// Step 7: Enter World
	c.log.Log(c.account, "Sending EnterWorld...")
	payload = c.gsWriter.Prepare(110)
	enterSize := l2net.EncodeGSEnterWorldTo(payload)
	c.logPacket("C2S", "GS:EnterWorld", payload[:enterSize])

	c.gsCrypt.Encrypt(payload[:enterSize])
	if err = c.gsWriter.Send(enterSize); err != nil {
		return err
	}

	c.State = StateGSLoggedIn
	return nil
}

// Close closes all active network connections.
func (c *Client) Close() {
	if c.conn != nil {
		_ = c.conn.Close()
	}
	if c.gsConn != nil {
		_ = c.gsConn.Close()
	}
}

// RunGameLoop keeps the connection alive, reads incoming packets, and simulates random movement.
func (c *Client) RunGameLoop(ctx context.Context, stationary bool) {
	if c.State != StateGSLoggedIn {
		return
	}

	// Movement simulation
	go func() {
		// Provide local scope for randomness
		rng := rand.New(rand.NewSource(time.Now().UnixNano()))
		socialActions := []int32{12, 13, 16, 17, 24, 31} // Greeting, Victory, Yes, No, Bow, Dance
		chatPhrases := []string{
			"Hello everyone!",
			"L2GO-Headless-Client is awesome!",
			"Testing chat spam logic...",
			"Anyone wants to party?",
			"WTB some items!",
			"Selling mana potions 1k each",
			"Human Mystic power!",
			"Human Fighter rocks!",
		}
		chatChannels := []int32{0, 1, 8} // General, Shout, Trade
		deathTaunts := []string{
			"brb respawn, you're finished!",
			"I'll be right back and you're done",
			"lucky hit, wait till I return",
			"see you at the res point, then it's over",
		}

		// Persistent roam heading so successive moves accumulate in one direction
		// (the bot genuinely travels far) instead of cancelling out as a random walk.
		roamAngle := rng.Float64() * 2 * math.Pi

		for {
			// After a teleport, ack with C_APPEARING so the server clears
			// IsTeleporting (else movement/ValidatePosition are ignored).
			if c.pendingAppear.CompareAndSwap(true, false) {
				payload := c.gsWriter.Prepare(4)
				size := l2net.EncodeGSAppearingTo(payload)
				c.gsCrypt.Encrypt(payload[:size])
				if err := c.gsWriter.Send(size); err != nil {
					return
				}
				c.log.Log(c.account, "Teleported → sent Appearing")
			}

			// Wait for delay or context cancellation
			delay := time.Second * time.Duration(rng.Intn(2)+1)
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}

			// Dead bots cannot act (the server rejects target/attack on the dead) —
			// they only taunt in chat, then wait. Models a killed player shouting.
			if c.dead.Load() {
				if rng.Intn(3) == 0 {
					phrase := deathTaunts[rng.Intn(len(deathTaunts))]
					payload := c.gsWriter.Prepare(256)
					size := l2net.EncodeGSSay2To(phrase, 0, payload)
					c.logPacket("C2S", "GS:Say2", payload[:size])
					c.gsCrypt.Encrypt(payload[:size])
					if err := c.gsWriter.Send(size); err != nil {
						return
					}
				}
				continue
			}

			// Randomly choose action: 0 = Move, 1 = Social Action, 2 = Use Item, 3 = Attack, 4 = Chat Spam
			actionChoice := rng.Intn(5)

			// Phase-aware: roam during the PvE phase (find village gremlins), but once
			// the convergence hook has teleported us into the PvP cluster, hold position
			// and fight — roaming would disperse the 1k-bot brawl out of attack range.
			effStationary := stationary || c.converged.Load()
			if effStationary {
				if actionChoice == 0 {
					actionChoice = 3
				}
			} else if actionChoice != 0 && rng.Intn(3) == 0 {
				actionChoice = 0
			}

			// Fail-safe: if we chose to Use Item but inventory is empty, fallback to Social Action
			if actionChoice == 2 && len(c.inventory) == 0 {
				actionChoice = 1
			}
			// Fail-safe: if we chose to Attack but no targets are around, fallback to Move
			if actionChoice == 3 && len(c.npcs) == 0 {
				actionChoice = 0
			}

			if actionChoice == 0 {
				// Roam: keep a persistent heading (re-pick occasionally) and take a
				// long stride along it, so the bot actually runs far over time
				// instead of jittering in place.
				if rng.Intn(4) == 0 {
					roamAngle = rng.Float64() * 2 * math.Pi
				}
				stride := float64(800 + rng.Intn(1200)) // 800..2000 units per step
				targetX := c.x + int32(math.Cos(roamAngle)*stride)
				targetY := c.y + int32(math.Sin(roamAngle)*stride)
				targetZ := c.z

				// Send MoveToLocation
				payload := c.gsWriter.Prepare(30)
				size := l2net.EncodeGSMoveToLocationTo(targetX, targetY, targetZ, c.x, c.y, c.z, payload)
				c.logPacket("C2S", "GS:MoveToLocation", payload[:size])
				c.gsCrypt.Encrypt(payload[:size])
				if err := c.gsWriter.Send(size); err != nil {
					return
				}

				c.log.Log(c.account, "Moving to ("+strconv.Itoa(int(targetX))+", "+strconv.Itoa(int(targetY))+")")

				// Simulate time to reach the destination or cancel
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Millisecond * 1500):
				}

				c.x, c.y = targetX, targetY

				// Send ValidatePosition
				payload = c.gsWriter.Prepare(30)
				size = l2net.EncodeGSValidatePositionTo(c.x, c.y, c.z, 0, payload)
				c.logPacket("C2S", "GS:ValidatePosition", payload[:size])
				c.gsCrypt.Encrypt(payload[:size])
				if err := c.gsWriter.Send(size); err != nil {
					return
				}
			} else if actionChoice == 1 {
				// Social Action
				actionId := socialActions[rng.Intn(len(socialActions))]
				c.log.Log(c.account, "Performing social action ID: "+strconv.Itoa(int(actionId)))

				payload := c.gsWriter.Prepare(15)
				size := l2net.EncodeGSRequestActionUseTo(actionId, false, false, payload)
				c.logPacket("C2S", "GS:RequestActionUse", payload[:size])
				c.gsCrypt.Encrypt(payload[:size])
				if err := c.gsWriter.Send(size); err != nil {
					return
				}
			} else if actionChoice == 2 {
				// Equip / Unequip random item
				if len(c.inventory) > 0 {
					itemObjId := c.inventory[rng.Intn(len(c.inventory))]
					c.log.Log(c.account, "Equipping/Unequipping item ObjectID: "+strconv.Itoa(int(itemObjId)))

					payload := c.gsWriter.Prepare(15)
					size := l2net.EncodeGSUseItemTo(itemObjId, false, payload)
					c.logPacket("C2S", "GS:UseItem", payload[:size])
					c.gsCrypt.Encrypt(payload[:size])
					if err := c.gsWriter.Send(size); err != nil {
						return
					}
				}
			} else if actionChoice == 3 {
				// Mass-PvP combat: retarget several times (2-5) like a real player
				// switching targets mid-siege, attacking/casting on each. This is
				// the load pattern that stresses target + attack/skill broadcast.
				if len(c.npcs) > 0 {
					switches := rng.Intn(4) + 2 // 2..5 targets
					for s := 0; s < switches; s++ {
						select {
						case <-ctx.Done():
							return
						default:
						}

						targetObjId := c.npcs[rng.Intn(len(c.npcs))]

						// Target the chosen object (C_ACTION).
						payload := c.gsWriter.Prepare(20)
						size := l2net.EncodeGSActionTo(targetObjId, c.x, c.y, c.z, 0, payload)
						c.logPacket("C2S", "GS:Action", payload[:size])
						c.gsCrypt.Encrypt(payload[:size])
						if err := c.gsWriter.Send(size); err != nil {
							return
						}

						// Class-specific offense. A mystic casts Wind Strike only when it
						// has the mana AND the skill is off cooldown.
						if c.classId == 10 && c.canCast(1177) {
							payload = c.gsWriter.Prepare(15)
							size = l2net.EncodeGSRequestMagicSkillUseTo(1177, false, false, payload)
							c.logPacket("C2S", "GS:MagicSkillUse", payload[:size])
						} else {
							// Fighters: physical attack (C_ATTACK 0x01)
							payload = c.gsWriter.Prepare(20)
							size = l2net.EncodeGSAttackRequestTo(targetObjId, c.x, c.y, c.z, 0, payload)
							c.logPacket("C2S", "GS:Attack", payload[:size])
						}
						c.gsCrypt.Encrypt(payload[:size])
						if err := c.gsWriter.Send(size); err != nil {
							return
						}

						// Drain a stale confirmation, then wait for THIS attack/cast to
						// actually land (server broadcasts S_ATTACK/MagicSkillUse →
						// attackChan) before retargeting. Must be longer than the swing
						// interval / cast time, otherwise rapid retargeting cancels every
						// swing before it lands (no combat ever resolves). Falls through
						// on timeout so a stuck/out-of-range target doesn't hang the bot.
						select {
						case <-c.attackChan:
						default:
						}
						select {
						case <-ctx.Done():
							return
						case <-c.attackChan:
						case <-time.After(time.Duration(2000+rng.Intn(1500)) * time.Millisecond):
						}
					}
					c.log.Log(c.account, "Cycled "+strconv.Itoa(switches)+" targets")

					// Sweep loot dropped by the mobs we just fought.
					// Action 5 = AutoPickup the nearest ground item.
					payload := c.gsWriter.Prepare(15)
					size := l2net.EncodeGSRequestActionUseTo(5, false, false, payload)
					c.logPacket("C2S", "GS:AutoPickup", payload[:size])
					c.gsCrypt.Encrypt(payload[:size])
					if err := c.gsWriter.Send(size); err != nil {
						return
					}
				}
			} else if actionChoice == 4 {
				// Chat Spam
				phrase := chatPhrases[rng.Intn(len(chatPhrases))]
				channel := chatChannels[rng.Intn(len(chatChannels))]

				c.log.Log(c.account, "Sending message to channel "+strconv.Itoa(int(channel))+": "+phrase)

				payload := c.gsWriter.Prepare(256)
				size := l2net.EncodeGSSay2To(phrase, channel, payload)
				c.logPacket("C2S", "GS:Say2", payload[:size])
				c.gsCrypt.Encrypt(payload[:size])
				if err := c.gsWriter.Send(size); err != nil {
					return
				}
			}
		}
	}()

	// Main read loop to consume packets and keep the TCP connection alive
	go func() {
		for {
			data, err := c.gsReader.Read()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					c.log.LogErr(c.account, "Game Server connection closed", err)
					return
				}
			}
			c.gsCrypt.Decrypt(data)

			if len(data) == 0 {
				continue
			}

			// Teleport: update local position
			if data[0] == l2net.OpGSTeleportToLocation {
				if len(data) >= 17 { // body: objectId, x@[5:9], y@[9:13], z@[13:17], ...
					c.x = int32(binary.LittleEndian.Uint32(data[5:9]))
					c.y = int32(binary.LittleEndian.Uint32(data[9:13]))
					c.z = int32(binary.LittleEndian.Uint32(data[13:17]))
				}
				c.logPacket("S2C", "GS:TeleportToLocation", data)
				c.pendingAppear.Store(true)
				c.converged.Store(true) // convergence teleport → stop roaming, hold for PvP
			} else if data[0] == l2net.OpGSDie {
				if len(data) >= 5 && binary.LittleEndian.Uint32(data[1:5]) == c.objectId {
					c.dead.Store(true)
					c.log.Log(c.account, "DIED — cannot act, only chat")
				}
				c.logPacket("S2C", "GS:Die", data)
				// Track our own MP so the bot only casts when it has mana.
			} else if data[0] == l2net.OpGSStatusUpdate {
				if mp, maxMp, ok := l2net.ParseSelfMp(data, c.objectId); ok {
					c.mp.Store(mp)
					if maxMp > 0 {
						c.maxMp.Store(maxMp)
					}
				}
				// Intercept ItemList to find equippable items
			} else if data[0] == l2net.OpGSItemList {
				c.logPacket("S2C", "GS:ItemList", data)
				newItems := l2net.ExtractEquippableItems(data)
				if len(newItems) > 0 {
					c.inventory = newItems
					c.log.Log(c.account, "Extracted "+strconv.Itoa(len(c.inventory))+" equippable items from inventory.")
				}
			} else if data[0] == l2net.OpGSNpcInfo {
				if len(data) >= 5 {
					npcId := binary.LittleEndian.Uint32(data[1:5])
					c.npcs = append(c.npcs, npcId)
				}
				c.logPacket("S2C", "GS:NpcInfo", data)
			} else if data[0] == l2net.OpGSCharInfo {
				if len(data) >= 22 {
					charId := binary.LittleEndian.Uint32(data[18:22])
					if charId != c.objectId {
						c.npcs = append(c.npcs, charId) // Treat other chars as targets too
					}
				}
				c.logPacket("S2C", "GS:CharInfo", data)
			} else if data[0] == l2net.OpGSAttack || data[0] == l2net.OpGSMagicSkillUse {
				if len(data) >= 5 {
					attackerId := binary.LittleEndian.Uint32(data[1:5])
					if attackerId == c.objectId {
						// Signal the movement goroutine that our action landed
						select {
						case c.attackChan <- struct{}{}:
						default:
						}
					}
				}
				if data[0] == l2net.OpGSAttack {
					c.logPacket("S2C", "GS:Attack", data)
				} else {
					// Our own cast confirmed — record the skill's reuse so the bot
					// won't recast it until the cooldown elapses.
					if skillId, reuseMs, ok := l2net.ParseOwnSkillReuse(data, c.objectId); ok && reuseMs > 0 {
						c.skillReady.Store(skillId, time.Now().Add(time.Duration(reuseMs)*time.Millisecond).UnixNano())
					}
					c.logPacket("S2C", "GS:MagicSkillUse", data)
				}
			} else {
				c.logPacket("S2C", "GS:Packet", data)
			}
		}
	}()

	// Block until context is cancelled
	<-ctx.Done()
	c.Logout()
}

// Logout sends the logout packet to the Game Server to gracefully exit.
func (c *Client) Logout() {
	if c.State != StateGSLoggedIn {
		return
	}
	c.log.Log(c.account, "Initiating graceful logout...")
	payload := c.gsWriter.Prepare(1)
	payload[0] = l2net.OpGSLogout
	c.logPacket("C2S", "GS:Logout", payload[:1])
	c.gsCrypt.Encrypt(payload[:1])
	_ = c.gsWriter.Send(1)
	// Give the server a small moment to process before the TCP connection is closed
	time.Sleep(500 * time.Millisecond)
}

// skillMpCost is a conservative MP gate for starter skills.
const skillMpCost = 15

// canCast reports whether the bot may cast skillId now: it has the mana and the skill is off cooldown.
func (c *Client) canCast(skillId uint32) bool {
	if c.mp.Load() < skillMpCost {
		return false
	}
	if v, ok := c.skillReady.Load(skillId); ok {
		if time.Now().UnixNano() < v.(int64) {
			return false
		}
	}
	return true
}

func (c *Client) logPacket(dir, name string, data []byte) {
	if c.log != nil {
		c.log.LogPacket(c.account, dir, name, data)
	}
}
