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
	"math/rand/v2"
	"net"
	"slices"
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
	conn          net.Conn
	gsConn        net.Conn
	reader        *l2net.Reader
	gsReader      *l2net.Reader
	gsWriter      *l2net.Writer
	log           *logger.Logger
	crypt         *crypto.Crypt
	writer        *l2net.Writer
	rsa           *crypto.RSA
	attackChan    chan struct{}
	inventory     atomic.Pointer[[]uint32]
	skillReady    sync.Map
	addr          string
	password      string
	account       string
	npcs          []uint32
	Servers       []l2net.GameServer
	staticKey     []byte
	npcsNext      int
	State         State
	npcsMu        sync.Mutex
	playKey2      uint32
	loginKey2     uint32
	playKey1      uint32
	sessionID     uint32
	objectID      uint32
	classID       uint32
	loginKey1     uint32
	x             atomic.Int32
	y             atomic.Int32
	z             atomic.Int32
	mp            atomic.Int32
	maxMp         atomic.Int32
	pendingAppear atomic.Bool
	converged     atomic.Bool
	dead          atomic.Bool
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
		npcs:       make([]uint32, 0, 256),
	}
}

// Connect establishes a TCP connection to the Login Server.
func (c *Client) Connect() error {
	var d net.Dialer
	conn, err := d.DialContext(context.Background(), "tcp4", c.addr)
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

	var d net.Dialer
	conn, err := d.DialContext(context.Background(), "tcp4", string(buf[:pos]))
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
	l2net.EncodeProtocolVersionTo(140, payload)
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

// createStarterCharacter creates a character at slot 0 derived from the account name,
// picking a Human Fighter or Mystic at random, and waits for the create result.
func (c *Client) createStarterCharacter() error {
	c.log.Log(c.account, "No characters found, creating a new one...")

	// Clean up account name to use as character name (must be alphanumeric)
	var validName []byte
	for i := range len(c.account) {
		b := c.account[i]
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') {
			validName = append(validName, b)
		}
	}
	if len(validName) == 0 || len(validName) > 16 {
		validName = []byte("BotTestPlayer")
	}

	classID := int32(0) // Human Fighter
	if rand.IntN(2) == 1 {
		classID = int32(10) // Human Mystic
	}

	payload := c.gsWriter.Prepare(100)
	createSize := l2net.EncodeGSCharacterCreateTo(string(validName), 0, false, classID, 0, 0, 0, payload)
	c.logPacket("C2S", "GS:CharacterCreate", payload[:createSize])

	c.gsCrypt.Encrypt(payload[:createSize])
	if err := c.gsWriter.Send(createSize); err != nil {
		return err
	}

	// Wait for CharCreateSuccess or Fail
	data, err := c.gsReader.Read()
	if err != nil {
		return err
	}
	c.gsCrypt.Decrypt(data)
	c.logPacket("S2C", "GS:CharCreateResponse", data)

	switch data[0] {
	case l2net.OpGSCharCreateFail:
		return errors.New("character creation failed")
	case l2net.OpGSCharCreateSuccess:
		c.log.Log(c.account, "Character created successfully.")
		return nil
	default:
		return errors.New("unexpected character create response opcode")
	}
}

// AuthGameServer performs the full handshake then enters the world with a character
// at slot 0 (auto-creating one if the account has none). This is the load-test path.
func (c *Client) AuthGameServer() error {
	charInfo, err := c.HandshakeToLobby()
	if err != nil {
		return err
	}

	if charInfo.CharacterCount == 0 {
		if err = c.createStarterCharacter(); err != nil {
			return err
		}
	}

	var data, payload []byte

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
			objID, classID, x, y, z, iErr := l2net.DecodeCharSelected(data)
			if iErr == nil {
				c.objectID = objID
				c.classID = classID
				c.x.Store(x)
				c.y.Store(y)
				c.z.Store(z)
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

	// The action loop is the sole writer to gsWriter and gsCrypt's outgoing key. Track
	// its lifetime so Logout (a writer too) only sends once it has fully stopped —
	// otherwise the two would race on the shared write buffer and cipher state. The read
	// loop never writes, so it is torn down lazily by Close when the connection drops.
	var actionLoop sync.WaitGroup
	actionLoop.Go(func() {
		c.runActionLoop(ctx, stationary)
	})

	go c.runReadLoop(ctx)

	<-ctx.Done()
	actionLoop.Wait()
	c.Logout()
}

// runActionLoop drives the bot's outbound behaviour until the context is cancelled
// or a send fails. Each helper returns false to signal the loop should stop.
func (c *Client) runActionLoop(ctx context.Context, stationary bool) {
	// Per-goroutine PRNG source avoids global rng contention across many bots.
	seed := uint64(time.Now().UnixNano())
	rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))

	// Persistent roam heading so successive moves accumulate in one direction
	// (the bot genuinely travels far) instead of cancelling out as a random walk.
	roamAngle := rng.Float64() * 2 * math.Pi

	for {
		// After a teleport, ack with C_APPEARING so the server clears
		// IsTeleporting (else movement/ValidatePosition are ignored).
		if !c.ackTeleport() {
			return
		}

		delaySec := rng.IntN(3)
		if !sleepCtx(ctx, time.Second*time.Duration(delaySec)) {
			return
		}

		// Dead bots cannot act (the server rejects target/attack on the dead) —
		// they only taunt in chat, then wait. Models a killed player shouting.
		if c.dead.Load() {
			if !c.doDeathTaunt(rng) {
				return
			}
			continue
		}

		if !c.doAction(ctx, rng, &roamAngle, stationary) {
			return
		}
	}
}

// doAction picks a behaviour for this tick (with phase-aware and fail-safe fallbacks) and dispatches it.
func (c *Client) doAction(ctx context.Context, rng *rand.Rand, roamAngle *float64, stationary bool) bool {
	// 0 = Move, 1 = Social Action, 2 = Use Item, 3 = Attack, 4 = Chat Spam
	actionChoice := rng.IntN(5)

	// Phase-aware: roam during the PvE phase (find village gremlins), but once
	// the convergence hook has teleported us into the PvP cluster, hold position
	// and fight — roaming would disperse the 1k-bot brawl out of attack range.
	effStationary := stationary || c.converged.Load()
	if effStationary {
		if actionChoice == 0 {
			actionChoice = 3
		}
	} else if actionChoice != 0 && rng.IntN(3) == 0 {
		actionChoice = 0
	}

	// Fail-safe: chose Use Item but inventory is empty → Social Action.
	if actionChoice == 2 && c.inventoryCount() == 0 {
		actionChoice = 1
	}
	// Fail-safe: chose Attack but no targets are around → Move.
	if actionChoice == 3 && c.targetCount() == 0 {
		actionChoice = 0
	}

	switch actionChoice {
	case 0:
		return c.doRoam(ctx, rng, roamAngle)
	case 1:
		return c.doSocialAction(rng)
	case 2:
		return c.doUseItem(rng)
	case 3:
		return c.doCombat(ctx, rng)
	case 4:
		return c.doChat(rng)
	}
	return true
}

// ackTeleport sends C_APPEARING when a teleport is pending so the server resumes
// processing our movement. Returns false on send failure.
func (c *Client) ackTeleport() bool {
	if !c.pendingAppear.CompareAndSwap(true, false) {
		return true
	}
	payload := c.gsWriter.Prepare(4)
	size := l2net.EncodeGSAppearingTo(payload)
	c.gsCrypt.Encrypt(payload[:size])
	if err := c.gsWriter.Send(size); err != nil {
		return false
	}
	c.log.Log(c.account, "Teleported → sent Appearing")
	return true
}

// doDeathTaunt occasionally shouts while dead. Returns false on send failure.
func (c *Client) doDeathTaunt(rng *rand.Rand) bool {
	if rng.IntN(3) != 0 {
		return true
	}

	deathTaunts := []string{
		"brb respawn, you're finished!",
		"I'll be right back and you're done",
		"lucky hit, wait till I return",
		"see you at the res point, then it's over",
	}
	phrase := deathTaunts[rng.IntN(len(deathTaunts))]
	payload := c.gsWriter.Prepare(256)
	size := l2net.EncodeGSSay2To(phrase, 0, payload)
	c.logPacket("C2S", "GS:Say2", payload[:size])
	c.gsCrypt.Encrypt(payload[:size])
	return c.gsWriter.Send(size) == nil
}

// doRoam moves the bot a long stride along its persistent heading, then validates the
// new position. Returns false on send failure or context cancellation.
func (c *Client) doRoam(ctx context.Context, rng *rand.Rand, roamAngle *float64) bool {
	// Re-pick the heading occasionally so the bot actually travels far over time.
	if rng.IntN(4) == 0 {
		*roamAngle = rng.Float64() * 2 * math.Pi
	}
	stride := float64(800 + rng.IntN(1200))
	originX, originY, originZ := c.x.Load(), c.y.Load(), c.z.Load()
	targetX := originX + int32(math.Cos(*roamAngle)*stride)
	targetY := originY + int32(math.Sin(*roamAngle)*stride)
	targetZ := originZ

	payload := c.gsWriter.Prepare(30)
	size := l2net.EncodeGSMoveToLocationTo(targetX, targetY, targetZ, originX, originY, originZ, payload)
	c.logPacket("C2S", "GS:MoveToLocation", payload[:size])
	c.gsCrypt.Encrypt(payload[:size])
	if err := c.gsWriter.Send(size); err != nil {
		return false
	}
	c.log.Log(c.account, "Moving to ("+strconv.Itoa(int(targetX))+", "+strconv.Itoa(int(targetY))+")")

	// Simulate time to reach the destination or cancel.
	if !sleepCtx(ctx, time.Duration(1500)*time.Millisecond) {
		return false
	}
	c.x.Store(targetX)
	c.y.Store(targetY)

	payload = c.gsWriter.Prepare(30)
	size = l2net.EncodeGSValidatePositionTo(targetX, targetY, targetZ, 0, payload)
	c.logPacket("C2S", "GS:ValidatePosition", payload[:size])
	c.gsCrypt.Encrypt(payload[:size])
	return c.gsWriter.Send(size) == nil
}

// doSocialAction performs a random emote. Returns false on send failure.
func (c *Client) doSocialAction(rng *rand.Rand) bool {
	socialActions := []int32{12, 13, 16, 17, 24, 31}
	actionID := socialActions[rng.IntN(len(socialActions))]
	c.log.Log(c.account, "Performing social action ID: "+strconv.Itoa(int(actionID)))
	payload := c.gsWriter.Prepare(15)
	size := l2net.EncodeGSRequestActionUseTo(actionID, false, false, payload)
	c.logPacket("C2S", "GS:RequestActionUse", payload[:size])
	c.gsCrypt.Encrypt(payload[:size])
	return c.gsWriter.Send(size) == nil
}

// doUseItem equips/unequips a random inventory item. Returns false on send failure.
func (c *Client) doUseItem(rng *rand.Rand) bool {
	itemObjID, ok := c.randomItem(rng)
	if !ok {
		return true
	}
	c.log.Log(c.account, "Equipping/Unequipping item ObjectID: "+strconv.Itoa(int(itemObjID)))
	payload := c.gsWriter.Prepare(15)
	size := l2net.EncodeGSUseItemTo(itemObjID, false, payload)
	c.logPacket("C2S", "GS:UseItem", payload[:size])
	c.gsCrypt.Encrypt(payload[:size])
	return c.gsWriter.Send(size) == nil
}

// doCombat retargets several times like a real player switching targets mid-siege,
// attacking/casting on each. This is the load pattern that stresses target +
// attack/skill broadcast. Returns false on send failure or context cancellation.
func (c *Client) doCombat(ctx context.Context, rng *rand.Rand) bool {
	switches := 2 + rng.IntN(4)
	for range switches {
		select {
		case <-ctx.Done():
			return false
		default:
		}

		targetObjID, ok := c.randomTarget(rng)
		if !ok {
			return true
		}
		if !c.sendAttack(targetObjID) {
			return false
		}

		// Drain a stale confirmation, then wait for THIS attack/cast to actually land
		// (server broadcasts S_ATTACK/MagicSkillUse → attackChan) before retargeting.
		// The wait must exceed the swing interval / cast time, otherwise rapid
		// retargeting cancels every swing before it lands (no combat ever resolves).
		// Falls through on timeout so a stuck/out-of-range target doesn't hang the bot.
		select {
		case <-c.attackChan:
		default:
		}
		select {
		case <-ctx.Done():
			return false
		case <-c.attackChan:
		case <-time.After(time.Duration(2000+rng.IntN(1500)) * time.Millisecond):
		}
	}
	c.log.Log(c.account, "Cycled "+strconv.Itoa(switches)+" targets")
	return c.sweepLoot()
}

// sendAttack targets the object then launches a class-specific offense: a mystic casts
// Wind Strike when it has the mana and the skill is off cooldown, otherwise a physical
// attack. Returns false on send failure.
func (c *Client) sendAttack(targetObjID uint32) bool {
	x, y, z := c.x.Load(), c.y.Load(), c.z.Load()
	payload := c.gsWriter.Prepare(20)
	size := l2net.EncodeGSActionTo(targetObjID, x, y, z, 0, payload)
	c.logPacket("C2S", "GS:Action", payload[:size])
	c.gsCrypt.Encrypt(payload[:size])
	if err := c.gsWriter.Send(size); err != nil {
		return false
	}

	if c.classID == 10 && c.canCast(1177) {
		payload = c.gsWriter.Prepare(15)
		size = l2net.EncodeGSRequestMagicSkillUseTo(1177, false, false, payload)
		c.logPacket("C2S", "GS:MagicSkillUse", payload[:size])
	} else {
		// Fighters: physical attack (C_ATTACK 0x01)
		payload = c.gsWriter.Prepare(20)
		size = l2net.EncodeGSAttackRequestTo(targetObjID, x, y, z, 0, payload)
		c.logPacket("C2S", "GS:Attack", payload[:size])
	}
	c.gsCrypt.Encrypt(payload[:size])
	return c.gsWriter.Send(size) == nil
}

// sweepLoot fires one AutoPickup for items dropped by the mobs we just fought.
// Returns false on send failure.
func (c *Client) sweepLoot() bool {
	payload := c.gsWriter.Prepare(15)
	size := l2net.EncodeGSRequestActionUseTo(5, false, false, payload) // Action 5 = AutoPickup
	c.logPacket("C2S", "GS:AutoPickup", payload[:size])
	c.gsCrypt.Encrypt(payload[:size])
	return c.gsWriter.Send(size) == nil
}

// doChat sends a random phrase on a random channel. Returns false on send failure.
func (c *Client) doChat(rng *rand.Rand) bool {
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
	phrase := chatPhrases[rng.IntN(len(chatPhrases))]
	chatChannels := []int32{0, 1, 8}
	channel := chatChannels[rng.IntN(len(chatChannels))]
	c.log.Log(c.account, "Sending message to channel "+strconv.Itoa(int(channel))+": "+phrase)
	payload := c.gsWriter.Prepare(256)
	size := l2net.EncodeGSSay2To(phrase, channel, payload)
	c.logPacket("C2S", "GS:Say2", payload[:size])
	c.gsCrypt.Encrypt(payload[:size])
	return c.gsWriter.Send(size) == nil
}

// runReadLoop consumes inbound packets and keeps the TCP connection alive until the
// connection drops or the context is cancelled.
func (c *Client) runReadLoop(ctx context.Context) {
	for {
		data, err := c.gsReader.Read()
		if err != nil {
			select {
			case <-ctx.Done():
			default:
				c.log.LogErr(c.account, "Game Server connection closed", err)
			}
			return
		}
		c.gsCrypt.Decrypt(data)
		if len(data) == 0 {
			continue
		}
		c.handlePacket(data)
	}
}

// handlePacket dispatches a single decrypted Game Server packet.
func (c *Client) handlePacket(data []byte) {
	switch data[0] {
	case l2net.OpGSTeleportToLocation:
		c.handleTeleport(data)
	case l2net.OpGSDie:
		c.handleDie(data)
	case l2net.OpGSStatusUpdate:
		// Track our own MP so the bot only casts when it has mana.
		if mp, maxMp, ok := l2net.ParseSelfMp(data, c.objectID); ok {
			c.mp.Store(mp)
			if maxMp > 0 {
				c.maxMp.Store(maxMp)
			}
		}
	case l2net.OpGSItemList:
		c.logPacket("S2C", "GS:ItemList", data)
		if newItems := l2net.ExtractEquippableItems(data); len(newItems) > 0 {
			c.setInventory(newItems)
			c.log.Log(c.account, "Extracted "+strconv.Itoa(len(newItems))+" equippable items from inventory.")
		}
	case l2net.OpGSNpcInfo:
		if len(data) >= 5 {
			c.addTarget(binary.LittleEndian.Uint32(data[1:5]))
		}
		c.logPacket("S2C", "GS:NpcInfo", data)
	case l2net.OpGSCharInfo:
		if len(data) >= 22 {
			c.addTarget(binary.LittleEndian.Uint32(data[18:22])) // Treat other chars as targets too
		}
		c.logPacket("S2C", "GS:CharInfo", data)
	case l2net.OpGSAttack, l2net.OpGSMagicSkillUse:
		c.handleCombatBroadcast(data)
	default:
		c.logPacket("S2C", "GS:Packet", data)
	}
}

// handleTeleport updates local position from a teleport packet and arms the
// post-teleport appearing-ack and PvP-hold flags.
func (c *Client) handleTeleport(data []byte) {
	if len(data) >= 17 { // body: objectID, x@[5:9], y@[9:13], z@[13:17], ...
		c.x.Store(int32(binary.LittleEndian.Uint32(data[5:9])))
		c.y.Store(int32(binary.LittleEndian.Uint32(data[9:13])))
		c.z.Store(int32(binary.LittleEndian.Uint32(data[13:17])))
	}
	c.logPacket("S2C", "GS:TeleportToLocation", data)
	c.pendingAppear.Store(true)
	c.converged.Store(true) // convergence teleport → stop roaming, hold for PvP
}

// handleDie marks the bot dead when the death packet targets our object.
func (c *Client) handleDie(data []byte) {
	if len(data) >= 5 && binary.LittleEndian.Uint32(data[1:5]) == c.objectID {
		c.dead.Store(true)
		c.log.Log(c.account, "DIED — cannot act, only chat")
	}
	c.logPacket("S2C", "GS:Die", data)
}

// handleCombatBroadcast signals the action loop when our own attack/cast lands and
// records skill reuse so the bot won't recast before the cooldown elapses.
func (c *Client) handleCombatBroadcast(data []byte) {
	if len(data) >= 5 && binary.LittleEndian.Uint32(data[1:5]) == c.objectID {
		select {
		case c.attackChan <- struct{}{}:
		default:
		}
	}
	if data[0] == l2net.OpGSAttack {
		c.logPacket("S2C", "GS:Attack", data)
		return
	}
	if skillID, reuseMs, ok := l2net.ParseOwnSkillReuse(data, c.objectID); ok && reuseMs > 0 {
		c.skillReady.Store(skillID, time.Now().Add(time.Duration(reuseMs)*time.Millisecond).UnixNano())
	}
	c.logPacket("S2C", "GS:MagicSkillUse", data)
}

// addTarget records a nearby object as a potential target. It deduplicates, skips our
// own object, and ring-replaces the oldest entry once the set is full so the tracked
// list stays bounded under a continuous packet stream. Safe for concurrent use with
// randomTarget/targetCount.
func (c *Client) addTarget(id uint32) {
	if id == 0 || id == c.objectID {
		return
	}
	c.npcsMu.Lock()
	defer c.npcsMu.Unlock()
	if slices.Contains(c.npcs, id) {
		return
	}
	if len(c.npcs) < 256 {
		c.npcs = append(c.npcs, id)
		return
	}
	c.npcs[c.npcsNext] = id
	c.npcsNext++
	if c.npcsNext >= 256 {
		c.npcsNext = 0
	}
}

// randomTarget returns a random tracked target, or false when none are known.
func (c *Client) randomTarget(rng *rand.Rand) (uint32, bool) {
	c.npcsMu.Lock()
	defer c.npcsMu.Unlock()
	if len(c.npcs) == 0 {
		return 0, false
	}
	return c.npcs[rng.IntN(len(c.npcs))], true
}

// targetCount reports how many distinct targets are currently tracked.
func (c *Client) targetCount() int {
	c.npcsMu.Lock()
	defer c.npcsMu.Unlock()
	return len(c.npcs)
}

// setInventory atomically replaces the tracked equippable inventory.
func (c *Client) setInventory(items []uint32) {
	c.inventory.Store(&items)
}

// randomItem returns a random equippable item, or false when none are known.
func (c *Client) randomItem(rng *rand.Rand) (uint32, bool) {
	inv := c.inventory.Load()
	if inv == nil || len(*inv) == 0 {
		return 0, false
	}
	items := *inv
	return items[rng.IntN(len(items))], true
}

// inventoryCount reports how many equippable items are currently tracked.
func (c *Client) inventoryCount() int {
	inv := c.inventory.Load()
	if inv == nil {
		return 0
	}
	return len(*inv)
}

// sleepCtx waits for d or context cancellation; it returns false if the context was cancelled.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
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
	time.Sleep(time.Duration(500) * time.Millisecond)
}

// canCast reports whether the bot may cast skillID now: it has the mana and the skill is off cooldown.
func (c *Client) canCast(skillID uint32) bool {
	if c.mp.Load() < 15 {
		return false
	}
	if v, ok := c.skillReady.Load(skillID); ok {
		if ts, isInt := v.(int64); isInt && time.Now().UnixNano() < ts {
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
