// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package client

import (
	"errors"
	"net"
	"strconv"

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
	addr      string
	account   string
	password  string
	staticKey []byte
	conn      net.Conn
	reader    *l2net.Reader
	writer    *l2net.Writer
	crypt     *crypto.Crypt
	rsa       *crypto.RSA
	log       *logger.Logger
	sessionID uint32
	loginKey1 uint32
	loginKey2 uint32
	playKey1  uint32
	playKey2  uint32
	Servers   []l2net.GameServer
	State     State

	// Game Server members
	gsConn   net.Conn
	gsReader *l2net.Reader
	gsWriter *l2net.Writer
	gsCrypt  crypto.GameCrypt
}

// NewClient creates a new headless client instance.
func NewClient(addr, account, password string, staticKey []byte, logger *logger.Logger) *Client {
	return &Client{
		addr:      addr,
		account:   account,
		password:  password,
		staticKey: staticKey,
		State:     StateDisconnected,
		log:       logger,
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
	return nil
}

// AuthGameServer performs the full authentication handshake with the Game Server.
func (c *Client) AuthGameServer() error {
	if c.State != StateGSConnected {
		return errors.New("must be connected to GS")
	}

	// Step 1: Protocol Version (plaintext)
	payload := c.gsWriter.Prepare(5)
	const gsProtocolVersion = 140
	l2net.EncodeProtocolVersionTo(gsProtocolVersion, payload)
	c.logPacket("C2S", "GS:ProtocolVersion", payload)
	if err := c.gsWriter.Send(5); err != nil {
		return err
	}

	// Step 2: Key Exchange (plaintext)
	data, err := c.gsReader.Read()
	if err != nil {
		return err
	}
	c.logPacket("S2C", "GS:KeyPacket", data)

	key, err := l2net.DecodeGSKeyPacket(data)
	if err != nil {
		return err
	}

	c.gsCrypt.Init(key)
	c.State = StateGSHandshake

	// Step 3: Game Auth Login (encrypted via Rolling XOR)
	size := 1 + len(c.account)*2 + 2 + 16
	payload = c.gsWriter.Prepare(size)
	actualSize := l2net.EncodeAuthLoginTo(c.account, c.playKey1, c.playKey2, c.loginKey1, c.loginKey2, payload)
	c.logPacket("C2S", "GS:AuthLogin", payload[:actualSize])

	c.gsCrypt.Encrypt(payload[:actualSize])
	if err = c.gsWriter.Send(actualSize); err != nil {
		return err
	}

	// Step 4: Login Result (encrypted)
	data, err = c.gsReader.Read()
	if err != nil {
		return err
	}
	c.gsCrypt.Decrypt(data)
	c.logPacket("S2C", "GS:LoginResult", data)
	if data[0] != l2net.OpGSLoginResult {
		return errors.New("unexpected login result opcode")
	}

	// Step 5: Character Selection Info (encrypted)
	data, err = c.gsReader.Read()
	if err != nil {
		return err
	}
	c.gsCrypt.Decrypt(data)
	c.logPacket("S2C", "GS:CharSelectionInfo", data)

	if data[0] != l2net.OpGSCharSelectionInfo {
		return errors.New("failed to enter lobby")
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

func (c *Client) logPacket(dir, name string, data []byte) {
	if c.log != nil {
		c.log.LogPacket(c.account, dir, name, data)
	}
}
