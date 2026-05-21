// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package net

import (
	"encoding/binary"
	"errors"

	"github.com/mmo-dev-team/l2go-headless-client/internal/crypto"
)

// Login Server Opcodes (S2C)
const (
	OpInit           = 0x00
	OpLoginFail      = 0x01
	OpLoginSuccess   = 0x03
	OpServerList     = 0x04
	OpPlayFail       = 0x06
	OpPlaySuccess    = 0x07
	OpGGAuthResponse = 0x0b
)

// Login Server Opcodes (C2S)
const (
	OpLoginRequest       = 0x00
	OpRequestServerLogin = 0x02
	OpRequestServerList  = 0x05
	OpAuthGGRequest      = 0x07
	OpRequestConfig      = 0x08
)

// Game Server Opcodes
const (
	OpGSCharSelectionInfo = 0x09
	OpGSLoginResult       = 0x0a
	OpGSProtocolVersion   = 0x0e
	OpGSAuthLogin         = 0x2b
	OpGSKeyPacket         = 0x2e
)

// RSA block layout constants
const (
	RSAOffsetAccount   = 0x5E
	RSAOffsetPassword  = 0x6C
	RSAOffsetSessionID = 0x7C
	RSABlockSize       = 128
)

// High Five Protocol constants
const (
	H5InitBlowfishKeyOffset = 153 // Offset of dynamic Blowfish key in H5 Init packet
	H5InitMinPacketSize     = 170 // Minimum expected size of H5 Init packet
	H5ServerListEntrySize   = 21  // Size of one server entry in H5 list
)

var loginFailReasons = map[uint32]string{
	0x01: "System error",
	0x02: "Invalid password",
	0x03: "Invalid user/password",
	0x04: "Access denied",
	0x05: "Account in use",
	0x07: "Server is full",
	0x08: "Account banned",
	0x10: "Internal server error",
}

// GetLoginFailReason converts a Login Server failure code into a human-readable string.
func GetLoginFailReason(data []byte) string {
	if len(data) < 5 {
		return "Unknown error (packet too short)"
	}
	reason := binary.LittleEndian.Uint32(data[1:5])
	if msg, ok := loginFailReasons[reason]; ok {
		return msg
	}
	return "Unknown error"
}

// InitPacket contains initial session data sent by the Login Server.
type InitPacket struct {
	SessionID       uint32
	ProtocolVersion uint32
	RSAModulus      []byte // 128 bytes
	BlowfishKey     []byte // 16 bytes for High Five
}

// DecodeInit parses the server's initial handshake packet.
func DecodeInit(data []byte) (*InitPacket, error) {
	if len(data) < H5InitMinPacketSize {
		return nil, errors.New("packet too short for Init")
	}

	if data[0] != OpInit {
		return nil, errors.New("invalid opcode for Init packet")
	}

	p := &InitPacket{}
	p.SessionID = binary.LittleEndian.Uint32(data[1:5])
	p.ProtocolVersion = binary.LittleEndian.Uint32(data[5:9])

	p.RSAModulus = make([]byte, 128)
	copy(p.RSAModulus, data[9:137])

	// Blowfish key starts after RSA and GG Data in High Five.
	if len(data) >= H5InitBlowfishKeyOffset+16 {
		p.BlowfishKey = make([]byte, 16)
		copy(p.BlowfishKey, data[H5InitBlowfishKeyOffset:H5InitBlowfishKeyOffset+16])
	}

	return p, nil
}

// EncodeAuthGGRequestTo writes a GameGuard authentication request into the provided buffer.
func EncodeAuthGGRequestTo(sessionID uint32, data []byte) {
	data[0] = OpAuthGGRequest
	binary.LittleEndian.PutUint32(data[1:5], sessionID)
	// Clear padding area to stay zero-alloc clean
	for i := 5; i < 25; i++ {
		data[i] = 0
	}
}

// LoginRequest represents account credentials for Login Server authentication.
type LoginRequest struct {
	Account   string
	Password  string
	SessionID uint32
}

// EncodeLoginRequest RSA-encrypts account credentials for authentication.
func EncodeLoginRequest(req *LoginRequest, rsa *crypto.RSA) ([]byte, error) {
	block := make([]byte, RSABlockSize)

	copy(block[RSAOffsetAccount:], req.Account)
	copy(block[RSAOffsetPassword:], req.Password)
	binary.LittleEndian.PutUint32(block[RSAOffsetSessionID:], req.SessionID)

	encrypted, err := rsa.Encrypt(block)
	if err != nil {
		return nil, err
	}

	// Resulting payload: Opcode(1) + RSA(128) + GGData(16 zeros) + Null(1)
	const totalLen = 1 + 128 + 16 + 1
	data := make([]byte, totalLen)
	data[0] = OpLoginRequest
	copy(data[1:129], encrypted)
	return data, nil
}

// LoginOk contains session keys obtained after successful Login Server authentication.
type LoginOk struct {
	LoginKey1 uint32
	LoginKey2 uint32
}

// DecodeLoginOk parses the LoginOk response from the Login Server.
func DecodeLoginOk(data []byte) (*LoginOk, error) {
	if len(data) < 9 {
		return nil, errors.New("packet too short for LoginOk")
	}
	return &LoginOk{
		LoginKey1: binary.LittleEndian.Uint32(data[1:5]),
		LoginKey2: binary.LittleEndian.Uint32(data[5:9]),
	}, nil
}

// GameServer contains information about an available game world.
type GameServer struct {
	ID             uint8
	IP             [4]byte
	Port           uint16
	AgeLimit       uint8
	PK             bool
	CurrentPlayers uint16
	MaxPlayers     uint16
	Online         bool
	Type           uint32
	Brackets       bool
}

// ServerListPacket contains the list of available game worlds.
type ServerListPacket struct {
	LastServerID uint8
	Servers      []GameServer
}

// DecodeServerList parses the server list sent by the Login Server.
func DecodeServerList(data []byte) (*ServerListPacket, error) {
	if len(data) < 3 {
		return nil, errors.New("packet too short for ServerList")
	}

	count := data[1]
	lastID := data[2]
	servers := make([]GameServer, 0, count)

	offset := 3
	for i := 0; i < int(count); i++ {
		if len(data) < offset+H5ServerListEntrySize {
			break
		}
		s := GameServer{}
		s.ID = data[offset]
		copy(s.IP[:], data[offset+1:offset+5])
		s.Port = uint16(binary.LittleEndian.Uint32(data[offset+5 : offset+9]))
		s.AgeLimit = data[offset+9]
		s.PK = data[offset+10] == 0x01
		s.CurrentPlayers = binary.LittleEndian.Uint16(data[offset+11 : offset+13])
		s.MaxPlayers = binary.LittleEndian.Uint16(data[offset+13 : offset+15])
		s.Online = data[offset+15] == 0x01
		s.Type = binary.LittleEndian.Uint32(data[offset+16 : offset+20])
		s.Brackets = data[offset+20] == 0x01
		servers = append(servers, s)
		offset += H5ServerListEntrySize
	}

	return &ServerListPacket{
		LastServerID: lastID,
		Servers:      servers,
	}, nil
}

// PlayOk contains session keys required to enter a specific Game Server world.
type PlayOk struct {
	PlayKey1 uint32
	PlayKey2 uint32
}

// DecodePlayOk parses the PlayOk response after server selection.
func DecodePlayOk(data []byte) (*PlayOk, error) {
	if len(data) < 9 {
		return nil, errors.New("packet too short for PlayOk")
	}
	return &PlayOk{
		PlayKey1: binary.LittleEndian.Uint32(data[1:5]),
		PlayKey2: binary.LittleEndian.Uint32(data[5:9]),
	}, nil
}

// EncodeRequestServerListTo writes a server list request into the provided buffer.
func EncodeRequestServerListTo(loginKey1, loginKey2 uint32, data []byte) {
	data[0] = OpRequestServerList
	binary.LittleEndian.PutUint32(data[1:5], loginKey1)
	binary.LittleEndian.PutUint32(data[5:9], loginKey2)
}

// EncodeRequestServerLoginTo writes a server selection request into the provided buffer.
func EncodeRequestServerLoginTo(loginKey1, loginKey2 uint32, serverID uint8, data []byte) {
	data[0] = OpRequestServerLogin
	binary.LittleEndian.PutUint32(data[1:5], loginKey1)
	binary.LittleEndian.PutUint32(data[5:9], loginKey2)
	data[9] = serverID
}

// EncodeProtocolVersionTo writes a Game Server protocol version check into the provided buffer.
func EncodeProtocolVersionTo(version int32, data []byte) {
	data[0] = OpGSProtocolVersion
	binary.LittleEndian.PutUint32(data[1:5], uint32(version))
}

// EncodeAuthLoginTo writes a Game Server authentication request into the provided buffer.
// It returns the actual number of bytes written.
func EncodeAuthLoginTo(account string, playKey1, playKey2, loginKey1, loginKey2 uint32, data []byte) int {
	data[0] = OpGSAuthLogin
	pos := 1
	// Write account name as UTF-16LE efficiently
	for i := 0; i < len(account); i++ {
		data[pos] = account[i]
		data[pos+1] = 0
		pos += 2
	}
	// Write NULL terminator for the string
	data[pos] = 0
	data[pos+1] = 0
	pos += 2

	binary.LittleEndian.PutUint32(data[pos:], playKey2)
	binary.LittleEndian.PutUint32(data[pos+4:], playKey1)
	binary.LittleEndian.PutUint32(data[pos+8:], loginKey1)
	binary.LittleEndian.PutUint32(data[pos+12:], loginKey2)
	return pos + 16
}

// DecodeGSKeyPacket extracts the XOR key from the Game Server's version check response.
func DecodeGSKeyPacket(data []byte) ([]byte, error) {
	// Offset 2 contains the start of the 16-byte XOR key in l2go-game.
	if len(data) < 18 {
		return nil, errors.New("packet too short for GS KeyPacket")
	}
	if data[0] != OpGSKeyPacket {
		return nil, errors.New("invalid opcode for GS KeyPacket")
	}
	key := make([]byte, 16)
	copy(key, data[2:18])
	return key, nil
}
