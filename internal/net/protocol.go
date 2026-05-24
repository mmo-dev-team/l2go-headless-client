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

// Login Server Opcodes
const (
	OpInit           = 0x00
	OpLoginFail      = 0x01
	OpLoginSuccess   = 0x03
	OpServerList     = 0x04
	OpPlayFail       = 0x06
	OpPlaySuccess    = 0x07
	OpGGAuthResponse = 0x0b
)

// Login Server Opcodes
const (
	OpLoginRequest       = 0x00
	OpRequestServerLogin = 0x02
	OpRequestServerList  = 0x05
	OpAuthGGRequest      = 0x07
)

// Game Server Opcodes
const (
	OpGSLogout               = 0x00
	OpGSCharSelectionInfo    = 0x09
	OpGSLoginResult          = 0x0a
	OpGSCharSelected         = 0x0b
	OpGSCharacterCreate      = 0x0c
	OpGSProtocolVersion      = 0x0e
	OpGSMoveToLocation       = 0x0f
	OpGSCharCreateSuccess    = 0x0f
	OpGSCharCreateFail       = 0x10
	OpGSEnterWorld           = 0x11
	OpGSItemList             = 0x11
	OpGSCharacterSelect      = 0x12
	OpGSUseItem              = 0x19
	OpGSAction               = 0x1f
	OpGSAuthLogin            = 0x2b
	OpGSKeyPacket            = 0x2e
	OpGSCharInfo             = 0x31
	OpGSAttackRequest        = 0x01
	OpGSAttack               = 0x33
	OpGSRequestMagicSkillUse = 0x39
	OpGSMagicSkillUse        = 0x48
	OpGSSay2                 = 0x49
	OpGSRequestActionUse     = 0x56
	OpGSValidatePosition     = 0x59
	OpGSNpcInfo              = 0x0c
)

// RSA block layout constants
const (
	RSAOffsetAccount   = 0x5E
	RSAOffsetPassword  = 0x6C
	RSAOffsetSessionID = 0x7C
	RSABlockSize       = 128
)

// Protocol constants
const (
	H5InitBlowfishKeyOffset = 153 // Offset of a dynamic Blowfish key in the Init packet
	H5InitMinPacketSize     = 170 // Minimum expected size of the Init packet
	H5ServerListEntrySize   = 21  // Size of one server entry in the list
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

	// Blowfish key starts after RSA and GG Data.
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
	// Offset 2 contains the start of the 16-byte XOR key.
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

// CharSelectionInfo contains the number of characters available.
type CharSelectionInfo struct {
	CharacterCount uint32
}

// DecodeCharSelectionInfo parses the character selection info packet.
func DecodeCharSelectionInfo(data []byte) (*CharSelectionInfo, error) {
	if len(data) < 5 {
		return nil, errors.New("packet too short for CharSelectionInfo")
	}
	if data[0] != OpGSCharSelectionInfo {
		return nil, errors.New("invalid opcode for CharSelectionInfo")
	}
	return &CharSelectionInfo{
		CharacterCount: binary.LittleEndian.Uint32(data[1:5]),
	}, nil
}

// EncodeGSCharacterCreateTo writes a Game Server character create request into the provided buffer.
// It returns the actual number of bytes written.
func EncodeGSCharacterCreateTo(name string, race int32, isFemale bool, classId int32, hairStyle, hairColor, face int32, data []byte) int {
	data[0] = OpGSCharacterCreate
	pos := 1

	for i := 0; i < len(name); i++ {
		data[pos] = name[i]
		data[pos+1] = 0
		pos += 2
	}
	data[pos] = 0
	data[pos+1] = 0
	pos += 2

	binary.LittleEndian.PutUint32(data[pos:], uint32(race))
	pos += 4
	if isFemale {
		binary.LittleEndian.PutUint32(data[pos:], 1)
	} else {
		binary.LittleEndian.PutUint32(data[pos:], 0)
	}
	pos += 4
	binary.LittleEndian.PutUint32(data[pos:], uint32(classId))
	pos += 4

	for i := 0; i < 6; i++ {
		binary.LittleEndian.PutUint32(data[pos:], 40)
		pos += 4
	}

	binary.LittleEndian.PutUint32(data[pos:], uint32(hairStyle))
	pos += 4
	binary.LittleEndian.PutUint32(data[pos:], uint32(hairColor))
	pos += 4
	binary.LittleEndian.PutUint32(data[pos:], uint32(face))
	pos += 4

	return pos
}

// EncodeGSCharacterSelectTo writes a Game Server character select request into the provided buffer.
// It returns the actual number of bytes written.
func EncodeGSCharacterSelectTo(charSlot int32, data []byte) int {
	data[0] = OpGSCharacterSelect
	pos := 1

	binary.LittleEndian.PutUint32(data[pos:], uint32(charSlot))
	pos += 4

	binary.LittleEndian.PutUint16(data[pos:], 0)
	pos += 2
	binary.LittleEndian.PutUint32(data[pos:], 0)
	pos += 4
	binary.LittleEndian.PutUint32(data[pos:], 0)
	pos += 4
	binary.LittleEndian.PutUint32(data[pos:], 0)
	pos += 4

	return pos
}

// DecodeCharSelected parses the CharSelected packet to extract initial coordinates, objectId, and classId.
func DecodeCharSelected(data []byte) (objId, classId uint32, x, y, z int32, err error) {
	if len(data) < 1 {
		return 0, 0, 0, 0, 0, errors.New("packet too short")
	}
	pos := 1

	// Helper to skip a UTF-16LE string
	skipString := func() error {
		for i := pos; i < len(data)-1; i += 2 {
			if data[i] == 0 && data[i+1] == 0 {
				pos = i + 2
				return nil
			}
		}
		return errors.New("string not terminated")
	}

	if err = skipString(); err != nil { // Name
		return 0, 0, 0, 0, 0, err
	}
	if pos+4 > len(data) {
		return 0, 0, 0, 0, 0, errors.New("packet too short")
	}
	objId = binary.LittleEndian.Uint32(data[pos:])
	pos += 4 // ObjectId

	if err = skipString(); err != nil { // Title
		return 0, 0, 0, 0, 0, err
	}

	if pos+36 > len(data) {
		return 0, 0, 0, 0, 0, errors.New("packet too short")
	}
	pos += 4 // SessionId
	pos += 4 // ClanId
	pos += 4 // ??
	pos += 4 // Sex
	pos += 4 // Race
	classId = binary.LittleEndian.Uint32(data[pos:])
	pos += 4 // ClassId
	pos += 4 // Active

	x = int32(binary.LittleEndian.Uint32(data[pos:]))
	pos += 4
	y = int32(binary.LittleEndian.Uint32(data[pos:]))
	pos += 4
	z = int32(binary.LittleEndian.Uint32(data[pos:]))

	return objId, classId, x, y, z, nil
}

// EncodeGSMoveToLocationTo writes a Game Server MoveToLocation request into the provided buffer.
func EncodeGSMoveToLocationTo(targetX, targetY, targetZ, originX, originY, originZ int32, data []byte) int {
	data[0] = OpGSMoveToLocation
	pos := 1

	binary.LittleEndian.PutUint32(data[pos:], uint32(targetX))
	pos += 4
	binary.LittleEndian.PutUint32(data[pos:], uint32(targetY))
	pos += 4
	binary.LittleEndian.PutUint32(data[pos:], uint32(targetZ))
	pos += 4
	binary.LittleEndian.PutUint32(data[pos:], uint32(originX))
	pos += 4
	binary.LittleEndian.PutUint32(data[pos:], uint32(originY))
	pos += 4
	binary.LittleEndian.PutUint32(data[pos:], uint32(originZ))
	pos += 4
	binary.LittleEndian.PutUint32(data[pos:], 1) // Movement mode: 1 = mouse
	pos += 4

	return pos
}

// EncodeGSValidatePositionTo writes a Game Server ValidatePosition request into the provided buffer.
func EncodeGSValidatePositionTo(x, y, z, heading int32, data []byte) int {
	data[0] = OpGSValidatePosition
	pos := 1

	binary.LittleEndian.PutUint32(data[pos:], uint32(x))
	pos += 4
	binary.LittleEndian.PutUint32(data[pos:], uint32(y))
	pos += 4
	binary.LittleEndian.PutUint32(data[pos:], uint32(z))
	pos += 4
	binary.LittleEndian.PutUint32(data[pos:], uint32(heading))
	pos += 4
	binary.LittleEndian.PutUint32(data[pos:], 0) // vehicle id
	pos += 4

	return pos
}

// EncodeGSRequestActionUseTo writes a Game Server RequestActionUse request into the provided buffer.
func EncodeGSRequestActionUseTo(actionId int32, ctrlPressed, shiftPressed bool, data []byte) int {
	data[0] = OpGSRequestActionUse
	pos := 1

	binary.LittleEndian.PutUint32(data[pos:], uint32(actionId))
	pos += 4

	if ctrlPressed {
		binary.LittleEndian.PutUint32(data[pos:], 1)
	} else {
		binary.LittleEndian.PutUint32(data[pos:], 0)
	}
	pos += 4

	if shiftPressed {
		data[pos] = 1
	} else {
		data[pos] = 0
	}
	pos += 1

	return pos
}

// EncodeGSUseItemTo writes a Game Server UseItem request into the provided buffer.
func EncodeGSUseItemTo(objectId uint32, ctrlPressed bool, data []byte) int {
	data[0] = OpGSUseItem
	pos := 1

	binary.LittleEndian.PutUint32(data[pos:], objectId)
	pos += 4

	if ctrlPressed {
		binary.LittleEndian.PutUint32(data[pos:], 1)
	} else {
		binary.LittleEndian.PutUint32(data[pos:], 0)
	}
	pos += 4

	return pos
}

// EncodeGSActionTo writes a Game Server Action request (to target/interact).
func EncodeGSActionTo(objectId uint32, originX, originY, originZ int32, actionId byte, data []byte) int {
	data[0] = OpGSAction
	pos := 1
	binary.LittleEndian.PutUint32(data[pos:], objectId)
	pos += 4
	binary.LittleEndian.PutUint32(data[pos:], uint32(originX))
	pos += 4
	binary.LittleEndian.PutUint32(data[pos:], uint32(originY))
	pos += 4
	binary.LittleEndian.PutUint32(data[pos:], uint32(originZ))
	pos += 4
	data[pos] = actionId
	pos += 1
	return pos
}

// EncodeGSAttackRequestTo writes a Game Server AttackRequest.
func EncodeGSAttackRequestTo(objectId uint32, originX, originY, originZ int32, attackId byte, data []byte) int {
	data[0] = OpGSAttackRequest
	pos := 1
	binary.LittleEndian.PutUint32(data[pos:], objectId)
	pos += 4
	binary.LittleEndian.PutUint32(data[pos:], uint32(originX))
	pos += 4
	binary.LittleEndian.PutUint32(data[pos:], uint32(originY))
	pos += 4
	binary.LittleEndian.PutUint32(data[pos:], uint32(originZ))
	pos += 4
	data[pos] = attackId
	pos += 1
	return pos
}

// EncodeGSRequestMagicSkillUseTo writes a Game Server RequestMagicSkillUse request into the provided buffer.
func EncodeGSRequestMagicSkillUseTo(magicId uint32, ctrlPressed, shiftPressed bool, data []byte) int {
	data[0] = OpGSRequestMagicSkillUse
	pos := 1

	binary.LittleEndian.PutUint32(data[pos:], magicId)
	pos += 4

	if ctrlPressed {
		binary.LittleEndian.PutUint32(data[pos:], 1)
	} else {
		binary.LittleEndian.PutUint32(data[pos:], 0)
	}
	pos += 4

	if shiftPressed {
		data[pos] = 1
	} else {
		data[pos] = 0
	}
	pos += 4

	return pos
}

// EncodeGSEnterWorldTo writes a Game Server EnterWorld request.
// It sends 104 bytes of padding as required by the protocol.
func EncodeGSEnterWorldTo(data []byte) int {
	data[0] = OpGSEnterWorld
	// Padding 104 bytes with zeros
	for i := 1; i <= 104; i++ {
		data[i] = 0
	}
	return 105
}

// EncodeGSSay2To writes a Game Server Say2 request (chat message).
func EncodeGSSay2To(text string, chatType int32, data []byte) int {
	data[0] = OpGSSay2
	pos := 1

	// Write text as UTF-16LE
	for i := 0; i < len(text); i++ {
		data[pos] = text[i]
		data[pos+1] = 0
		pos += 2
	}
	data[pos] = 0
	data[pos+1] = 0
	pos += 2

	binary.LittleEndian.PutUint32(data[pos:], uint32(chatType))
	pos += 4

	// Target is only for WHISPER, we skip it for General/Shout/Trade
	return pos
}

// ExtractEquippableItems parses an ItemList packet and extracts ObjectIDs of equippable items.
func ExtractEquippableItems(data []byte) []uint32 {
	var items []uint32

	if len(data) < 11 || data[0] != OpGSItemList {
		return items
	}

	sendType := data[1]
	pos := 2

	var count uint32
	if sendType == 2 {
		if pos+8 > len(data) {
			return items
		}
		pos += 4 // skip count1
		count = binary.LittleEndian.Uint32(data[pos:])
		pos += 4
	} else {
		return items // Only sendType 2 contains the actual items in the payload
	}

	for i := uint32(0); i < count; i++ {
		if pos+43 > len(data) {
			break
		}

		mask := data[pos]
		objectId := binary.LittleEndian.Uint32(data[pos+1 : pos+5])
		type2 := data[pos+18]

		// Type 2: 00-weapon, 01-shield/armor, 02-ring/earring/necklace
		if type2 <= 2 {
			items = append(items, objectId)
		}

		pos += 43

		if mask&1 != 0 { // AUGMENT_BONUS
			pos += 8
		}
		if mask&2 != 0 { // ELEMENTAL_ATTRIBUTE
			pos += 16
		}
		if mask&4 != 0 { // ENCHANT_EFFECT
			pos += 12 // 3 ints
		}
		if mask&8 != 0 { // VISUAL_ID
			pos += 4
		}
		if mask&16 != 0 { // SOUL_CRYSTAL
			if pos >= len(data) {
				break
			}
			regSize := int(data[pos])
			pos += 1 + regSize*4
			if pos >= len(data) {
				break
			}
			specSize := int(data[pos])
			pos += 1 + specSize*4
		}
	}

	return items
}
