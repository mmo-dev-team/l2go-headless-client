// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package crypto

import (
	"encoding/binary"
)

// GameCrypt handles Game Server encryption and decryption using the Rolling XOR algorithm.
type GameCrypt struct {
	inKey  [16]byte
	outKey [16]byte
	init   bool
}

// gsStaticKey is the static part of the XOR key for the High Five chronicle.
var gsStaticKey = [8]byte{0xc8, 0x27, 0x93, 0x01, 0xa1, 0x6c, 0x31, 0x97}

// Init initializes the rolling XOR keys using the dynamic key provided by the Game Server.
func (c *GameCrypt) Init(dynamicKey []byte) {
	copy(c.inKey[:8], dynamicKey[:8])
	copy(c.inKey[8:], gsStaticKey[:])
	copy(c.outKey[:], c.inKey[:])
	c.init = true
}

// Decrypt decrypts the given buffer in-place using the incoming rolling XOR key.
// It also updates the key based on the processed packet size.
func (c *GameCrypt) Decrypt(data []byte) {
	if !c.init {
		return
	}

	var prev byte
	for i := 0; i < len(data); i++ {
		temp := data[i]
		data[i] = temp ^ c.inKey[i%16] ^ prev
		prev = temp
	}

	// Update the key based on packet size (rolling mechanism)
	c.updateKey(&c.inKey, len(data))
}

// Encrypt encrypts the given buffer in-place using the outgoing rolling XOR key.
// It also updates the key based on the processed packet size.
func (c *GameCrypt) Encrypt(data []byte) {
	if !c.init {
		return
	}

	var prev byte
	for i := 0; i < len(data); i++ {
		data[i] = data[i] ^ c.outKey[i%16] ^ prev
		prev = data[i]
	}

	// Update the key based on packet size (rolling mechanism)
	c.updateKey(&c.outKey, len(data))
}

// updateKey modifies the static part of the XOR key to prevent pattern analysis.
func (c *GameCrypt) updateKey(key *[16]byte, size int) {
	// The 32-bit integer at offsets 8-11 is incremented by the payload size.
	oldKey := binary.LittleEndian.Uint32(key[8:12])
	oldKey += uint32(size)
	binary.LittleEndian.PutUint32(key[8:12], oldKey)
}
