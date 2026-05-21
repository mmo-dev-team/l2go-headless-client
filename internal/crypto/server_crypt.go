// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package crypto

import (
	"encoding/binary"

	authcrypto "github.com/mmo-dev-team/l2go-auth/pkg/crypto"
)

// Crypt handles packet encryption and decryption using the Blowfish algorithm and a custom XOR-based checksum.
// It is designed for the Lineage 2 Login Server protocol.
type Crypt struct {
	updatedKey bool
	cipher     *authcrypto.BlowfishCipher
}

// NewCrypt creates a new Crypt instance with the given Blowfish key.
func NewCrypt(key []byte) *Crypt {
	return &Crypt{
		updatedKey: false,
		cipher:     authcrypto.NewBlowfishCipher(key),
	}
}

// UpdateKey updates the Blowfish key used for subsequent operations.
func (c *Crypt) UpdateKey(key []byte) {
	// Re-initializing the cipher since the shared library uses unexported setKey method.
	c.cipher = authcrypto.NewBlowfishCipher(key)
}

// Encrypt encrypts the given payload in-place, adding a checksum and padding as required by the protocol.
// The provided slice must have enough capacity for the added overhead (usually 12-16 bytes + padding).
func (c *Crypt) Encrypt(data []byte) []byte {
	payloadLen := len(data)

	// Protocol constants for Login Server encryption
	const (
		checksumSize   = 4
		defaultReserve = 12 // Standard overhead
		initReserve    = 16 // First packet overhead
		blockSize      = 8  // Blowfish block size
	)

	reserve := defaultReserve
	if !c.updatedKey {
		reserve = initReserve
	}

	totalLen := payloadLen + reserve
	pad := blockSize - (totalLen % blockSize)
	if pad != blockSize {
		totalLen += pad
	}

	// Reslice to full size if capacity allows, otherwise reallocate (should be avoided by caller)
	if cap(data) < totalLen {
		newData := make([]byte, totalLen)
		copy(newData, data)
		data = newData
	} else {
		data = data[:totalLen]
		// Zero out padding/reserve area
		for i := payloadLen; i < totalLen; i++ {
			data[i] = 0
		}
	}

	// Calculate and append the 4-byte XOR checksum
	var chk uint32
	for i := 0; i < totalLen-checksumSize; i += 4 {
		chk ^= binary.LittleEndian.Uint32(data[i : i+4])
	}
	binary.LittleEndian.PutUint32(data[totalLen-checksumSize:], chk)

	// Blowfish encryption in ECB mode
	c.cipher.CipherRange(data, 0, totalLen)
	c.updatedKey = true
	return data
}

// Decrypt decrypts the given data using the Blowfish algorithm.
// It returns false if the data size is invalid for Blowfish (not a multiple of 8).
func (c *Crypt) Decrypt(data []byte) bool {
	size := len(data)
	if size%8 != 0 || size <= 0 {
		return false
	}

	c.cipher.DecipherRange(data, 0, size)
	return true
}

// DecryptInit handles the special decryption flow for the server's first (Init) packet,
// which includes both Blowfish and an XOR pass.
func (c *Crypt) DecryptInit(data []byte) {
	size := len(data)
	if size%8 != 0 || size <= 0 {
		return
	}

	c.cipher.DecipherRange(data, 0, size)
	c.decXorPass(data, uint32(size))
}

func (c *Crypt) decXorPass(raw []byte, size uint32) {
	if size < 8 {
		return
	}
	pos := size - 8
	ecx := binary.LittleEndian.Uint32(raw[pos : pos+4])
	pos -= 4
	for pos >= 4 {
		edx := binary.LittleEndian.Uint32(raw[pos : pos+4])
		edx ^= ecx
		ecx -= edx
		binary.LittleEndian.PutUint32(raw[pos:pos+4], edx)
		pos -= 4
	}
}
