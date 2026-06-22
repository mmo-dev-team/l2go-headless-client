// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package crypto

import (
	"crypto/rsa"
	"math/big"
)

// RSA implements the specific RSA encryption logic used for Lineage 2 login credentials.
type RSA struct {
	publicKey *rsa.PublicKey
}

// NewRSA creates a new RSA instance by unscrambling the provided 128-byte modulus.
func NewRSA(modulus []byte) *RSA {
	// Protocol constants for L2 RSA
	const (
		modulusSize = 128
		publicExp   = 65537
	)

	// Unscramble the modulus before using it to reverse the proprietary obfuscation.
	unscrambled := make([]byte, modulusSize)
	copy(unscrambled, modulus)
	UnscrambleModulus(unscrambled)

	m := new(big.Int).SetBytes(unscrambled)
	return &RSA{
		publicKey: &rsa.PublicKey{
			N: m,
			E: publicExp,
		},
	}
}

// UnscrambleModulus reverses the proprietary scrambling applied by the NCSoft protocol to the RSA modulus.
func UnscrambleModulus(mod []byte) {
	if len(mod) != 128 {
		return
	}

	for i := range 0x40 {
		mod[0x40+i] ^= mod[i]
	}
	for i := range 4 {
		mod[0x0d+i] ^= mod[0x34+i]
	}
	for i := range 0x40 {
		mod[i] ^= mod[0x40+i]
	}
	for i := range 4 {
		mod[i], mod[0x4d+i] = mod[0x4d+i], mod[i]
	}
}

// Encrypt performs raw RSA encryption on the given data using the public key.
// It returns a 128-byte encrypted block.
func (r *RSA) Encrypt(data []byte) ([]byte, error) {
	m := new(big.Int).SetBytes(data)
	c := new(big.Int).Exp(m, big.NewInt(int64(r.publicKey.E)), r.publicKey.N)

	res := c.Bytes()
	// Ensure the result is exactly 128 bytes with leading zeros if necessary.
	if len(res) < 128 {
		padded := make([]byte, 128)
		copy(padded[128-len(res):], res)
		return padded, nil
	}
	return res, nil
}
