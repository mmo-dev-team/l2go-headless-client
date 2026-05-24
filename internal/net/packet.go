// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package net

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	// MaxPacketSize is the maximum size allowed for an L2 packet (including header).
	MaxPacketSize = 65535
	// HeaderSize is the size of the packet length header (uint16).
	HeaderSize = 2
)

// Reader is a zero-allocation packet reader that reuses an internal buffer to eliminate per-packet allocations.
type Reader struct {
	r   io.Reader
	buf []byte
}

// NewReader creates a new high-performance packet reader for the given input stream.
func NewReader(r io.Reader) *Reader {
	return &Reader{
		r:   r,
		buf: make([]byte, MaxPacketSize),
	}
}

// Read reads the next packet from the stream into the internal buffer.
// It returns a slice pointing to the payload (excluding the 2-byte header).
// Note: The returned slice is only valid until the next call to Read.
func (pr *Reader) Read() ([]byte, error) {
	// Read the 2-byte length header efficiently
	if _, err := io.ReadFull(pr.r, pr.buf[:HeaderSize]); err != nil {
		return nil, err
	}

	size := binary.LittleEndian.Uint16(pr.buf[:HeaderSize])
	if size < HeaderSize {
		return nil, errors.New("invalid packet size")
	}

	payloadSize := int(size - HeaderSize)
	if payloadSize > 0 {
		// Read the actual payload into the pre-allocated buffer
		if _, err := io.ReadFull(pr.r, pr.buf[:payloadSize]); err != nil {
			return nil, err
		}
	}

	return pr.buf[:payloadSize], nil
}

// Writer is a zero-allocation packet writer that reuses an internal buffer to avoid heap usage.
type Writer struct {
	w   io.Writer
	buf []byte
}

// NewWriter creates a new high-performance packet writer for the given output stream.
func NewWriter(w io.Writer) *Writer {
	return &Writer{
		w:   w,
		buf: make([]byte, MaxPacketSize),
	}
}

// Write wraps the given raw data into an L2 packet (adds length header) and writes it to the stream.
func (pw *Writer) Write(data []byte) error {
	size := len(data) + HeaderSize
	if size > MaxPacketSize {
		return errors.New("packet too large")
	}

	binary.LittleEndian.PutUint16(pw.buf[:HeaderSize], uint16(size))
	copy(pw.buf[HeaderSize:], data)

	_, err := pw.w.Write(pw.buf[:size])
	return err
}

// Prepare returns a slice representing the payload area of the internal buffer.
// This allows callers to construct the packet content directly in the writer's buffer,
// completely eliminating the need for temporary byte slices and copies.
func (pw *Writer) Prepare(payloadLen int) []byte {
	totalSize := payloadLen + HeaderSize
	if totalSize > MaxPacketSize {
		return nil
	}
	return pw.buf[HeaderSize : HeaderSize+payloadLen]
}

// Send finalizes and writes the packet to the underlying stream after the payload has been
// prepared directly in the buffer via the slice returned by Prepare.
func (pw *Writer) Send(payloadLen int) error {
	size := payloadLen + HeaderSize
	binary.LittleEndian.PutUint16(pw.buf[:HeaderSize], uint16(size))
	_, err := pw.w.Write(pw.buf[:size])
	return err
}
