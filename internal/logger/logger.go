// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package logger

import (
	"bufio"
	"os"
	"sync"
	"time"
)

// Logger is a high-performance, concurrent-safe logger that avoids heap allocations.
type Logger struct {
	out      *bufio.Writer
	mu       sync.Mutex
	detailed bool
	scratch  [128]byte // Pre-allocated buffer for formatting
}

// NewLogger creates a new high-performance logger instance.
func NewLogger(detailed bool) *Logger {
	return &Logger{
		out:      bufio.NewWriterSize(os.Stdout, 65536),
		detailed: detailed,
	}
}

// Write writes a raw byte slice to the output.
func (l *Logger) Write(data []byte) {
	l.mu.Lock()
	l.out.Write(data)
	l.mu.Unlock()
}

// Log writes a standard info message to the output.
func (l *Logger) Log(account, msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.writeHeader(account)
	l.out.WriteString(msg)
	l.out.WriteByte('\n')
	l.out.Flush()
}

// LogErr writes an error message to the output.
func (l *Logger) LogErr(account, msg string, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.writeHeader(account)
	l.out.WriteString("ERROR: ")
	l.out.WriteString(msg)
	if err != nil {
		l.out.WriteString(": ")
		l.out.WriteString(err.Error())
	}
	l.out.WriteByte('\n')
	l.out.Flush()
}

// LogPacket implements the client.Logger interface for descriptive protocol tracing.
func (l *Logger) LogPacket(account, dir, name string, _ []byte) {
	if !l.detailed {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.writeHeader(account)
	l.out.WriteString(dir)
	l.out.WriteString(": ")
	l.out.WriteString(name)
	l.out.WriteByte('\n')
	l.out.Flush()
}

// writeHeader writes the timestamp and account context to the buffer.
func (l *Logger) writeHeader(account string) {
	l.out.WriteByte('[')
	now := time.Now()
	res := now.AppendFormat(l.scratch[:0], "15:04:05")
	l.out.Write(res)
	l.out.WriteString("] ")
	if account != "" {
		l.out.WriteByte('(')
		l.out.WriteString(account)
		l.out.WriteString(") ")
	}
}

// Flush ensures all buffered data is written to the underlying stream.
func (l *Logger) Flush() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.out.Flush()
}
