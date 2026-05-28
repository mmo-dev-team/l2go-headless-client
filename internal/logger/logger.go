// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
// Copyright (c) 2026 whiteo. All rights reserved.

package logger

import (
	"bufio"
	"os"
	"time"
)

type entryKind uint8

const (
	kindLog entryKind = iota
	kindErr
	kindPacket
	kindRaw
	kindFlush
)

type logEntry struct {
	t       time.Time
	account string
	msg     string
	dir     string
	name    string
	raw     []byte
	done    chan struct{}
	err     error
	kind    entryKind
}

// Logger is a high-performance, concurrent-safe logger backed by a channel.
// All callers are non-blocking; a single drain goroutine owns the output buffer.
type Logger struct {
	ch       chan logEntry
	detailed bool
}

// NewLogger creates a new logger instance. Call Flush() before process exit to drain the buffer.
func NewLogger(detailed bool) *Logger {
	l := &Logger{
		ch:       make(chan logEntry, 4096),
		detailed: detailed,
	}
	go l.drain()
	return l
}

// Write writes a raw byte slice to the output.
func (l *Logger) Write(data []byte) {
	cp := make([]byte, len(data))
	copy(cp, data)
	l.ch <- logEntry{kind: kindRaw, raw: cp}
}

// Log writes a standard info message to the output.
func (l *Logger) Log(account, msg string) {
	l.ch <- logEntry{
		kind:    kindLog,
		t:       time.Now(),
		account: account,
		msg:     msg,
	}
}

// LogErr writes an error message to the output.
func (l *Logger) LogErr(account, msg string, err error) {
	l.ch <- logEntry{
		kind:    kindErr,
		t:       time.Now(),
		account: account,
		msg:     msg,
		err:     err,
	}
}

// LogPacket implements the client.Logger interface for descriptive protocol tracing.
func (l *Logger) LogPacket(account, dir, name string, _ []byte) {
	if !l.detailed {
		return
	}
	l.ch <- logEntry{
		kind:    kindPacket,
		t:       time.Now(),
		account: account,
		dir:     dir,
		name:    name,
	}
}

// Flush blocks until all pending log entries are written and the buffer is flushed.
func (l *Logger) Flush() {
	done := make(chan struct{})
	l.ch <- logEntry{kind: kindFlush, done: done}
	<-done
}

func (l *Logger) drain() {
	out := bufio.NewWriterSize(os.Stdout, 65536)
	var scratch [128]byte
	for e := range l.ch {
		switch e.kind {
		case kindFlush:
			out.Flush()
			close(e.done)
		case kindRaw:
			out.Write(e.raw)
		default:
			writeEntry(out, scratch[:], e)
		}
	}
}

func writeEntry(out *bufio.Writer, scratch []byte, e logEntry) {
	out.WriteByte('[')
	out.Write(e.t.AppendFormat(scratch[:0], "15:04:05"))
	out.WriteString("] ")
	if e.account != "" {
		out.WriteByte('(')
		out.WriteString(e.account)
		out.WriteString(") ")
	}
	switch e.kind {
	case kindLog:
		out.WriteString(e.msg)
		out.WriteByte('\n')
	case kindErr:
		out.WriteString("ERROR: ")
		out.WriteString(e.msg)
		if e.err != nil {
			out.WriteString(": ")
			out.WriteString(e.err.Error())
		}
		out.WriteByte('\n')
	case kindPacket:
		out.WriteString(e.dir)
		out.WriteString(": ")
		out.WriteString(e.name)
		out.WriteByte('\n')
	}
}
