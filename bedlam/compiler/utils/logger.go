//
// Copyright (c) 2020 Markku Rossi
//
// All rights reserved.
//

package utils

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

// Logger implements compiler logging facility.
type Logger struct {
	out io.Writer
}

// NewLogger creates a new logger outputting to the argument io.Writer.
func NewLogger(out io.Writer) *Logger {
	return &Logger{
		out: out,
	}
}

// Errorf logs an error message.
func (l *Logger) Errorf(loc Point, format string, a ...interface{}) error {
	msg := fmt.Sprintf(format, a...)
	if len(msg) > 0 && msg[len(msg)-1] != '\n' {
		msg += "\n"
	}
	if loc.Undefined() {
		fmt.Fprintf(l.out, "%s: %s", loc.Source, msg)
	} else {
		fmt.Fprintf(l.out, "%s: %s", loc, msg)
	}

	idx := strings.IndexRune(msg, '\n')
	if idx > 0 {
		msg = msg[:idx]
	}
	return errors.New(msg)
}

// Warningf logs a warning message.
func (l *Logger) Warningf(loc Point, format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	if len(msg) > 0 && msg[len(msg)-1] != '\n' {
		msg += "\n"
	}
	if loc.Undefined() {
		fmt.Fprintf(l.out, "%s: warning: %s", loc.Source, msg)
	} else {
		fmt.Fprintf(l.out, "%s: warning: %s", loc, msg)
	}
}
