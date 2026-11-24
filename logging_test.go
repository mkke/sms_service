package main

import (
	"bytes"
	"errors"
	"log"
	"testing"
)

// Without syslog every severity writes to the one destination.
func TestNewLevelLog(t *testing.T) {
	var buf bytes.Buffer
	lv := newLevelLog(&buf, 0)
	for _, l := range []*log.Logger{lv.Error, lv.Warning, lv.Notice, lv.Info, lv.Debug} {
		l.Print("x")
	}
	if got := buf.String(); got != "x\nx\nx\nx\nx\n" {
		t.Errorf("log = %q, want five lines", got)
	}
}

// A writerFunc hands each line to its function whole, and reports the
// function's error.
func TestWriterFunc(t *testing.T) {
	var lines []string
	l := log.New(writerFunc(func(s string) error {
		lines = append(lines, s)
		return nil
	}), "", 0)
	l.Printf("modem: %s", "SIM not inserted")
	if len(lines) != 1 || lines[0] != "modem: SIM not inserted\n" {
		t.Errorf("lines = %q", lines)
	}
	failed := errors.New("no syslog")
	if n, err := writerFunc(func(string) error { return failed }).Write([]byte("x")); n != 0 || err != failed {
		t.Errorf("Write = %d, %v, want 0 and the function's error", n, err)
	}
}
