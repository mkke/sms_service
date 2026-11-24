package main

import (
	"io"
	"log"
	"log/syslog"
)

// levelLog has one logger per syslog severity the program writes at. Error
// is for a failure that ends the program, Warning for a modem error, Notice
// for the start and the modem's state, Info for a request or a message, and
// Debug for the traffic on the modem's port.
type levelLog struct {
	Error, Warning, Notice, Info, Debug *log.Logger
}

// newLevelLog returns a levelLog whose loggers all write to w with flags, so
// the severities are not told apart.
func newLevelLog(w io.Writer, flags int) *levelLog {
	l := log.New(w, "", flags)
	return &levelLog{Error: l, Warning: l, Notice: l, Info: l, Debug: l}
}

// newSyslogLevelLog returns a levelLog that writes to the local syslog with
// facility daemon and tag, each logger at its own severity.
func newSyslogLevelLog(tag string) (*levelLog, error) {
	w, err := syslog.New(syslog.LOG_DAEMON|syslog.LOG_NOTICE, tag)
	if err != nil {
		return nil, err
	}
	return &levelLog{
		Error:   log.New(writerFunc(w.Err), "", 0),
		Warning: log.New(writerFunc(w.Warning), "", 0),
		Notice:  log.New(writerFunc(w.Notice), "", 0),
		Info:    log.New(writerFunc(w.Info), "", 0),
		Debug:   log.New(writerFunc(w.Debug), "", 0),
	}, nil
}

// writerFunc is an io.Writer that hands each write to a syslog.Writer method
// of one severity.
type writerFunc func(string) error

func (f writerFunc) Write(p []byte) (int, error) {
	if err := f(string(p)); err != nil {
		return 0, err
	}
	return len(p), nil
}
