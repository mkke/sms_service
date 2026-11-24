package main

import (
	"context"
	"errors"
	"io"
	"log"
	"sync"
	"time"

	"github.com/mkke/gogsmmodem"
)

// errStarting is the state of a modemLink before its first attempt ends.
var errStarting = errors.New("modem not yet initialised")

// errConnectionLost is the state of a modemLink after a read from the port
// failed, as when the USB modem is gone.
var errConnectionLost = errors.New("connection to the modem lost")

// notReadyError is the error of a command while no modem is ready. Cause is
// the error that keeps the modem from being ready.
type notReadyError struct {
	cause error
}

func (e notReadyError) Error() string { return "modem not ready: " + e.cause.Error() }

func (e notReadyError) Unwrap() error { return e.cause }

// modemLink keeps the connection to the modem. Its run loop opens the port
// and initialises the modem. When that fails, or when the modem stops
// later, the loop tries again after retry. Commands go through do, one at a
// time, and fail with a notReadyError while no modem is ready. Each distinct
// error is logged once, until the modem is ready again.
type modemLink struct {
	// open opens the modem's port.
	open func() (io.ReadWriteCloser, error)
	// retry is the time between two attempts.
	retry time.Duration
	// debug makes gogsmmodem log every read and write on the port.
	debug bool
	log   *log.Logger
	// onMessage is called for each new-message report, from the goroutine
	// of run. It can call do.
	onMessage func(gogsmmodem.MessageNotification)

	// cmd makes the callers of do take turns.
	cmd sync.Mutex

	// mu guards the fields below it.
	mu     sync.Mutex
	modem  *gogsmmodem.Modem
	err    error
	signal gogsmmodem.SignalStatus
	logged string
}

// newModemLink returns a modemLink that is not ready. Start its loop with
// run.
func newModemLink(open func() (io.ReadWriteCloser, error), retry time.Duration, logger *log.Logger) *modemLink {
	return &modemLink{open: open, retry: retry, log: logger, err: errStarting}
}

// run connects to the modem and keeps it connected until ctx is done. It
// closes the modem before it returns.
func (l *modemLink) run(ctx context.Context) {
	for {
		if m, err := l.connect(); err != nil {
			l.setNotReady(nil, err)
		} else {
			l.serve(ctx, m)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(l.retry):
		}
	}
}

// connect opens the port, initialises the modem on it and deletes the
// messages stored on it. On an error it closes the port.
func (l *modemLink) connect() (*gogsmmodem.Modem, error) {
	port, err := l.open()
	if err != nil {
		return nil, err
	}
	m, err := gogsmmodem.New(port, l.debug)
	if err != nil {
		port.Close()
		return nil, err
	}
	msgs, err := m.ListMessages("ALL")
	if err != nil {
		m.Close()
		return nil, err
	}
	for _, msg := range *msgs {
		m.DeleteMessage(msg.Index)
	}
	return m, nil
}

// serve makes m the ready modem and processes its reports until it stops:
// when its port fails, when do closes it on a SIM error, or when ctx is
// done.
func (l *modemLink) serve(ctx context.Context, m *gogsmmodem.Modem) {
	l.mu.Lock()
	l.modem = m
	l.err = nil
	l.logged = ""
	l.mu.Unlock()
	l.log.Println("modem ready")

	stop := context.AfterFunc(ctx, func() { m.Close() })
	defer stop()
	for packet := range m.OOB {
		l.log.Printf("%#v\n", packet)
		switch p := packet.(type) {
		case gogsmmodem.SignalStatus:
			l.mu.Lock()
			l.signal = p
			l.mu.Unlock()
		case gogsmmodem.MessageNotification:
			if l.onMessage != nil {
				l.onMessage(p)
			}
		}
	}
	m.Close()
	l.setNotReady(m, errConnectionLost)
}

// setNotReady records err as the reason no modem is ready, and logs it
// unless it is the error logged last. With m set, it does so only while m is
// the ready modem, so a reason recorded for m first stays.
func (l *modemLink) setNotReady(m *gogsmmodem.Modem, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.modem != m {
		return
	}
	l.modem = nil
	l.err = err
	l.signal = gogsmmodem.SignalStatus{}
	if msg := err.Error(); msg != l.logged {
		l.logged = msg
		l.log.Println("modem:", msg)
	}
}

// status returns the last signal report of the ready modem, or the error
// that keeps the modem from being ready.
func (l *modemLink) status() (gogsmmodem.SignalStatus, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.signal, l.err
}

// do calls f with the ready modem and returns its error. While no modem is
// ready it returns a notReadyError instead. When f fails with a SIM error or
// with gogsmmodem.ErrTimeout, do records that error as the reason and closes
// the modem, and run connects again after retry.
func (l *modemLink) do(f func(*gogsmmodem.Modem) error) error {
	l.cmd.Lock()
	defer l.cmd.Unlock()
	l.mu.Lock()
	m, cause := l.modem, l.err
	l.mu.Unlock()
	if m == nil {
		return notReadyError{cause}
	}
	err := f(m)
	if isSIMError(err) || err == gogsmmodem.ErrTimeout {
		l.setNotReady(m, err)
		m.Close()
	}
	return err
}

// isSIMError reports whether err is a +CME error about the SIM.
func isSIMError(err error) bool {
	var me *gogsmmodem.ModemError
	if !errors.As(err, &me) || me.CMS {
		return false
	}
	switch me.Code {
	case gogsmmodem.CMESIMNotInserted, gogsmmodem.CMESIMPINRequired,
		gogsmmodem.CMESIMFailure, gogsmmodem.CMESIMBusy, gogsmmodem.CMESIMWrong:
		return true
	}
	return false
}
