package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mkke/gogsmmodem"
)

// initReplay is the dialogue of gogsmmodem.New and the ListMessages of
// connect with a modem that has a SIM and no stored message.
var initReplay = []string{
	"->ATZ\r\n", "<-\r\nOK\r\n",
	"->ATE0\r\n", "<-\r\nOK\r\n",
	"->AT+CPMS=\"SM\",\"SM\",\"SM\"\r\n", "<-\r\n+CPMS: 0,50,0,50,0,50\r\nOK\r\n",
	"->AT+CMGF=1\r\n", "<-\r\nOK\r\n",
	"->AT+CNMI=0,1,0,1,1\r\n", "<-\r\nOK\r\n",
	"->AT+CSCA?\r\n", "<-\r\n+CSCA: \"+491770610000\",145\r\nOK\r\n",
	"->AT+CSCA=\"+491770610000\",145\r\n", "<-\r\nOK\r\n",
	"->AT+CMGL=\"ALL\"\r\n", "<-\r\nOK\r\n",
}

// noSIMReplay is the dialogue of gogsmmodem.New with a modem without a SIM.
var noSIMReplay = []string{
	"->ATZ\r\n", "<-\r\nOK\r\n",
	"->ATE0\r\n", "<-\r\nOK\r\n",
	"->AT+CPMS=\"SM\",\"SM\",\"SM\"\r\n", "<-\r\n+CME ERROR: 10\r\n",
	"->AT+CPMS=\"SM\",\"SM\"\r\n", "<-\r\n+CME ERROR: 10\r\n",
}

// syncBuffer is a log destination that the test reads while run writes.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// startLink runs a modemLink over the ports that open returns, with a retry
// of one millisecond, until the test ends.
func startLink(t *testing.T, open func() (io.ReadWriteCloser, error)) (link *modemLink, logs *syncBuffer) {
	t.Helper()
	logs = &syncBuffer{}
	l := newModemLink(open, time.Millisecond, log.New(logs, "", 0))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		l.run(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return l, logs
}

// waitFor waits up to a second for cond.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(time.Second); !cond(); time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting until %s", what)
		}
	}
}

// isReady reports whether l has a ready modem.
func isReady(l *modemLink) bool {
	_, err := l.status()
	return err == nil
}

// The link retries until the port opens, logs each distinct error once, and
// is ready after that.
func TestLinkRetries(t *testing.T) {
	errA, errB := errors.New("no such device"), errors.New("busy")
	var opens atomic.Int32
	l, logs := startLink(t, func() (io.ReadWriteCloser, error) {
		switch n := opens.Add(1); {
		case n <= 3:
			return nil, errA
		case n <= 5:
			return nil, errB
		default:
			return gogsmmodem.NewMockSerialPort(initReplay), nil
		}
	})
	waitFor(t, "the modem is ready", func() bool { return isReady(l) })
	out := logs.String()
	for _, want := range []string{"modem: no such device\n", "modem: busy\n", "modem ready\n"} {
		if n := strings.Count(out, want); n != 1 {
			t.Errorf("log has %q %d times, want once:\n%s", want, n, out)
		}
	}
}

// Without a SIM the link stays not ready with the modem's error, and logs
// it once however often it tries.
func TestLinkWithoutSIM(t *testing.T) {
	var opens atomic.Int32
	l, logs := startLink(t, func() (io.ReadWriteCloser, error) {
		opens.Add(1)
		return gogsmmodem.NewMockSerialPort(noSIMReplay), nil
	})
	waitFor(t, "three attempts", func() bool { return opens.Load() >= 3 })
	_, err := l.status()
	var me *gogsmmodem.ModemError
	if !errors.As(err, &me) || me.Code != gogsmmodem.CMESIMNotInserted {
		t.Errorf("status error = %v, want CME error 10", err)
	}
	if n := strings.Count(logs.String(), "SIM not inserted"); n != 1 {
		t.Errorf("the SIM error is logged %d times, want once:\n%s", n, logs.String())
	}
	err = l.do(func(*gogsmmodem.Modem) error { return nil })
	if !errors.As(err, new(notReadyError)) || !strings.Contains(err.Error(), "SIM not inserted") {
		t.Errorf("do = %v, want a notReadyError with the SIM error", err)
	}
}

// When the port fails, the link is not ready, and it connects again.
func TestLinkLostPort(t *testing.T) {
	ports := make(chan *gogsmmodem.MockSerialPort, 2)
	l, logs := startLink(t, func() (io.ReadWriteCloser, error) {
		p := gogsmmodem.NewMockSerialPort(initReplay)
		select {
		case ports <- p:
		default:
		}
		return p, nil
	})
	first := <-ports
	waitFor(t, "the modem is ready", func() bool { return isReady(l) })
	first.Close()
	second := <-ports
	waitFor(t, "the modem is ready again", func() bool { return isReady(l) })
	second.Close()
	if !strings.Contains(logs.String(), "modem: "+errConnectionLost.Error()) {
		t.Errorf("log does not name the lost connection:\n%s", logs.String())
	}
}

// A SIM error of a command makes the link not ready with that error, and it
// connects again.
func TestLinkSIMErrorOfCommand(t *testing.T) {
	var opens atomic.Int32
	l, _ := startLink(t, func() (io.ReadWriteCloser, error) {
		opens.Add(1)
		return gogsmmodem.NewMockSerialPort(initReplay), nil
	})
	waitFor(t, "the modem is ready", func() bool { return isReady(l) })
	simErr := &gogsmmodem.ModemError{Command: "+CMGS", Status: "+CME ERROR: 10", Code: 10}
	if err := l.do(func(*gogsmmodem.Modem) error { return simErr }); err != simErr {
		t.Errorf("do = %v, want the command's error", err)
	}
	waitFor(t, "a second attempt", func() bool { return opens.Load() >= 2 })
}

// Another error of a command keeps the modem ready.
func TestLinkOtherErrorOfCommand(t *testing.T) {
	l, _ := startLink(t, func() (io.ReadWriteCloser, error) {
		return gogsmmodem.NewMockSerialPort(initReplay), nil
	})
	waitFor(t, "the modem is ready", func() bool { return isReady(l) })
	cmsErr := &gogsmmodem.ModemError{Command: "+CMGS", Status: "+CMS ERROR: 10", Code: 10, CMS: true}
	l.do(func(*gogsmmodem.Modem) error { return cmsErr })
	if !isReady(l) {
		t.Error("a CMS error made the modem not ready")
	}
}

func TestIsSIMError(t *testing.T) {
	for _, c := range []struct {
		err  error
		want bool
	}{
		{&gogsmmodem.ModemError{Code: 10}, true},
		{&gogsmmodem.ModemError{Code: 15}, true},
		{&gogsmmodem.ModemError{Code: 12}, false},
		{&gogsmmodem.ModemError{Code: 10, CMS: true}, false},
		{errors.New("other"), false},
		{nil, false},
	} {
		if got := isSIMError(c.err); got != c.want {
			t.Errorf("isSIMError(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}
