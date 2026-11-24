package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mkke/gogsmmodem"
)

// newTestServer returns a server over l with the password "pw", the heater
// number 491701234567, the heater code 1234 and a response timeout of 10 ms.
func newTestServer(l *modemLink) *server {
	return &server{
		link:              l,
		log:               newLevelLog(io.Discard, 0),
		password:          "pw",
		heaterPhoneNumber: "491701234567",
		heaterCode:        "1234",
		responseTimeout:   10 * time.Millisecond,
		received:          make(chan *gogsmmodem.Message, 2),
	}
}

// get returns the status and the body of the server's answer to target.
func get(s *server, target string) (code int, body string) {
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
	return w.Code, w.Body.String()
}

// notReadyLink returns a modemLink that has not run.
func notReadyLink() *modemLink {
	return newModemLink(nil, time.Minute, newLevelLog(io.Discard, 0))
}

func TestSignalNotReady(t *testing.T) {
	code, body := get(newTestServer(notReadyLink()), "/signal")
	var got map[string]string
	if err := json.Unmarshal([]byte(body), &got); err != nil || code != http.StatusOK {
		t.Fatalf("/signal = %d %q, %v", code, body, err)
	}
	if got["modem"] != errStarting.Error() {
		t.Errorf("/signal = %q, want the modem error", body)
	}
}

func TestSignalReady(t *testing.T) {
	l, _ := startLink(t, func() (io.ReadWriteCloser, error) {
		return gogsmmodem.NewMockSerialPort(initReplay), nil
	})
	waitFor(t, "the modem is ready", func() bool { return isReady(l) })
	l.mu.Lock()
	l.signal = gogsmmodem.SignalStatus{Signal: "LTE", RSSI: 40, RSSP: 50, SINR: 60, RSRQ: 20}
	l.mu.Unlock()
	_, body := get(newTestServer(l), "/signal")
	if want := `{"signal":"LTE","rssi":40,"rssp":50,"sinr":60,"rsrq":20}`; body != want {
		t.Errorf("/signal = %q, want %q", body, want)
	}
}

// /send checks the password, then the command, then that the modem is
// ready.
func TestSendChecks(t *testing.T) {
	s := newTestServer(notReadyLink())
	for target, want := range map[string]int{
		"/send?password=wrong&command=on": http.StatusUnauthorized,
		"/send?command=on":                http.StatusUnauthorized,
		"/send?password=pw":               http.StatusBadRequest,
		"/send?password=pw&command=on":    http.StatusServiceUnavailable,
	} {
		if code, body := get(s, target); code != want {
			t.Errorf("%s = %d %q, want %d", target, code, body, want)
		}
	}
	_, body := get(s, "/send?password=pw&command=on")
	var got map[string]string
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("/send = %q: %v", body, err)
	}
	if got["send-status"] != "ERROR" || !strings.HasPrefix(got["error"], "modem not ready: ") {
		t.Errorf("/send = %q, want ERROR and modem not ready", body)
	}
}

// A ready modem sends the heater code and the command, and /send reports
// the timeout when the heater does not answer.
func TestSendReady(t *testing.T) {
	replay := append(append([]string{}, initReplay...),
		"->AT+CMGS=\"491701234567\"\r\n", "<-> \r\n",
		"->1234on\x1a", "<-\r\nOK\r\n",
	)
	l, _ := startLink(t, func() (io.ReadWriteCloser, error) {
		return gogsmmodem.NewMockSerialPort(replay), nil
	})
	waitFor(t, "the modem is ready", func() bool { return isReady(l) })
	code, body := get(newTestServer(l), "/send?password=pw&command=on")
	if code != http.StatusOK || !strings.HasPrefix(body, `{"send-status":"OK","response-status":"TIMEOUT"`) {
		t.Errorf("/send = %d %q", code, body)
	}
}
