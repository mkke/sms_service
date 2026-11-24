package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/mkke/gogsmmodem"
)

// server answers the HTTP API and forwards the messages the modem receives.
// A message from the heater goes to the /send call that waits for it, and
// any other message goes out by mail when smtpHost is set.
type server struct {
	link              *modemLink
	log               *levelLog
	password          string
	heaterPhoneNumber string
	heaterCode        string
	responseTimeout   time.Duration
	smtpHost          string
	smtpAuth          Auth
	smsForwardAddress string
	senderAddress     string
	// received carries the heater's answers to /send.
	received chan *gogsmmodem.Message
}

// handleMessage reads the message that n reports, hands it on and deletes it
// from the modem.
func (s *server) handleMessage(n gogsmmodem.MessageNotification) {
	s.log.Info.Println("Message notification:", n)
	s.link.do(func(m *gogsmmodem.Modem) error {
		msg, err := m.GetMessage(n.Index)
		if err != nil {
			return err
		}
		if msg.Telephone == s.heaterPhoneNumber {
			s.received <- msg
		} else if s.smtpHost != "" {
			go s.forward(msg)
		}
		s.log.Info.Printf("Message from %s: %s\n", msg.Telephone, msg.Body)
		m.DeleteMessage(n.Index)
		return nil
	})
}

// forward mails msg to smsForwardAddress.
func (s *server) forward(msg *gogsmmodem.Message) {
	body := strings.Replace(msg.Body, "\n", "\015\012", -1)
	mail := []byte("To: " + s.smsForwardAddress + "\015\012" +
		"Subject: SMS von " + msg.Telephone + " " +
		msg.Timestamp.Format("02.01.2006 15:04:05") + "\015\012" +
		"From: " + s.senderAddress + "\015\012" +
		"\015\012" +
		body + "\015\012")
	err := SendMail(s.smtpHost+":25", s.smtpAuth, s.senderAddress,
		[]string{s.smsForwardAddress}, mail)
	if err != nil {
		s.log.Warning.Println("Forwarding SMS failed: ", err)
	}
}

// ServeHTTP answers /signal with the modem's signal, or with the error that
// keeps the modem from being ready. It answers /send by sending the heater
// the command, then waiting for the heater's answer. /send checks the
// password (401), then the command (400), then that the modem is ready
// (503).
func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	s.log.Info.Printf("HTTP: %s\n", r.URL)
	switch r.URL.Path[1:] {
	case "signal":
		w.Header().Set("Content-Type", "application/json")
		signal, err := s.link.status()
		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{"modem": err.Error()})
		} else if signal.Signal != "" {
			fmt.Fprintf(w, "{\"signal\":\"%s\",\"rssi\":%d,\"rssp\":%d,\"sinr\":%d,\"rsrq\":%d}",
				signal.Signal, signal.RSSI, signal.RSSP, signal.SINR, signal.RSRQ)
		} else {
			fmt.Fprintf(w, "{}")
		}
	case "send":
		if r.FormValue("password") != s.password {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		command := r.FormValue("command")
		if command == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		err := s.link.do(func(m *gogsmmodem.Modem) error {
			// drain received messages
			for len(s.received) > 0 {
				<-s.received
			}
			return m.SendMessage(s.heaterPhoneNumber, s.heaterCode+command)
		})

		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			if errors.As(err, new(notReadyError)) {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
			json.NewEncoder(w).Encode(map[string]string{"send-status": "ERROR", "error": err.Error()})
		} else {
			// send chunk after sms is sent
			flusher, ok := w.(http.Flusher)
			if !ok {
				log.Panic("expected http.ResponseWriter to be an http.Flusher")
			}
			// tell browser to not sniff mime type for chunking to work
			w.Header().Set("X-Content-Type-Options", "nosniff")
			fmt.Fprintf(w, "{\"send-status\":\"OK\"")
			flusher.Flush()

			// wait for received message
			select {
			case msg := <-s.received:
				fmt.Fprintf(w, ",\"response-status\":\"OK\",\"message\":\"%s\"}", msg.Body)
			case <-time.After(s.responseTimeout):
				fmt.Fprintf(w, ",\"response-status\":\"TIMEOUT\",\"error\":\"no response within %d seconds\"}", int(s.responseTimeout/time.Second))
			}
		}
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}
