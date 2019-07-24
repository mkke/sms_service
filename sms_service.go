package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mkke/gogsmmodem"
	"github.com/sevlyar/go-daemon"
	"github.com/tarm/serial"
)

// GitInfo is set via linker option
var GitInfo = "<wip>"

func main() {
    log.SetFlags(log.Ldate|log.Ltime|log.LUTC)

	devicePath := flag.String("device", "/dev/ttyU0.2", "modem device path")
	baudRate := flag.Int("baudrate", 9600, "baud rate")
	heaterPhoneNumber := flag.String("heater-phone-number", "", "heater phone number")
	heaterCode := flag.String("heater-code", "1234", "heater code")
	responseTimeout := flag.Int("response-timeout", 30, "response timeout (seconds)")
	password := flag.String("password", "", "API password")
	httpListen := flag.String("http-listen", ":5051", "HTTP listen interface")
	daemonize := flag.Bool("daemon", false, "daemonize process")
	smtpUsername := flag.String("smtp-username", "", "SMTP username")
	smtpPassword := flag.String("smtp-password", "", "SMTP password")
	smtpHost := flag.String("smtp-host", "", "SMTP host")
	smsForwardAddress := flag.String("sms-forward-address", "", "SMS forwarding email address")
	senderAddress := flag.String("sender-address", "", "email sender address")
	logPath := flag.String("log", "-", "log file path ('-' = stdout)")
	flag.Parse()

	if logPath != nil && len(*logPath) > 0 && *logPath != "-" {
		f, err := os.OpenFile(*logPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0664)
		if err != nil {
			panic(err)
		}

		defer f.Close()
		log.SetOutput(f)
	}

    log.Printf("sms_service commit=%s\n", GitInfo)

	conf := serial.Config{Name: *devicePath, Baud: *baudRate}
	modem, err := gogsmmodem.Open(&conf, true)
	if err != nil {
		log.Panic(err)
	}

	msgs, err := modem.ListMessages("ALL")
	if err != nil {
		log.Panic(err)
	}
	for _, msg := range *msgs {
		modem.DeleteMessage(msg.Index)
	}

	if *daemonize {
		cntxt := &daemon.Context{}

		d, err := cntxt.Reborn()
		if err != nil {
			log.Panic(err)
		}
		if d != nil {
			return
		}
        defer cntxt.Release()

        // re-open the logfile in child process
        if logPath != nil && len(*logPath) > 0 && *logPath != "-" {
            f, err := os.OpenFile(*logPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0664)
            if err != nil {
                panic(err)
            }
    
            defer f.Close()
            log.SetOutput(f)
        }
    
        log.Println("daemonized")
	}

	smtpAuth := CRAMMD5Auth(*smtpUsername, *smtpPassword)

	var modemLock = &sync.Mutex{}

	lastSignalStatus := gogsmmodem.SignalStatus{}
	receivedMessages := make(chan *gogsmmodem.Message, 2)

	go func() {
		for packet := range modem.OOB {
			log.Printf("%#v\n", packet)
			switch p := packet.(type) {
			case gogsmmodem.MessageNotification:
				log.Println("Message notification:", p)
				modemLock.Lock()
				msg, err := modem.GetMessage(p.Index)
				if err == nil {
					if msg.Telephone == *heaterPhoneNumber {
						receivedMessages <- msg
					} else if *smtpHost != "" {
						go func() {
							body := strings.Replace(msg.Body, "\n", "\015\012", -1)
							mail := []byte("To: " + *smsForwardAddress + "\015\012" +
								"Subject: SMS von " + msg.Telephone + " " +
								msg.Timestamp.Format("02.01.2006 15:04:05") + "\015\012" +
								"From: " + *senderAddress + "\015\012" +
								"\015\012" +
								body + "\015\012")
							err := SendMail(*smtpHost+":25", smtpAuth, *senderAddress,
								[]string{*smsForwardAddress}, mail)
							if err != nil {
								log.Println("Forwarding SMS failed: ", err)
							}
						}()
					}
					log.Printf("Message from %s: %s\n", msg.Telephone, msg.Body)
					modem.DeleteMessage(p.Index)
				}
				modemLock.Unlock()
			case gogsmmodem.SignalStatus:
				lastSignalStatus = packet.(gogsmmodem.SignalStatus)
			}
		}
	}()

	go func() {
		log.Panic(http.ListenAndServe(*httpListen, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.ParseForm()
			log.Printf("HTTP: %s\n", r.URL)
			switch r.URL.Path[1:] {
			case "signal":
				w.Header().Set("Content-Type", "application/json")
				if lastSignalStatus.Signal != "" {
					fmt.Fprintf(w, "{\"signal\":\"%s\",\"rssi\":%d,\"rssp\":%d,\"sinr\":%d,\"rsrq\":%d}",
						lastSignalStatus.Signal, lastSignalStatus.RSSI, lastSignalStatus.RSSP, lastSignalStatus.SINR, lastSignalStatus.RSRQ)
				} else {
					fmt.Fprintf(w, "{}")
				}
			case "send":
				if r.FormValue("password") != *password {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}

				command := r.FormValue("command")
				if command == "" {
					w.WriteHeader(http.StatusBadRequest)
					return
				}

				modemLock.Lock()
				// drain received messages
				for len(receivedMessages) > 0 {
					<-receivedMessages
				}
				err = modem.SendMessage(*heaterPhoneNumber, *heaterCode+command)
				modemLock.Unlock()

				w.Header().Set("Content-Type", "application/json")
				if err != nil {
					fmt.Fprintf(w, "{\"send-status\":\"ERROR\",\"error\":\"%s\"}", err)
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
					case msg := <-receivedMessages:
						fmt.Fprintf(w, ",\"response-status\":\"OK\",\"message\":\"%s\"}", msg.Body)
					case <-time.After(time.Duration(*responseTimeout) * time.Second):
						fmt.Fprintf(w, ",\"response-status\":\"TIMEOUT\",\"error\":\"no response within %d seconds\"}", *responseTimeout)
					}
				}
			default:
				w.WriteHeader(http.StatusBadRequest)
			}
		})))
	}()

	select {}
}
