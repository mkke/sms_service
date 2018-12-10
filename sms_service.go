package main

import (
    "fmt"
    "flag"
    "sync"
    "time"
    "strings"
    "net/http"
    "github.com/mkke/gogsmmodem"
    "github.com/tarm/serial"
    "github.com/sevlyar/go-daemon"
)

func main() {
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
    flag.Parse()

    conf := serial.Config{Name: *devicePath, Baud: *baudRate}
    modem, err := gogsmmodem.Open(&conf, true)
    if err != nil {
        panic(err)
    }

    msgs, err := modem.ListMessages("ALL")
    if err != nil {
        panic(err)
    }
    for _, msg := range *msgs {
        modem.DeleteMessage(msg.Index)
    }

    if *daemonize {
        cntxt := &daemon.Context{}

        d, err := cntxt.Reborn()
        if err != nil {
            panic(err)
        }
        if d != nil {
	    return
        }
        defer cntxt.Release()
    }

    smtpAuth := CRAMMD5Auth(*smtpUsername, *smtpPassword)

    var modemLock = &sync.Mutex{}

    lastSignalStatus := gogsmmodem.SignalStatus{}
    receivedMessages := make(chan *gogsmmodem.Message, 2);

    go func() {
    for packet := range modem.OOB {
        fmt.Printf("%#v\n", packet)
        switch p := packet.(type) {
        case gogsmmodem.MessageNotification:
            fmt.Println("Message notification:", p)
            modemLock.Lock();
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
                        err := SendMail(*smtpHost + ":25", smtpAuth, *senderAddress,
                                        []string{*smsForwardAddress}, mail)
                        if err != nil {
                            fmt.Println("Forwarding SMS failed: ", err)
                        }
                    }()
                }
                fmt.Printf("Message from %s: %s\n", msg.Telephone, msg.Body)
                modem.DeleteMessage(p.Index)
            }
            modemLock.Unlock();
        case gogsmmodem.SignalStatus:
            lastSignalStatus = packet.(gogsmmodem.SignalStatus)
        }
    }
    }()

    go func() {
    panic(http.ListenAndServe(*httpListen, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        r.ParseForm();
        fmt.Printf("HTTP: %s\n", r.URL.Path[1:])
        switch r.URL.Path[1:] {
        case "signal":
            w.Header().Set("Content-Type", "application/json")
            if lastSignalStatus.Signal != "" {
                fmt.Fprintf(w, "{signal:\"%s\",rssi:%d,rssp=%d,sinr=%d,rsrq=%d}",
                    lastSignalStatus.Signal, lastSignalStatus.RSSI, lastSignalStatus.RSSP, lastSignalStatus.SINR, lastSignalStatus.RSRQ);
            } else {
                fmt.Fprintf(w, "{}");
            }
        case "send":
            if r.FormValue("password") != *password {
                w.WriteHeader(http.StatusUnauthorized);
                return;
            }

            command := r.FormValue("command");
            if command == "" {
                w.WriteHeader(http.StatusBadRequest);
                return;
            }

            modemLock.Lock();
            // drain received messages
            for len(receivedMessages) > 0 {
                <-receivedMessages
            }
            err = modem.SendMessage(*heaterPhoneNumber, *heaterCode + command);
            modemLock.Unlock();

            w.Header().Set("Content-Type", "application/json")
            if err != nil {
                fmt.Fprintf(w, "{status:\"ERROR\",error:\"%s\"}", err);
            } else {
                // wait for received message
                select {
                case msg := <-receivedMessages:
                    fmt.Fprintf(w, "{status:\"OK\",message=\"%s\"}", msg.Body);
                case <-time.After(time.Duration(*responseTimeout) * time.Second):
                    fmt.Fprintf(w, "{status:\"ERROR\",error:\"no response within %d seconds\"}", *responseTimeout);
                }
            }
        default:
            w.WriteHeader(http.StatusBadRequest);
        }
    })));
    }()

    select {}
}

