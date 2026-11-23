package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/mkke/gogsmmodem"
	"go.bug.st/serial"
)

// GitInfo is set via linker option
var GitInfo = "<wip>"

func main() {
    log.SetFlags(log.Ldate|log.Ltime|log.LUTC)

	devicePath := flag.String("device", "", "modem device path; empty finds the modem by --usb-device")
	usbDevice := flag.String("usb-device", "12d1:15c1", "USB ID vendor:product of the modem")
	usbSerial := flag.String("usb-serial", "", "USB serial number of the modem; empty matches any")
	usbPort := flag.Int("usb-port", 2, "number of the modem's serial port that answers AT commands")
	baudRate := flag.Int("baudrate", 9600, "baud rate")
	heaterPhoneNumber := flag.String("heater-phone-number", "", "heater phone number")
	heaterCodeFile := flag.String("heater-code-file", "", "file holding the heater code; empty uses the code 1234")
	responseTimeout := flag.Int("response-timeout", 90, "response timeout (seconds)")
	passwordFile := flag.String("password-file", "", "file holding the API password")
	httpListen := flag.String("http-listen", ":5051", "HTTP listen interface")
	smtpUsername := flag.String("smtp-username", "", "SMTP username")
	smtpPasswordFile := flag.String("smtp-password-file", "", "file holding the SMTP password")
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

	password, err := readSecret(*passwordFile)
	if err != nil {
		log.Panic(err)
	}
	smtpPassword, err := readSecret(*smtpPasswordFile)
	if err != nil {
		log.Panic(err)
	}
	heaterCode := "1234"
	if *heaterCodeFile != "" {
		heaterCode, err = readSecret(*heaterCodeFile)
		if err != nil {
			log.Panic(err)
		}
	}

	// The modem is looked up again on each attempt, as a USB modem that
	// comes back can get another device path.
	open := func() (io.ReadWriteCloser, error) {
		device, err := modemDevice(*devicePath, *usbDevice, *usbSerial, *usbPort)
		if err != nil {
			return nil, err
		}
		port, err := serial.Open(device, &serial.Mode{BaudRate: *baudRate})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", device, err)
		}
		log.Printf("modem on %s\n", device)
		return port, nil
	}
	link := newModemLink(open, time.Minute, log.Default())
	link.debug = true

	s := &server{
		link:              link,
		log:               log.Default(),
		password:          password,
		heaterPhoneNumber: *heaterPhoneNumber,
		heaterCode:        heaterCode,
		responseTimeout:   time.Duration(*responseTimeout) * time.Second,
		smtpHost:          *smtpHost,
		smtpAuth:          CRAMMD5Auth(*smtpUsername, smtpPassword),
		smsForwardAddress: *smsForwardAddress,
		senderAddress:     *senderAddress,
		received:          make(chan *gogsmmodem.Message, 2),
	}
	link.onMessage = s.handleMessage

	go link.run(context.Background())
	log.Panic(http.ListenAndServe(*httpListen, s))
}
