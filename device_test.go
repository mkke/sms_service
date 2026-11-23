package main

import (
	"errors"
	"testing"

	"git.mallorn.de/usb"
)

// stubFindPort makes modemDevice's USB lookup answer path and err, and
// records what it was asked.
func stubFindPort(t *testing.T, path string, err error) (asked *[]string) {
	t.Helper()
	saved := findPort
	var calls []string
	findPort = func(devices usb.UsbDevices, serialNumber string, port int) (string, error) {
		calls = append(calls, devices.Strings()[0]+"/"+serialNumber)
		return path, err
	}
	t.Cleanup(func() { findPort = saved })
	return &calls
}

func TestModemDeviceExplicit(t *testing.T) {
	asked := stubFindPort(t, "/dev/cuaU9.9", nil)
	if got, err := modemDevice("/dev/cuaU0.2", "12d1:15c1", "", 2); err != nil || got != "/dev/cuaU0.2" {
		t.Errorf("modemDevice = %q, %v", got, err)
	}
	if len(*asked) != 0 {
		t.Errorf("a set --device still looked up the USB device: %v", *asked)
	}
}

func TestModemDeviceByUSB(t *testing.T) {
	asked := stubFindPort(t, "/dev/cuaU0.2", nil)
	if got, err := modemDevice("", "12d1:15c1", "0123456789ABCDEF", 2); err != nil || got != "/dev/cuaU0.2" {
		t.Errorf("modemDevice = %q, %v", got, err)
	}
	if len(*asked) != 1 || (*asked)[0] != "12D1:15C1/0123456789ABCDEF" {
		t.Errorf("lookup asked %v", *asked)
	}
}

func TestModemDeviceErrors(t *testing.T) {
	cause := errors.New("no serial port belongs to a USB device 12d1:15c1")
	stubFindPort(t, "", cause)
	if _, err := modemDevice("", "12d1:15c1", "", 2); !errors.Is(err, cause) {
		t.Errorf("err = %v, want the lookup error", err)
	}
	if _, err := modemDevice("", "not an id", "", 2); err == nil {
		t.Error("an unparsable --usb-device gave no error")
	}
}
