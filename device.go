package main

import (
	"fmt"

	"git.mallorn.de/serial/usbport"
	"git.mallorn.de/usb"
)

// findPort returns the device path of port number port of the USB device in
// devices with serialNumber. It is a variable so tests replace the lookup of
// the system's ports.
var findPort = func(devices usb.UsbDevices, serialNumber string, port int) (string, error) {
	p, err := usbport.FindPort(devices, serialNumber, port)
	if err != nil {
		return "", err
	}
	return p.Name, nil
}

// modemDevice returns the device path of the modem. A device that is set is
// returned as it is. Otherwise the path is port number port of the USB device
// usbID, written vendor:product, with serial number serialNumber. An empty
// serialNumber matches any. It returns an error when usbID does not parse and
// when the lookup finds no such port.
func modemDevice(device, usbID, serialNumber string, port int) (string, error) {
	if device != "" {
		return device, nil
	}
	devices, err := usb.ParseUsbDevices([]string{usbID})
	if err != nil {
		return "", fmt.Errorf("--usb-device %q: %w", usbID, err)
	}
	return findPort(devices, serialNumber, port)
}
