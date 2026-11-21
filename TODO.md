# sms_service: TODO

The service moves from the pfSense 2.4.5 firewall to OPNsense 26.7
(FreeBSD 15.1, `opnsense.mallorn.de`), installed as a package from the
repository freebsdpkg-backend serves. The user's request: "i want to move
my old pfsense 2.4.5 configuration to a modern opnsense on another hardware
... i have a sms_gateway binary in pfsense that i want to package properly".

The program builds for FreeBSD amd64 with `CGO_ENABLED=0` since 6339de1,
which opens the modem with go.bug.st/serial.

## Find the modem's AT command port

The modem is a Huawei ME906s LTE M.2 module on USB, vendor `12d1`, product
`15c1`, serial number `0123456789ABCDEF` (a placeholder the vendor sets on
many units). FreeBSD's `u3g` driver gives it five ports, `/dev/cuaU0.0` to
`/dev/cuaU0.4`, owned by `uucp:dialer`. Which one answers AT commands for
SMS is not established: send `ATI` to each and read the answers, one SSH
call announced to the user first. The old firewall ran
`usbconfig -d 0.2 set_config 3` at boot for a different modem; the ME906s
runs in configuration 0. `--device` defaults to `/dev/ttyU0.2`, which on
FreeBSD waits for carrier detect; the callout device `cuaU0.N` does not.

## Package it

- A manifest for `freebsdpkg create`, a staging tree and an `rc.d` script
  started through `daemon(8)`, with its settings in
  `/etc/rc.conf.d/sms_service`.
- The user: "we don't have to use the fixed uids for freebsd". A service
  user, if it gets one, takes the next free system id.
- The API password and the SMTP password are command-line flags today, so
  they show in `ps` on the firewall. They need another source before the
  service is packaged.
- pfSense passed TCP 5051 from LAN to the service and started it with
  `/root/start_sms_service`; the OPNsense firewall needs the same rule.

## Smaller findings

- `go vet` reports non-constant format strings in `smtp.go` at lines 213
  and 239.
