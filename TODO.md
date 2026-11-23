# sms_service: TODO

The service moves from the pfSense 2.4.5 firewall to OPNsense 26.7
(FreeBSD 15.1, `opnsense.mallorn.de`), installed as a package from the
repository freebsdpkg-backend serves. The user's request: "i want to move
my old pfsense 2.4.5 configuration to a modern opnsense on another hardware
... i have a sms_gateway binary in pfsense that i want to package properly".

The program builds for FreeBSD amd64 with `CGO_ENABLED=0` since 6339de1,
which opens the modem with go.bug.st/serial.

## Package it as an OPNsense plugin

The user: "build it as an OPNsense plugin", one package with the program in
it ("go with B"), in the opnsense/plugins layout ("use the official
opnsense/plugins layout"), built with `freebsdpkgctl plugin build --add`
and checked with `freebsdpkgctl plugin lint` (the opnsense-plugin skill).

- The modem is a Huawei ME906s, USB `12d1:15c1`, serial number
  `0123456789ABCDEF` (a vendor placeholder), five `u3g` ports
  `/dev/cuaU0.0` to `/dev/cuaU0.4` in USB configuration 0. `ATI` answers on
  `cuaU0.0` (Modem), `cuaU0.2` (Pcui) and `cuaU0.3`. The program finds
  `cuaU0.2` by default (`--usb-device 12d1:15c1 --usb-port 2`). On pfSense
  `cuaU0.0` also carried the LTE backup WAN.
- The user: "we don't have to use the fixed uids for freebsd". A service
  user, if it gets one, takes the next free system id.
- The passwords come from `--password-file` and `--smtp-password-file`,
  which the plugin's templates render into a 0700 directory.
- pfSense passed TCP 5051 from LAN to the service and started it with
  `/root/start_sms_service`; the OPNsense firewall needs the same rule. How
  (a rule in the GUI, or a `_firewall` hook in the plugin) is the user's
  decision, not yet asked.
- `os-sms_service` 1.0 (e90035a, ce53eac) is installed on
  opnsense.mallorn.de and disabled. The install test passed: registration,
  user `sms_service` uid 100 in `dialer` (68), the 0700 directory, the
  configd topic `smsservice`, the rendered rc.conf.d file, the secret files
  at `-r--------` for the user after `start_precmd`, the `daemon(8)`
  supervisor's pid file for `service sms_service status`, the port
  `/dev/cuaU0.2` from `usbport.FindPort`, output in `/var/log/smsservice/`.
  The removal test (`pkg delete -y os-sms_service`, `register.php remove
  os-sms_service`, nothing left, user and group gone) has not run.

## Handle a modem without a SIM

The user: "note there is no sim card present", then "disabled. we should
implement missing sim handling in the daemon". The ME906s answers
`AT+CPMS="SM","SM","SM"` with `+CME ERROR: 10` (SIM not inserted) inside
`gogsmmodem.New`; `log.Panic` at `sms_service.go:84` ends the program and
`daemon -r` restarts it every second.

1. gogsmmodem (github.com/mkke/gogsmmodem, `go 1.18`; a push publishes on
   GitHub and needs the user's yes). Approved and started, uncommitted in
   `/Users/ms/git/gogsmmodem`: `errors.go` (`*ModemError` with command,
   status line, code, CMS flag; `CMESIMNotInserted = 10` and other SIM
   codes; `Error()` appends the 27.007 meaning), `errors_test.go`,
   `packets.go` (`ERROR.Status`), `gsm.go` (`parsePacket` keeps the status,
   `send`/`sendBody` return `*ModemError`). The new tests pass alone and the
   old ones pass alone; the full run fails without naming a test. Open: the
   `listen` goroutine (`gsm.go:255`) and the `lineChannel` reader never
   exit, so a failed `New` leaks them and they spin on the closed port
   (`Read("") = (0, Port has been closed)` in the firewall log). Give
   `listen` a shutdown on `New` failure and in `Close`, find the full-run
   failure, add the README changelog entry, commit, ask about the push,
   then pin it here.
2. sms_service: start the HTTP server first; a goroutine opens the port and
   runs `gogsmmodem.New`, on failure closes the port and retries every 60
   seconds, logging each distinct error once. While the modem is not ready,
   `/signal` answers `{"modem":"<error>"}` and `/send` answers 503 with
   `{"send-status":"ERROR","error":"modem not ready: ..."}` (heater-backend's
   `relay.Signal` and its `send-status`/`error` patterns read both).
