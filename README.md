# RenkuRemoteDesktop

An RDP server for RenkuOS and Haiku. Connect from Windows Remote Desktop
Connection (`mstsc`), Windows App on macOS, iOS, and Android, or FreeRDP and
Remmina on Linux, and use the desktop that is on the machine's screen.

**Status: early development.** Do not expose it to the internet. Network Level
Authentication (NLA) is not implemented yet. The password is checked after
TLS is up, from the client's logon information.

## What works

- TLS 1.2 with a self-signed certificate made on first start. The SHA-256
  fingerprint is logged, so you can compare it with what the client shows.
- Password login, with a delay after each failure and a ten-minute block
  after five failures from one address.
- The screen, as lossless RDP 6.0 planar bitmaps, in 64×64 tiles that are sent
  only when they change.
- Keyboard and mouse: scancodes through the RenkuOS keymap, Unicode input,
  absolute pointer, buttons, wheel, and lock-key sync.
- Session takeover: a new login replaces the current session.
- Resize on connect, with a choice of policy (see below).

Not yet: NLA, clipboard, file transfer, the fast capture path, the preferences
add-on, and a launch_daemon service. See
[docs/testing.md](docs/testing.md) for what has been tested.

## Building

On RenkuOS or Haiku, with `haiku_devel` and `openssl3_devel` installed:

```sh
make
make test
```

This builds two files in `build/Haiku/`:

- `RenkuRemoteDesktop`, the server
- `RenkuRemoteDesktopInput`, an input_server add-on. Copy it to
  `~/config/non-packaged/add-ons/input_server/devices/`. input_server loads
  it right away.

On Linux, `make` builds `rrd-test-server` instead. It serves a generated test
pattern and logs input, so the protocol can be tested against RDP clients
without Haiku.

## Running

```sh
build/Haiku/RenkuRemoteDesktop --set-password
build/Haiku/RenkuRemoteDesktop
```

Settings, the certificate, and the key are in
`~/config/settings/RenkuRemoteDesktop/`. Options:

| Option | Meaning |
|---|---|
| `--set-password` | Read a new password (eight characters or more) and save its hash |
| `--resize fastest` | Default. Switch the display to the client's size when that means fewer pixels; otherwise keep it |
| `--resize match-client` | Switch to the client's size whenever the display offers it |
| `--resize keep` | Never change the display mode |
| `--port N`, `--bind ADDRESS` | Where to listen (default: port 3389, all interfaces) |
| `-v`, `-vv` | Debug and trace logging |

## Design

The protocol is written from Microsoft's published specifications
([MS-RDPBCGR], [MS-RDPEGDI], [MS-CSSP], [MS-NLMP], [MS-RDPECLIP]). No code
comes from other RDP implementations. Comments cite the specification
sections.

`src/core` is portable C++ (POSIX and OpenSSL). `src/haiku` holds the screen
capture, the input forwarding, and the input_server add-on. `src/linux` holds
the test harness.

## License

MIT. See [LICENSE](LICENSE).
