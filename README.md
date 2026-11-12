# RenkuRemoteDesktop

An RDP server for RenkuOS and Haiku. Connect from Windows Remote Desktop
Connection (`mstsc`), Windows App on macOS, iOS, and Android, or FreeRDP and
Remmina on Linux, and use the desktop that is on the machine's screen.

**Status: early development.** Do not expose it to the internet.

## What works

- Network Level Authentication (NLA): CredSSP with NTLMv2 inside TLS, so the
  password is checked before any RDP data is exchanged. Windows clients need
  it. Clients that offer only TLS log in with the password from their logon
  information instead.
- TLS 1.2 with a self-signed certificate made on first start. Its SHA-256
  fingerprint is in the preferences and the log, to compare with what the
  client shows.
- A delay after each failed login, and a ten-minute block after five failures
  from one address.
- The screen, as lossless RDP 6.0 planar bitmaps in 64×64 tiles, sent only
  where something changed. On RenkuOS, app_server reports the changes (its
  screen observer), so capturing costs almost nothing. On Haiku the server
  reads the whole screen each frame instead.
- The client draws the mouse pointer, in the shape RenkuOS shows.
- Keyboard and mouse: scancodes through the RenkuOS keymap, Unicode input,
  absolute pointer, buttons, wheel, and lock-key sync.
- Session takeover: a new login replaces the current session.
- Resize on connect and when the client's window changes size (display
  control), with a choice of policy. The display can only take sizes its
  driver offers.
- The clipboard in both directions: text, and files. Files copied on the
  client are copied into `~/Desktop/Remote files/` and then put on the
  clipboard, so Paste in Tracker works. Files copied in Tracker can be
  pasted on the client. Copies from the client above 500 MB are refused
  (`incoming_files_limit_mb`), and copies older than a week are removed when
  the server starts.
- The Remote Desktop preferences: on and off, password, port, address,
  screen size, the certificate fingerprint, and who is connected.

See [docs/testing.md](docs/testing.md) for what has been tested, with which
clients.

## Building

On RenkuOS or Haiku, with `haiku_devel` and `openssl3_devel` installed:

```sh
make
make test
```

This builds, in `build/Haiku/`:

- `RenkuRemoteDesktop`, the server
- `RemoteDesktopPrefs`, the preferences
- `RenkuRemoteDesktopInput`, the input_server add-on that types and moves
  the mouse for the client

`make install` puts them, and the launch_daemon service, below
`/boot/system/non-packaged` (or `PREFIX`, with an optional `DESTDIR` for
staging):

| File | Installed as |
|---|---|
| Server | `servers/RenkuRemoteDesktop` |
| Preferences | `preferences/Remote Desktop` |
| Input add-on | `add-ons/input_server/devices/RenkuRemoteDesktopInput` |
| Service | `data/user_launch/RenkuRemoteDesktop` |

input_server loads the add-on right away. launch_daemon reads the service at
the next login.

On Linux, `make` builds `rrd-test-server` instead. It serves a generated test
pattern and logs input, so the protocol can be tested against RDP clients
without Haiku.

## Using it

Open **Remote Desktop** in the Preferences menu, set a password, and turn on
"Allow remote desktop connections to this computer". launch_daemon then
starts the server, now and at each login, until it is turned off again.

The settings, the certificate, and the key are in
`~/config/settings/RenkuRemoteDesktop/`. The settings file holds a PBKDF2
hash of the password and its NT hash, which NLA needs. Anyone who has the NT
hash can log in over NLA, so the file is readable only by its owner.

The server also runs by hand:

| Option | Meaning |
|---|---|
| `--set-password` | Read a new password (eight characters or more) and save its hashes |
| `--resize fastest` | Default. Switch the display to the client's size when that means fewer pixels; otherwise keep it |
| `--resize match-client` | Switch to the client's size whenever the display offers it |
| `--resize keep` | Never change the display mode |
| `--port N`, `--bind ADDRESS` | Where to listen (default: port 3389, all interfaces) |
| `--poll` | Read the whole screen each frame, even where app_server can report changes |
| `--service` | Used by launch_daemon: wait 30 seconds before exiting when the server cannot start |
| `-v`, `-vv` | Debug and trace logging |

## Design

The protocol is written from Microsoft's published specifications
([MS-RDPBCGR], [MS-RDPEGDI], [MS-CSSP], [MS-NLMP], [MS-SPNG],
[MS-RDPECLIP], [MS-RDPEDYC], [MS-RDPEDISP]). No code
comes from other RDP implementations. Comments cite the specification
sections.

`src/core` is portable C++ (POSIX and OpenSSL). `src/haiku` holds the screen
capture, the input forwarding, the input_server add-on, and the preferences.
`src/linux` holds the test harness.

## License

MIT. See [LICENSE](LICENSE).
