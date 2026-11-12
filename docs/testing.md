# Testing log

## 2026-11-11, first build

### Setup

- **Server on RenkuOS:** the Supermicro Test Desktop, running RenkuOS hrev60072+645 (Nov 8 2026) with
  GCC 13.3.0 and openssl3 3.5.7. Display: AMD Radeon R7 260X (Bonaire XTX,
  PCI `1002:6658`) on the `radeon_hd` driver, at 1920×1200.
- **Server on Linux:** the `rrd-test-server` harness on Linux Mint 22.3, OpenSSL 3.0.13.
- **Client:** FreeRDP 3.32.2 (`xfreerdp3`) on an Xvfb display, driven with
  xdotool and checked with screenshots.

### Results

| Test | Result |
|---|---|
| Unit tests: planar RLE against the [MS-RDPEGDI] 3.1.9.2 worked examples, a planar round trip, resize policy, password hashing, UTF-16, and Connect-Initial parsing of the [MS-RDPBCGR] 4.1.3 dump | 44 of 44 pass, on Linux and on RenkuOS |
| Connection sequence with FreeRDP: X.224 negotiation, TLS 1.2 (ECDHE-RSA-AES256-GCM-SHA384), MCS and GCC, channel joins, Client Info, licensing, capability exchange, finalization | Pass |
| Picture (Linux harness test pattern): orientation, colors, gradients, moving square, checkerboard | Pass. Planar data in bitmap updates is bottom-up |
| Picture (RenkuOS): the real desktop at 1920×1200 | Pass |
| Typing into StyledEdit on RenkuOS: letters, Shift symbols, digits, Enter | Pass: `Hello from RDP! Typing test: abc XYZ 123 ()[]{}<>?/;:@#` arrived exactly |
| Mouse: click to place the caret, click the File menu | Pass |
| Modifiers: Ctrl+A (this keymap's Command key) selects all | Pass |
| Wrong password | Refused before any screen data is sent (harness) |
| Session takeover | Pass. The first client is disconnected and the second is activated (harness) |
| Resize policy "fastest" | Pass on the harness (1280×800 to 1024×768). On RenkuOS see the crash below |
| Wheel, Unicode input, lock-key sync, extended mouse buttons | **Not tested** |
| Windows `mstsc`, Windows App on macOS, mobile clients | **Not tested** (no Windows client was available) |
| Display size change during a session (Deactivation-Reactivation) | **Not tested** |

FreeRDP 3.32 does not set `RNS_UD_CS_SUPPORT_ERRINFO_PDU` (its early
capability flags are 0x0fb2). The server therefore sends no Set Error Info PDU
on takeover, and FreeRDP reports "logoff by user". That is correct per the
specification.

### Capture backend A performance (RenkuOS, Radeon R7 260X, 1920×1200)

From the server's own statistics (`-v`), with an idle desktop:

```
last 10.1 s: 30 polls, capture 293.8 ms and encode 2.5 ms per poll, 55 tiles, 27.2 KB/s
```

- `BScreen::ReadBitmap()` takes **about 294 ms** for a full frame (about 31 MB/s
  read from video memory). That limits backend A to about 3.4 frames a second
  on this card.
- During those reads, `top` shows the app_server thread that serves the server
  at 10.9% of total CPU, which is close to one core.
- Encoding is fast: 2.5 to 4.4 ms per poll.

So the fast capture path (backend B, reading app_server's back buffer in RAM)
is needed for usable frame rates, at least on this card. Polling backs off to
every 200 ms after two idle seconds, but at about 294 ms per read that saves
nothing on this machine.

### Crash in the development `radeon_hd` accelerant

The first RenkuOS test switched the display from 1920×1200 to 1280×960 (resize
policy "fastest"; the client asked for 1600×1000). An app_server thread then
stopped with a general protection fault:

```
KERN: debug_server: Thread 647 entered the debugger: General protection fault
KERN: stack trace, current PC 0x1696aa14325  </boot/home/config/non-packaged/add-ons/accelerants/radeon_hd.accelerant> radeon_get_pixel_clock_limits + 0x85:
```

- The accelerant is a non-packaged build dated Nov 10 14:18. The offset 0x85
  is the function's `ret` (0x15325 in that file). The function's pushes and
  pops balance, so the return address was already bad when it returned. That
  points to stack corruption on the caller's side, or a hook signature
  mismatch between this accelerant and the installed app_server. This is
  inferred from the disassembly, not confirmed.
- app_server hung. `shutdown -r` could not complete, and the box needed an
  IPMI power cycle.
- **Not reproduced.** After the power cycle, the mode list has only
  1920×1200 (pixel clock 193155), while the current mode uses pixel clock
  154128. `screenmode 1280 960` now fails cleanly ("No such file or
  directory"). The syslog from the crash is saved on the Supermicro Test Desktop as
  `/boot/home/syslog-radeon-gpf-20261111.txt`.
- Testing continued with `--resize keep`.

The power cycle also exposed a bug here: the certificate and key written four
minutes earlier came back zero-filled. Both are now written through a
temporary file, fsync, and rename. A damaged pair is moved aside as `.bad` and
replaced, which was tested on the zero-filled files.

### Fixes from code review, and their tests

Blockers-only reviews found eight problems, and testing on RenkuOS found three more. All are fixed:

| Problem | Fix | Test |
|---|---|---|
| Use-after-free when three logins race for the desktop | Takeover loop re-reads the active session on every pass | Clients a, b, and c in quick succession: each takes over cleanly (harness) |
| Silent clients could hold every login slot | 20 s socket timeouts, a 30 s login deadline, at most 4 pending logins and 2 per address; the active session does not count | Four silent connections time out and a real login then works; a client sending one byte every 5 s is closed after 40 s; a third pending connection from one address is refused (harness) |
| Heap overflow if the display mode changes between `Size()` and `Capture()` | `Capture()` takes the expected size and refuses any other | Not tested directly (needs a mode change mid-capture) |
| Keymap race in the input add-on | `BLocker` around keymap use, as in Haiku's keyboard device | Typing retested on RenkuOS; a keymap change during typing is **not tested** |
| Use-after-free at shutdown with a session connected | `Run()` aborts all sessions and waits for them before returning | Ctrl+C with a live session exits cleanly (harness) |
| The server never quit on Haiku: `shutdown()` does not wake `accept()` there | The accept loop polls every 500 ms | `hey application/x-vnd.RenkuOS-RemoteDesktop quit` ends the server on RenkuOS |
| Found in testing: quitting with a live session hung. A debugger backtrace showed the session blocked in `BPrivateScreen::ReadBitmap`, waiting for app_server, while the looper waited in `QuitRequested()` | `QuitRequested()` only asks the server to stop. The application quits once the server thread reports that all sessions have ended | Quit with a live session: the server exits within 1 s (RenkuOS) |
| Found in testing: a crash at exit, "You need to have a valid app_server connection first!", from deleting the capture `BBitmap` after the BApplication was gone | The frame source frees the bitmap and restores the mode before the application quits | No debugger entries after quitting (RenkuOS) |
| Found in testing: on Haiku, `shutdown()` does not make `poll()` or writes fail, so an aborted session kept running | `Abort()` also sets a flag that the session loop checks | Part of the quit test above |
| Review: the first `QuitRequested()` reply of false made the registrar treat the server as a user app that aborted the shutdown | The app is flagged `B_BACKGROUND_APP` (and `B_EXCLUSIVE_LAUNCH`) in `RenkuRemoteDesktop.rdef` | `shutdown -r` with the server running rebooted the Supermicro Test Desktop. A shutdown during a live session was **not tested** |

On Haiku, `shutdown()` also does not wake a thread blocked in a socket read,
so takeover and shutdown can wait up to the 20 s socket timeout. That is
bounded and noted for later.

Also seen: a mouse move over RDP wakes the screen saver, because the input
add-on's events count as user activity.

## 2026-11-12, capture backend B (app_server screen observer)

### Setup

- **Server:** the Supermicro Test Desktop, as above, with an app_server built
  from RenkuOS/Source `origin/main` (af22bfb13d) plus the screen observer
  change (branch `appserver/screen-observer`). It runs from
  `~/config/non-packaged/servers/app_server` through the launch override
  `~/config/settings/launch/app_server-screen-observer`. Deleting that file
  and rebooting goes back to the packaged app_server. The protocol between
  libbe and app_server did not change between the installed build and
  `origin/main`.
- **Client:** FreeRDP 3.32.2 at 1920×1200, as above.

### Results

| Test | Result |
|---|---|
| Unit tests, now including the pointer encoder (32 bpp and 24 bpp, masks, cropping) | 47 of 47 pass, on Linux and on RenkuOS |
| Backend selection on the packaged app_server (no observer) | Pass: "capture: reading the whole screen each frame" (backend A) |
| Backend selection on the observer app_server | Pass: "capture: app_server screen observer" |
| Picture: whole desktop at connect | Pass |
| Picture compared pixel by pixel with a `screenshot` taken on the machine | Pass: identical except for 16 to 58 pixels in the Deskbar CPU meter, which changes between the two captures |
| Dragging a window continuously for 6 s | Pass: no trails or stale tiles |
| Pointer shape: arrow, hand, and I-beam over a text field | Pass: the client draws Haiku's cursors (checked on a capture with the client cursor drawn in) |
| Takeover by a second client | Pass: the new session gets the whole desktop |
| Quit with a live session | Pass: exits within 1 s |
| `kill -9` with a live session, then restart and reconnect | Pass: app_server cleans up and keeps running; the new server gets a new observer |
| Linux harness with change tracking (moving square, alternating pointer shapes) | Pass: no trails; FreeRDP accepts both pointer updates |
| `--poll` forces backend A on the observer app_server | Pass |
| `tests/haiku/ObserverProbe`: a valid read; a bytes-per-row value whose product with the height wraps in 32 bits; an area shrunk after app_server cloned it; an area without `B_CLONEABLE_AREA` | Pass: B_OK, then B_MISMATCHED_VALUES twice, then B_BAD_VALUE. app_server kept running. Run on x86_64 only, so the 32-bit wrap itself is **not tested** |
| Typing and clicking | **Not retested** this round (the input path did not change) |
| Display mode change with the observer running | **Not tested** (the Supermicro Test Desktop stays at `resize = keep`, see the radeon_hd crash above) |
| A screen with a non-32-bit or single-buffered drawing buffer | **Not tested** |

### Performance, backend A against backend B (same machine, 1920×1200)

| | Backend A (ReadBitmap) | Backend B (observer) |
|---|---|---|
| Capture per poll | 293.8 ms | 0.0 to 0.1 ms |
| Polls a second | about 3 | 25 (the configured 40 ms frame interval) |
| app_server thread serving the server | about 10.9% of total CPU, close to one core | 3.9 ms of CPU in 3 s while a window was dragged (about 0.1% of one core) |
| Server's session thread while dragging | not measured | 134 ms of CPU in 3 s (about 4.5% of one core) |
| Encoding per poll | 2.5 to 4.4 ms | 0.3 ms idle, 0.9 ms while dragging |

Code review found two blockers in the first version of the READ size
check: the product could wrap on 32-bit targets, and the area size was
cached when the area was cloned, so a client that shrank its area could make
app_server write past its end. Both are fixed: the check now uses 64 bits and
the clone's current size. The probe above covers them.

A crash during this testing was caused by the install step, not the code:
copying a new app_server over the file the running app_server was executing
from. app_server then faulted in `ServerWindow::_MessageLooper` at shutdown,
and the reboot hung until the crash's Debugger was killed. Install a new
binary under a temporary name and `mv` it into place instead.

Backend B polls app_server every frame, even when idle, because a poll with
nothing changed costs one message round trip.

## 2026-11-12, NLA and Windows mstsc

### Why mstsc failed before

1. **Channel IDs.** The user channel was always 1007, while static channels are
   numbered from 1004. mstsc asks for four static channels (rdpdr, rdpsnd,
   cliprdr, drdynvc), so drdynvc also got 1007, and mstsc stopped during the
   channel setup. The user channel now comes after the static channels.
2. **No NLA.** Once past the channels, mstsc sent an empty user name and
   password in the Client Info PDU: it asks for the password only through
   NLA. The server now does NLA (CredSSP with NTLMv2).

### Results

| Test | Result |
|---|---|
| Unit tests: MD4 ([RFC1320] A.5), RC4, NTOWFv1 ([MS-NLMP] 4.2.2.1.2), NTLMv2 verification and unsealing with the [MS-NLMP] 4.2.4 messages, a wrong password, a client without sealing, DER integers and TSRequest round trip, SPNEGO parsing | 77 of 77 pass, on Linux and on RenkuOS |
| FreeRDP 3.32, `/sec:nla`, Linux harness | Pass: CredSSP version 6, raw NTLM |
| FreeRDP 3.32, wrong password | Refused; FreeRDP reports `ERRCONNECT_LOGON_FAILURE` |
| FreeRDP 3.32, `/sec:tls` | Pass: the password is still checked from the Client Info PDU |
| FreeRDP 3.32, NLA, Supermicro Test Desktop | Pass |
| **Windows 11 mstsc (build 26100), Supermicro Test Desktop** | **Pass**: CredSSP version 6, raw NTLM, session active at 1920×1200 (tested by Kevin) |
| NTLM inside SPNEGO with a real client | **Not tested** (FreeRDP and mstsc both sent raw NTLM) |
| CredSSP versions 2 to 4 | **Not tested** |

mstsc opens two connections per attempt. One finishes or stalls in TLS and
is closed by the server's 20-second read timeout; the other is the session.

Code review found one blocker: the bounds check on NTLM message fields could
wrap on 32-bit targets. It is fixed.

## 2026-11-12, Remote Desktop preferences and the launch_daemon service

### Setup

`make install DESTDIR=… PREFIX=/boot/system/non-packaged` staged the files,
which were then moved into `/boot/system/non-packaged` on the Supermicro
Test Desktop: `servers/RenkuRemoteDesktop`, `preferences/Remote Desktop`,
the input add-on, and `data/user_launch/RenkuRemoteDesktop`. The panel was
driven through an RDP session from FreeRDP 3.32 (xdotool clicks), and with
`hey` where no session was possible.

### Results

| Test | Result |
|---|---|
| launch_daemon reads the service after a reboot; condition `file_exists …/enabled`, launch path from `PREFIX` | Pass (`launch_roster info`) |
| Switch on (enabled file, then launch_daemon start) | Pass: started under launch_daemon, fast capture |
| Panel status while connected | Pass: "Connected: kevin from 192.168.74.137 since 13:52." |
| Certificate fingerprint in the panel | Pass: matches the server log |
| Password dialog: hidden typing, too short, mismatch | Pass: "The two passwords differ.", button disabled |
| Port 3389 to 3390 in the panel | Pass: settings saved, server quit and was relaunched by launch_daemon on 3390, job still enabled |
| Defaults (port 3389, resize fastest) | Pass: restarted on 3389 |
| Revert | Pass: back to `keep`; reloaded without a restart, session kept |
| Disconnect | Pass after the input fix below: "disconnecting … on request", client ended |
| Switch off | Pass: session ended, enabled file removed, job disabled, still stopped 10 s later |
| Switch on again (panel handler, through `hey`) | Pass: relaunched under launch_daemon, "On. Waiting for connections on port 3389." |
| Listen address not on the machine | Pass: "cannot listen … Can't assign requested address", "trying again in 30 seconds"; panel shows "Not running. The system log (syslog) has the reason." |
| Recovery once the address is fixed | Pass: back on the next attempt, one failure logged (no restart loop) |
| Reboot with the switch on | Pass: started with the desktop; NLA login works |
| Set a new password from the panel | **Not tested** (the dialog was only cancelled) |
| Panel listed in the Deskbar Preferences menu | **Not tested** (non-packaged install) |

### Found in testing: clicks landing outside buttons

The panel's Disconnect button stayed pressed and never fired. The mouse
events showed `screen_where` at the previous pointer position. app_server
takes the cursor position only from `B_MOUSE_MOVED` and fills in
`screen_where` for button events from it (`EventDispatcher.cpp`). FreeRDP
sends "move here and click" as just a button event with the new position,
so the input add-on now sends a `B_MOUSE_MOVED` first whenever a button
event comes with a new position. This affected clicks everywhere, not only
the panel, whenever a client sent no separate move before a click.

Replacing the input add-on file while input_server runs unloaded the old one
without loading the new one; restarting input_server fixed that.

## 2026-11-12, clipboard and dynamic resize

### Results

| Test | Result |
|---|---|
| Unit tests: clipboard text conversion and format lists, the channel in both directions, file lists (including sizes above 4 GB), unsafe names, folder walking, a 1.5 MB download in pieces, serving a range, the size limit, a skipped name keeping list positions, a file without a size stopped at the limit; dynamic channel capabilities, creation, fragmentation both ways, and a monitor layout | 146 of 146 pass, on Linux and on RenkuOS |
| Text, client to server (FreeRDP 3.32 `+clipboard`, Linux harness): UTF-8 and line ends | Pass |
| Text, server to client | Pass |
| 234,398 bytes of text, both ways | Pass: identical |
| Files, client to server: a folder with a subfolder and a 3 MB file | Pass: identical, in a new timestamped folder |
| Files, server to client, FreeRDP on Linux | **Not working with FreeRDP**: it receives the list but its FUSE view returns nothing. To be tested with mstsc and Windows Explorer |
| Dynamic resize (FreeRDP `/dynamic-resolution`, `resize = match-client`): 1280×800 to 1024×768 to 1600×900 | Pass: display switched and the client reactivated, picture correct |
| Text, client to server, Supermicro Test Desktop (FreeRDP) | Pass: `clipboard -p` shows the text with its Unicode |
| Text, server to client, Supermicro Test Desktop (`clipboard -c`) | Pass |
| Files, client to server, Supermicro Test Desktop | Pass: in `~/Desktop/Remote files/<date time>/`, `photo.bin` identical (MD5); the clipboard holds Tracker's `r<device>_<node>` refs with `'Tcsl'` (copy) modes |
| Text with Windows 11 mstsc, several copies in a row | First version: some copies were never fetched. mstsc answered the immediate request with "fail" (log: PDU 0x0005, flags 0x2), so RenkuOS kept the older text. Fixed: a refused request is repeated after 250, 500, and 1000 ms. Retest: **pass**, every paste was the latest copy (4 texts fetched, 2 of them after a retry) |
| Files, Windows 11 Explorer to RenkuOS, Paste in Tracker (mstsc) | Pass (Kevin): one file into `Remote files/<date time>/`, then pasted in Tracker |
| Files, Tracker to Windows Explorer (mstsc) | Pass (Kevin): one file; Explorer asked for the file list 20 times and the contents once |
| Resizing the mstsc window | Pass (Kevin): "display control: the client's window is now 1920x1080"; the display stays at 1920×1200, the only mode the driver offers |
| Many files, folders, or large files with mstsc | **Not tested** |

Review of the dynamic channels found two more problems, both fixed with
tests: a message of 1,591 to 1,593 bytes read past its buffer, and under
"fastest" a client window larger than the console could still shrink it.

Code review found two blockers in the file copy from the client, both fixed
with regression tests: the size limit could be passed with a file that
gives no size, with sizes that wrap the total, or with oversized pieces; and
a skipped file name shifted the list positions, so later files got another
file's contents.
