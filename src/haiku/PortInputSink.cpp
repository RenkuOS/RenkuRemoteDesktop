/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */


#include "PortInputSink.h"

#include <string.h>

#include "InputProtocol.h"
#include "Log.h"


PortInputSink::PortInputSink()
	:
	fPort(-1),
	fLastLookup(0),
	fWarned(false)
{
}


void
PortInputSink::Key(uint8_t scancode, bool extended, bool extended1, bool down)
{
	_Send(RRD_INPUT_KEY, scancode,
		(extended ? RRD_KEY_EXTENDED : 0) | (extended1 ? RRD_KEY_EXTENDED1 : 0),
		down);
}


void
PortInputSink::UnicodeKey(uint16_t codeUnit, bool down)
{
	_Send(RRD_INPUT_UNICODE, codeUnit, 0, down);
}


void
PortInputSink::Pointer(int32_t x, int32_t y, uint32_t buttons)
{
	_Send(RRD_INPUT_POINTER, x, y, buttons);
}


void
PortInputSink::Wheel(int32_t delta, bool horizontal)
{
	_Send(RRD_INPUT_WHEEL, delta, horizontal, 0);
}


void
PortInputSink::SyncLocks(uint32_t flags)
{
	_Send(RRD_INPUT_LOCKS, flags, 0, 0);
}


void
PortInputSink::ReleaseAll()
{
	_Send(RRD_INPUT_RELEASE_ALL, 0, 0, 0);
}


void
PortInputSink::_Send(int32 type, int32 a, int32 b, int32 c)
{
	remote_input_event event = { kRemoteInputVersion, type, a, b, c };

	for (int attempt = 0; attempt < 2; attempt++) {
		if (fPort < 0) {
			// Look the port up again at most once a second, so a missing
			// add-on does not cost a lookup per mouse move.
			bigtime_t now = system_time();
			if (attempt > 0 || now - fLastLookup < 1000000)
				return;
			fLastLookup = now;
			fPort = find_port(RRD_INPUT_PORT_NAME);
			if (fPort < 0) {
				if (!fWarned) {
					LOG_W("input add-on not running (no port \"%s\"); "
						"remote input is ignored", RRD_INPUT_PORT_NAME);
					fWarned = true;
				}
				return;
			}
			fWarned = false;
		}

		// Never block the session on a stuck input_server.
		status_t status = write_port_etc(fPort, type, &event, sizeof(event),
			B_RELATIVE_TIMEOUT, 100000);
		if (status == B_OK)
			return;
		if (status == B_BAD_PORT_ID) {
			// input_server restarted; find the new port.
			fPort = -1;
			fLastLookup = 0;
			continue;
		}
		LOG_W("cannot send input to the add-on: %s", strerror(status));
		return;
	}
}
