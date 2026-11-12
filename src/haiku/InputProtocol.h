/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */
#ifndef RRD_INPUT_PROTOCOL_H
#define RRD_INPUT_PROTOCOL_H


// Messages from the server process to the input_server add-on, written to
// a port. Both sides are built from this header; bump kRemoteInputVersion
// on any change.


#include <SupportDefs.h>


#define RRD_INPUT_PORT_NAME "RenkuRemoteDesktop input"

static const int32 kRemoteInputVersion = 1;

enum {
	RRD_INPUT_KEY = 1,			// a: AT set 1 scancode, b: flags, c: down
	RRD_INPUT_UNICODE,			// a: UTF-16 code unit, c: down
	RRD_INPUT_POINTER,			// a: x, b: y, c: button mask
	RRD_INPUT_WHEEL,			// a: delta (120 per notch), b: horizontal
	RRD_INPUT_LOCKS,			// a: RDP lock flags (1 scroll, 2 num, 4 caps)
	RRD_INPUT_RELEASE_ALL
};

enum {
	RRD_KEY_EXTENDED = 0x01,	// E0 prefix
	RRD_KEY_EXTENDED1 = 0x02	// E1 prefix
};

struct remote_input_event {
	int32	version;
	int32	type;
	int32	a;
	int32	b;
	int32	c;
};


#endif	// RRD_INPUT_PROTOCOL_H
