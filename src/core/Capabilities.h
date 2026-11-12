/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */
#ifndef RRD_CAPABILITIES_H
#define RRD_CAPABILITIES_H


// Capability exchange, [MS-RDPBCGR] 2.2.1.13 and 2.2.7.


#include <vector>

#include "ByteStream.h"


namespace rrd {


enum {
	CAPSTYPE_GENERAL = 0x0001,
	CAPSTYPE_BITMAP = 0x0002,
	CAPSTYPE_ORDER = 0x0003,
	CAPSTYPE_POINTER = 0x0008,
	CAPSTYPE_SHARE = 0x0009,
	CAPSTYPE_INPUT = 0x000D,
	CAPSTYPE_FONT = 0x000E,
	CAPSTYPE_VIRTUALCHANNEL = 0x0014,
	CAPSETTYPE_MULTIFRAGMENTUPDATE = 0x001A,
	CAPSETTYPE_LARGE_POINTER = 0x001B,

	// 2.2.7.1.1 extraFlags
	FASTPATH_OUTPUT_SUPPORTED = 0x0001,
	LONG_CREDENTIALS_SUPPORTED = 0x0004,
	NO_BITMAP_COMPRESSION_HDR_FLAG = 0x0400,

	// 2.2.7.1.2 drawingFlags
	DRAW_ALLOW_SKIP_ALPHA = 0x08,

	// 2.2.7.1.6 inputFlags
	INPUT_FLAG_SCANCODES = 0x0001,
	INPUT_FLAG_MOUSEX = 0x0004,
	INPUT_FLAG_FASTPATH_INPUT = 0x0008,
	INPUT_FLAG_UNICODE = 0x0010,
	INPUT_FLAG_FASTPATH_INPUT2 = 0x0020,
	TS_INPUT_FLAG_MOUSE_HWHEEL = 0x0100,

	// 2.2.7.2.5
	FONTSUPPORT_FONTLIST = 0x0001
};


// What the client said in its Confirm Active PDU.
struct ClientCapabilities {
				ClientCapabilities();

	uint16_t	generalExtraFlags;
	uint16_t	preferredBitsPerPixel;
	uint16_t	desktopWidth;
	uint16_t	desktopHeight;
	uint8_t		drawingFlags;
	uint16_t	inputFlags;
	uint32_t	multifragmentMaxRequestSize;
	uint16_t	colorPointerCacheSize;
	uint16_t	pointerCacheSize;
	bool		havePointerCacheSize;
	bool		haveBitmap;
	bool		haveGeneral;
};


// The capabilitySets of the server's Demand Active PDU, with the count.
std::vector<uint8_t> BuildServerCapabilities(uint16_t width, uint16_t height,
	uint16_t& count);

// Parses the capability sets of a Confirm Active PDU.
bool ParseClientCapabilities(Reader& reader, uint16_t count,
	ClientCapabilities& capabilities);


}	// namespace rrd


#endif	// RRD_CAPABILITIES_H
