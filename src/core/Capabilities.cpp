/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */


#include "Capabilities.h"

#include "Log.h"
#include "Protocol.h"


namespace rrd {


ClientCapabilities::ClientCapabilities()
	:
	generalExtraFlags(0),
	preferredBitsPerPixel(0),
	desktopWidth(0),
	desktopHeight(0),
	drawingFlags(0),
	inputFlags(0),
	multifragmentMaxRequestSize(0),
	colorPointerCacheSize(0),
	pointerCacheSize(0),
	havePointerCacheSize(false),
	haveBitmap(false),
	haveGeneral(false)
{
}


// Starts a capability set; returns the offset of its length field.
static size_t
BeginCapability(Writer& writer, uint16_t type)
{
	writer.U16LE(type);
	size_t lengthOffset = writer.Size();
	writer.U16LE(0);
	return lengthOffset;
}


static void
EndCapability(Writer& writer, size_t lengthOffset)
{
	writer.PatchU16LE(lengthOffset, writer.Size() - (lengthOffset - 2));
}


std::vector<uint8_t>
BuildServerCapabilities(uint16_t width, uint16_t height, uint16_t& count)
{
	Writer writer;
	count = 0;
	size_t length;

	// 2.2.7.1.1 General
	length = BeginCapability(writer, CAPSTYPE_GENERAL);
	writer.U16LE(0);		// osMajorType: unspecified
	writer.U16LE(0);		// osMinorType: unspecified
	writer.U16LE(0x0200);	// protocolVersion: TS_CAPS_PROTOCOLVERSION
	writer.U16LE(0);		// pad2octetsA
	writer.U16LE(0);		// compressionTypes
	writer.U16LE(FASTPATH_OUTPUT_SUPPORTED | LONG_CREDENTIALS_SUPPORTED
		| NO_BITMAP_COMPRESSION_HDR_FLAG);
	writer.U16LE(0);		// updateCapabilityFlag
	writer.U16LE(0);		// remoteUnshareFlag
	writer.U16LE(0);		// compressionLevel
	writer.U8(1);			// refreshRectSupport
	writer.U8(1);			// suppressOutputSupport
	EndCapability(writer, length);
	count++;

	// 2.2.7.1.2 Bitmap
	length = BeginCapability(writer, CAPSTYPE_BITMAP);
	writer.U16LE(32);		// preferredBitsPerPixel
	writer.U16LE(1);		// receive1BitPerPixel
	writer.U16LE(1);		// receive4BitsPerPixel
	writer.U16LE(1);		// receive8BitsPerPixel
	writer.U16LE(width);
	writer.U16LE(height);
	writer.U16LE(0);		// pad2octets
	writer.U16LE(1);		// desktopResizeFlag
	writer.U16LE(1);		// bitmapCompressionFlag
	writer.U8(0);			// highColorFlags
	writer.U8(0);			// drawingFlags
	writer.U16LE(1);		// multipleRectangleSupport
	writer.U16LE(0);		// pad2octetsB
	EndCapability(writer, length);
	count++;

	// 2.2.7.1.3 Order: no drawing orders are used, only bitmap updates.
	length = BeginCapability(writer, CAPSTYPE_ORDER);
	writer.Zero(16);		// terminalDescriptor
	writer.U32LE(0);		// pad4octetsA
	writer.U16LE(1);		// desktopSaveXGranularity
	writer.U16LE(20);		// desktopSaveYGranularity
	writer.U16LE(0);		// pad2octetsA
	writer.U16LE(1);		// maximumOrderLevel: ORD_LEVEL_1_ORDERS
	writer.U16LE(0);		// numberFonts
	writer.U16LE(0x0022);	// orderFlags: NEGOTIATEORDERSUPPORT,
							// ZEROBOUNDSDELTASSUPPORT
	writer.Zero(32);		// orderSupport: none
	writer.U16LE(0);		// textFlags
	writer.U16LE(0);		// orderSupportExFlags
	writer.U32LE(0);		// pad4octetsB
	writer.U32LE(0);		// desktopSaveSize
	writer.U16LE(0);		// pad2octetsC
	writer.U16LE(0);		// pad2octetsD
	writer.U16LE(0);		// textANSICodePage
	writer.U16LE(0);		// pad2octetsE
	EndCapability(writer, length);
	count++;

	// 2.2.7.1.5 Pointer
	length = BeginCapability(writer, CAPSTYPE_POINTER);
	writer.U16LE(1);		// colorPointerFlag
	writer.U16LE(25);		// colorPointerCacheSize
	writer.U16LE(25);		// pointerCacheSize
	EndCapability(writer, length);
	count++;

	// 2.2.7.1.6 Input
	length = BeginCapability(writer, CAPSTYPE_INPUT);
	writer.U16LE(INPUT_FLAG_SCANCODES | INPUT_FLAG_MOUSEX
		| INPUT_FLAG_UNICODE | INPUT_FLAG_FASTPATH_INPUT2
		| TS_INPUT_FLAG_MOUSE_HWHEEL);
	writer.U16LE(0);		// pad2octetsA
	writer.U32LE(0);		// keyboardLayout
	writer.U32LE(0);		// keyboardType
	writer.U32LE(0);		// keyboardSubType
	writer.U32LE(0);		// keyboardFunctionKey
	writer.Zero(64);		// imeFileName
	EndCapability(writer, length);
	count++;

	// 2.2.7.1.10 Virtual Channel: no compression.
	length = BeginCapability(writer, CAPSTYPE_VIRTUALCHANNEL);
	writer.U32LE(0);
	EndCapability(writer, length);
	count++;

	// 2.2.7.2.4 Share
	length = BeginCapability(writer, CAPSTYPE_SHARE);
	writer.U16LE(MCS_SERVER_CHANNEL_ID);
	writer.U16LE(0);
	EndCapability(writer, length);
	count++;

	// 2.2.7.2.5 Font
	length = BeginCapability(writer, CAPSTYPE_FONT);
	writer.U16LE(FONTSUPPORT_FONTLIST);
	writer.U16LE(0);
	EndCapability(writer, length);
	count++;

	return writer.Data();
}


bool
ParseClientCapabilities(Reader& reader, uint16_t count,
	ClientCapabilities& capabilities)
{
	for (uint16_t i = 0; i < count; i++) {
		uint16_t type = reader.U16LE();
		uint16_t length = reader.U16LE();
		if (!reader.Ok() || length < 4) {
			LOG_W("bad capability set header");
			return false;
		}
		Reader set = reader.Sub(length - 4);
		if (!reader.Ok()) {
			LOG_W("capability set 0x%04x overruns the PDU", type);
			return false;
		}

		switch (type) {
			case CAPSTYPE_GENERAL:
				set.Skip(10);
				capabilities.generalExtraFlags = set.U16LE();
				capabilities.haveGeneral = set.Ok();
				break;
			case CAPSTYPE_BITMAP:
				capabilities.preferredBitsPerPixel = set.U16LE();
				set.Skip(6);
				capabilities.desktopWidth = set.U16LE();
				capabilities.desktopHeight = set.U16LE();
				set.Skip(6);
				set.Skip(1);	// highColorFlags
				capabilities.drawingFlags = set.U8();
				capabilities.haveBitmap = set.Ok();
				break;
			case CAPSTYPE_INPUT:
				capabilities.inputFlags = set.U16LE();
				break;
			case CAPSTYPE_POINTER:
				// 2.2.7.1.5: pointerCacheSize is optional.
				set.U16LE();	// colorPointerFlag
				capabilities.colorPointerCacheSize = set.U16LE();
				if (set.Remaining() >= 2) {
					capabilities.pointerCacheSize = set.U16LE();
					capabilities.havePointerCacheSize = true;
				}
				break;
			case CAPSETTYPE_MULTIFRAGMENTUPDATE:
				capabilities.multifragmentMaxRequestSize = set.U32LE();
				break;
			default:
				break;
		}
		LOG_T("client capability set 0x%04x, %u bytes", type, length);
	}
	return true;
}


}	// namespace rrd
