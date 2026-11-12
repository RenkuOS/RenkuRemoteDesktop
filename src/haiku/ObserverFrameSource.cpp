/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */


#include "ObserverFrameSource.h"

#include <GraphicsDefs.h>
#include <Point.h>
#include <Region.h>

#include <private/app/AppServerLink.h>
#include <private/app/ServerProtocol.h>

#include <string.h>

#include "Log.h"


using rrd::DisplaySize;
using rrd::PointerImage;
using rrd::Rect;


// RenkuOS's screen observer codes (headers/private/app/ServerProtocol.h
// in RenkuOS/Source). They are fixed values, so they are repeated here: a
// build against Haiku's headers still compiles, and Haiku's app_server
// answers them with B_ERROR.
enum {
	kScreenObserverStart	= 'RSos',
	kScreenObserverStop		= 'RSoe',
	kScreenObserverRead		= 'RSor',
};


ObserverFrameSource::ObserverFrameSource()
	:
	fStarted(false),
	fArea(-1),
	fBits(NULL),
	fBytesPerRow(0),
	fCursorGeneration(0)
{
	fAreaSize.width = 0;
	fAreaSize.height = 0;
}


ObserverFrameSource::~ObserverFrameSource()
{
	_DeleteArea();
}


bool
ObserverFrameSource::Start()
{
	std::lock_guard<std::mutex> lock(fObserverLock);
	BPrivate::AppServerLink link;
	link.StartMessage(kScreenObserverStart);
	int32 code;
	if (link.FlushWithReply(code) != B_OK || code != B_OK)
		return false;
	fStarted = true;
	return true;
}


void
ObserverFrameSource::Release()
{
	{
		std::lock_guard<std::mutex> lock(fObserverLock);
		if (fStarted) {
			BPrivate::AppServerLink link;
			link.StartMessage(kScreenObserverStop);
			int32 code;
			link.FlushWithReply(code);
			fStarted = false;
		}
		_DeleteArea();
	}
	ScreenFrameSource::Release();
}


bool
ObserverFrameSource::Capture(uint8_t* pixels, size_t stride,
	const DisplaySize& size, bool full, std::vector<Rect>& changed)
{
	std::lock_guard<std::mutex> lock(fObserverLock);
	if (!fStarted || size.width <= 0 || size.height <= 0
		|| (size_t)size.width * 4 > stride) {
		return false;
	}
	if (!_SetAreaSize(size))
		return false;

	BPrivate::AppServerLink link;
	link.StartMessage(kScreenObserverRead);
	link.Attach<area_id>(fArea);
	link.Attach<int32>(fBytesPerRow);
	int32 code;
	if (link.FlushWithReply(code) != B_OK)
		return false;

	if (code != B_OK) {
		if (code == B_MISMATCHED_VALUES) {
			// The mode changed. The session notices through Size().
			LOG_D("screen observer: the screen no longer has our size");
		} else
			LOG_W("screen observer: read failed: %s", strerror(code));
		return false;
	}

	int32 width;
	int32 height;
	int32 generation;
	int32 count;
	link.Read<int32>(&width);
	link.Read<int32>(&height);
	link.Read<int32>(&generation);
	if (link.Read<int32>(&count) != B_OK || count < 0)
		return false;
	fCursorGeneration = (uint32_t)generation;

	std::vector<clipping_rect> rects(count);
	for (int32 i = 0; i < count; i++) {
		if (link.Read<clipping_rect>(&rects[i]) != B_OK)
			return false;
	}

	if (width != size.width || height != size.height) {
		// The screen shrank under us. app_server copied what fit, but
		// the frame is not the one the caller asked for.
		return false;
	}

	if (full) {
		for (int32 y = 0; y < height; y++) {
			memcpy(pixels + (size_t)y * stride,
				fBits + (size_t)y * fBytesPerRow, (size_t)width * 4);
		}
		Rect all = { 0, 0, width, height };
		changed.push_back(all);
		return true;
	}

	for (int32 i = 0; i < count; i++) {
		const clipping_rect& clip = rects[i];
		if (clip.left < 0 || clip.top < 0 || clip.right >= width
			|| clip.bottom >= height || clip.left > clip.right
			|| clip.top > clip.bottom) {
			continue;
		}
		size_t bytes = (size_t)(clip.right - clip.left + 1) * 4;
		for (int32 y = clip.top; y <= clip.bottom; y++) {
			memcpy(pixels + (size_t)y * stride + (size_t)clip.left * 4,
				fBits + (size_t)y * fBytesPerRow + (size_t)clip.left * 4,
				bytes);
		}
		Rect rect = { clip.left, clip.top, clip.right - clip.left + 1,
			clip.bottom - clip.top + 1 };
		changed.push_back(rect);
	}
	return true;
}


bool
ObserverFrameSource::PointerShape(uint32_t& generation, PointerImage& image)
{
	std::lock_guard<std::mutex> lock(fObserverLock);
	if (!fStarted || generation == fCursorGeneration)
		return false;

	BPrivate::AppServerLink link;
	link.StartMessage(AS_GET_CURSOR_BITMAP);
	int32 code;
	if (link.FlushWithReply(code) != B_OK || code != B_OK) {
		// No cursor to read: keep the last shape until the next change.
		generation = fCursorGeneration;
		return false;
	}

	uint32 size;
	uint32 width;
	uint32 height;
	color_space space;
	BPoint hotSpot;
	link.Read<uint32>(&size);
	link.Read<uint32>(&width);
	link.Read<uint32>(&height);
	link.Read<color_space>(&space);
	if (link.Read<BPoint>(&hotSpot) != B_OK)
		return false;
	if ((space != B_RGBA32 && space != B_RGB32) || width > 256
		|| height > 256 || size < width * height * 4) {
		LOG_W("screen observer: unexpected cursor, %ux%u, space 0x%x",
			(unsigned)width, (unsigned)height, (unsigned)space);
		// Do not ask again for the same cursor.
		generation = fCursorGeneration;
		return false;
	}
	std::vector<uint8_t> bits(size);
	if (link.Read(bits.data(), size) != B_OK)
		return false;

	// app_server's cursor bits have premultiplied alpha (see
	// HWInterface::_DrawCursor()); RDP pointers have straight alpha. Rows
	// are width * 4 bytes, as AS_GET_CURSOR_BITMAP sends BitsLength().
	size_t rowBytes = size / height;
	image.width = width;
	image.height = height;
	image.hotX = (int32_t)hotSpot.x;
	image.hotY = (int32_t)hotSpot.y;
	image.pixels.assign((size_t)width * height * 4, 0);
	for (uint32 y = 0; y < height; y++) {
		const uint8* source = bits.data() + y * rowBytes;
		uint8_t* target = image.pixels.data() + (size_t)y * width * 4;
		for (uint32 x = 0; x < width; x++) {
			const uint8* pixel = source + x * 4;
			uint8 alpha = space == B_RGB32 ? 255 : pixel[3];
			uint8_t* out = target + x * 4;
			if (alpha == 0)
				continue;
			for (int c = 0; c < 3; c++) {
				uint32 value = alpha == 255 ? pixel[c]
					: (uint32)pixel[c] * 255 / alpha;
				out[c] = value > 255 ? 255 : (uint8_t)value;
			}
			out[3] = alpha;
		}
	}
	generation = fCursorGeneration;
	return true;
}


bool
ObserverFrameSource::_SetAreaSize(const DisplaySize& size)
{
	if (fArea >= 0 && fAreaSize.width == size.width
		&& fAreaSize.height == size.height) {
		return true;
	}
	_DeleteArea();

	int32 bytesPerRow = size.width * 4;
	size_t bytes = (size_t)bytesPerRow * size.height;
	bytes = (bytes + B_PAGE_SIZE - 1) & ~(size_t)(B_PAGE_SIZE - 1);
	void* address;
	area_id area = create_area("RenkuRemoteDesktop screen", &address,
		B_ANY_ADDRESS, bytes, B_NO_LOCK,
		B_READ_AREA | B_WRITE_AREA | B_CLONEABLE_AREA);
	if (area < 0) {
		LOG_E("screen observer: cannot create a %zu byte area: %s", bytes,
			strerror(area));
		return false;
	}
	fArea = area;
	fBits = (uint8*)address;
	fBytesPerRow = bytesPerRow;
	fAreaSize = size;
	return true;
}


void
ObserverFrameSource::_DeleteArea()
{
	if (fArea >= 0)
		delete_area(fArea);
	fArea = -1;
	fBits = NULL;
	fBytesPerRow = 0;
	fAreaSize.width = 0;
	fAreaSize.height = 0;
}
