/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */


#include "ScreenFrameSource.h"

#include <Screen.h>

#include <stdlib.h>
#include <string.h>

#include "Log.h"


using rrd::DisplaySize;


static float
RefreshRate(const display_mode& mode)
{
	uint32 total = (uint32)mode.timing.h_total * mode.timing.v_total;
	if (total == 0)
		return 0;
	return mode.timing.pixel_clock * 1000.0f / total;
}


ScreenFrameSource::ScreenFrameSource()
	:
	fBitmap(NULL),
	fModeChanged(false)
{
	memset(&fOriginalMode, 0, sizeof(fOriginalMode));
}


ScreenFrameSource::~ScreenFrameSource()
{
	// Release() has to have run already; without an app_server connection
	// neither call below is possible.
}


void
ScreenFrameSource::Release()
{
	RestoreSize();
	std::lock_guard<std::mutex> lock(fLock);
	delete fBitmap;
	fBitmap = NULL;
}


DisplaySize
ScreenFrameSource::Size()
{
	BScreen screen(B_MAIN_SCREEN_ID);
	BRect frame = screen.Frame();
	DisplaySize size = { frame.IntegerWidth() + 1, frame.IntegerHeight() + 1 };
	return size;
}


bool
ScreenFrameSource::Capture(uint8_t* pixels, size_t stride,
	const DisplaySize& size, bool full, std::vector<rrd::Rect>& changed)
{
	(void)full;

	std::lock_guard<std::mutex> lock(fLock);

	BScreen screen(B_MAIN_SCREEN_ID);
	BRect frame = screen.Frame();
	if (frame.IntegerWidth() + 1 != size.width
		|| frame.IntegerHeight() + 1 != size.height
		|| (size_t)size.width * 4 > stride) {
		return false;
	}
	if (fBitmap == NULL || fBitmap->Bounds() != frame) {
		delete fBitmap;
		fBitmap = new BBitmap(frame, B_RGB32);
		if (fBitmap->InitCheck() != B_OK) {
			delete fBitmap;
			fBitmap = NULL;
			return false;
		}
	}

	if (screen.ReadBitmap(fBitmap, false) != B_OK)
		return false;

	// The mode can change between Frame() and ReadBitmap(); copy only what
	// both the bitmap and the caller's buffer hold.
	if (fBitmap->Bounds() != frame)
		return false;
	int32 width = size.width;
	int32 height = size.height;

	const uint8* source = (const uint8*)fBitmap->Bits();
	int32 sourceStride = fBitmap->BytesPerRow();
	for (int32 y = 0; y < height; y++) {
		memcpy(pixels + (size_t)y * stride, source + (size_t)y * sourceStride,
			(size_t)width * 4);
	}
	rrd::Rect all = { 0, 0, width, height };
	changed.push_back(all);
	return true;
}


std::vector<DisplaySize>
ScreenFrameSource::AvailableSizes()
{
	std::vector<DisplaySize> sizes;
	BScreen screen(B_MAIN_SCREEN_ID);
	display_mode* modes;
	uint32 count;
	if (screen.GetModeList(&modes, &count) != B_OK)
		return sizes;

	display_mode current;
	screen.GetMode(&current);
	for (uint32 i = 0; i < count; i++) {
		if (modes[i].space != current.space)
			continue;
		DisplaySize size = { modes[i].virtual_width, modes[i].virtual_height };
		bool known = false;
		for (size_t j = 0; j < sizes.size() && !known; j++)
			known = sizes[j].width == size.width
				&& sizes[j].height == size.height;
		if (!known)
			sizes.push_back(size);
	}
	free(modes);
	return sizes;
}


bool
ScreenFrameSource::SetSize(const DisplaySize& size)
{
	BScreen screen(B_MAIN_SCREEN_ID);
	display_mode current;
	if (screen.GetMode(&current) != B_OK)
		return false;

	display_mode* modes;
	uint32 count;
	if (screen.GetModeList(&modes, &count) != B_OK)
		return false;

	// Same color space; the refresh rate closest to the current one.
	float currentRate = RefreshRate(current);
	int32 best = -1;
	float bestDistance = 0;
	for (uint32 i = 0; i < count; i++) {
		if (modes[i].space != current.space
			|| modes[i].virtual_width != size.width
			|| modes[i].virtual_height != size.height) {
			continue;
		}
		float distance = RefreshRate(modes[i]) - currentRate;
		if (distance < 0)
			distance = -distance;
		if (best < 0 || distance < bestDistance) {
			best = i;
			bestDistance = distance;
		}
	}

	bool ok = false;
	if (best >= 0) {
		display_mode mode = modes[best];
		if (!fModeChanged)
			fOriginalMode = current;
		// Not the default mode: a reboot keeps the user's own setting.
		ok = screen.SetMode(&mode, false) == B_OK;
		if (ok)
			fModeChanged = true;
	}
	free(modes);
	return ok;
}


void
ScreenFrameSource::RestoreSize()
{
	if (!fModeChanged)
		return;
	BScreen screen(B_MAIN_SCREEN_ID);
	if (screen.SetMode(&fOriginalMode, false) != B_OK)
		LOG_W("cannot restore the original display mode");
	fModeChanged = false;
}


DisplaySize
ScreenFrameSource::OriginalSize()
{
	if (!fModeChanged)
		return Size();
	DisplaySize size = { fOriginalMode.virtual_width,
		fOriginalMode.virtual_height };
	return size;
}
