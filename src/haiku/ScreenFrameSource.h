/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */
#ifndef RRD_SCREEN_FRAME_SOURCE_H
#define RRD_SCREEN_FRAME_SOURCE_H


#include <Accelerant.h>
#include <Bitmap.h>

#include <mutex>

#include "Platform.h"


// Capture backend A ([scope doc] section 6): polls BScreen::ReadBitmap().
// Public API only, so it works on stock Haiku as well as RenkuOS.
class ScreenFrameSource : public rrd::FrameSource {
public:
								ScreenFrameSource();
	virtual						~ScreenFrameSource();

	virtual	rrd::DisplaySize	Size();
	virtual	bool				Capture(uint8_t* pixels, size_t stride,
									const rrd::DisplaySize& size, bool full,
									std::vector<rrd::Rect>& changed);
	// ReadBitmap() reads the front buffer, where app_server draws the
	// cursor, whatever its drawCursor argument says.
	virtual	bool				IncludesCursor() { return true; }

	virtual	std::vector<rrd::DisplaySize> AvailableSizes();
	virtual	bool				SetSize(const rrd::DisplaySize& size);
	virtual	void				RestoreSize();
	virtual	rrd::DisplaySize	OriginalSize();

			// Restores the display mode and frees the bitmap. Call it while
			// the BApplication still exists: both need app_server.
	virtual	void				Release();

private:
			std::mutex			fLock;
			BBitmap*			fBitmap;
			display_mode		fOriginalMode;
			bool				fModeChanged;
};


#endif	// RRD_SCREEN_FRAME_SOURCE_H
