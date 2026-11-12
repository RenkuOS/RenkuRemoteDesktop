/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */
#ifndef RRD_PLATFORM_H
#define RRD_PLATFORM_H


// The interfaces between the protocol core and the operating system: where
// pixels come from and where input goes.


#include <stdint.h>

#include <vector>


namespace rrd {


struct DisplaySize {
	int32_t		width;
	int32_t		height;
};


struct Rect {
	int32_t		x;
	int32_t		y;
	int32_t		width;
	int32_t		height;
};


// A mouse pointer image: B, G, R, A bytes with straight (not premultiplied)
// alpha, rows top-down.
struct PointerImage {
	int32_t		width;
	int32_t		height;
	int32_t		hotX;
	int32_t		hotY;
	std::vector<uint8_t> pixels;
};


class FrameSource {
public:
	virtual						~FrameSource() {}

	// Current size of the shared desktop.
	virtual	DisplaySize			Size() = 0;

	// Brings pixels up to date with the desktop: 32 bits per pixel in B, G,
	// R, X byte order, rows top-down, stride in bytes. The buffer holds
	// exactly size.height rows. With full set, pixels holds nothing useful
	// and the whole desktop is written. Otherwise pixels still holds what
	// the previous call left there, and only what changed has to be
	// written. changed receives the areas that may differ from before; a
	// source that cannot tell reports the whole desktop. Fails, without
	// writing, unless the desktop has exactly that size.
	virtual	bool				Capture(uint8_t* pixels, size_t stride,
									const DisplaySize& size, bool full,
									std::vector<Rect>& changed) = 0;

	// True when Capture() knows what changed, so that calling it when
	// nothing did is cheap.
	virtual	bool				TracksChanges() { return false; }

	// True when captured frames already contain the mouse cursor. The
	// client's own cursor is then hidden, so only one is shown.
	virtual	bool				IncludesCursor() { return false; }

	// When the pointer shape differs from the one generation names, fills
	// image, updates generation, and returns true. Sources that include the
	// cursor in their frames return false.
	virtual	bool				PointerShape(uint32_t& generation,
									PointerImage& image)
									{ (void)generation; (void)image;
										return false; }

	// Sizes the display can be switched to. Empty when switching is not
	// supported.
	virtual	std::vector<DisplaySize> AvailableSizes()
									{ return std::vector<DisplaySize>(); }
	virtual	bool				SetSize(const DisplaySize& size)
									{ (void)size; return false; }
	// Undoes SetSize() when the last client leaves.
	virtual	void				RestoreSize() {}
};


class InputSink {
public:
	virtual						~InputSink() {}

	// PC/AT scancode set 1, with the E0 (extended) and E1 (extended1)
	// prefixes as flags.
	virtual	void				Key(uint8_t scancode, bool extended,
									bool extended1, bool down) = 0;
	virtual	void				UnicodeKey(uint16_t codeUnit, bool down) = 0;

	// Absolute desktop coordinates. buttons is a mask: 1 left, 2 right,
	// 4 middle, 8 and 16 extra buttons.
	virtual	void				Pointer(int32_t x, int32_t y,
									uint32_t buttons) = 0;
	// Wheel steps in RDP units (120 per notch), positive away from the user
	// or to the right.
	virtual	void				Wheel(int32_t delta, bool horizontal) = 0;

	// Caps, Num, and Scroll Lock state from the client:
	// 1 scroll, 2 num, 4 caps (2.2.8.1.1.3.1.1.5).
	virtual	void				SyncLocks(uint32_t flags) = 0;

	// Releases every key and button the client holds down, for example when
	// a session ends.
	virtual	void				ReleaseAll() = 0;
};


}	// namespace rrd


#endif	// RRD_PLATFORM_H
