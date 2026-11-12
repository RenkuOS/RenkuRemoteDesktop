/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */
#ifndef RRD_OBSERVER_FRAME_SOURCE_H
#define RRD_OBSERVER_FRAME_SOURCE_H


#include <OS.h>

#include <mutex>

#include "ScreenFrameSource.h"


// Capture backend B ([scope doc] section 6): RenkuOS's app_server screen
// observer. app_server reports what changed and copies only that, from its
// back buffer in RAM, into an area of ours. The back buffer has no cursor,
// so the client draws the pointer, with the shape from PointerShape().
// Display modes are handled as in backend A.
class ObserverFrameSource : public ScreenFrameSource {
public:
								ObserverFrameSource();
	virtual						~ObserverFrameSource();

			// Asks app_server for an observer. Fails on an app_server
			// without one, such as Haiku's.
			bool				Start();
	virtual	void				Release();

	virtual	bool				Capture(uint8_t* pixels, size_t stride,
									const rrd::DisplaySize& size, bool full,
									std::vector<rrd::Rect>& changed);
	virtual	bool				TracksChanges() { return true; }
	virtual	bool				IncludesCursor() { return false; }
	virtual	bool				PointerShape(uint32_t& generation,
									rrd::PointerImage& image);

private:
			bool				_SetAreaSize(const rrd::DisplaySize& size);
			void				_DeleteArea();

			std::mutex			fObserverLock;
			bool				fStarted;
			area_id				fArea;
			uint8*				fBits;
			int32				fBytesPerRow;
			rrd::DisplaySize	fAreaSize;
			uint32_t			fCursorGeneration;
};


#endif	// RRD_OBSERVER_FRAME_SOURCE_H
