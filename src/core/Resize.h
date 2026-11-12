/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */
#ifndef RRD_RESIZE_H
#define RRD_RESIZE_H


#include <vector>

#include "Platform.h"


namespace rrd {


enum ResizePolicy {
	// Never send more pixels than the console has. Switch down to the
	// client's size (or the largest mode that fits inside it); keep the
	// console's size when the client is larger. The default.
	RESIZE_FASTEST = 0,
	// Match the client's size whenever the display offers a mode for it,
	// also when that means more pixels.
	RESIZE_MATCH_CLIENT,
	// Never change the display mode.
	RESIZE_KEEP
};


// Picks the session size. Returns true and sets target when the display
// should switch modes; returns false to keep the console size.
bool ChooseSessionSize(ResizePolicy policy, const DisplaySize& client,
	const DisplaySize& console, const std::vector<DisplaySize>& available,
	DisplaySize& target);

const char* ResizePolicyName(ResizePolicy policy);
bool ParseResizePolicy(const char* name, ResizePolicy& policy);


}	// namespace rrd


#endif	// RRD_RESIZE_H
