/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */


#include "Resize.h"

#include <stdint.h>
#include <string.h>


namespace rrd {


static int64_t
Area(const DisplaySize& size)
{
	return (int64_t)size.width * size.height;
}


static bool
Same(const DisplaySize& a, const DisplaySize& b)
{
	return a.width == b.width && a.height == b.height;
}


bool
ChooseSessionSize(ResizePolicy policy, const DisplaySize& client,
	const DisplaySize& console, const std::vector<DisplaySize>& available,
	DisplaySize& target)
{
	if (policy == RESIZE_KEEP || available.empty() || Same(client, console))
		return false;

	bool fastest = policy == RESIZE_FASTEST;
	// "Fastest" never switches away from a console that fits the client.
	if (fastest && console.width <= client.width
		&& console.height <= client.height) {
		return false;
	}

	// An exact match first.
	for (size_t i = 0; i < available.size(); i++) {
		if (!Same(available[i], client))
			continue;
		if (fastest && Area(client) >= Area(console))
			return false;
		target = client;
		return true;
	}

	// Otherwise the largest mode that fits inside the client's window.
	const DisplaySize* best = NULL;
	for (size_t i = 0; i < available.size(); i++) {
		const DisplaySize& size = available[i];
		if (size.width > client.width || size.height > client.height)
			continue;
		if (fastest && Area(size) >= Area(console))
			continue;
		if (best == NULL || Area(size) > Area(*best))
			best = &size;
	}
	if (best == NULL || Same(*best, console))
		return false;

	// Without an exact match, only switch if the result is closer to the
	// client's size than the console is; a much smaller mode would make the
	// picture worse for little gain.
	if (!fastest && Area(console) <= Area(client)
		&& Area(*best) <= Area(console)) {
		return false;
	}

	target = *best;
	return true;
}


const char*
ResizePolicyName(ResizePolicy policy)
{
	switch (policy) {
		case RESIZE_FASTEST:
			return "fastest";
		case RESIZE_MATCH_CLIENT:
			return "match-client";
		case RESIZE_KEEP:
			return "keep";
	}
	return "?";
}


bool
ParseResizePolicy(const char* name, ResizePolicy& policy)
{
	if (strcmp(name, "fastest") == 0)
		policy = RESIZE_FASTEST;
	else if (strcmp(name, "match-client") == 0)
		policy = RESIZE_MATCH_CLIENT;
	else if (strcmp(name, "keep") == 0)
		policy = RESIZE_KEEP;
	else
		return false;
	return true;
}


}	// namespace rrd
