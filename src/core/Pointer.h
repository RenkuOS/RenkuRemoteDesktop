/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */
#ifndef RRD_POINTER_H
#define RRD_POINTER_H


#include <stdint.h>

#include <vector>

#include "Platform.h"


namespace rrd {


// Encodes a pointer image for cache slot 0. With alpha set, it is a New
// Pointer Update with 32 bpp ([MS-RDPBCGR] 2.2.9.1.1.4.5); otherwise a
// Color Pointer Update with 24 bpp (2.2.9.1.1.4.4), with pixels under half
// opacity left transparent. The image is cropped to maxSize pixels on each
// side. Returns the update data for FASTPATH_UPDATETYPE_POINTER or
// FASTPATH_UPDATETYPE_COLOR.
std::vector<uint8_t> EncodePointer(const PointerImage& image, int maxSize,
	bool alpha);


}	// namespace rrd


#endif	// RRD_POINTER_H
