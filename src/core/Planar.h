/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */
#ifndef RRD_PLANAR_H
#define RRD_PLANAR_H


// RDP 6.0 Bitmap Compression ("planar"), lossless ARGB variant only:
// [MS-RDPEGDI] 2.2.2.5.1 (RDP6_BITMAP_STREAM) and 3.1.9 (encoding).


#include <stddef.h>
#include <stdint.h>

#include <vector>


namespace rrd {


// FormatHeader bits ([MS-RDPEGDI] 2.2.2.5.1). The diagram lists fields
// from the least significant bit: CLL (bits 0-2), CS, RLE, NA.
enum {
	PLANAR_FORMAT_RLE = 0x10,
	PLANAR_FORMAT_NO_ALPHA = 0x20
};


// Encodes the RLE segments for one color plane of width x height bytes,
// whose rows are given in transmission order. Appends to out.
void EncodePlanarPlaneRle(const uint8_t* plane, int width, int height,
	std::vector<uint8_t>& out);

// Encodes width x height pixels of 32-bit B, G, R, X memory order (Haiku's
// B_RGB32, little endian) into an RDP6_BITMAP_STREAM. stride is in bytes.
// When skipAlpha is set, the alpha plane is left out (NA = 1) and the
// pixels are taken as opaque; otherwise an all-0xFF alpha plane is sent.
// bottomUp transmits the last source row first.
void EncodePlanar(const uint8_t* pixels, size_t stride, int width,
	int height, bool skipAlpha, bool bottomUp, std::vector<uint8_t>& out);


}	// namespace rrd


#endif	// RRD_PLANAR_H
