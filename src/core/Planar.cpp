/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */


#include "Planar.h"

#include <string.h>


namespace rrd {


// Delta transform of [MS-RDPEGDI] 3.1.9.2.1: a non-negative delta d becomes
// 2d, a negative delta d becomes 2|d| - 1, both taken modulo 256.
static inline uint8_t
EncodeDelta(uint8_t current, uint8_t previous)
{
	int8_t delta = (int8_t)(uint8_t)(current - previous);
	if (delta >= 0)
		return (uint8_t)(delta << 1);
	return (uint8_t)((-(int)delta) * 2 - 1);
}


// Encodes one scan line of already transformed values as RDP6_RLE_SEGMENTs
// ([MS-RDPEGDI] 2.2.2.5.1.2). Every segment carries at least one RAW byte:
// the specification says a RUN without RAW bytes repeats the value zero,
// but leaves open whether that holds mid-line, so the encoder never relies
// on it. The run field never takes the values 1 or 2, which mean "long run"
// (16+ or 32+ values) rather than a run of 1 or 2.
static void
EncodeLine(const uint8_t* values, int count, std::vector<uint8_t>& out)
{
	int position = 0;
	while (position < count) {
		int rawStart = position;
		int rawCount = 0;
		int run = 0;

		while (true) {
			uint8_t value = values[position++];
			rawCount++;

			run = 0;
			while (position + run < count && run < 15
				&& values[position + run] == value) {
				run++;
			}
			if (run >= 3) {
				position += run;
				break;
			}
			run = 0;
			if (rawCount == 15 || position == count)
				break;
		}

		out.push_back((uint8_t)((rawCount << 4) | run));
		out.insert(out.end(), values + rawStart, values + rawStart + rawCount);
	}
}


void
EncodePlanarPlaneRle(const uint8_t* plane, int width, int height,
	std::vector<uint8_t>& out)
{
	std::vector<uint8_t> line(width);
	for (int y = 0; y < height; y++) {
		const uint8_t* current = plane + (size_t)y * width;
		if (y == 0) {
			EncodeLine(current, width, out);
			continue;
		}
		const uint8_t* previous = current - width;
		for (int x = 0; x < width; x++)
			line[x] = EncodeDelta(current[x], previous[x]);
		EncodeLine(line.data(), width, out);
	}
}


void
EncodePlanar(const uint8_t* pixels, size_t stride, int width, int height,
	bool skipAlpha, bool bottomUp, std::vector<uint8_t>& out)
{
	size_t planeSize = (size_t)width * height;
	// Planes in transmission order: R, G, B.
	std::vector<uint8_t> planes(3 * planeSize);
	uint8_t* red = planes.data();
	uint8_t* green = red + planeSize;
	uint8_t* blue = green + planeSize;

	for (int y = 0; y < height; y++) {
		int sourceRow = bottomUp ? height - 1 - y : y;
		const uint8_t* source = pixels + (size_t)sourceRow * stride;
		size_t offset = (size_t)y * width;
		for (int x = 0; x < width; x++) {
			blue[offset + x] = source[4 * x];
			green[offset + x] = source[4 * x + 1];
			red[offset + x] = source[4 * x + 2];
		}
	}

	std::vector<uint8_t> alpha;
	if (!skipAlpha)
		alpha.assign(planeSize, 0xff);

	// Try RLE; fall back to raw planes if that is not smaller.
	std::vector<uint8_t> rle;
	rle.reserve(planeSize);
	if (!skipAlpha)
		EncodePlanarPlaneRle(alpha.data(), width, height, rle);
	for (int i = 0; i < 3; i++)
		EncodePlanarPlaneRle(planes.data() + i * planeSize, width, height, rle);

	size_t rawSize = (skipAlpha ? 3 : 4) * planeSize + 1;
	uint8_t header = skipAlpha ? PLANAR_FORMAT_NO_ALPHA : 0;
	if (rle.size() < rawSize) {
		out.push_back(header | PLANAR_FORMAT_RLE);
		out.insert(out.end(), rle.begin(), rle.end());
	} else {
		out.push_back(header);
		if (!skipAlpha)
			out.insert(out.end(), alpha.begin(), alpha.end());
		out.insert(out.end(), planes.begin(), planes.end());
		out.push_back(0);	// Pad, present when RLE is 0
	}
}


}	// namespace rrd
