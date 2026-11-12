/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */


#include "Pointer.h"

#include "ByteStream.h"


namespace rrd {


std::vector<uint8_t>
EncodePointer(const PointerImage& image, int maxSize, bool alpha)
{
	int width = image.width < maxSize ? image.width : maxSize;
	int height = image.height < maxSize ? image.height : maxSize;
	if (width < 0 || height < 0
		|| image.pixels.size() < (size_t)image.width * image.height * 4) {
		width = height = 0;
	}
	int hotX = image.hotX < 0 ? 0 : image.hotX >= width ? width - 1
		: image.hotX;
	int hotY = image.hotY < 0 ? 0 : image.hotY >= height ? height - 1
		: image.hotY;
	if (hotX < 0)
		hotX = 0;
	if (hotY < 0)
		hotY = 0;

	// Scan lines are padded to two bytes (2.2.9.1.1.4.4).
	int bytesPerPixel = alpha ? 4 : 3;
	size_t xorStride = ((size_t)width * bytesPerPixel + 1) & ~(size_t)1;
	size_t andStride = (((size_t)width + 7) / 8 + 1) & ~(size_t)1;

	std::vector<uint8_t> xorMask(xorStride * height, 0);
	std::vector<uint8_t> andMask(andStride * height, 0);

	// Both masks are bottom-up. Where a pixel is transparent the AND bit
	// is set and the XOR pixel is zero, which leaves the screen as it is
	// under both the mask rules and alpha blending.
	for (int y = 0; y < height; y++) {
		const uint8_t* source = image.pixels.data()
			+ ((size_t)y * image.width) * 4;
		uint8_t* xorRow = xorMask.data() + (size_t)(height - 1 - y)
			* xorStride;
		uint8_t* andRow = andMask.data() + (size_t)(height - 1 - y)
			* andStride;
		for (int x = 0; x < width; x++) {
			const uint8_t* pixel = source + (size_t)x * 4;
			bool transparent = alpha ? pixel[3] == 0 : pixel[3] < 128;
			if (transparent) {
				andRow[x / 8] |= 0x80 >> (x % 8);
				continue;
			}
			uint8_t* target = xorRow + (size_t)x * bytesPerPixel;
			target[0] = pixel[0];
			target[1] = pixel[1];
			target[2] = pixel[2];
			if (alpha)
				target[3] = pixel[3];
		}
	}

	Writer writer;
	if (alpha)
		writer.U16LE(32);			// xorBpp
	writer.U16LE(0);				// cacheIndex
	writer.U16LE((uint16_t)hotX);	// hotSpot
	writer.U16LE((uint16_t)hotY);
	writer.U16LE((uint16_t)width);
	writer.U16LE((uint16_t)height);
	writer.U16LE((uint16_t)andMask.size());	// lengthAndMask
	writer.U16LE((uint16_t)xorMask.size());	// lengthXorMask
	writer.Bytes(xorMask);
	writer.Bytes(andMask);
	return writer.Data();
}


}	// namespace rrd
