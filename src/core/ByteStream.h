/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */
#ifndef RRD_BYTE_STREAM_H
#define RRD_BYTE_STREAM_H


#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <string>
#include <vector>


namespace rrd {


// Bounds-checked reader over a byte buffer. Every read past the end sets
// the error flag and returns zero, so parsers can read a whole structure and
// check Ok() once. Network input is untrusted: never index the buffer
// directly.
class Reader {
public:
						Reader(const uint8_t* data, size_t size)
							:
							fData(data),
							fSize(size),
							fPos(0),
							fError(false)
						{
						}

						Reader(const std::vector<uint8_t>& data)
							:
							fData(data.data()),
							fSize(data.size()),
							fPos(0),
							fError(false)
						{
						}

			bool		Ok() const { return !fError; }
			void		SetError() { fError = true; }
			size_t		Position() const { return fPos; }
			size_t		Remaining() const
							{ return fError ? 0 : fSize - fPos; }
			const uint8_t* Current() const { return fData + fPos; }

			bool		Has(size_t count)
						{
							if (fError || count > fSize - fPos) {
								fError = true;
								return false;
							}
							return true;
						}

			void		Skip(size_t count)
						{
							if (Has(count))
								fPos += count;
						}

			uint8_t		U8()
						{
							if (!Has(1))
								return 0;
							return fData[fPos++];
						}

			uint16_t	U16LE()
						{
							if (!Has(2))
								return 0;
							uint16_t value = fData[fPos] | (fData[fPos + 1] << 8);
							fPos += 2;
							return value;
						}

			uint16_t	U16BE()
						{
							if (!Has(2))
								return 0;
							uint16_t value = (fData[fPos] << 8) | fData[fPos + 1];
							fPos += 2;
							return value;
						}

			uint32_t	U32LE()
						{
							if (!Has(4))
								return 0;
							uint32_t value = (uint32_t)fData[fPos]
								| ((uint32_t)fData[fPos + 1] << 8)
								| ((uint32_t)fData[fPos + 2] << 16)
								| ((uint32_t)fData[fPos + 3] << 24);
							fPos += 4;
							return value;
						}

			bool		Bytes(void* out, size_t count)
						{
							if (!Has(count)) {
								memset(out, 0, count);
								return false;
							}
							memcpy(out, fData + fPos, count);
							fPos += count;
							return true;
						}

			// Returns a sub-reader over the next count bytes and skips them.
			Reader		Sub(size_t count)
						{
							if (!Has(count))
								return Reader(fData, 0, true);
							Reader sub(fData + fPos, count);
							fPos += count;
							return sub;
						}

private:
						Reader(const uint8_t* data, size_t size, bool error)
							:
							fData(data),
							fSize(size),
							fPos(0),
							fError(error)
						{
						}

			const uint8_t* fData;
			size_t		fSize;
			size_t		fPos;
			bool		fError;
};


// Growable writer. Supports reserving a field and patching it later, which
// most RDP headers need because they carry the length of what follows.
class Writer {
public:
			void		U8(uint8_t value) { fData.push_back(value); }

			void		U16LE(uint16_t value)
						{
							fData.push_back(value & 0xff);
							fData.push_back(value >> 8);
						}

			void		U16BE(uint16_t value)
						{
							fData.push_back(value >> 8);
							fData.push_back(value & 0xff);
						}

			void		U32LE(uint32_t value)
						{
							for (int i = 0; i < 4; i++)
								fData.push_back((value >> (8 * i)) & 0xff);
						}

			void		Bytes(const void* data, size_t count)
						{
							const uint8_t* bytes = (const uint8_t*)data;
							fData.insert(fData.end(), bytes, bytes + count);
						}

			void		Bytes(const std::vector<uint8_t>& data)
						{ fData.insert(fData.end(), data.begin(), data.end()); }

			void		Zero(size_t count) { fData.resize(fData.size() + count, 0); }

			// UTF-16LE text with a terminating NUL, from ASCII.
			void		Utf16Ascii(const char* text)
						{
							for (; *text != '\0'; text++)
								U16LE((uint8_t)*text);
							U16LE(0);
						}

			size_t		Size() const { return fData.size(); }

			void		PatchU16LE(size_t offset, uint16_t value)
						{
							fData[offset] = value & 0xff;
							fData[offset + 1] = value >> 8;
						}

			void		PatchU16BE(size_t offset, uint16_t value)
						{
							fData[offset] = value >> 8;
							fData[offset + 1] = value & 0xff;
						}

			void		PatchU32LE(size_t offset, uint32_t value)
						{
							for (int i = 0; i < 4; i++)
								fData[offset + i] = (value >> (8 * i)) & 0xff;
						}

			std::vector<uint8_t>& Data() { return fData; }
			const std::vector<uint8_t>& Data() const { return fData; }

private:
			std::vector<uint8_t> fData;
};


}	// namespace rrd


#endif	// RRD_BYTE_STREAM_H
