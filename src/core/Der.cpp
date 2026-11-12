/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */


#include "Der.h"


namespace rrd {


// Lengths above this are refused; nothing in CredSSP comes close.
static const size_t kMaxLength = 1 << 20;


static bool
ParseHeader(const uint8_t* data, size_t size, uint8_t& tag,
	size_t& headerSize, size_t& length, size_t* needed)
{
	if (needed != NULL)
		*needed = 0;
	if (size < 2) {
		if (needed != NULL)
			*needed = 2;
		return false;
	}
	tag = data[0];
	if ((tag & 0x1f) == 0x1f)
		return false;	// high tag numbers: not used here
	uint8_t first = data[1];
	if ((first & 0x80) == 0) {
		headerSize = 2;
		length = first;
		return true;
	}
	size_t count = first & 0x7f;
	if (count == 0 || count > 3)
		return false;	// indefinite or too long
	if (size < 2 + count) {
		if (needed != NULL)
			*needed = 2 + count;
		return false;
	}
	length = 0;
	for (size_t i = 0; i < count; i++)
		length = (length << 8) | data[2 + i];
	if (length > kMaxLength)
		return false;
	headerSize = 2 + count;
	return true;
}


size_t
DerElementSize(const uint8_t* data, size_t size, size_t& needed)
{
	uint8_t tag;
	size_t headerSize;
	size_t length;
	if (!ParseHeader(data, size, tag, headerSize, length, &needed))
		return 0;
	needed = 0;
	return headerSize + length;
}


// #pragma mark - DerReader


DerReader::DerReader(const uint8_t* data, size_t size)
	:
	fData(data),
	fSize(size),
	fOk(true)
{
}


bool
DerReader::_Header(uint8_t& tag, size_t& headerSize, size_t& length) const
{
	if (!fOk)
		return false;
	if (!ParseHeader(fData, fSize, tag, headerSize, length, NULL))
		return false;
	return headerSize + length <= fSize;
}


int
DerReader::PeekTag() const
{
	if (!fOk || fSize == 0)
		return -1;
	return fData[0];
}


bool
DerReader::Read(uint8_t tag, DerReader& contents, const uint8_t** element,
	size_t* elementSize)
{
	uint8_t actual;
	size_t headerSize;
	size_t length;
	if (!_Header(actual, headerSize, length) || actual != tag) {
		fOk = false;
		return false;
	}
	contents = DerReader(fData + headerSize, length);
	if (element != NULL)
		*element = fData;
	if (elementSize != NULL)
		*elementSize = headerSize + length;
	fData += headerSize + length;
	fSize -= headerSize + length;
	return true;
}


bool
DerReader::ReadInteger(int64_t& value)
{
	DerReader contents(NULL, 0);
	if (!Read(DER_INTEGER, contents))
		return false;
	if (contents.fSize == 0 || contents.fSize > 8) {
		fOk = false;
		return false;
	}
	value = (contents.fData[0] & 0x80) != 0 ? -1 : 0;
	for (size_t i = 0; i < contents.fSize; i++)
		value = (int64_t)(((uint64_t)value << 8) | contents.fData[i]);
	return true;
}


bool
DerReader::ReadOctetString(std::vector<uint8_t>& value)
{
	DerReader contents(NULL, 0);
	if (!Read(DER_OCTET_STRING, contents))
		return false;
	value.assign(contents.fData, contents.fData + contents.fSize);
	return true;
}


bool
DerReader::Skip()
{
	uint8_t tag;
	size_t headerSize;
	size_t length;
	if (!_Header(tag, headerSize, length)) {
		fOk = false;
		return false;
	}
	fData += headerSize + length;
	fSize -= headerSize + length;
	return true;
}


// #pragma mark - DerWriter


void
DerWriter::Raw(const std::vector<uint8_t>& data)
{
	fData.insert(fData.end(), data.begin(), data.end());
}


void
DerWriter::Raw(const uint8_t* data, size_t size)
{
	fData.insert(fData.end(), data, data + size);
}


void
DerWriter::Element(uint8_t tag, const std::vector<uint8_t>& contents)
{
	fData.push_back(tag);
	size_t length = contents.size();
	if (length < 0x80)
		fData.push_back((uint8_t)length);
	else if (length < 0x100) {
		fData.push_back(0x81);
		fData.push_back((uint8_t)length);
	} else if (length < 0x10000) {
		fData.push_back(0x82);
		fData.push_back((uint8_t)(length >> 8));
		fData.push_back((uint8_t)length);
	} else {
		fData.push_back(0x83);
		fData.push_back((uint8_t)(length >> 16));
		fData.push_back((uint8_t)(length >> 8));
		fData.push_back((uint8_t)length);
	}
	Raw(contents);
}


void
DerWriter::Integer(int64_t value)
{
	// Minimal two's complement, big-endian.
	std::vector<uint8_t> bytes;
	int count = 8;
	while (count > 1) {
		uint8_t top = (uint8_t)(value >> (8 * (count - 1)));
		uint8_t next = (uint8_t)(value >> (8 * (count - 2)));
		if ((top == 0x00 && (next & 0x80) == 0)
			|| (top == 0xff && (next & 0x80) != 0)) {
			count--;
		} else
			break;
	}
	for (int i = count - 1; i >= 0; i--)
		bytes.push_back((uint8_t)(value >> (8 * i)));
	Element(DER_INTEGER, bytes);
}


void
DerWriter::OctetString(const std::vector<uint8_t>& value)
{
	Element(DER_OCTET_STRING, value);
}


void
DerWriter::OctetString(const uint8_t* data, size_t size)
{
	Element(DER_OCTET_STRING, std::vector<uint8_t>(data, data + size));
}


void
DerWriter::Enumerated(int value)
{
	Element(DER_ENUMERATED, std::vector<uint8_t>(1, (uint8_t)value));
}


}	// namespace rrd
