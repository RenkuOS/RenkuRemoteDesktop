/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */
#ifndef RRD_DER_H
#define RRD_DER_H


// The small part of ASN.1 DER ([X690]) that CredSSP and SPNEGO use: tags
// below 31, definite lengths, INTEGER, OCTET STRING, OBJECT IDENTIFIER,
// ENUMERATED, and constructed types.


#include <stddef.h>
#include <stdint.h>

#include <vector>


namespace rrd {


enum {
	DER_INTEGER = 0x02,
	DER_OCTET_STRING = 0x04,
	DER_OID = 0x06,
	DER_ENUMERATED = 0x0a,
	DER_SEQUENCE = 0x30,
};

// Context-specific constructed tag [n].
static inline uint8_t
DerContext(int n)
{
	return (uint8_t)(0xa0 | n);
}


class DerReader {
public:
						DerReader(const uint8_t* data, size_t size);

			bool		AtEnd() const { return fSize == 0; }
			bool		Ok() const { return fOk; }

			// Tag of the next element, or -1 at the end.
			int			PeekTag() const;

			// Reads the next element, which must have the given tag. Its
			// contents become a new reader. element, if given, receives the
			// whole encoding, header included.
			bool		Read(uint8_t tag, DerReader& contents,
							const uint8_t** element = NULL,
							size_t* elementSize = NULL);
			bool		ReadInteger(int64_t& value);
			bool		ReadOctetString(std::vector<uint8_t>& value);
			bool		Skip();

			const uint8_t* Data() const { return fData; }
			size_t		Size() const { return fSize; }

private:
			bool		_Header(uint8_t& tag, size_t& headerSize,
							size_t& length) const;

			const uint8_t* fData;
			size_t		fSize;
			bool		fOk;
};


// Length of a whole element from its first bytes, or 0 when more bytes are
// needed (with needed set to how many) or the header is invalid.
size_t DerElementSize(const uint8_t* data, size_t size, size_t& needed);


class DerWriter {
public:
			void		Raw(const std::vector<uint8_t>& data);
			void		Raw(const uint8_t* data, size_t size);
			void		Element(uint8_t tag, const std::vector<uint8_t>& contents);
			void		Integer(int64_t value);
			void		OctetString(const std::vector<uint8_t>& value);
			void		OctetString(const uint8_t* data, size_t size);
			void		Enumerated(int value);

			const std::vector<uint8_t>& Data() const { return fData; }

private:
			std::vector<uint8_t> fData;
};


}	// namespace rrd


#endif	// RRD_DER_H
