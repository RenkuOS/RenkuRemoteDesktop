/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */
#ifndef RRD_CRYPTO_H
#define RRD_CRYPTO_H


// The hash and cipher primitives NTLM needs ([MS-NLMP] section 6). MD4 and
// RC4 are implemented here: OpenSSL 3 only has them in its legacy provider,
// which is not always installed or loaded.


#include <stddef.h>
#include <stdint.h>

#include <vector>


namespace rrd {


typedef std::vector<uint8_t> Bytes;


// MD4 ([RFC1320]).
void Md4(const uint8_t* data, size_t size, uint8_t digest[16]);

// RC4 with a persistent key state, as NTLM's sealing handles use it.
class Rc4 {
public:
						Rc4();
						~Rc4();

			void		Init(const uint8_t* key, size_t size);
			void		Process(const uint8_t* input, uint8_t* output,
							size_t size);

private:
			uint8_t		fState[256];
			uint8_t		fI;
			uint8_t		fJ;
};

void Md5(const uint8_t* data, size_t size, uint8_t digest[16]);
void HmacMd5(const uint8_t* key, size_t keySize, const uint8_t* data,
	size_t size, uint8_t digest[16]);
void Sha256(const uint8_t* data, size_t size, uint8_t digest[32]);

bool RandomBytes(uint8_t* buffer, size_t size);

// Compares in time that does not depend on where the inputs differ.
bool SameBytes(const uint8_t* a, const uint8_t* b, size_t size);

// Overwrites memory in a way the compiler cannot drop.
void Wipe(void* buffer, size_t size);


}	// namespace rrd


#endif	// RRD_CRYPTO_H
