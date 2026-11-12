/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */


#include "Crypto.h"

#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>


namespace rrd {


// #pragma mark - MD4


static inline uint32_t
Rotate(uint32_t value, int bits)
{
	return (value << bits) | (value >> (32 - bits));
}


// One 64-byte block, as in [RFC1320] section 3.4.
static void
Md4Block(uint32_t state[4], const uint8_t block[64])
{
	uint32_t x[16];
	for (int i = 0; i < 16; i++) {
		x[i] = (uint32_t)block[i * 4] | ((uint32_t)block[i * 4 + 1] << 8)
			| ((uint32_t)block[i * 4 + 2] << 16)
			| ((uint32_t)block[i * 4 + 3] << 24);
	}

	uint32_t r[4] = { state[0], state[1], state[2], state[3] };

	// Each step updates one of a, b, c, d in turn: a, d, c, b.
	static const int kRound1Shift[4] = { 3, 7, 11, 19 };
	for (int i = 0; i < 16; i++) {
		uint32_t& a = r[(4 - i % 4) % 4];
		uint32_t b = r[(5 - i % 4) % 4];
		uint32_t c = r[(6 - i % 4) % 4];
		uint32_t d = r[(7 - i % 4) % 4];
		a = Rotate(a + ((b & c) | (~b & d)) + x[i], kRound1Shift[i % 4]);
	}

	static const int kRound2Order[16] = { 0, 4, 8, 12, 1, 5, 9, 13, 2, 6,
		10, 14, 3, 7, 11, 15 };
	static const int kRound2Shift[4] = { 3, 5, 9, 13 };
	for (int i = 0; i < 16; i++) {
		uint32_t& a = r[(4 - i % 4) % 4];
		uint32_t b = r[(5 - i % 4) % 4];
		uint32_t c = r[(6 - i % 4) % 4];
		uint32_t d = r[(7 - i % 4) % 4];
		a = Rotate(a + ((b & c) | (b & d) | (c & d)) + x[kRound2Order[i]]
			+ 0x5a827999, kRound2Shift[i % 4]);
	}

	static const int kRound3Order[16] = { 0, 8, 4, 12, 2, 10, 6, 14, 1, 9,
		5, 13, 3, 11, 7, 15 };
	static const int kRound3Shift[4] = { 3, 9, 11, 15 };
	for (int i = 0; i < 16; i++) {
		uint32_t& a = r[(4 - i % 4) % 4];
		uint32_t b = r[(5 - i % 4) % 4];
		uint32_t c = r[(6 - i % 4) % 4];
		uint32_t d = r[(7 - i % 4) % 4];
		a = Rotate(a + (b ^ c ^ d) + x[kRound3Order[i]] + 0x6ed9eba1,
			kRound3Shift[i % 4]);
	}

	for (int i = 0; i < 4; i++)
		state[i] += r[i];
	Wipe(x, sizeof(x));
}


void
Md4(const uint8_t* data, size_t size, uint8_t digest[16])
{
	uint32_t state[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };

	size_t whole = size / 64 * 64;
	for (size_t offset = 0; offset < whole; offset += 64)
		Md4Block(state, data + offset);

	// Padding: 0x80, zeros up to 56 bytes mod 64, then the length in bits
	// as a 64-bit little-endian number.
	uint8_t tail[128];
	memset(tail, 0, sizeof(tail));
	size_t rest = size - whole;
	memcpy(tail, data + whole, rest);
	tail[rest] = 0x80;
	size_t tailSize = rest < 56 ? 64 : 128;
	uint64_t bits = (uint64_t)size * 8;
	for (int i = 0; i < 8; i++)
		tail[tailSize - 8 + i] = (uint8_t)(bits >> (8 * i));
	Md4Block(state, tail);
	if (tailSize == 128)
		Md4Block(state, tail + 64);
	Wipe(tail, sizeof(tail));

	for (int i = 0; i < 4; i++) {
		digest[i * 4] = (uint8_t)state[i];
		digest[i * 4 + 1] = (uint8_t)(state[i] >> 8);
		digest[i * 4 + 2] = (uint8_t)(state[i] >> 16);
		digest[i * 4 + 3] = (uint8_t)(state[i] >> 24);
	}
}


// #pragma mark - RC4


Rc4::Rc4()
	:
	fI(0),
	fJ(0)
{
	memset(fState, 0, sizeof(fState));
}


Rc4::~Rc4()
{
	Wipe(fState, sizeof(fState));
}


void
Rc4::Init(const uint8_t* key, size_t size)
{
	for (int i = 0; i < 256; i++)
		fState[i] = (uint8_t)i;
	uint8_t j = 0;
	for (int i = 0; i < 256; i++) {
		j = (uint8_t)(j + fState[i] + key[i % size]);
		uint8_t swap = fState[i];
		fState[i] = fState[j];
		fState[j] = swap;
	}
	fI = 0;
	fJ = 0;
}


void
Rc4::Process(const uint8_t* input, uint8_t* output, size_t size)
{
	for (size_t n = 0; n < size; n++) {
		fI = (uint8_t)(fI + 1);
		fJ = (uint8_t)(fJ + fState[fI]);
		uint8_t swap = fState[fI];
		fState[fI] = fState[fJ];
		fState[fJ] = swap;
		output[n] = input[n]
			^ fState[(uint8_t)(fState[fI] + fState[fJ])];
	}
}


// #pragma mark - OpenSSL wrappers


void
Md5(const uint8_t* data, size_t size, uint8_t digest[16])
{
	EVP_Digest(data, size, digest, NULL, EVP_md5(), NULL);
}


void
HmacMd5(const uint8_t* key, size_t keySize, const uint8_t* data,
	size_t size, uint8_t digest[16])
{
	unsigned int length = 16;
	HMAC(EVP_md5(), key, (int)keySize, data, size, digest, &length);
}


void
Sha256(const uint8_t* data, size_t size, uint8_t digest[32])
{
	EVP_Digest(data, size, digest, NULL, EVP_sha256(), NULL);
}


bool
RandomBytes(uint8_t* buffer, size_t size)
{
	return RAND_bytes(buffer, (int)size) == 1;
}


bool
SameBytes(const uint8_t* a, const uint8_t* b, size_t size)
{
	return CRYPTO_memcmp(a, b, size) == 0;
}


void
Wipe(void* buffer, size_t size)
{
	OPENSSL_cleanse(buffer, size);
}


}	// namespace rrd
