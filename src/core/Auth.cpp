/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */


#include "Auth.h"

#include "Ntlm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>


namespace rrd {


static const int kIterations = 200000;
static const size_t kSaltSize = 16;
static const size_t kHashSize = 32;


static std::string
ToHex(const uint8_t* data, size_t size)
{
	std::string text;
	char digits[3];
	for (size_t i = 0; i < size; i++) {
		snprintf(digits, sizeof(digits), "%02x", data[i]);
		text += digits;
	}
	return text;
}


static bool
FromHex(const std::string& text, uint8_t* data, size_t size)
{
	if (text.size() != 2 * size)
		return false;
	for (size_t i = 0; i < size; i++) {
		char digits[3] = { text[2 * i], text[2 * i + 1], '\0' };
		char* end;
		unsigned long value = strtoul(digits, &end, 16);
		if (*end != '\0')
			return false;
		data[i] = (uint8_t)value;
	}
	return true;
}


static bool
Derive(const std::string& password, const uint8_t* salt, int iterations,
	uint8_t* hash)
{
	return PKCS5_PBKDF2_HMAC(password.data(), password.size(), salt,
		kSaltSize, iterations, EVP_sha256(), kHashSize, hash) == 1;
}


std::string
HashPassword(const std::string& password)
{
	uint8_t salt[kSaltSize];
	uint8_t hash[kHashSize];
	if (RAND_bytes(salt, sizeof(salt)) != 1
		|| !Derive(password, salt, kIterations, hash)) {
		return std::string();
	}

	char iterations[16];
	snprintf(iterations, sizeof(iterations), "%d", kIterations);
	std::string result = std::string("pbkdf2-sha256$") + iterations + "$"
		+ ToHex(salt, sizeof(salt)) + "$" + ToHex(hash, sizeof(hash));
	OPENSSL_cleanse(hash, sizeof(hash));
	return result;
}


bool
VerifyPassword(const std::string& password, const std::string& stored)
{
	static const char kPrefix[] = "pbkdf2-sha256$";
	if (stored.compare(0, sizeof(kPrefix) - 1, kPrefix) != 0)
		return false;

	size_t first = sizeof(kPrefix) - 1;
	size_t second = stored.find('$', first);
	size_t third = second == std::string::npos
		? std::string::npos : stored.find('$', second + 1);
	if (third == std::string::npos)
		return false;

	int iterations = atoi(stored.substr(first, second - first).c_str());
	uint8_t salt[kSaltSize];
	uint8_t expected[kHashSize];
	uint8_t actual[kHashSize];
	if (iterations < 1000 || iterations > 10000000
		|| !FromHex(stored.substr(second + 1, third - second - 1), salt,
			sizeof(salt))
		|| !FromHex(stored.substr(third + 1), expected, sizeof(expected))
		|| !Derive(password, salt, iterations, actual)) {
		return false;
	}

	bool match = CRYPTO_memcmp(actual, expected, kHashSize) == 0;
	OPENSSL_cleanse(actual, sizeof(actual));
	return match;
}


std::string
Utf16LeToUtf8(const uint8_t* data, size_t size)
{
	std::string text;
	size_t count = size / 2;
	for (size_t i = 0; i < count; i++) {
		uint32_t c = data[2 * i] | (data[2 * i + 1] << 8);
		if (c >= 0xd800 && c <= 0xdbff && i + 1 < count) {
			uint32_t low = data[2 * i + 2] | (data[2 * i + 3] << 8);
			if (low >= 0xdc00 && low <= 0xdfff) {
				c = 0x10000 + ((c - 0xd800) << 10) + (low - 0xdc00);
				i++;
			} else
				c = 0xfffd;
		} else if (c >= 0xd800 && c <= 0xdfff)
			c = 0xfffd;

		if (c < 0x80) {
			text += (char)c;
		} else if (c < 0x800) {
			text += (char)(0xc0 | (c >> 6));
			text += (char)(0x80 | (c & 0x3f));
		} else if (c < 0x10000) {
			text += (char)(0xe0 | (c >> 12));
			text += (char)(0x80 | ((c >> 6) & 0x3f));
			text += (char)(0x80 | (c & 0x3f));
		} else {
			text += (char)(0xf0 | (c >> 18));
			text += (char)(0x80 | ((c >> 12) & 0x3f));
			text += (char)(0x80 | ((c >> 6) & 0x3f));
			text += (char)(0x80 | (c & 0x3f));
		}
	}
	return text;
}


std::string
NtHashHex(const std::string& password)
{
	uint8_t hash[16];
	NtHash(password, hash);
	static const char kHex[] = "0123456789abcdef";
	std::string text;
	for (int i = 0; i < 16; i++) {
		text += kHex[hash[i] >> 4];
		text += kHex[hash[i] & 0xf];
	}
	OPENSSL_cleanse(hash, sizeof(hash));
	return text;
}


bool
ParseNtHash(const std::string& hex, uint8_t hash[16])
{
	if (hex.size() != 32)
		return false;
	for (int i = 0; i < 32; i++) {
		char c = hex[i];
		int value = c >= '0' && c <= '9' ? c - '0'
			: c >= 'a' && c <= 'f' ? c - 'a' + 10
			: c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
		if (value < 0)
			return false;
		if (i % 2 == 0)
			hash[i / 2] = (uint8_t)(value << 4);
		else
			hash[i / 2] |= (uint8_t)value;
	}
	return true;
}


std::vector<uint8_t>
Utf8ToUtf16Le(const std::string& text)
{
	std::vector<uint8_t> out;
	size_t i = 0;
	while (i < text.size()) {
		uint8_t lead = (uint8_t)text[i];
		uint32_t c = 0xfffd;
		size_t count = 0;
		if (lead < 0x80) {
			c = lead;
			count = 1;
		} else if ((lead & 0xe0) == 0xc0) {
			c = lead & 0x1f;
			count = 2;
		} else if ((lead & 0xf0) == 0xe0) {
			c = lead & 0x0f;
			count = 3;
		} else if ((lead & 0xf8) == 0xf0) {
			c = lead & 0x07;
			count = 4;
		}
		bool valid = count > 0 && i + count <= text.size();
		for (size_t k = 1; valid && k < count; k++) {
			uint8_t next = (uint8_t)text[i + k];
			if ((next & 0xc0) != 0x80)
				valid = false;
			else
				c = (c << 6) | (next & 0x3f);
		}
		if (!valid || (count == 2 && c < 0x80) || (count == 3 && c < 0x800)
			|| (count == 4 && (c < 0x10000 || c > 0x10ffff))
			|| (c >= 0xd800 && c <= 0xdfff)) {
			c = 0xfffd;
			count = 1;
		}
		i += count;

		if (c >= 0x10000) {
			uint32_t high = 0xd800 + ((c - 0x10000) >> 10);
			uint32_t low = 0xdc00 + ((c - 0x10000) & 0x3ff);
			out.push_back((uint8_t)high);
			out.push_back((uint8_t)(high >> 8));
			out.push_back((uint8_t)low);
			out.push_back((uint8_t)(low >> 8));
		} else {
			out.push_back((uint8_t)c);
			out.push_back((uint8_t)(c >> 8));
		}
	}
	return out;
}


void
WipeString(std::string& text)
{
	if (!text.empty())
		OPENSSL_cleanse(&text[0], text.size());
	text.clear();
}


}	// namespace rrd
