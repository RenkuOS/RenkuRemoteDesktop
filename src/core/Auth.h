/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */
#ifndef RRD_AUTH_H
#define RRD_AUTH_H


#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>


namespace rrd {


// Hashes a password for the settings file, as
// "pbkdf2-sha256$<iterations>$<salt hex>$<hash hex>".
std::string HashPassword(const std::string& password);

// The NT hash of a password ([MS-NLMP] 3.3.1) as 32 hex digits, for the
// settings file. NLA needs it. Anyone who has it can log in over NTLM, so
// it is kept as carefully as the password.
std::string NtHashHex(const std::string& password);

// Parses NtHashHex() output. Fails unless it is exactly 32 hex digits.
bool ParseNtHash(const std::string& hex, uint8_t hash[16]);

// Checks a password against a stored hash in constant time.
bool VerifyPassword(const std::string& password, const std::string& stored);

// Converts UTF-16LE (without a terminator) to UTF-8. Unpaired surrogates
// become U+FFFD.
std::string Utf16LeToUtf8(const uint8_t* data, size_t size);

// Converts UTF-8 to UTF-16LE without a terminator. Invalid sequences become
// U+FFFD.
std::vector<uint8_t> Utf8ToUtf16Le(const std::string& text);

// Overwrites a string's bytes before it is released.
void WipeString(std::string& text);


}	// namespace rrd


#endif	// RRD_AUTH_H
