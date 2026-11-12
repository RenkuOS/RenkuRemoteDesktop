/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */


#include "Ntlm.h"

#include <string.h>
#include <time.h>

#include "Auth.h"
#include "Log.h"


namespace rrd {


static const uint8_t kSignature[8] = { 'N', 'T', 'L', 'M', 'S', 'S', 'P', 0 };

// AV_PAIR IDs (2.2.2.1)
enum {
	MSV_AV_EOL = 0,
	MSV_AV_NB_COMPUTER_NAME = 1,
	MSV_AV_NB_DOMAIN_NAME = 2,
	MSV_AV_DNS_COMPUTER_NAME = 3,
	MSV_AV_DNS_DOMAIN_NAME = 4,
	MSV_AV_FLAGS = 6,
	MSV_AV_TIMESTAMP = 7
};

// MsvAvFlags: the AUTHENTICATE_MESSAGE carries a MIC.
static const uint32_t kAvFlagMicPresent = 0x00000002;

// Header sizes: the AUTHENTICATE_MESSAGE fields up to NegotiateFlags, then
// Version (8 bytes) and MIC (16 bytes).
static const size_t kAuthenticateFixedSize = 64;
static const size_t kMicOffset = 72;

// The NTLMv2_CLIENT_CHALLENGE ahead of its AV pairs (2.2.2.7).
static const size_t kClientChallengeHeaderSize = 28;

static const char kClientSignMagic[]
	= "session key to client-to-server signing key magic constant";
static const char kServerSignMagic[]
	= "session key to server-to-client signing key magic constant";
static const char kClientSealMagic[]
	= "session key to client-to-server sealing key magic constant";
static const char kServerSealMagic[]
	= "session key to server-to-client sealing key magic constant";


static inline uint16_t
Get16(const uint8_t* data)
{
	return (uint16_t)(data[0] | (data[1] << 8));
}


static inline uint32_t
Get32(const uint8_t* data)
{
	return (uint32_t)data[0] | ((uint32_t)data[1] << 8)
		| ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}


static void
Put16(Bytes& out, uint16_t value)
{
	out.push_back((uint8_t)value);
	out.push_back((uint8_t)(value >> 8));
}


static void
Put32(Bytes& out, uint32_t value)
{
	for (int i = 0; i < 4; i++)
		out.push_back((uint8_t)(value >> (8 * i)));
}


static void
PutAvPair(Bytes& out, uint16_t id, const Bytes& value)
{
	Put16(out, id);
	Put16(out, (uint16_t)value.size());
	out.insert(out.end(), value.begin(), value.end());
}


// A length, maximum length, and offset triple ("Fields", 2.2.1.3), checked
// against the message.
static bool
GetField(const Bytes& message, size_t at, Bytes& value)
{
	uint16_t length = Get16(message.data() + at);
	uint32_t offset = Get32(message.data() + at + 4);
	// Written so that nothing can wrap, also where size_t is 32 bits.
	if (offset > message.size() || length > message.size() - offset)
		return false;
	value.assign(message.begin() + offset, message.begin() + offset + length);
	return true;
}


// Upper case for user names. NTLM upper-cases the UTF-16 user name
// (NTOWFv2, 3.3.2); this covers ASCII and Latin-1, which is what account
// names here use.
static void
UpperCaseUtf16(Bytes& text)
{
	for (size_t i = 0; i + 1 < text.size(); i += 2) {
		uint16_t c = Get16(text.data() + i);
		if ((c >= 'a' && c <= 'z') || (c >= 0xe0 && c <= 0xfe && c != 0xf7))
			c -= 0x20;
		else if (c == 0xff)
			c = 0x178;
		text[i] = (uint8_t)c;
		text[i + 1] = (uint8_t)(c >> 8);
	}
}


static void
Md5WithMagic(const uint8_t* key, size_t keySize, const char* magic,
	uint8_t out[16])
{
	// The magic constants include their terminating NUL (3.4.5.2).
	Bytes input(key, key + keySize);
	input.insert(input.end(), magic, magic + strlen(magic) + 1);
	Md5(input.data(), input.size(), out);
	Wipe(input.data(), input.size());
}


static uint64_t
FileTimeNow()
{
	// 100 ns ticks since 1601-01-01 UTC ([MS-DTYP] 2.3.3).
	struct timespec now;
	clock_gettime(CLOCK_REALTIME, &now);
	return ((uint64_t)now.tv_sec + 11644473600ULL) * 10000000ULL
		+ (uint64_t)now.tv_nsec / 100;
}


void
NtHash(const std::string& utf8Password, uint8_t hash[16])
{
	Bytes unicode = Utf8ToUtf16Le(utf8Password);
	Md4(unicode.data(), unicode.size(), hash);
	Wipe(unicode.data(), unicode.size());
}


// #pragma mark - NtlmServer


NtlmServer::NtlmServer(const uint8_t ntHash[16],
	const std::string& computerName)
	:
	fComputerName(computerName),
	fTimestamp(0),
	fFixedChallenge(false),
	fFlags(0),
	fKeyExchange(false),
	fSendSequence(0),
	fReceiveSequence(0),
	fAuthenticated(false)
{
	memcpy(fNtHash, ntHash, sizeof(fNtHash));
	memset(fServerChallenge, 0, sizeof(fServerChallenge));
	memset(fClientSignKey, 0, sizeof(fClientSignKey));
	memset(fServerSignKey, 0, sizeof(fServerSignKey));
}


NtlmServer::~NtlmServer()
{
	Wipe(fNtHash, sizeof(fNtHash));
	Wipe(fClientSignKey, sizeof(fClientSignKey));
	Wipe(fServerSignKey, sizeof(fServerSignKey));
}


void
NtlmServer::SetChallengeForTest(const uint8_t challenge[8], uint64_t timestamp)
{
	memcpy(fServerChallenge, challenge, 8);
	fTimestamp = timestamp;
	fFixedChallenge = true;
}


bool
NtlmServer::HandleNegotiate(const Bytes& negotiate, Bytes& challenge)
{
	// NEGOTIATE_MESSAGE (2.2.1.1): signature, type 1, flags.
	if (negotiate.size() < 16
		|| memcmp(negotiate.data(), kSignature, 8) != 0
		|| Get32(negotiate.data() + 8) != 1) {
		LOG_W("NTLM: not a NEGOTIATE_MESSAGE");
		return false;
	}
	uint32_t clientFlags = Get32(negotiate.data() + 12);
	LOG_D("NTLM: client flags 0x%08x", clientFlags);

	// CredSSP needs sealing, and only NTLMv2 with extended session
	// security is supported.
	uint32_t required = NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_SEAL
		| NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY;
	if ((clientFlags & required) != required) {
		LOG_W("NTLM: the client does not offer Unicode, signing, sealing, "
			"and extended session security (flags 0x%08x)", clientFlags);
		return false;
	}

	fFlags = NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_REQUEST_TARGET
		| NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
		| NTLMSSP_TARGET_TYPE_SERVER
		| NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
		| NTLMSSP_NEGOTIATE_TARGET_INFO
		| (clientFlags & (NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL
			| NTLMSSP_NEGOTIATE_VERSION | NTLMSSP_NEGOTIATE_56
			| NTLMSSP_NEGOTIATE_128 | NTLMSSP_NEGOTIATE_KEY_EXCH));

	if (!fFixedChallenge) {
		if (!RandomBytes(fServerChallenge, sizeof(fServerChallenge)))
			return false;
		fTimestamp = FileTimeNow();
	}

	// Server naming. A stand-alone server uses its own name as the domain
	// (2.2.1.2, TargetName).
	Bytes name = Utf8ToUtf16Le(fComputerName);
	std::string lower = fComputerName;
	for (size_t i = 0; i < lower.size(); i++) {
		if (lower[i] >= 'A' && lower[i] <= 'Z')
			lower[i] += 'a' - 'A';
	}
	Bytes dnsName = Utf8ToUtf16Le(lower);

	Bytes targetInfo;
	PutAvPair(targetInfo, MSV_AV_NB_DOMAIN_NAME, name);
	PutAvPair(targetInfo, MSV_AV_NB_COMPUTER_NAME, name);
	PutAvPair(targetInfo, MSV_AV_DNS_DOMAIN_NAME, dnsName);
	PutAvPair(targetInfo, MSV_AV_DNS_COMPUTER_NAME, dnsName);
	Bytes timestamp;
	for (int i = 0; i < 8; i++)
		timestamp.push_back((uint8_t)(fTimestamp >> (8 * i)));
	PutAvPair(targetInfo, MSV_AV_TIMESTAMP, timestamp);
	PutAvPair(targetInfo, MSV_AV_EOL, Bytes());

	// CHALLENGE_MESSAGE (2.2.1.2): 56 bytes of header, then TargetName and
	// TargetInfo.
	const uint32_t headerSize = 56;
	challenge.clear();
	challenge.insert(challenge.end(), kSignature, kSignature + 8);
	Put32(challenge, 2);
	Put16(challenge, (uint16_t)name.size());
	Put16(challenge, (uint16_t)name.size());
	Put32(challenge, headerSize);
	Put32(challenge, fFlags);
	challenge.insert(challenge.end(), fServerChallenge, fServerChallenge + 8);
	challenge.insert(challenge.end(), 8, 0);		// Reserved
	Put16(challenge, (uint16_t)targetInfo.size());
	Put16(challenge, (uint16_t)targetInfo.size());
	Put32(challenge, headerSize + (uint32_t)name.size());
	// VERSION (2.2.2.10): only used for debugging. NTLMSSP revision 15.
	static const uint8_t kVersion[8] = { 1, 0, 0, 0, 0, 0, 0, 0x0f };
	if ((fFlags & NTLMSSP_NEGOTIATE_VERSION) != 0)
		challenge.insert(challenge.end(), kVersion, kVersion + 8);
	else
		challenge.insert(challenge.end(), 8, 0);
	challenge.insert(challenge.end(), name.begin(), name.end());
	challenge.insert(challenge.end(), targetInfo.begin(), targetInfo.end());

	fNegotiateMessage = negotiate;
	fChallengeMessage = challenge;
	return true;
}


NtlmServer::Result
NtlmServer::HandleAuthenticate(const Bytes& authenticate)
{
	if (fChallengeMessage.empty())
		return kBadMessage;
	if (authenticate.size() < kAuthenticateFixedSize
		|| memcmp(authenticate.data(), kSignature, 8) != 0
		|| Get32(authenticate.data() + 8) != 3) {
		LOG_W("NTLM: not an AUTHENTICATE_MESSAGE");
		return kBadMessage;
	}

	Bytes ntResponse;
	Bytes domain;
	Bytes user;
	Bytes encryptedKey;
	if (!GetField(authenticate, 20, ntResponse)
		|| !GetField(authenticate, 28, domain)
		|| !GetField(authenticate, 36, user)
		|| !GetField(authenticate, 52, encryptedKey)) {
		LOG_W("NTLM: an AUTHENTICATE_MESSAGE field is out of bounds");
		return kBadMessage;
	}
	uint32_t flags = Get32(authenticate.data() + 60);

	fUserName = Utf16LeToUtf8(user.data(), user.size());
	fDomainName = Utf16LeToUtf8(domain.data(), domain.size());

	// Anonymous logins and NTLMv1 (a 24-byte response) are refused.
	if (user.empty() || ntResponse.size() < 16 + kClientChallengeHeaderSize) {
		LOG_W("NTLM: anonymous or NTLMv1 authentication refused");
		return kWrongPassword;
	}
	uint32_t required = NTLMSSP_NEGOTIATE_SEAL | NTLMSSP_NEGOTIATE_SIGN
		| NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY;
	if ((flags & required) != required) {
		LOG_W("NTLM: the client's final flags 0x%08x lack signing, sealing, "
			"or extended session security", flags);
		return kBadMessage;
	}
	// Key exchange and key strength only as offered in the challenge.
	flags &= fFlags | ~(NTLMSSP_NEGOTIATE_KEY_EXCH | NTLMSSP_NEGOTIATE_128
		| NTLMSSP_NEGOTIATE_56);

	// NTLMv2 (3.3.2): NTProofStr = HMAC_MD5(ResponseKeyNT,
	// ServerChallenge + temp), where temp is the rest of the response.
	const uint8_t* proof = ntResponse.data();
	Bytes temp(ntResponse.begin() + 16, ntResponse.end());
	Bytes challengeAndTemp(fServerChallenge, fServerChallenge + 8);
	challengeAndTemp.insert(challengeAndTemp.end(), temp.begin(), temp.end());

	Bytes upperUser = user;
	UpperCaseUtf16(upperUser);

	uint8_t responseKey[16];
	uint8_t expected[16];
	bool match = false;
	// First with the domain the client sent, then with none, as servers
	// SHOULD allow (3.2.5.1.2).
	for (int attempt = 0; attempt < 2 && !match; attempt++) {
		Bytes identity = upperUser;
		if (attempt == 0)
			identity.insert(identity.end(), domain.begin(), domain.end());
		else if (domain.empty())
			break;
		HmacMd5(fNtHash, 16, identity.data(), identity.size(), responseKey);
		HmacMd5(responseKey, 16, challengeAndTemp.data(),
			challengeAndTemp.size(), expected);
		match = SameBytes(expected, proof, 16);
	}
	if (!match) {
		Wipe(responseKey, sizeof(responseKey));
		return kWrongPassword;
	}

	// SessionBaseKey; KeyExchangeKey is the same for NTLMv2 (3.4.5.1).
	uint8_t keyExchangeKey[16];
	HmacMd5(responseKey, 16, proof, 16, keyExchangeKey);
	Wipe(responseKey, sizeof(responseKey));

	uint8_t exportedKey[16];
	fKeyExchange = (flags & NTLMSSP_NEGOTIATE_KEY_EXCH) != 0;
	if (fKeyExchange) {
		if (encryptedKey.size() != 16) {
			LOG_W("NTLM: key exchange without a 16-byte session key");
			Wipe(keyExchangeKey, sizeof(keyExchangeKey));
			return kBadMessage;
		}
		Rc4 rc4;
		rc4.Init(keyExchangeKey, 16);
		rc4.Process(encryptedKey.data(), exportedKey, 16);
	} else
		memcpy(exportedKey, keyExchangeKey, 16);
	Wipe(keyExchangeKey, sizeof(keyExchangeKey));

	// The MIC, if the client says it sent one (MsvAvFlags bit 0x2 in the
	// AV pairs of temp).
	bool micPresent = false;
	size_t at = kClientChallengeHeaderSize;
	while (at + 4 <= temp.size()) {
		uint16_t id = Get16(temp.data() + at);
		uint16_t length = Get16(temp.data() + at + 2);
		if (id == MSV_AV_EOL || at + 4 + length > temp.size())
			break;
		if (id == MSV_AV_FLAGS && length >= 4)
			micPresent = (Get32(temp.data() + at + 4) & kAvFlagMicPresent) != 0;
		at += 4 + length;
	}
	if (micPresent) {
		if (authenticate.size() < kMicOffset + 16) {
			Wipe(exportedKey, sizeof(exportedKey));
			return kBadMessage;
		}
		Bytes all = fNegotiateMessage;
		all.insert(all.end(), fChallengeMessage.begin(),
			fChallengeMessage.end());
		size_t authenticateStart = all.size();
		all.insert(all.end(), authenticate.begin(), authenticate.end());
		memset(all.data() + authenticateStart + kMicOffset, 0, 16);
		uint8_t mic[16];
		HmacMd5(exportedKey, 16, all.data(), all.size(), mic);
		if (!SameBytes(mic, authenticate.data() + kMicOffset, 16)) {
			LOG_W("NTLM: the MIC does not match");
			Wipe(exportedKey, sizeof(exportedKey));
			return kBadMessage;
		}
	}

	// Signing and sealing keys (3.4.5.2, 3.4.5.3).
	Md5WithMagic(exportedKey, 16, kClientSignMagic, fClientSignKey);
	Md5WithMagic(exportedKey, 16, kServerSignMagic, fServerSignKey);
	size_t sealSize = (flags & NTLMSSP_NEGOTIATE_128) != 0 ? 16
		: (flags & NTLMSSP_NEGOTIATE_56) != 0 ? 7 : 5;
	uint8_t sealKey[16];
	Md5WithMagic(exportedKey, sealSize, kClientSealMagic, sealKey);
	fClientSeal.Init(sealKey, 16);
	Md5WithMagic(exportedKey, sealSize, kServerSealMagic, sealKey);
	fServerSeal.Init(sealKey, 16);
	Wipe(sealKey, sizeof(sealKey));
	Wipe(exportedKey, sizeof(exportedKey));

	fSendSequence = 0;
	fReceiveSequence = 0;
	fAuthenticated = true;
	return kOk;
}


void
NtlmServer::_Signature(Rc4& handle, const uint8_t* signKey, uint32_t sequence,
	const Bytes& message, uint8_t signature[16])
{
	// MAC() with extended session security (3.4.4.2).
	Bytes input;
	Put32(input, sequence);
	input.insert(input.end(), message.begin(), message.end());
	uint8_t digest[16];
	HmacMd5(signKey, 16, input.data(), input.size(), digest);

	signature[0] = 1;
	signature[1] = signature[2] = signature[3] = 0;
	if (fKeyExchange)
		handle.Process(digest, signature + 4, 8);
	else
		memcpy(signature + 4, digest, 8);
	for (int i = 0; i < 4; i++)
		signature[12 + i] = (uint8_t)(sequence >> (8 * i));
}


Bytes
NtlmServer::Wrap(const Bytes& message)
{
	// SEAL() (3.4.3): encrypt the message, then sign the plaintext with the
	// same RC4 state.
	Bytes out(16 + message.size());
	if (!fAuthenticated)
		return Bytes();
	fServerSeal.Process(message.data(), out.data() + 16, message.size());
	_Signature(fServerSeal, fServerSignKey, fSendSequence++, message,
		out.data());
	return out;
}


bool
NtlmServer::Unwrap(const Bytes& wrapped, Bytes& message)
{
	if (!fAuthenticated || wrapped.size() < 16)
		return false;
	message.resize(wrapped.size() - 16);
	fClientSeal.Process(wrapped.data() + 16, message.data(), message.size());
	uint8_t expected[16];
	_Signature(fClientSeal, fClientSignKey, fReceiveSequence++, message,
		expected);
	if (!SameBytes(expected, wrapped.data(), 16)) {
		LOG_W("NTLM: bad signature on a sealed message");
		Wipe(message.data(), message.size());
		message.clear();
		return false;
	}
	return true;
}


Bytes
NtlmServer::GetMic(const Bytes& message, bool keepKeyState)
{
	Bytes signature(16);
	if (!fAuthenticated)
		return Bytes();
	Rc4 saved = fServerSeal;
	_Signature(fServerSeal, fServerSignKey, fSendSequence++, message,
		signature.data());
	if (keepKeyState)
		fServerSeal = saved;
	return signature;
}


bool
NtlmServer::VerifyMic(const Bytes& message, const Bytes& signature,
	bool keepKeyState)
{
	if (!fAuthenticated || signature.size() != 16)
		return false;
	Rc4 saved = fClientSeal;
	uint8_t expected[16];
	_Signature(fClientSeal, fClientSignKey, fReceiveSequence++, message,
		expected);
	if (keepKeyState)
		fClientSeal = saved;
	return SameBytes(expected, signature.data(), 16);
}


}	// namespace rrd
