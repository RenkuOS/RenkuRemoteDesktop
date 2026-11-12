/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */


// Unit tests for the protocol core. Test vectors come from the
// specifications' own examples where they exist.


#include <stdio.h>
#include <string.h>

#include <vector>

#include "Auth.h"
#include "ByteStream.h"
#include "CredSsp.h"
#include "Crypto.h"
#include "Der.h"
#include "Mcs.h"
#include "Ntlm.h"
#include "Planar.h"
#include "Pointer.h"
#include "Resize.h"


using namespace rrd;


static int sFailures = 0;
static int sChecks = 0;


#define CHECK(condition) \
	do { \
		sChecks++; \
		if (!(condition)) { \
			sFailures++; \
			fprintf(stderr, "%s:%d: FAILED: %s\n", __FILE__, __LINE__, \
				#condition); \
		} \
	} while (false)


static bool
SameBytes(const std::vector<uint8_t>& actual, const uint8_t* expected,
	size_t size)
{
	if (actual.size() != size) {
		fprintf(stderr, "  size %zu, expected %zu\n", actual.size(), size);
		return false;
	}
	for (size_t i = 0; i < size; i++) {
		if (actual[i] != expected[i]) {
			fprintf(stderr, "  byte %zu is 0x%02x, expected 0x%02x\n", i,
				actual[i], expected[i]);
			return false;
		}
	}
	return true;
}


// Decoder for RDP 6.0 RLE planes, written from [MS-RDPEGDI] 2.2.2.5.1.2 and
// 3.1.9.2, to round-trip the encoder.
static bool
DecodePlane(const uint8_t*& data, const uint8_t* end, int width, int height,
	std::vector<uint8_t>& plane)
{
	plane.assign((size_t)width * height, 0);
	for (int y = 0; y < height; y++) {
		std::vector<uint8_t> line;
		while ((int)line.size() < width) {
			if (data >= end)
				return false;
			uint8_t control = *data++;
			int raw = control >> 4;
			int run = control & 0xf;
			if (run == 1) {
				run = 16 + raw;
				raw = 0;
			} else if (run == 2) {
				run = 32 + raw;
				raw = 0;
			}
			if (end - data < raw)
				return false;
			uint8_t last = 0;
			for (int i = 0; i < raw; i++) {
				last = *data++;
				line.push_back(last);
			}
			for (int i = 0; i < run; i++)
				line.push_back(last);
		}
		if ((int)line.size() != width)
			return false;
		for (int x = 0; x < width; x++) {
			uint8_t value = line[x];
			if (y == 0) {
				plane[x] = value;
				continue;
			}
			int delta = (value & 1) != 0 ? -((value + 1) >> 1) : value >> 1;
			plane[(size_t)y * width + x]
				= (uint8_t)(plane[(size_t)(y - 1) * width + x] + delta);
		}
	}
	return true;
}


static void
TestPlanarSpecExample()
{
	// [MS-RDPEGDI] 3.1.9.2.1: three scan lines of six values.
	static const uint8_t kPlane[] = {
		255, 255, 255, 255, 254, 253,
		254, 192, 132, 96, 75, 25,
		253, 140, 62, 14, 135, 193
	};
	static const uint8_t kExpected[] = {
		0x13, 0xff,
		0x20, 0xfe, 0xfd,
		0x60, 0x01, 0x7d, 0xf5, 0xc2, 0x9a, 0x38,
		0x60, 0x01, 0x67, 0x8b, 0xa3, 0x78, 0xaf
	};
	std::vector<uint8_t> out;
	EncodePlanarPlaneRle(kPlane, 6, 3, out);
	CHECK(SameBytes(out, kExpected, sizeof(kExpected)));

	// The 3.1.9.2 text example: AAAABBCCCCCD.
	static const uint8_t kLine[] = "AAAABBCCCCCD";
	static const uint8_t kLineExpected[] = {
		0x13, 'A', 0x34, 'B', 'B', 'C', 0x10, 'D'
	};
	out.clear();
	EncodePlanarPlaneRle(kLine, 12, 1, out);
	CHECK(SameBytes(out, kLineExpected, sizeof(kLineExpected)));
}


static void
TestPlanarRoundTrip()
{
	// Pseudo-random image with runs, checked through the decoder above.
	const int width = 68;
	const int height = 37;
	std::vector<uint8_t> pixels((size_t)width * height * 4);
	uint32_t seed = 12345;
	for (size_t i = 0; i < pixels.size(); i++) {
		seed = seed * 1103515245 + 12345;
		bool run = (i / 64) % 3 == 0;
		pixels[i] = run ? 0x40 : (uint8_t)(seed >> 16);
	}

	for (int bottomUp = 0; bottomUp < 2; bottomUp++) {
		for (int skipAlpha = 0; skipAlpha < 2; skipAlpha++) {
			std::vector<uint8_t> stream;
			EncodePlanar(pixels.data(), width * 4, width, height,
				skipAlpha != 0, bottomUp != 0, stream);
			CHECK(!stream.empty());
			if (stream.empty())
				continue;

			uint8_t header = stream[0];
			CHECK(((header & PLANAR_FORMAT_NO_ALPHA) != 0) == (skipAlpha != 0));
			const uint8_t* data = stream.data() + 1;
			const uint8_t* end = stream.data() + stream.size();

			std::vector<uint8_t> planes[4];
			int count = skipAlpha ? 3 : 4;
			bool ok = true;
			for (int p = 0; p < count && ok; p++) {
				if ((header & PLANAR_FORMAT_RLE) != 0)
					ok = DecodePlane(data, end, width, height, planes[p]);
				else {
					size_t size = (size_t)width * height;
					ok = (size_t)(end - data) >= size;
					if (ok) {
						planes[p].assign(data, data + size);
						data += size;
					}
				}
			}
			CHECK(ok);
			if (!ok)
				continue;

			int first = skipAlpha ? 0 : 1;
			bool same = true;
			for (int y = 0; y < height && same; y++) {
				int sourceRow = bottomUp ? height - 1 - y : y;
				for (int x = 0; x < width; x++) {
					const uint8_t* pixel = pixels.data()
						+ ((size_t)sourceRow * width + x) * 4;
					size_t index = (size_t)y * width + x;
					if (planes[first][index] != pixel[2]
						|| planes[first + 1][index] != pixel[1]
						|| planes[first + 2][index] != pixel[0]) {
						same = false;
						fprintf(stderr, "  mismatch at %d,%d\n", x, y);
						break;
					}
					if (!skipAlpha && planes[0][index] != 0xff)
						same = false;
				}
			}
			CHECK(same);
		}
	}
}


static void
TestResize()
{
	std::vector<DisplaySize> modes;
	DisplaySize sizes[] = { { 1024, 768 }, { 1280, 720 }, { 1366, 768 },
		{ 1920, 1080 }, { 2560, 1440 } };
	modes.assign(sizes, sizes + 5);
	DisplaySize console = { 1920, 1080 };
	DisplaySize target;

	DisplaySize laptop = { 1366, 768 };
	CHECK(ChooseSessionSize(RESIZE_FASTEST, laptop, console, modes, target));
	CHECK(target.width == 1366 && target.height == 768);

	DisplaySize big = { 2560, 1440 };
	CHECK(!ChooseSessionSize(RESIZE_FASTEST, big, console, modes, target));
	CHECK(ChooseSessionSize(RESIZE_MATCH_CLIENT, big, console, modes, target));
	CHECK(target.width == 2560);

	DisplaySize odd = { 1300, 740 };	// no exact mode
	CHECK(ChooseSessionSize(RESIZE_FASTEST, odd, console, modes, target));
	CHECK(target.width == 1280 && target.height == 720);

	CHECK(!ChooseSessionSize(RESIZE_KEEP, laptop, console, modes, target));
	CHECK(!ChooseSessionSize(RESIZE_FASTEST, console, console, modes, target));

	std::vector<DisplaySize> none;
	CHECK(!ChooseSessionSize(RESIZE_FASTEST, laptop, console, none, target));
}


static void
TestPassword()
{
	std::string hash = HashPassword("correct horse");
	CHECK(hash.compare(0, 14, "pbkdf2-sha256$") == 0);
	CHECK(VerifyPassword("correct horse", hash));
	CHECK(!VerifyPassword("correct horsf", hash));
	CHECK(!VerifyPassword("", hash));
	CHECK(!VerifyPassword("correct horse", ""));
	CHECK(!VerifyPassword("correct horse", "pbkdf2-sha256$5$00$00"));

	static const uint8_t kUtf16[] = { 'h', 0, 0xe9, 0, 0x3d, 0xd8, 0x00, 0xde };
	CHECK(Utf16LeToUtf8(kUtf16, sizeof(kUtf16)) == "h\xc3\xa9\xf0\x9f\x98\x80");
}


static void
TestConnectInitial()
{
	// [MS-RDPBCGR] 4.1.3, from the BER header to the end of the client
	// network data (the X.224 header removed), extracted from the dump.
	static const uint8_t kPdu[] = {
		0x7f, 0x65, 0x82, 0x01, 0x94, 0x04, 0x01, 0x01, 0x04, 0x01, 0x01,
		0x01, 0x01, 0xff, 0x30, 0x19, 0x02, 0x01, 0x22, 0x02, 0x01, 0x02,
		0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01,
		0x01, 0x02, 0x02, 0xff, 0xff, 0x02, 0x01, 0x02, 0x30, 0x19, 0x02,
		0x01, 0x01, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
		0x02, 0x01, 0x00, 0x02, 0x01, 0x01, 0x02, 0x02, 0x04, 0x20, 0x02,
		0x01, 0x02, 0x30, 0x1c, 0x02, 0x02, 0xff, 0xff, 0x02, 0x02, 0xfc,
		0x17, 0x02, 0x02, 0xff, 0xff, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00,
		0x02, 0x01, 0x01, 0x02, 0x02, 0xff, 0xff, 0x02, 0x01, 0x02, 0x04,
		0x82, 0x01, 0x33, 0x00, 0x05, 0x00, 0x14, 0x7c, 0x00, 0x01, 0x81,
		0x2a, 0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0xc0, 0x00, 0x44, 0x75,
		0x63, 0x61, 0x81, 0x1c, 0x01, 0xc0, 0xd8, 0x00, 0x04, 0x00, 0x08,
		0x00, 0x00, 0x05, 0x00, 0x04, 0x01, 0xca, 0x03, 0xaa, 0x09, 0x04,
		0x00, 0x00, 0xce, 0x0e, 0x00, 0x00, 0x45, 0x00, 0x4c, 0x00, 0x54,
		0x00, 0x4f, 0x00, 0x4e, 0x00, 0x53, 0x00, 0x2d, 0x00, 0x44, 0x00,
		0x45, 0x00, 0x56, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x01, 0xca, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x18, 0x00, 0x07, 0x00, 0x01, 0x00, 0x36, 0x00, 0x39, 0x00,
		0x37, 0x00, 0x31, 0x00, 0x32, 0x00, 0x2d, 0x00, 0x37, 0x00, 0x38,
		0x00, 0x33, 0x00, 0x2d, 0x00, 0x30, 0x00, 0x33, 0x00, 0x35, 0x00,
		0x37, 0x00, 0x39, 0x00, 0x37, 0x00, 0x34, 0x00, 0x2d, 0x00, 0x34,
		0x00, 0x32, 0x00, 0x37, 0x00, 0x31, 0x00, 0x34, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x04, 0xc0, 0x0c, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x02, 0xc0, 0x0c, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x03, 0xc0, 0x2c, 0x00, 0x03, 0x00, 0x00, 0x00, 0x72,
		0x64, 0x70, 0x64, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x80,
		0x63, 0x6c, 0x69, 0x70, 0x72, 0x64, 0x72, 0x00, 0x00, 0x00, 0xa0,
		0xc0, 0x72, 0x64, 0x70, 0x73, 0x6e, 0x64, 0x00, 0x00, 0x00, 0x00,
		0x00, 0xc0
	};
	Reader reader(kPdu, sizeof(kPdu));
	ClientSettings settings;
	CHECK(ParseConnectInitial(reader, settings));
	CHECK(settings.desktopWidth == 1280);
	CHECK(settings.desktopHeight == 1024);
	CHECK(settings.keyboardLayout == 0x409);
	CHECK(settings.clientName == "ELTONS-DEV2");
	CHECK(settings.channels.size() == 3);
	if (settings.channels.size() == 3) {
		CHECK(strcmp(settings.channels[1].name, "cliprdr") == 0);
	}

	// The response must carry the three channel IDs from 1004.
	std::vector<uint8_t> response = BuildConnectResponse(settings, 0);
	CHECK(response.size() > 2 && response[0] == 0x7f && response[1] == 0x66);
	CHECK(settings.channels.size() == 3 && settings.channels[2].id == 1006);
}


static void
TestPointer()
{
	PointerImage image;
	image.width = 3;
	image.height = 2;
	image.hotX = 1;
	image.hotY = 1;
	static const uint8_t kPixels[] = {
		1, 2, 3, 255,	9, 9, 9, 0,		4, 5, 6, 100,
		0, 0, 0, 0,		7, 8, 9, 255,	10, 11, 12, 1
	};
	image.pixels.assign(kPixels, kPixels + sizeof(kPixels));

	// New Pointer Update, 32 bpp: bottom-up, alpha kept, AND bits only
	// where alpha is zero, scan lines padded to two bytes.
	static const uint8_t kAlpha[] = {
		32, 0,  0, 0,  1, 0, 1, 0,  3, 0,  2, 0,  4, 0,  24, 0,
		0, 0, 0, 0,  7, 8, 9, 255,  10, 11, 12, 1,
		1, 2, 3, 255,  0, 0, 0, 0,  4, 5, 6, 100,
		0x80, 0,  0x40, 0
	};
	std::vector<uint8_t> out = EncodePointer(image, 32, true);
	CHECK(SameBytes(out, kAlpha, sizeof(kAlpha)));

	// Color Pointer Update, 24 bpp: pixels under half opacity are
	// transparent.
	static const uint8_t kColor[] = {
		0, 0,  1, 0, 1, 0,  3, 0,  2, 0,  4, 0,  20, 0,
		0, 0, 0,  7, 8, 9,  0, 0, 0,  0,
		1, 2, 3,  0, 0, 0,  0, 0, 0,  0,
		0xa0, 0,  0x60, 0
	};
	out = EncodePointer(image, 32, false);
	CHECK(SameBytes(out, kColor, sizeof(kColor)));

	// Cropped to the maximum size, with the hot spot kept inside.
	image.hotX = 5;
	image.hotY = 5;
	out = EncodePointer(image, 2, true);
	CHECK(out.size() > 12 && out[4] == 1 && out[6] == 1 && out[8] == 2
		&& out[10] == 2);
}


static std::vector<uint8_t>
Hex(const char* text)
{
	std::vector<uint8_t> out;
	int high = -1;
	for (const char* c = text; *c != '\0'; c++) {
		int value = *c >= '0' && *c <= '9' ? *c - '0'
			: *c >= 'a' && *c <= 'f' ? *c - 'a' + 10 : -1;
		if (value < 0)
			continue;
		if (high < 0)
			high = value;
		else {
			out.push_back((uint8_t)(high << 4 | value));
			high = -1;
		}
	}
	return out;
}


static void
TestCrypto()
{
	// MD4 ([RFC1320] appendix A.5)
	uint8_t digest[16];
	Md4((const uint8_t*)"", 0, digest);
	CHECK(SameBytes(std::vector<uint8_t>(digest, digest + 16),
		Hex("31d6cfe0d16ae931b73c59d7e0c089c0").data(), 16));
	Md4((const uint8_t*)"abc", 3, digest);
	CHECK(SameBytes(std::vector<uint8_t>(digest, digest + 16),
		Hex("a448017aaf21d8525fc10ae87aa6729d").data(), 16));
	const char* long80 = "1234567890123456789012345678901234567890"
		"1234567890123456789012345678901234567890";
	Md4((const uint8_t*)long80, 80, digest);
	CHECK(SameBytes(std::vector<uint8_t>(digest, digest + 16),
		Hex("e33b4ddc9c38f2199c3e7b164fcc0536").data(), 16));

	// RC4: the widely published "Key" / "Plaintext" vector.
	Rc4 rc4;
	rc4.Init((const uint8_t*)"Key", 3);
	uint8_t out[9];
	rc4.Process((const uint8_t*)"Plaintext", out, 9);
	CHECK(SameBytes(std::vector<uint8_t>(out, out + 9),
		Hex("bbf316e8d940af0ad3").data(), 9));

	// NTOWFv1("Password") ([MS-NLMP] 4.2.2.1.2)
	NtHash("Password", digest);
	CHECK(SameBytes(std::vector<uint8_t>(digest, digest + 16),
		Hex("a4f49c406510bdcab6824ee7c30fd852").data(), 16));
	CHECK(NtHashHex("Password") == "a4f49c406510bdcab6824ee7c30fd852");
	uint8_t parsed[16];
	CHECK(ParseNtHash("A4F49C406510BDCAB6824EE7C30FD852", parsed)
		&& memcmp(parsed, digest, 16) == 0);
	CHECK(!ParseNtHash("a4f49c40", parsed));

	// UTF-8 to UTF-16LE, with a character outside the BMP.
	std::vector<uint8_t> unicode = Utf8ToUtf16Le("a\xc3\xa9\xf0\x9f\x98\x80");
	CHECK(SameBytes(unicode, Hex("6100 e900 3dd8 00de").data(), 8));
}


static void
TestDer()
{
	DerWriter writer;
	writer.Integer(6);
	writer.Integer((int32_t)0xc000006d);
	writer.Integer(128);
	CHECK(SameBytes(writer.Data(),
		Hex("020106 0204c000006d 02020080").data(), 13));

	DerReader reader(writer.Data().data(), writer.Data().size());
	int64_t a = 0, b = 0, c = 0;
	CHECK(reader.ReadInteger(a) && reader.ReadInteger(b)
		&& reader.ReadInteger(c) && reader.AtEnd());
	CHECK(a == 6 && b == (int32_t)0xc000006d && c == 128);

	// TSRequest round trip, and the long length form.
	TsRequest request;
	request.version = 6;
	request.hasNegoToken = true;
	request.negoToken.assign(300, 0x41);
	request.hasClientNonce = true;
	request.clientNonce.assign(32, 0x07);
	std::vector<uint8_t> encoded = BuildTsRequest(request);
	size_t needed = 0;
	CHECK(DerElementSize(encoded.data(), 2, needed) == 0 && needed == 4);
	CHECK(DerElementSize(encoded.data(), encoded.size(), needed)
		== encoded.size());
	TsRequest decoded;
	CHECK(ParseTsRequest(encoded, decoded));
	CHECK(decoded.version == 6 && decoded.hasNegoToken
		&& decoded.negoToken == request.negoToken && decoded.hasClientNonce
		&& decoded.clientNonce == request.clientNonce
		&& !decoded.hasPubKeyAuth && !decoded.hasAuthInfo);
}


static void
TestNtlm()
{
	// [MS-NLMP] 4.2.4: NTLMv2 with "User", "Domain", "Password", server
	// challenge 0123456789abcdef, and RandomSessionKey 55..55.
	uint8_t hash[16];
	NtHash("Password", hash);
	NtlmServer server(hash, "Server");
	static const uint8_t kChallenge[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
		0xcd, 0xef };
	server.SetChallengeForTest(kChallenge, 0);

	std::vector<uint8_t> negotiate = Hex("4e544c4d53535000 01000000 358288e2");
	std::vector<uint8_t> challenge;
	CHECK(server.HandleNegotiate(negotiate, challenge));
	CHECK(challenge.size() > 56 && memcmp(challenge.data() + 24, kChallenge,
		8) == 0);

	std::vector<uint8_t> authenticate = Hex(
		"4e544c4d53535000030000001800180"
		"06c00000054005400840000000c000c00"
		"480000000800080054000000100010"
		"005c000000100010 00d8000000358288e2"
		"0501280a0000000f44006f006d006100"
		"69006e00550073006500720043004f00"
		"4d005000550054004500520086c35097"
		"ac9cec102554764a57cccc19aaaaaaaa"
		"aaaaaaaa68cd0ab851e51c96aabc927b"
		"ebef6a1c010100000000000000000000"
		"00000000aaaaaaaaaaaaaaaa00000000"
		"02000c0044006f006d00610069006e00"
		"01000c005300650072007600650072 00"
		"0000000000000000c5dad2544fc97990"
		"94ce1ce90bc9d03e");
	CHECK(authenticate.size() == 0xe8);
	CHECK(server.HandleAuthenticate(authenticate) == NtlmServer::kOk);
	CHECK(server.UserName() == "User" && server.DomainName() == "Domain");

	// 4.2.4.4: the client's sealed "Plaintext" with its signature.
	std::vector<uint8_t> wrapped = Hex(
		"01000000 7fb38ec5c55d4976 00000000"
		"54e50165bf1936dc996020c1811b0f06fb5f");
	std::vector<uint8_t> plain;
	CHECK(server.Unwrap(wrapped, plain));
	CHECK(SameBytes(plain, Hex("50006c00610069006e007400650078007400").data(),
		18));
	// The same message again has the wrong sequence number.
	std::vector<uint8_t> again;
	CHECK(!server.Unwrap(wrapped, again));

	// A wrong password is refused.
	uint8_t wrong[16];
	NtHash("Passw0rd", wrong);
	NtlmServer other(wrong, "Server");
	other.SetChallengeForTest(kChallenge, 0);
	CHECK(other.HandleNegotiate(negotiate, challenge));
	CHECK(other.HandleAuthenticate(authenticate) == NtlmServer::kWrongPassword);

	// A client that does not offer sealing is refused at once.
	NtlmServer third(hash, "Server");
	CHECK(!third.HandleNegotiate(Hex("4e544c4d53535000 01000000 05820800"),
		challenge));

	// SPNEGO: a negTokenInit with NTLM first and a mechToken.
	std::vector<uint8_t> init = Hex(
		"6040 0606 2b0601050502"
		"a036 3034"
		"a00e 300c 060a 2b0601040182370202 0a"
		"a222 0420 4e544c4d53535000 01000000 358288e2"
		"000000000000000000000000000000000000");
	SpnegoToken token;
	CHECK(ParseSpnego(init, token));
	CHECK(token.init && token.offersNtlm && token.ntlmFirst && token.hasToken
		&& token.token.size() == 32 && token.mechTypes.size() == 14);
	std::vector<uint8_t> response = BuildSpnegoResponse(
		SPNEGO_ACCEPT_INCOMPLETE, true, &negotiate, NULL);
	SpnegoToken parsedResponse;
	CHECK(ParseSpnego(response, parsedResponse) && !parsedResponse.init
		&& parsedResponse.hasToken && parsedResponse.token == negotiate);
}


int
main()
{
	TestPlanarSpecExample();
	TestPlanarRoundTrip();
	TestResize();
	TestPassword();
	TestPointer();
	TestCrypto();
	TestDer();
	TestNtlm();
	TestConnectInitial();

	printf("%d checks, %d failed\n", sChecks, sFailures);
	return sFailures == 0 ? 0 : 1;
}
