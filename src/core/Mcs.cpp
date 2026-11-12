/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */


#include "Mcs.h"

#include "Log.h"
#include "Protocol.h"


namespace rrd {


ClientSettings::ClientSettings()
	:
	version(0),
	desktopWidth(0),
	desktopHeight(0),
	keyboardLayout(0),
	clientBuild(0),
	keyboardType(0),
	keyboardSubType(0),
	keyboardFunctionKey(0),
	highColorDepth(0),
	supportedColorDepths(0),
	earlyCapabilityFlags(0),
	serverSelectedProtocol(0),
	monitorCount(0)
{
}


// #pragma mark - BER and PER


static bool
ReadBerLength(Reader& reader, size_t& length)
{
	uint8_t first = reader.U8();
	if ((first & 0x80) == 0) {
		length = first;
		return reader.Ok();
	}

	int count = first & 0x7f;
	if (count < 1 || count > 2) {
		reader.SetError();
		return false;
	}
	length = 0;
	for (int i = 0; i < count; i++)
		length = (length << 8) | reader.U8();
	return reader.Ok();
}


static void
WriteBerLength(Writer& writer, size_t length)
{
	if (length < 0x80) {
		writer.U8(length);
	} else if (length <= 0xff) {
		writer.U8(0x81);
		writer.U8(length);
	} else {
		writer.U8(0x82);
		writer.U16BE(length);
	}
}


// Skips one BER element with the given single-byte tag.
static bool
SkipBerElement(Reader& reader, uint8_t tag)
{
	if (reader.U8() != tag) {
		reader.SetError();
		return false;
	}
	size_t length;
	if (!ReadBerLength(reader, length))
		return false;
	reader.Skip(length);
	return reader.Ok();
}


static void
WriteBerInteger(Writer& writer, uint32_t value)
{
	// Minimal two's complement encoding of a non-negative value.
	uint8_t bytes[5];
	int count = 0;
	do {
		bytes[count++] = value & 0xff;
		value >>= 8;
	} while (value != 0);
	if ((bytes[count - 1] & 0x80) != 0)
		bytes[count++] = 0;

	writer.U8(0x02);
	writer.U8(count);
	while (count > 0)
		writer.U8(bytes[--count]);
}


bool
ReadPerLength(Reader& reader, uint16_t& length)
{
	uint8_t first = reader.U8();
	if ((first & 0x80) != 0)
		length = ((first & 0x7f) << 8) | reader.U8();
	else
		length = first;
	return reader.Ok();
}


void
WritePerLength(Writer& writer, uint16_t length)
{
	if (length < 0x80)
		writer.U8(length);
	else
		writer.U16BE(0x8000 | length);
}


// #pragma mark - Connect-Initial


static void
ParseClientCore(Reader& block, ClientSettings& settings)
{
	settings.version = block.U32LE();
	settings.desktopWidth = block.U16LE();
	settings.desktopHeight = block.U16LE();
	block.Skip(2);	// colorDepth
	block.Skip(2);	// SASSequence
	settings.keyboardLayout = block.U32LE();
	settings.clientBuild = block.U32LE();

	// clientName: up to 15 UTF-16 characters plus a NUL in 32 bytes. Keep
	// printable ASCII only; the name is used for logging.
	settings.clientName.clear();
	for (int i = 0; i < 16; i++) {
		uint16_t c = block.U16LE();
		if (c == 0) {
			block.Skip(2 * (15 - i));
			break;
		}
		settings.clientName += c >= 0x20 && c < 0x7f ? (char)c : '?';
	}

	settings.keyboardType = block.U32LE();
	settings.keyboardSubType = block.U32LE();
	settings.keyboardFunctionKey = block.U32LE();
	block.Skip(64);	// imeFileName
	if (!block.Ok())
		return;

	// The remaining fields are optional, but each one requires the ones
	// before it.
	if (block.Remaining() >= 2)
		block.Skip(2);	// postBeta2ColorDepth
	if (block.Remaining() >= 2)
		block.Skip(2);	// clientProductId
	if (block.Remaining() >= 4)
		block.Skip(4);	// serialNumber
	if (block.Remaining() >= 2)
		settings.highColorDepth = block.U16LE();
	if (block.Remaining() >= 2)
		settings.supportedColorDepths = block.U16LE();
	if (block.Remaining() >= 2)
		settings.earlyCapabilityFlags = block.U16LE();
	if (block.Remaining() >= 64)
		block.Skip(64);	// clientDigProductId
	if (block.Remaining() >= 2)
		block.Skip(2);	// connectionType, pad1octet
	if (block.Remaining() >= 4)
		settings.serverSelectedProtocol = block.U32LE();
}


static void
ParseClientNetwork(Reader& block, ClientSettings& settings)
{
	uint32_t count = block.U32LE();
	if (count > MCS_MAX_STATIC_CHANNELS) {
		LOG_W("client requested %u static channels, using the first %d",
			count, MCS_MAX_STATIC_CHANNELS);
		count = MCS_MAX_STATIC_CHANNELS;
	}

	settings.channels.clear();
	for (uint32_t i = 0; i < count && block.Ok(); i++) {
		ClientChannel channel;
		block.Bytes(channel.name, 8);
		channel.name[8] = '\0';
		channel.options = block.U32LE();
		channel.id = 0;
		if (block.Ok())
			settings.channels.push_back(channel);
	}
}


bool
ParseConnectInitial(Reader& reader, ClientSettings& settings)
{
	// Connect-Initial ::= [APPLICATION 101] IMPLICIT SEQUENCE (4.1.3)
	if (reader.U8() != 0x7f || reader.U8() != 0x65) {
		LOG_W("not an MCS Connect-Initial");
		return false;
	}
	size_t length;
	if (!ReadBerLength(reader, length))
		return false;

	if (!SkipBerElement(reader, 0x04)		// callingDomainSelector
		|| !SkipBerElement(reader, 0x04)	// calledDomainSelector
		|| !SkipBerElement(reader, 0x01)	// upwardFlag
		|| !SkipBerElement(reader, 0x30)	// targetParameters
		|| !SkipBerElement(reader, 0x30)	// minimumParameters
		|| !SkipBerElement(reader, 0x30)) {	// maximumParameters
		LOG_W("malformed MCS Connect-Initial");
		return false;
	}

	if (reader.U8() != 0x04 || !ReadBerLength(reader, length))
		return false;
	Reader gcc = reader.Sub(length);
	if (!reader.Ok())
		return false;

	// GCC ConnectData: Key (object identifier T.124 v1), then the PER
	// length of the ConferenceCreateRequest, whose user data is keyed with
	// the client-to-server H.221 key "Duca". The request's own PER fields
	// (4.1.3) carry nothing the server uses, so find the key and read the
	// user data that follows it.
	static const uint8_t kT124Key[] = { 0x00, 0x05, 0x00, 0x14, 0x7c, 0x00,
		0x01 };
	uint8_t key[sizeof(kT124Key)];
	gcc.Bytes(key, sizeof(key));
	uint16_t connectPduLength;
	if (!gcc.Ok() || memcmp(key, kT124Key, sizeof(key)) != 0
		|| !ReadPerLength(gcc, connectPduLength)) {
		LOG_W("unexpected GCC ConnectData");
		return false;
	}

	bool found = false;
	for (int i = 0; i < 16 && gcc.Remaining() >= 4; i++) {
		const uint8_t* p = gcc.Current();
		if (p[0] == 'D' && p[1] == 'u' && p[2] == 'c' && p[3] == 'a') {
			gcc.Skip(4);
			found = true;
			break;
		}
		gcc.Skip(1);
	}
	uint16_t userDataLength;
	if (!found || !ReadPerLength(gcc, userDataLength)) {
		LOG_W("GCC Conference Create Request without client data");
		return false;
	}

	Reader blocks = gcc.Sub(userDataLength);
	if (!gcc.Ok())
		return false;

	bool haveCore = false;
	while (blocks.Remaining() >= 4) {
		uint16_t type = blocks.U16LE();
		uint16_t blockLength = blocks.U16LE();
		if (blockLength < 4) {
			LOG_W("bad client data block length %u", blockLength);
			return false;
		}
		Reader block = blocks.Sub(blockLength - 4);
		if (!blocks.Ok())
			return false;

		switch (type) {
			case CS_CORE:
				ParseClientCore(block, settings);
				haveCore = block.Ok();
				break;
			case CS_NET:
				ParseClientNetwork(block, settings);
				break;
			case CS_MONITOR:
				block.Skip(4);	// flags
				settings.monitorCount = block.U32LE();
				break;
			default:
				LOG_D("ignoring client data block 0x%04x", type);
				break;
		}
	}

	if (!haveCore)
		LOG_W("no valid client core data");
	return haveCore;
}


// #pragma mark - Connect-Response


std::vector<uint8_t>
BuildConnectResponse(ClientSettings& settings, uint32_t requestedProtocols)
{
	Writer userData;

	// TS_UD_SC_CORE (2.2.1.4.2)
	userData.U16LE(SC_CORE);
	userData.U16LE(16);
	userData.U32LE(RDP_VERSION_5_PLUS);
	userData.U32LE(requestedProtocols);
	userData.U32LE(0);	// earlyCapabilityFlags

	// TS_UD_SC_SEC1 (2.2.1.4.3): with Enhanced RDP Security, method and
	// level MUST be 0 and the random and certificate are absent.
	userData.U16LE(SC_SECURITY);
	userData.U16LE(12);
	userData.U32LE(0);
	userData.U32LE(0);

	// TS_UD_SC_NET (2.2.1.4.4)
	size_t count = settings.channels.size();
	bool pad = (count % 2) != 0;
	userData.U16LE(SC_NET);
	userData.U16LE(8 + 2 * count + (pad ? 2 : 0));
	userData.U16LE(MCS_IO_CHANNEL_ID);
	userData.U16LE(count);
	for (size_t i = 0; i < count; i++) {
		settings.channels[i].id = MCS_FIRST_STATIC_CHANNEL_ID + i;
		userData.U16LE(settings.channels[i].id);
	}
	if (pad)
		userData.U16LE(0);

	// GCC Conference Create Response (4.1.4): nodeID 31219, tag 1, result
	// success, one user data set keyed "McDn".
	Writer response;
	static const uint8_t kResponseHeader[] = { 0x14, 0x76, 0x0a, 0x01, 0x01,
		0x00, 0x01, 0xc0, 0x00, 'M', 'c', 'D', 'n' };
	response.Bytes(kResponseHeader, sizeof(kResponseHeader));
	WritePerLength(response, userData.Size());
	response.Bytes(userData.Data());

	Writer gcc;
	static const uint8_t kT124Key[] = { 0x00, 0x05, 0x00, 0x14, 0x7c, 0x00,
		0x01 };
	gcc.Bytes(kT124Key, sizeof(kT124Key));
	WritePerLength(gcc, response.Size());
	gcc.Bytes(response.Data());

	// Connect-Response ::= [APPLICATION 102] (4.1.4)
	Writer body;
	body.U8(0x0a);	// result: rt-successful
	body.U8(0x01);
	body.U8(0x00);
	WriteBerInteger(body, 0);	// calledConnectId

	Writer parameters;
	WriteBerInteger(parameters, 34);	// maxChannelIds
	WriteBerInteger(parameters, 3);		// maxUserIds
	WriteBerInteger(parameters, 0);		// maxTokenIds
	WriteBerInteger(parameters, 1);		// numPriorities
	WriteBerInteger(parameters, 0);		// minThroughput
	WriteBerInteger(parameters, 1);		// maxHeight
	WriteBerInteger(parameters, 65528);	// maxMCSPDUsize
	WriteBerInteger(parameters, 2);		// protocolVersion
	body.U8(0x30);
	WriteBerLength(body, parameters.Size());
	body.Bytes(parameters.Data());

	body.U8(0x04);
	WriteBerLength(body, gcc.Size());
	body.Bytes(gcc.Data());

	Writer pdu;
	pdu.U8(0x7f);
	pdu.U8(0x66);
	WriteBerLength(pdu, body.Size());
	pdu.Bytes(body.Data());
	return pdu.Data();
}


// #pragma mark - framing and domain PDUs


std::vector<uint8_t>
WrapX224Data(const std::vector<uint8_t>& payload)
{
	Writer writer;
	size_t total = 4 + 3 + payload.size();
	writer.U8(3);		// TPKT version
	writer.U8(0);
	writer.U16BE(total);
	writer.U8(2);		// X.224 length indicator
	writer.U8(0xf0);	// Data TPDU
	writer.U8(0x80);	// EOT
	writer.Bytes(payload);
	return writer.Data();
}


std::vector<uint8_t>
BuildAttachUserConfirm(uint16_t userId)
{
	// 4.1.7: attachUserConfirm with the initiator present, result success.
	Writer writer;
	writer.U8((MCS_ATTACH_USER_CONFIRM << 2) | 0x02);
	writer.U8(0x00);
	writer.U16BE(userId - MCS_BASE_CHANNEL_ID);
	return writer.Data();
}


std::vector<uint8_t>
BuildChannelJoinConfirm(uint16_t userId, uint16_t channelId)
{
	// 4.1.8: channelJoinConfirm with the channelId present, result success.
	Writer writer;
	writer.U8((MCS_CHANNEL_JOIN_CONFIRM << 2) | 0x02);
	writer.U8(0x00);
	writer.U16BE(userId - MCS_BASE_CHANNEL_ID);
	writer.U16BE(channelId);	// requested
	writer.U16BE(channelId);	// channelId
	return writer.Data();
}


void
WriteSendDataIndication(Writer& writer, uint16_t channelId,
	const uint8_t* data, size_t size)
{
	// 4.1.11: initiator 1002, high priority, begin and end segmentation.
	writer.U8(MCS_SEND_DATA_INDICATION << 2);
	writer.U16BE(MCS_SERVER_CHANNEL_ID - MCS_BASE_CHANNEL_ID);
	writer.U16BE(channelId);
	writer.U8(0x70);
	WritePerLength(writer, size);
	writer.Bytes(data, size);
}


std::vector<uint8_t>
BuildDisconnectProviderUltimatum()
{
	// DPUM with reason rn-user-requested (3), as two PER bytes.
	Writer writer;
	writer.U8((MCS_DISCONNECT_PROVIDER_ULTIMATUM << 2) | (3 >> 1));
	writer.U8((3 & 1) << 7);
	return writer.Data();
}


}	// namespace rrd
