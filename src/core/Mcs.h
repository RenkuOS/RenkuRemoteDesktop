/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */
#ifndef RRD_MCS_H
#define RRD_MCS_H


// T.125 MCS and T.124 GCC encoding, limited to what an RDP server needs.
// The layouts follow the annotated dumps in [MS-RDPBCGR] 4.1.3 to 4.1.8.


#include <string>
#include <vector>

#include "ByteStream.h"


namespace rrd {


struct ClientChannel {
	char		name[9];
	uint32_t	options;
	uint16_t	id;
};


// The parts of the client's GCC user data that the server uses
// ([MS-RDPBCGR] 2.2.1.3).
struct ClientSettings {
				ClientSettings();

	// TS_UD_CS_CORE
	uint32_t	version;
	uint16_t	desktopWidth;
	uint16_t	desktopHeight;
	uint32_t	keyboardLayout;
	uint32_t	clientBuild;
	std::string	clientName;
	uint32_t	keyboardType;
	uint32_t	keyboardSubType;
	uint32_t	keyboardFunctionKey;
	uint16_t	highColorDepth;
	uint16_t	supportedColorDepths;
	uint16_t	earlyCapabilityFlags;
	uint32_t	serverSelectedProtocol;

	// TS_UD_CS_NET
	std::vector<ClientChannel> channels;

	// TS_UD_CS_MONITOR (only counted in phase 1)
	uint32_t	monitorCount;
};


// T.123 TPKT header plus the X.224 Data TPDU header, around payload.
std::vector<uint8_t> WrapX224Data(const std::vector<uint8_t>& payload);

// Parses an MCS Connect-Initial (BER) with its GCC Conference Create
// Request (PER), starting right after the X.224 data header.
bool ParseConnectInitial(Reader& reader, ClientSettings& settings);

// Builds the MCS Connect-Response with the GCC Conference Create Response,
// without TPKT and X.224 headers. Assigns channel IDs in settings.
std::vector<uint8_t> BuildConnectResponse(ClientSettings& settings,
	uint32_t requestedProtocols);

// PER length determinant as used by MCS and GCC.
bool ReadPerLength(Reader& reader, uint16_t& length);
void WritePerLength(Writer& writer, uint16_t length);

// MCS domain PDUs (PER).
std::vector<uint8_t> BuildAttachUserConfirm(uint16_t userId);
std::vector<uint8_t> BuildChannelJoinConfirm(uint16_t userId,
	uint16_t channelId);
// Send Data Indication header followed by data.
void WriteSendDataIndication(Writer& writer, uint16_t channelId,
	const uint8_t* data, size_t size);
std::vector<uint8_t> BuildDisconnectProviderUltimatum();


}	// namespace rrd


#endif	// RRD_MCS_H
