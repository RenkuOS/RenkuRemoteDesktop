/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */


#include "Session.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "Auth.h"
#include "CredSsp.h"
#include "Crypto.h"
#include "Log.h"
#include "Planar.h"
#include "Pointer.h"
#include "Protocol.h"
#include "Transport.h"


namespace rrd {


static const int kTileSize = 64;
// Largest TPKT we accept from a client. Slow-path PDUs from clients are
// small; this only bounds memory use.
static const size_t kMaxIncomingPdu = 0x10000;
// A wrong password costs the client this long, to slow down guessing.
static const useconds_t kFailedLoginDelay = 2000000;
// After this long without screen changes or input, poll the screen less
// often: with capture backend A every poll costs app_server a full read of
// the frame buffer.
static const int64_t kIdleAfterMs = 2000;
static const int kIdleFrameIntervalMs = 200;
// The NetBIOS-style name NTLM reports: the host name up to the first dot,
// upper case, at most 15 characters.
static std::string
ComputerName()
{
	char host[256];
	if (gethostname(host, sizeof(host)) != 0)
		return "RENKUOS";
	host[sizeof(host) - 1] = '\0';
	std::string name;
	for (const char* c = host; *c != '\0' && *c != '.' && name.size() < 15;
			c++) {
		name += *c >= 'a' && *c <= 'z' ? *c - 'a' + 'A' : *c;
	}
	return name.empty() ? std::string("RENKUOS") : name;
}


// A pointer generation no frame source uses: forces the first shape out.
static const uint32_t kNoPointer = 0xffffffff;
// Without the Large Pointer Capability Set, pointers are at most 32 by 32
// pixels (2.2.9.1.1.4.4).
static const int kMaxPointerSize = 32;


static int64_t
NowMs()
{
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}


ServerConfig::ServerConfig()
	:
	allowWithoutPassword(false),
	resize(RESIZE_FASTEST),
	frameIntervalMs(40),
	port(3389)
{
}


Session::Session(int fd, const ServerConfig& config, TlsContext& tls,
	FrameSource& frames, InputSink& input, SessionHost& host)
	:
	fFd(fd),
	fConfig(config),
	fTls(tls),
	fFrames(frames),
	fInput(input),
	fHost(host),
	fTransport(new Transport(fd)),
	fRequestedProtocols(0),
	fSelectedProtocol(0),
	fShareId(0x000103ea),
	fUserChannelId(0),
	fNlaAuthenticated(false),
	fLoginTime(0),
	fOwnsDesktop(false),
	fActive(false),
	fOutputSuppressed(false),
	fFullRefresh(true),
	fSizeChanged(false),
	fButtons(0),
	fLastActivityMs(0),
	fStatsStartMs(0),
	fCaptureMs(0),
	fEncodeMs(0),
	fFramesPolled(0),
	fTilesSent(0),
	fBytesSent(0),
	fFrameStale(true),
	fPointerGeneration(kNoPointer),
	fKicked(false),
	fAborted(false),
	fKickReason(0)
{
	fSize.width = 0;
	fSize.height = 0;
}


Session::~Session()
{
	delete fTransport;
}


const std::string&
Session::Peer() const
{
	return fTransport->PeerAddress();
}


void
Session::Kick(uint32_t errorInfo)
{
	fKickReason = errorInfo;
	fKicked = true;
}


void
Session::Abort()
{
	// On Haiku, shutdown() neither wakes a blocked read nor makes poll()
	// or the next write fail, so the main loop also checks this flag.
	fAborted = true;
	fTransport->Shutdown();
}


void
Session::Run()
{
	LOG_I("connection from %s", Peer().c_str());

	if (_Negotiate() && _BasicSettings() && _ChannelsAndClientInfo()
		&& _SendLicense()) {
		fHost.SessionActivating(this);
		fOwnsDesktop = true;
		_ChooseSize();
		if (_SendDemandActive())
			_MainLoop();
	}

	if (fOwnsDesktop) {
		fInput.ReleaseAll();
		fFrames.RestoreSize();
	}
	fHost.SessionEnded(this);
	LOG_I("connection from %s ended", Peer().c_str());
}


// #pragma mark - reading


bool
Session::_ReadPdu(Pdu& pdu)
{
	uint8_t first;
	if (!fTransport->ReadExact(&first, 1))
		return false;

	pdu.header = first;
	if (first == 0x03) {
		// TPKT ([T123] section 8): version 3, reserved, length (BE).
		uint8_t rest[3];
		if (!fTransport->ReadExact(rest, 3))
			return false;
		size_t length = (rest[1] << 8) | rest[2];
		if (length < 4 + 3 || length > kMaxIncomingPdu) {
			LOG_W("bad TPKT length %zu", length);
			return false;
		}
		pdu.fastPath = false;
		pdu.data.resize(length - 4);
		return fTransport->ReadExact(pdu.data.data(), pdu.data.size());
	}

	if ((first & 0x3) != 0) {
		LOG_W("unknown PDU header byte 0x%02x", first);
		return false;
	}

	// Fast-path input (2.2.8.1.2): length1, and length2 if length1 has the
	// high bit set. The length includes the header.
	uint8_t length1;
	if (!fTransport->ReadExact(&length1, 1))
		return false;
	size_t length = length1;
	size_t headerSize = 2;
	if ((length1 & 0x80) != 0) {
		uint8_t length2;
		if (!fTransport->ReadExact(&length2, 1))
			return false;
		length = ((length1 & 0x7f) << 8) | length2;
		headerSize = 3;
	}
	if (length < headerSize || length > kMaxIncomingPdu) {
		LOG_W("bad fast-path length %zu", length);
		return false;
	}
	if ((first >> 6) != 0) {
		// Encryption flags only apply to Standard RDP Security.
		LOG_W("encrypted fast-path input is not supported");
		return false;
	}
	pdu.fastPath = true;
	pdu.data.resize(length - headerSize);
	return fTransport->ReadExact(pdu.data.data(), pdu.data.size());
}


bool
Session::_ReadX224Data(Pdu& pdu, Reader& reader)
{
	if (pdu.fastPath) {
		LOG_W("unexpected fast-path PDU");
		return false;
	}
	reader = Reader(pdu.data);
	// X.224 Data TPDU: length indicator 2, code 0xF0, EOT 0x80.
	uint8_t lengthIndicator = reader.U8();
	uint8_t code = reader.U8();
	if (!reader.Ok() || lengthIndicator != 2 || (code & 0xf0) != 0xf0) {
		LOG_W("expected an X.224 Data TPDU, got code 0x%02x", code);
		return false;
	}
	reader.Skip(1);
	return reader.Ok();
}


bool
Session::_ReadMcsSendData(Reader& reader, uint16_t& channel, Reader& payload)
{
	// sendDataRequest (4.1.10): initiator, channelId, priority and
	// segmentation, PER length, data.
	reader.U16BE();		// initiator
	channel = reader.U16BE();
	reader.U8();
	uint16_t length;
	if (!ReadPerLength(reader, length))
		return false;
	payload = reader.Sub(length);
	return reader.Ok();
}


// #pragma mark - connection sequence


bool
Session::_Negotiate()
{
	// 2.2.1.1 Client X.224 Connection Request
	Pdu pdu;
	if (!_ReadPdu(pdu) || pdu.fastPath)
		return false;

	Reader reader(pdu.data);
	uint8_t lengthIndicator = reader.U8();
	uint8_t code = reader.U8();
	reader.Skip(5);		// dst-ref, src-ref, class
	if (!reader.Ok() || (code & 0xf0) != 0xe0
		|| lengthIndicator + 1u > pdu.data.size() || lengthIndicator < 6) {
		LOG_W("expected an X.224 Connection Request");
		return false;
	}
	Reader variable = reader.Sub(lengthIndicator - 6);

	// Optional routing token or cookie, each ending in CR LF.
	if (variable.Remaining() > 0 && variable.Current()[0] != TYPE_RDP_NEG_REQ) {
		while (variable.Remaining() >= 2) {
			if (variable.Current()[0] == '\r'
				&& variable.Current()[1] == '\n') {
				variable.Skip(2);
				break;
			}
			variable.Skip(1);
		}
	}

	bool haveNegotiation = false;
	if (variable.Remaining() >= 8
		&& variable.Current()[0] == TYPE_RDP_NEG_REQ) {
		variable.U8();
		variable.U8();		// flags
		variable.U16LE();	// length
		fRequestedProtocols = variable.U32LE();
		haveNegotiation = variable.Ok();
	}

	LOG_I("%s requests protocols 0x%x", Peer().c_str(), fRequestedProtocols);

	// 2.2.1.2 Server X.224 Connection Confirm
	Writer confirm;
	confirm.U8(3);
	confirm.U8(0);
	confirm.U16BE(19);
	confirm.U8(14);		// length indicator
	confirm.U8(0xd0);	// Connection Confirm
	confirm.U16BE(0);	// dst-ref
	confirm.U16BE(0x1234);	// src-ref
	confirm.U8(0);		// class 0

	bool ok = true;
	uint8_t ntHash[16];
	bool haveNtHash = ParseNtHash(fConfig.ntHash, ntHash);
	if (haveNegotiation && (fRequestedProtocols & PROTOCOL_HYBRID) != 0
		&& haveNtHash) {
		// NLA: CredSSP over TLS checks the password before anything else.
		fSelectedProtocol = PROTOCOL_HYBRID;
		confirm.U8(TYPE_RDP_NEG_RSP);
		confirm.U8(EXTENDED_CLIENT_DATA_SUPPORTED);
		confirm.U16LE(8);
		confirm.U32LE(fSelectedProtocol);
	} else if (haveNegotiation
		&& (fRequestedProtocols & PROTOCOL_SSL) != 0) {
		// TLS only: the password comes in the Client Info PDU. Windows
		// clients do not send one there, so they need NLA.
		if ((fRequestedProtocols & PROTOCOL_HYBRID) != 0 && !haveNtHash) {
			LOG_W("the client asks for NLA, but no NT hash is stored; run "
				"--set-password again to enable it");
		}
		fSelectedProtocol = PROTOCOL_SSL;
		confirm.U8(TYPE_RDP_NEG_RSP);
		confirm.U8(EXTENDED_CLIENT_DATA_SUPPORTED);
		confirm.U16LE(8);
		confirm.U32LE(fSelectedProtocol);
	} else {
		// Standard RDP Security is never offered.
		LOG_W("%s does not support TLS, refusing", Peer().c_str());
		confirm.U8(TYPE_RDP_NEG_FAILURE);
		confirm.U8(0);
		confirm.U16LE(8);
		confirm.U32LE(SSL_REQUIRED_BY_SERVER);
		ok = false;
	}

	if (!fTransport->WriteAll(confirm.Data()) || !ok) {
		Wipe(ntHash, sizeof(ntHash));
		return false;
	}

	if (!fTransport->StartTls(fTls.Context())) {
		Wipe(ntHash, sizeof(ntHash));
		return false;
	}
	if (fSelectedProtocol != PROTOCOL_HYBRID)
		return true;

	CredSspServer credSsp(*fTransport, fTls.SubjectPublicKey(), ntHash,
		fConfig.passwordHash, ComputerName());
	Wipe(ntHash, sizeof(ntHash));
	CredSspServer::Result result = credSsp.Run();
	if (result == CredSspServer::kAuthenticated) {
		fNlaAuthenticated = true;
		fNlaUser = credSsp.UserName();
		LOG_I("NLA login from %s (user \"%s\") accepted", Peer().c_str(),
			fNlaUser.c_str());
		return true;
	}
	if (result == CredSspServer::kWrongPassword) {
		LOG_W("NLA login from %s (user \"%s\") refused", Peer().c_str(),
			credSsp.UserName().c_str());
		fHost.LoginFailed(Peer());
		usleep(kFailedLoginDelay);
	} else
		LOG_W("NLA with %s failed", Peer().c_str());
	return false;
}


bool
Session::_BasicSettings()
{
	// 2.2.1.3 MCS Connect Initial with GCC Conference Create Request
	Pdu pdu;
	Reader reader(NULL, 0);
	if (!_ReadPdu(pdu) || !_ReadX224Data(pdu, reader))
		return false;
	if (!ParseConnectInitial(reader, fClient))
		return false;

	LOG_I("client \"%s\" build %u, %ux%u, keyboard layout 0x%08x, "
		"%zu static channels", fClient.clientName.c_str(),
		fClient.clientBuild, fClient.desktopWidth, fClient.desktopHeight,
		fClient.keyboardLayout, fClient.channels.size());
	LOG_D("client early capability flags 0x%04x, color depths 0x%04x",
		fClient.earlyCapabilityFlags, fClient.supportedColorDepths);
	for (size_t i = 0; i < fClient.channels.size(); i++)
		LOG_D("  channel %s", fClient.channels[i].name);

	// 3.3.5.3.3: the protocol the client says the server selected has to
	// match, or the negotiation was tampered with.
	if (fClient.serverSelectedProtocol != fSelectedProtocol) {
		LOG_W("client reports selected protocol %u, expected %u",
			fClient.serverSelectedProtocol, fSelectedProtocol);
		return false;
	}

	if ((fClient.supportedColorDepths & RNS_UD_32BPP_SUPPORT) == 0)
		LOG_W("client does not list 32 bpp support; trying anyway");

	std::vector<uint8_t> response = BuildConnectResponse(fClient,
		fRequestedProtocols);
	// BuildConnectResponse() numbers the static channels from
	// MCS_FIRST_STATIC_CHANNEL_ID. The user channel must not share an ID
	// with any of them.
	fUserChannelId = MCS_FIRST_STATIC_CHANNEL_ID + fClient.channels.size();
	LOG_D("sending the Connect Response, user channel %u", fUserChannelId);
	return fTransport->WriteAll(WrapX224Data(response));
}


bool
Session::_ChannelsAndClientInfo()
{
	// 2.2.1.5 to 2.2.1.9, then 2.2.1.11 Client Info PDU.
	bool attached = false;
	while (true) {
		Pdu pdu;
		Reader reader(NULL, 0);
		if (!_ReadPdu(pdu) || !_ReadX224Data(pdu, reader))
			return false;

		uint8_t choice = reader.U8() >> 2;
		switch (choice) {
			case MCS_ERECT_DOMAIN_REQUEST:
				LOG_D("Erect Domain Request");
				break;

			case MCS_ATTACH_USER_REQUEST:
				LOG_D("Attach User Request");
				if (!fTransport->WriteAll(WrapX224Data(
						BuildAttachUserConfirm(fUserChannelId)))) {
					return false;
				}
				attached = true;
				break;

			case MCS_CHANNEL_JOIN_REQUEST:
			{
				reader.U16BE();	// initiator
				uint16_t channel = reader.U16BE();
				LOG_D("Channel Join Request for %u", channel);
				bool known = channel == fUserChannelId
					|| channel == MCS_IO_CHANNEL_ID;
				for (size_t i = 0; i < fClient.channels.size(); i++)
					known |= fClient.channels[i].id == channel;
				if (!reader.Ok() || !attached || !known) {
					LOG_W("bad channel join for %u", channel);
					return false;
				}
				if (!fTransport->WriteAll(WrapX224Data(
						BuildChannelJoinConfirm(fUserChannelId,
							channel)))) {
					return false;
				}
				break;
			}

			case MCS_SEND_DATA_REQUEST:
			{
				uint16_t channel;
				Reader payload(NULL, 0);
				if (!_ReadMcsSendData(reader, channel, payload))
					return false;
				if (channel != MCS_IO_CHANNEL_ID) {
					LOG_D("ignoring early data on channel %u", channel);
					break;
				}
				LOG_D("Client Info PDU");
				return _HandleClientInfo(payload);
			}

			case MCS_DISCONNECT_PROVIDER_ULTIMATUM:
				return false;

			default:
				LOG_W("unexpected MCS PDU %u during channel setup", choice);
				return false;
		}
	}
}


bool
Session::_HandleClientInfo(Reader& reader)
{
	// Basic security header with SEC_INFO_PKT (2.2.1.11.1)
	uint16_t flags = reader.U16LE();
	reader.U16LE();
	if (!reader.Ok() || (flags & SEC_INFO_PKT) == 0) {
		LOG_W("expected the Client Info PDU");
		return false;
	}

	// TS_INFO_PACKET (2.2.1.11.1.1)
	reader.U32LE();		// CodePage
	uint32_t infoFlags = reader.U32LE();
	uint16_t domainSize = reader.U16LE();
	uint16_t userSize = reader.U16LE();
	uint16_t passwordSize = reader.U16LE();
	reader.U16LE();		// cbAlternateShell
	reader.U16LE();		// cbWorkingDir
	if ((infoFlags & INFO_UNICODE) == 0) {
		LOG_W("client info is not Unicode; not supported");
		return false;
	}
	if (domainSize > 510 || userSize > 510 || passwordSize > 510) {
		LOG_W("client info field too long");
		return false;
	}

	reader.Skip(domainSize + 2);
	Reader user = reader.Sub(userSize);
	reader.Skip(2);
	Reader passwordField = reader.Sub(passwordSize);
	if (!reader.Ok()) {
		LOG_W("truncated Client Info PDU");
		return false;
	}

	std::string userName = Utf16LeToUtf8(user.Current(), userSize);
	std::string password = Utf16LeToUtf8(passwordField.Current(),
		passwordSize);

	bool allowed;
	if (fNlaAuthenticated) {
		// The password was checked by CredSSP already.
		allowed = true;
	} else if (fConfig.passwordHash.empty()) {
		allowed = fConfig.allowWithoutPassword;
		if (!allowed)
			LOG_W("no password is set; refusing all connections");
	} else
		allowed = VerifyPassword(password, fConfig.passwordHash);
	WipeString(password);

	if (!allowed) {
		LOG_W("login from %s (user \"%s\") refused", Peer().c_str(),
			userName.c_str());
		fHost.LoginFailed(Peer());
		usleep(kFailedLoginDelay);
		fTransport->WriteAll(WrapX224Data(BuildDisconnectProviderUltimatum()));
		return false;
	}

	if (!fNlaAuthenticated) {
		LOG_I("login from %s (user \"%s\") accepted", Peer().c_str(),
			userName.c_str());
	}
	// With NLA, the name the client proved is the one that counts.
	fUserName = fNlaAuthenticated ? fNlaUser : userName;
	fLoginTime = time(NULL);
	return true;
}


bool
Session::_SendLicense()
{
	// 2.2.1.12 Server License Error PDU - Valid Client, as in 4.1.11.
	Writer writer;
	writer.U16LE(SEC_LICENSE_PKT);
	writer.U16LE(0);
	writer.U8(LICENSE_ERROR_ALERT);
	writer.U8(LICENSE_PREAMBLE_VERSION_3_0);
	writer.U16LE(16);	// wMsgSize, including the preamble
	writer.U32LE(STATUS_VALID_CLIENT);
	writer.U32LE(ST_NO_TRANSITION);
	writer.U16LE(BB_ERROR_BLOB);
	writer.U16LE(0);
	return _SendIo(writer.Data());
}


void
Session::_ChooseSize()
{
	DisplaySize console = fFrames.Size();
	DisplaySize client = { fClient.desktopWidth, fClient.desktopHeight };
	DisplaySize target;
	std::vector<DisplaySize> available = fFrames.AvailableSizes();
	if (ChooseSessionSize(fConfig.resize, client, console, available,
			target)) {
		LOG_I("switching the display from %dx%d to %dx%d (%s)",
			console.width, console.height, target.width, target.height,
			ResizePolicyName(fConfig.resize));
		if (!fFrames.SetSize(target))
			LOG_W("display mode switch failed");
	} else if (client.width != console.width
		|| client.height != console.height) {
		// Say why, since the client's window then does not fit.
		std::string sizes;
		for (size_t i = 0; i < available.size(); i++) {
			char text[32];
			snprintf(text, sizeof(text), "%s%dx%d", i > 0 ? ", " : "",
				available[i].width, available[i].height);
			sizes += text;
		}
		LOG_I("keeping the display at %dx%d for a %dx%d client (%s); "
			"display modes: %s", console.width, console.height,
			client.width, client.height, ResizePolicyName(fConfig.resize),
			sizes.empty() ? "none reported" : sizes.c_str());
	}
	fSize = fFrames.Size();
}


bool
Session::_SendDemandActive()
{
	// 2.2.1.13.1 Server Demand Active PDU
	uint16_t count;
	std::vector<uint8_t> capabilities = BuildServerCapabilities(fSize.width,
		fSize.height, count);

	Writer body;
	body.U32LE(fShareId);
	body.U16LE(4);		// lengthSourceDescriptor
	body.U16LE(4 + capabilities.size());	// lengthCombinedCapabilities
	body.Bytes("RDP", 4);
	body.U16LE(count);
	body.U16LE(0);		// pad2Octets
	body.Bytes(capabilities);
	body.U32LE(0);		// sessionId

	fActive = false;
	LOG_D("sending Demand Active for %dx%d", fSize.width, fSize.height);
	return _SendShareControl(PDUTYPE_DEMANDACTIVEPDU, body.Data());
}


bool
Session::_HandleConfirmActive(Reader& reader)
{
	// 2.2.1.13.2.1 TS_CONFIRM_ACTIVE_PDU, after the share control header.
	uint32_t shareId = reader.U32LE();
	reader.U16LE();		// originatorId
	uint16_t sourceLength = reader.U16LE();
	reader.U16LE();		// lengthCombinedCapabilities
	reader.Skip(sourceLength);
	uint16_t count = reader.U16LE();
	reader.U16LE();
	if (!reader.Ok() || shareId != fShareId) {
		LOG_W("bad Confirm Active PDU");
		return false;
	}

	fCapabilities = ClientCapabilities();
	if (!ParseClientCapabilities(reader, count, fCapabilities))
		return false;

	LOG_I("client capabilities: %u bpp, %ux%u, extra flags 0x%04x, "
		"drawing flags 0x%02x, input flags 0x%04x",
		fCapabilities.preferredBitsPerPixel, fCapabilities.desktopWidth,
		fCapabilities.desktopHeight, fCapabilities.generalExtraFlags,
		fCapabilities.drawingFlags, fCapabilities.inputFlags);

	if ((fCapabilities.generalExtraFlags & FASTPATH_OUTPUT_SUPPORTED) == 0) {
		LOG_E("client does not support fast-path output");
		return false;
	}
	if (fCapabilities.preferredBitsPerPixel != 32) {
		LOG_E("client wants %u bpp; only 32 bpp is implemented",
			fCapabilities.preferredBitsPerPixel);
		return false;
	}
	return true;
}


// #pragma mark - main loop


void
Session::_MainLoop()
{
	int64_t nextFrame = NowMs();

	while (true) {
		if (fAborted) {
			LOG_I("ending the session from %s", Peer().c_str());
			return;
		}
		if (fKicked) {
			if (fKickReason == ERRINFO_DISCONNECTED_BY_OTHERCONNECTION) {
				LOG_I("session from %s replaced by a new connection",
					Peer().c_str());
			} else
				LOG_I("session from %s ended on request", Peer().c_str());
			_SendErrorInfo(fKickReason);
			fTransport->WriteAll(
				WrapX224Data(BuildDisconnectProviderUltimatum()));
			return;
		}

		int64_t now = NowMs();
		int timeout = fActive && !fOutputSuppressed
			? (int)(nextFrame > now ? nextFrame - now : 0) : 200;

		int readable = fTransport->WaitReadable(timeout);
		if (readable < 0)
			return;
		if (readable > 0) {
			Pdu pdu;
			if (!_ReadPdu(pdu))
				return;
			if (pdu.fastPath) {
				_HandleFastPathInput(pdu);
				// Input usually changes the screen soon: poll at full rate.
				fLastActivityMs = NowMs();
				if (nextFrame > fLastActivityMs + fConfig.frameIntervalMs)
					nextFrame = fLastActivityMs + fConfig.frameIntervalMs;
			}
			else if (!_HandleSlowPath(pdu))
				return;
			continue;
		}

		if (fActive && !fOutputSuppressed && NowMs() >= nextFrame) {
			if (!_SendFrame())
				return;
			// A source that tracks changes is cheap to ask, so it is
			// asked at the full rate even when the desktop is idle.
			bool idle = !fFrames.TracksChanges()
				&& NowMs() - fLastActivityMs > kIdleAfterMs;
			nextFrame = NowMs() + (idle && kIdleFrameIntervalMs
					> fConfig.frameIntervalMs
				? kIdleFrameIntervalMs : fConfig.frameIntervalMs);

			if (fSizeChanged) {
				// Deactivation-Reactivation Sequence (1.3.1.3) with the new
				// size.
				fSizeChanged = false;
				Writer body;
				body.U32LE(fShareId);
				body.U16LE(1);
				body.U8(0);
				if (!_SendShareControl(PDUTYPE_DEACTIVATEALLPDU, body.Data()))
					return;
				fSize = fFrames.Size();
				if (!_SendDemandActive())
					return;
			}
		}
	}
}


bool
Session::_HandleSlowPath(Pdu& pdu)
{
	Reader reader(NULL, 0);
	if (!_ReadX224Data(pdu, reader))
		return false;

	uint8_t choice = reader.U8() >> 2;
	if (choice == MCS_DISCONNECT_PROVIDER_ULTIMATUM) {
		LOG_I("client disconnected");
		return false;
	}
	if (choice != MCS_SEND_DATA_REQUEST) {
		LOG_D("ignoring MCS PDU %u", choice);
		return true;
	}

	uint16_t channel;
	Reader payload(NULL, 0);
	if (!_ReadMcsSendData(reader, channel, payload))
		return false;
	if (channel != MCS_IO_CHANNEL_ID) {
		LOG_T("ignoring %zu bytes on channel %u", payload.Remaining(),
			channel);
		return true;
	}

	// Share Control Header (2.2.8.1.1.1.1)
	uint16_t totalLength = payload.U16LE();
	uint16_t pduType = payload.U16LE();
	payload.U16LE();	// pduSource
	if (!payload.Ok() || totalLength < 6)
		return false;

	switch (pduType & 0xf) {
		case PDUTYPE_CONFIRMACTIVEPDU:
			if (!_HandleConfirmActive(payload))
				return false;
			return true;
		case PDUTYPE_DATAPDU:
			return _HandleShareData(payload);
		default:
			LOG_D("ignoring share control PDU type %u", pduType & 0xf);
			return true;
	}
}


bool
Session::_HandleShareData(Reader& reader)
{
	// Share Data Header (2.2.8.1.1.1.2), after the control header.
	reader.U32LE();		// shareId
	reader.U8();		// pad1
	reader.U8();		// streamId
	reader.U16LE();		// uncompressedLength
	uint8_t type = reader.U8();
	uint8_t compressedType = reader.U8();
	reader.U16LE();		// compressedLength
	if (!reader.Ok())
		return false;
	if ((compressedType & 0x20) != 0) {
		// PACKET_COMPRESSED: never negotiated, so never expected.
		LOG_W("compressed data PDU from client");
		return false;
	}

	switch (type) {
		case PDUTYPE2_SYNCHRONIZE:
		{
			// 2.2.1.19 Server Synchronize PDU
			Writer body;
			body.U16LE(SYNCMSGTYPE_SYNC);
			body.U16LE(MCS_SERVER_CHANNEL_ID);
			return _SendShareData(PDUTYPE2_SYNCHRONIZE, body.Data());
		}

		case PDUTYPE2_CONTROL:
		{
			uint16_t action = reader.U16LE();
			Writer body;
			if (action == CTRLACTION_COOPERATE) {
				// 2.2.1.20 Server Control PDU - Cooperate
				body.U16LE(CTRLACTION_COOPERATE);
				body.U16LE(0);
				body.U32LE(0);
			} else if (action == CTRLACTION_REQUEST_CONTROL) {
				// 2.2.1.21 Server Control PDU - Granted Control
				body.U16LE(CTRLACTION_GRANTED_CONTROL);
				body.U16LE(fUserChannelId);
				body.U32LE(MCS_SERVER_CHANNEL_ID);
			} else
				return true;
			return _SendShareData(PDUTYPE2_CONTROL, body.Data(), STREAM_MED);
		}

		case PDUTYPE2_FONTLIST:
		{
			// 2.2.1.22 Server Font Map PDU ends the connection sequence.
			Writer body;
			body.U16LE(0);		// numberEntries
			body.U16LE(0);		// totalNumEntries
			body.U16LE(FONTMAP_FIRST | FONTMAP_LAST);
			body.U16LE(4);		// entrySize
			if (!_SendShareData(PDUTYPE2_FONTMAP, body.Data()))
				return false;

			// Show exactly one cursor: the client's default arrow, or none
			// when the captured frames already contain the cursor.
			if (!_SendFastPathUpdate(fFrames.IncludesCursor()
						? FASTPATH_UPDATETYPE_PTR_NULL
						: FASTPATH_UPDATETYPE_PTR_DEFAULT,
					std::vector<uint8_t>())) {
				return false;
			}

			fActive = true;
			fFullRefresh = true;
			fPointerGeneration = kNoPointer;
			LOG_I("session active at %dx%d", fSize.width, fSize.height);
			return true;
		}

		case PDUTYPE2_INPUT:
			_HandleSlowPathInput(reader);
			return true;

		case PDUTYPE2_REFRESH_RECT:
			fFullRefresh = true;
			return true;

		case PDUTYPE2_SUPPRESS_OUTPUT:
		{
			uint8_t allow = reader.U8();
			fOutputSuppressed = allow == 0;
			if (!fOutputSuppressed)
				fFullRefresh = true;
			LOG_D("display updates %s", allow ? "resumed" : "suppressed");
			return true;
		}

		case PDUTYPE2_SHUTDOWN_REQUEST:
			LOG_I("client asked to disconnect");
			return false;

		case PDUTYPE2_BITMAPCACHE_PERSISTENT_LIST:
			return true;

		default:
			LOG_D("ignoring data PDU type 0x%02x", type);
			return true;
	}
}


// #pragma mark - input


void
Session::_PointerEvent(uint16_t flags, uint16_t x, uint16_t y, bool extended)
{
	if (!extended) {
		if ((flags & PTRFLAGS_WHEEL) != 0 || (flags & PTRFLAGS_HWHEEL) != 0) {
			// 9-bit two's complement rotation (2.2.8.1.1.3.1.1.3).
			int32_t delta = flags & WheelRotationMask;
			if ((flags & PTRFLAGS_WHEEL_NEGATIVE) != 0)
				delta -= 0x200;
			fInput.Wheel(delta, (flags & PTRFLAGS_HWHEEL) != 0);
			return;
		}

		uint32_t button = 0;
		if ((flags & PTRFLAGS_BUTTON1) != 0)
			button = 1;
		else if ((flags & PTRFLAGS_BUTTON2) != 0)
			button = 2;
		else if ((flags & PTRFLAGS_BUTTON3) != 0)
			button = 4;
		if (button != 0) {
			if ((flags & PTRFLAGS_DOWN) != 0)
				fButtons |= button;
			else
				fButtons &= ~button;
		}
	} else {
		uint32_t button = 0;
		if ((flags & PTRXFLAGS_BUTTON1) != 0)
			button = 8;
		else if ((flags & PTRXFLAGS_BUTTON2) != 0)
			button = 16;
		if (button != 0) {
			if ((flags & PTRXFLAGS_DOWN) != 0)
				fButtons |= button;
			else
				fButtons &= ~button;
		}
	}

	int32_t clampedX = x < fSize.width ? x : fSize.width - 1;
	int32_t clampedY = y < fSize.height ? y : fSize.height - 1;
	fInput.Pointer(clampedX, clampedY, fButtons);
}


void
Session::_HandleFastPathInput(Pdu& pdu)
{
	if (!fActive)
		return;

	// 2.2.8.1.2: numEvents is in bits 2-5 of the header, or in a byte of
	// its own when those bits are zero.
	Reader reader(pdu.data);
	unsigned count = (pdu.header >> 2) & 0xf;
	if (count == 0)
		count = reader.U8();

	for (unsigned i = 0; i < count && reader.Ok(); i++) {
		uint8_t eventHeader = reader.U8();
		uint8_t flags = eventHeader & 0x1f;
		uint8_t code = eventHeader >> 5;

		switch (code) {
			case FASTPATH_INPUT_EVENT_SCANCODE:
			{
				uint8_t scancode = reader.U8();
				if (reader.Ok()) {
					fInput.Key(scancode,
						(flags & FASTPATH_INPUT_KBDFLAGS_EXTENDED) != 0,
						(flags & FASTPATH_INPUT_KBDFLAGS_EXTENDED1) != 0,
						(flags & FASTPATH_INPUT_KBDFLAGS_RELEASE) == 0);
				}
				break;
			}
			case FASTPATH_INPUT_EVENT_MOUSE:
			case FASTPATH_INPUT_EVENT_MOUSEX:
			{
				uint16_t pointerFlags = reader.U16LE();
				uint16_t x = reader.U16LE();
				uint16_t y = reader.U16LE();
				if (reader.Ok()) {
					_PointerEvent(pointerFlags, x, y,
						code == FASTPATH_INPUT_EVENT_MOUSEX);
				}
				break;
			}
			case FASTPATH_INPUT_EVENT_SYNC:
				fInput.SyncLocks(flags);
				break;
			case FASTPATH_INPUT_EVENT_UNICODE:
			{
				uint16_t unicode = reader.U16LE();
				if (reader.Ok()) {
					fInput.UnicodeKey(unicode,
						(flags & FASTPATH_INPUT_KBDFLAGS_RELEASE) == 0);
				}
				break;
			}
			case FASTPATH_INPUT_EVENT_RELMOUSE:
				reader.Skip(6);
				break;
			case FASTPATH_INPUT_EVENT_QOE_TIMESTAMP:
				reader.Skip(4);
				break;
			default:
				LOG_W("unknown fast-path input event %u", code);
				return;
		}
	}
}


void
Session::_HandleSlowPathInput(Reader& reader)
{
	if (!fActive)
		return;

	// 2.2.8.1.1.3.1 TS_INPUT_PDU_DATA
	uint16_t count = reader.U16LE();
	reader.U16LE();
	for (uint16_t i = 0; i < count && reader.Ok(); i++) {
		reader.U32LE();		// eventTime
		uint16_t type = reader.U16LE();
		switch (type) {
			case INPUT_EVENT_SCANCODE:
			{
				uint16_t flags = reader.U16LE();
				uint16_t key = reader.U16LE();
				reader.U16LE();
				if (reader.Ok()) {
					fInput.Key(key & 0xff, (flags & KBDFLAGS_EXTENDED) != 0,
						(flags & KBDFLAGS_EXTENDED1) != 0,
						(flags & KBDFLAGS_RELEASE) == 0);
				}
				break;
			}
			case INPUT_EVENT_UNICODE:
			{
				uint16_t flags = reader.U16LE();
				uint16_t unicode = reader.U16LE();
				reader.U16LE();
				if (reader.Ok())
					fInput.UnicodeKey(unicode, (flags & KBDFLAGS_RELEASE) == 0);
				break;
			}
			case INPUT_EVENT_MOUSE:
			case INPUT_EVENT_MOUSEX:
			{
				uint16_t flags = reader.U16LE();
				uint16_t x = reader.U16LE();
				uint16_t y = reader.U16LE();
				if (reader.Ok())
					_PointerEvent(flags, x, y, type == INPUT_EVENT_MOUSEX);
				break;
			}
			case INPUT_EVENT_SYNC:
			{
				reader.U16LE();
				uint32_t toggles = reader.U32LE();
				if (reader.Ok())
					fInput.SyncLocks(toggles);
				break;
			}
			default:
				LOG_W("unknown slow-path input event 0x%04x", type);
				return;
		}
	}
}


// #pragma mark - sending


bool
Session::_SendIo(const std::vector<uint8_t>& payload)
{
	Writer mcs;
	WriteSendDataIndication(mcs, MCS_IO_CHANNEL_ID, payload.data(),
		payload.size());
	return fTransport->WriteAll(WrapX224Data(mcs.Data()));
}


bool
Session::_SendShareControl(uint16_t type, const std::vector<uint8_t>& body)
{
	Writer writer;
	writer.U16LE(6 + body.size());
	writer.U16LE(type | TS_PROTOCOL_VERSION);
	writer.U16LE(MCS_SERVER_CHANNEL_ID);
	writer.Bytes(body);
	return _SendIo(writer.Data());
}


bool
Session::_SendShareData(uint8_t type, const std::vector<uint8_t>& body,
	uint8_t stream)
{
	// Share Data Header; uncompressedLength matches totalLength as in the
	// examples of 4.1.19 to 4.1.22.
	size_t total = 6 + 12 + body.size();
	Writer writer;
	writer.U32LE(fShareId);
	writer.U8(0);
	writer.U8(stream);
	writer.U16LE(total);
	writer.U8(type);
	writer.U8(0);		// compressedType
	writer.U16LE(0);	// compressedLength
	writer.Bytes(body);
	return _SendShareControl(PDUTYPE_DATAPDU, writer.Data());
}


bool
Session::_SendErrorInfo(uint32_t errorInfo)
{
	if ((fClient.earlyCapabilityFlags & RNS_UD_CS_SUPPORT_ERRINFO_PDU) == 0)
		return true;
	Writer body;
	body.U32LE(errorInfo);
	return _SendShareData(PDUTYPE2_SET_ERROR_INFO_PDU, body.Data());
}


bool
Session::_SendFastPathUpdate(uint8_t code, const std::vector<uint8_t>& data)
{
	// 2.2.9.1.2: fpOutputHeader (action fast-path, no encryption), a
	// two-byte length, then one TS_FP_UPDATE.
	size_t total = 3 + 3 + data.size();
	if (total > FASTPATH_MAX_PDU_SIZE) {
		LOG_E("fast-path update too large (%zu bytes)", total);
		return false;
	}
	Writer writer;
	writer.U8(0x00);
	writer.U16BE(0x8000 | total);
	writer.U8(code | (FASTPATH_FRAGMENT_SINGLE << 4));
	writer.U16LE(data.size());
	writer.Bytes(data);
	fBytesSent += writer.Size();
	return fTransport->WriteAll(writer.Data());
}


// #pragma mark - graphics


bool
Session::_EncodeRect(int x, int y, int width, int height,
	std::vector<uint8_t>& out)
{
	// TS_BITMAP_DATA (2.2.9.1.1.3.1.2.2). The bitmap width is padded to a
	// multiple of four; the destination rectangle clips the padding.
	int paddedWidth = (width + 3) & ~3;
	size_t stride = (size_t)fSize.width * 4;
	fScratch.resize((size_t)paddedWidth * height * 4);
	for (int row = 0; row < height; row++) {
		const uint8_t* source = fFrame.data() + (size_t)(y + row) * stride
			+ (size_t)x * 4;
		uint8_t* target = fScratch.data() + (size_t)row * paddedWidth * 4;
		memcpy(target, source, (size_t)width * 4);
		for (int column = width; column < paddedWidth; column++)
			memcpy(target + column * 4, source + (width - 1) * 4, 4);
	}

	std::vector<uint8_t> stream;
	bool skipAlpha = (fCapabilities.drawingFlags & DRAW_ALLOW_SKIP_ALPHA) != 0;
	// Bitmap data in bitmap updates is stored bottom-up (2.2.9.1.1.3.1.2.2).
	EncodePlanar(fScratch.data(), (size_t)paddedWidth * 4, paddedWidth, height,
		skipAlpha, true, stream);

	bool header = (fCapabilities.generalExtraFlags
		& NO_BITMAP_COMPRESSION_HDR_FLAG) == 0;
	size_t length = stream.size() + (header ? 8 : 0);
	if (length > 0xffff)
		return false;

	Writer writer;
	writer.U16LE(x);
	writer.U16LE(y);
	writer.U16LE(x + width - 1);
	writer.U16LE(y + height - 1);
	writer.U16LE(paddedWidth);
	writer.U16LE(height);
	writer.U16LE(32);
	writer.U16LE(BITMAP_COMPRESSION
		| (header ? 0 : NO_BITMAP_COMPRESSION_HDR));
	writer.U16LE(length);
	if (header) {
		// TS_CD_HEADER (2.2.9.1.1.3.1.2.3)
		writer.U16LE(0);
		writer.U16LE(stream.size());
		writer.U16LE(paddedWidth);
		writer.U16LE((paddedWidth * height * 4) & 0xffff);
	}
	writer.Bytes(stream);
	out.insert(out.end(), writer.Data().begin(), writer.Data().end());
	return true;
}


bool
Session::_FlushBitmaps(Writer& rects, uint16_t& count)
{
	if (count == 0)
		return true;

	// TS_UPDATE_BITMAP_DATA (2.2.9.1.1.3.1.2.1)
	std::vector<uint8_t> data;
	data.reserve(4 + rects.Size());
	data.push_back(UPDATETYPE_BITMAP & 0xff);
	data.push_back(UPDATETYPE_BITMAP >> 8);
	data.push_back(count & 0xff);
	data.push_back(count >> 8);
	data.insert(data.end(), rects.Data().begin(), rects.Data().end());

	rects.Data().clear();
	count = 0;
	return _SendFastPathUpdate(FASTPATH_UPDATETYPE_BITMAP, data);
}


bool
Session::_SendPointerShape()
{
	PointerImage image;
	if (!fFrames.PointerShape(fPointerGeneration, image))
		return true;

	if (image.width <= 0 || image.height <= 0)
		return _SendFastPathUpdate(FASTPATH_UPDATETYPE_PTR_NULL,
			std::vector<uint8_t>());

	// The New Pointer Update carries alpha, but only when the client has a
	// cache for it (2.2.7.1.5). Otherwise the 24 bpp Color Pointer Update,
	// which every client has to support.
	bool alpha = fCapabilities.havePointerCacheSize
		&& fCapabilities.pointerCacheSize > 0;
	if (!alpha && fCapabilities.colorPointerCacheSize == 0) {
		LOG_D("the client has no pointer cache; keeping its own pointer");
		return true;
	}
	LOG_T("pointer shape %dx%d, hot spot %d,%d", image.width, image.height,
		image.hotX, image.hotY);
	return _SendFastPathUpdate(alpha ? FASTPATH_UPDATETYPE_POINTER
			: FASTPATH_UPDATETYPE_COLOR,
		EncodePointer(image, kMaxPointerSize, alpha));
}


bool
Session::_SendFrame()
{
	DisplaySize size = fFrames.Size();
	if (size.width != fSize.width || size.height != fSize.height) {
		LOG_I("display size changed to %dx%d", size.width, size.height);
		fSizeChanged = true;
		fFullRefresh = true;
		return true;
	}

	size_t stride = (size_t)fSize.width * 4;
	size_t frameSize = stride * fSize.height;
	if (fFrame.size() != frameSize || fPrevious.size() != frameSize) {
		fFrame.assign(frameSize, 0);
		fPrevious.assign(frameSize, 0);
		fFrameStale = true;
		fFullRefresh = true;
	}

	if (!_SendPointerShape())
		return false;

	int64_t captureStart = NowMs();
	fChanged.clear();
	if (!fFrames.Capture(fFrame.data(), stride, fSize, fFrameStale,
			fChanged)) {
		return true;	// try again next frame
	}
	fFrameStale = false;
	int64_t encodeStart = NowMs();
	fCaptureMs += encodeStart - captureStart;
	fFramesPolled++;

	bool full = fFullRefresh;
	fFullRefresh = false;

	// Mark the tiles that the changed areas touch.
	int tilesX = (fSize.width + kTileSize - 1) / kTileSize;
	int tilesY = (fSize.height + kTileSize - 1) / kTileSize;
	fTileMask.assign((size_t)tilesX * tilesY, full ? 1 : 0);
	if (!full) {
		for (size_t i = 0; i < fChanged.size(); i++) {
			const Rect& rect = fChanged[i];
			int left = rect.x < 0 ? 0 : rect.x;
			int top = rect.y < 0 ? 0 : rect.y;
			int right = rect.x + rect.width;
			int bottom = rect.y + rect.height;
			if (right > fSize.width)
				right = fSize.width;
			if (bottom > fSize.height)
				bottom = fSize.height;
			if (left >= right || top >= bottom)
				continue;
			for (int ty = top / kTileSize; ty <= (bottom - 1) / kTileSize;
					ty++) {
				for (int tx = left / kTileSize;
						tx <= (right - 1) / kTileSize; tx++) {
					fTileMask[(size_t)ty * tilesX + tx] = 1;
				}
			}
		}
	}

	// The largest TS_BITMAP_DATA payload that still fits a fast-path PDU
	// with its headers (3 + 3 + 4 bytes).
	const size_t kMaxRects = FASTPATH_MAX_PDU_SIZE - 10;

	Writer rects;
	uint16_t rectCount = 0;
	int tiles = 0;

	for (int y = 0; y < fSize.height; y += kTileSize) {
		int height = fSize.height - y < kTileSize ? fSize.height - y
			: kTileSize;
		for (int x = 0; x < fSize.width; x += kTileSize) {
			int width = fSize.width - x < kTileSize ? fSize.width - x
				: kTileSize;

			if (!fTileMask[(size_t)(y / kTileSize) * tilesX + x / kTileSize])
				continue;
			if (!full) {
				bool changed = false;
				for (int row = 0; row < height && !changed; row++) {
					size_t offset = (size_t)(y + row) * stride
						+ (size_t)x * 4;
					changed = memcmp(fFrame.data() + offset,
						fPrevious.data() + offset, (size_t)width * 4) != 0;
				}
				if (!changed)
					continue;
			}

			// Encode in horizontal bands so one rectangle always fits a
			// fast-path PDU, even with an alpha plane and no compression.
			int bandHeight = height;
			std::vector<std::vector<uint8_t> > pieces;
			while (true) {
				pieces.clear();
				bool fits = true;
				for (int band = 0; band < height; band += bandHeight) {
					int rows = height - band < bandHeight ? height - band
						: bandHeight;
					pieces.push_back(std::vector<uint8_t>());
					if (!_EncodeRect(x, y + band, width, rows, pieces.back()))
						return false;
					if (pieces.back().size() > kMaxRects) {
						fits = false;
						break;
					}
				}
				if (fits)
					break;
				if (bandHeight == 1) {
					LOG_E("cannot fit a %d pixel row into a fast-path PDU",
						width);
					return false;
				}
				bandHeight = (bandHeight + 1) / 2;
			}

			for (size_t i = 0; i < pieces.size(); i++) {
				if (rects.Size() + pieces[i].size() > kMaxRects
					&& !_FlushBitmaps(rects, rectCount)) {
					return false;
				}
				rects.Bytes(pieces[i]);
				rectCount++;
			}
			tiles++;

			// The client now has this tile.
			for (int row = 0; row < height; row++) {
				size_t offset = (size_t)(y + row) * stride + (size_t)x * 4;
				memcpy(fPrevious.data() + offset, fFrame.data() + offset,
					(size_t)width * 4);
			}
		}
	}

	if (!_FlushBitmaps(rects, rectCount))
		return false;

	int64_t now = NowMs();
	fEncodeMs += now - encodeStart;
	fTilesSent += tiles;
	if (fStatsStartMs == 0)
		fStatsStartMs = now;
	if (now - fStatsStartMs >= 10000 && fFramesPolled > 0) {
		LOG_D("last %.1f s: %d polls, capture %.1f ms and encode %.1f ms per "
			"poll, %d tiles, %.1f KB/s", (now - fStatsStartMs) / 1000.0,
			fFramesPolled, (double)fCaptureMs / fFramesPolled,
			(double)fEncodeMs / fFramesPolled, fTilesSent,
			fBytesSent / 1024.0 / ((now - fStatsStartMs) / 1000.0));
		fStatsStartMs = now;
		fCaptureMs = fEncodeMs = 0;
		fFramesPolled = fTilesSent = 0;
		fBytesSent = 0;
	}

	if (tiles > 0) {
		fLastActivityMs = now;
		LOG_T("sent %d tiles%s", tiles, full ? " (full)" : "");
	}

	return true;
}


}	// namespace rrd
