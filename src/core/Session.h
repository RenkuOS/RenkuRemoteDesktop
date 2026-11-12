/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */
#ifndef RRD_SESSION_H
#define RRD_SESSION_H


#include <atomic>
#include <string>
#include <vector>

#include "ByteStream.h"
#include "Capabilities.h"
#include "Mcs.h"
#include "Platform.h"
#include "Protocol.h"
#include "Resize.h"


namespace rrd {


class Session;
class TlsContext;
class Transport;


struct ServerConfig {
				ServerConfig();

	// PBKDF2 hash from HashPassword(). An empty hash refuses every
	// connection unless allowWithoutPassword is set (test builds only).
	std::string	passwordHash;
	// The password's NT hash as hex, for NLA (CredSSP with NTLM). Without
	// it the server offers TLS only, and Windows clients cannot log in.
	std::string	ntHash;
	bool		allowWithoutPassword;

	ResizePolicy resize;
	int			frameIntervalMs;
	uint16_t	port;
	std::string	bindAddress;
};


// Implemented by the server: decides which session owns the desktop.
class SessionHost {
public:
	virtual					~SessionHost() {}

	// Called once a session has authenticated, before it touches the
	// FrameSource or InputSink. Ends any other active session (takeover)
	// and returns when the desktop is free.
	virtual	void			SessionActivating(Session* session) = 0;
	virtual	void			SessionEnded(Session* session) = 0;

	// Failed-login tracking per client address.
	virtual	bool			AllowConnection(const std::string& peer) = 0;
	virtual	void			LoginFailed(const std::string& peer) = 0;
};


class Session {
public:
							Session(int fd, const ServerConfig& config,
								TlsContext& tls, FrameSource& frames,
								InputSink& input, SessionHost& host);
							~Session();

			// Runs the connection to its end, on the calling thread.
			void			Run();

			// Asks the session to end with the given Set Error Info code.
			// Safe to call from another thread.
			void			Kick(uint32_t errorInfo);
			// Unblocks the session's socket. Safe from another thread.
			void			Abort();

			const std::string& Peer() const;
			// Set once the login succeeded, and not changed afterwards.
			const std::string& UserName() const { return fUserName; }
			bool			UsedNla() const { return fNlaAuthenticated; }
			// Wall-clock time of the login, in seconds since the epoch.
			int64_t			LoginTime() const { return fLoginTime; }

private:
			struct Pdu {
				bool					fastPath;
				uint8_t					header;
				std::vector<uint8_t>	data;
			};

			bool			_ReadPdu(Pdu& pdu);
			bool			_ReadX224Data(Pdu& pdu, Reader& reader);
			bool			_ReadMcsSendData(Reader& reader, uint16_t& channel,
								Reader& payload);

			bool			_Negotiate();
			bool			_BasicSettings();
			bool			_ChannelsAndClientInfo();
			bool			_HandleClientInfo(Reader& reader);
			bool			_SendLicense();
			void			_ChooseSize();
			bool			_SendDemandActive();
			bool			_HandleConfirmActive(Reader& reader);
			void			_MainLoop();

			bool			_HandleSlowPath(Pdu& pdu);
			bool			_HandleShareData(Reader& reader);
			void			_HandleSlowPathInput(Reader& reader);
			void			_HandleFastPathInput(Pdu& pdu);
			void			_PointerEvent(uint16_t flags, uint16_t x,
								uint16_t y, bool extended);

			bool			_SendIo(const std::vector<uint8_t>& payload);
			bool			_SendShareControl(uint16_t type,
								const std::vector<uint8_t>& body);
			bool			_SendShareData(uint8_t type,
								const std::vector<uint8_t>& body,
								uint8_t stream = STREAM_LOW);
			bool			_SendErrorInfo(uint32_t errorInfo);
			bool			_SendFastPathUpdate(uint8_t code,
								const std::vector<uint8_t>& data);

			bool			_SendFrame();
			bool			_SendPointerShape();
			bool			_EncodeRect(int x, int y, int width, int height,
								std::vector<uint8_t>& out);
			bool			_FlushBitmaps(Writer& rects, uint16_t& count);

			int				fFd;
			// A copy: the server can change its settings while this session
			// runs.
			const ServerConfig fConfig;
			TlsContext&		fTls;
			FrameSource&	fFrames;
			InputSink&		fInput;
			SessionHost&	fHost;
			Transport*		fTransport;

			uint32_t		fRequestedProtocols;
			uint32_t		fSelectedProtocol;
			ClientSettings	fClient;
			ClientCapabilities fCapabilities;
			uint32_t		fShareId;
			uint16_t		fUserChannelId;
			bool			fNlaAuthenticated;
			std::string		fNlaUser;
			std::string		fUserName;
			int64_t			fLoginTime;
			bool			fOwnsDesktop;
			bool			fActive;
			bool			fOutputSuppressed;
			bool			fFullRefresh;
			bool			fSizeChanged;
			uint32_t		fButtons;
			int64_t			fLastActivityMs;

			// Statistics, logged every ten seconds at debug level.
			int64_t			fStatsStartMs;
			int64_t			fCaptureMs;
			int64_t			fEncodeMs;
			int				fFramesPolled;
			int				fTilesSent;
			uint64_t		fBytesSent;

			DisplaySize		fSize;
			// The desktop as last captured, and as the client has it.
			std::vector<uint8_t> fFrame;
			std::vector<uint8_t> fPrevious;
			bool			fFrameStale;
			std::vector<Rect> fChanged;
			std::vector<uint8_t> fTileMask;
			uint32_t		fPointerGeneration;
			std::vector<uint8_t> fScratch;

			std::atomic<bool> fKicked;
			std::atomic<bool> fAborted;
			std::atomic<uint32_t> fKickReason;
};


}	// namespace rrd


#endif	// RRD_SESSION_H
