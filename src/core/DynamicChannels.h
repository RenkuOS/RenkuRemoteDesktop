/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */
#ifndef RRD_DYNAMIC_CHANNELS_H
#define RRD_DYNAMIC_CHANNELS_H


// Dynamic virtual channels ([MS-RDPEDYC]), version 1, over the static
// channel "drdynvc", and the display control channel ([MS-RDPEDISP]) that
// runs on one.


#include <stdint.h>

#include <map>
#include <string>
#include <vector>

#include "ClipboardChannel.h"


namespace rrd {


enum {
	// DVC header Cmd values (2.2)
	DYNVC_CREATE = 0x01,
	DYNVC_DATA_FIRST = 0x02,
	DYNVC_DATA = 0x03,
	DYNVC_CLOSE = 0x04,
	DYNVC_CAPABILITIES = 0x05,

	// DISPLAYCONTROL_HEADER Type ([MS-RDPEDISP] 2.2.1.1)
	DISPLAYCONTROL_PDU_TYPE_MONITOR_LAYOUT = 0x00000002,
	DISPLAYCONTROL_PDU_TYPE_CAPS = 0x00000005,
	DISPLAYCONTROL_MONITOR_PRIMARY = 0x00000001
};


class DynamicChannels;


// One kind of dynamic channel on the server side.
class DynamicChannelHandler {
public:
	virtual					~DynamicChannelHandler() {}

	// The client opened the channel; it can be used now.
	virtual	bool			Opened(DynamicChannels& channels,
								uint32_t id) = 0;
	// One complete message from the client.
	virtual	bool			Receive(DynamicChannels& channels, uint32_t id,
								const Bytes& message) = 0;
};


class DynamicChannels {
public:
							// sender delivers on the "drdynvc" static
							// channel.
							DynamicChannels(ChannelSender& sender);

			// A channel to open once the client is ready. Call before
			// Start().
			void			Add(const char* name,
								DynamicChannelHandler* handler);

			// Sends the Capabilities Request (2.2.1.1.1).
			bool			Start();
			// One reassembled "drdynvc" message from the client.
			bool			Receive(const Bytes& pdu);
			// Sends a message on an open channel, fragmenting it.
			bool			Send(uint32_t id, const Bytes& message);

private:
			struct Channel {
				std::string	name;
				DynamicChannelHandler* handler;
				bool		open;
				Bytes		pending;
				uint32_t	pendingTotal;
			};

			bool			_SendPdu(const Bytes& pdu);
			bool			_OpenChannels();

			ChannelSender&	fSender;
			bool			fReady;
			std::vector<std::pair<std::string, DynamicChannelHandler*> >
							fWanted;
			std::map<uint32_t, Channel> fChannels;
			uint32_t		fNextId;
};


// Receives the client's monitor layout and asks for a new display size.
class DisplaySizeRequester {
public:
	virtual					~DisplaySizeRequester() {}
	virtual	void			ClientSizeChanged(int32_t width,
								int32_t height) = 0;
};


// "Microsoft::Windows::RDS::DisplayControl" ([MS-RDPEDISP]): one monitor.
class DisplayControl : public DynamicChannelHandler {
public:
							DisplayControl(DisplaySizeRequester& requester);

	static	const char*		Name();

	virtual	bool			Opened(DynamicChannels& channels, uint32_t id);
	virtual	bool			Receive(DynamicChannels& channels, uint32_t id,
								const Bytes& message);

private:
			DisplaySizeRequester& fRequester;
};


}	// namespace rrd


#endif	// RRD_DYNAMIC_CHANNELS_H
