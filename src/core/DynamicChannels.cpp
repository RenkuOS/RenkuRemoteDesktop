/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */


#include "DynamicChannels.h"

#include <string.h>

#include "ByteStream.h"
#include "Log.h"


namespace rrd {


// A DVC PDU travels in one static channel chunk (2.2.3).
static const size_t kMaxPdu = 1600;
// A message of up to this many bytes fits in a single DYNVC_DATA PDU.
static const size_t kMaxSingleData = 1590;
// Reassembled messages from the client larger than this are dropped.
static const uint32_t kMaxMessage = 1024 * 1024;


static uint8_t
Header(uint8_t cmd, uint8_t sp, uint8_t cbId)
{
	return (uint8_t)((cmd << 4) | (sp << 2) | cbId);
}


static bool
ReadVariable(Reader& reader, uint8_t sizeCode, uint32_t& value)
{
	switch (sizeCode) {
		case 0:
			value = reader.U8();
			break;
		case 1:
			value = reader.U16LE();
			break;
		case 2:
			value = reader.U32LE();
			break;
		default:
			return false;
	}
	return reader.Ok();
}


// Our channel IDs stay below 256, so they take one byte (cbId 0).
static void
WriteChannelId(Writer& writer, uint32_t id)
{
	writer.U8((uint8_t)id);
}


DynamicChannels::DynamicChannels(ChannelSender& sender)
	:
	fSender(sender),
	fReady(false),
	fNextId(1)
{
}


void
DynamicChannels::Add(const char* name, DynamicChannelHandler* handler)
{
	fWanted.push_back(std::make_pair(std::string(name), handler));
}


bool
DynamicChannels::Start()
{
	// DYNVC_CAPS_VERSION1: no priorities and no compression.
	Writer caps;
	caps.U8(Header(DYNVC_CAPABILITIES, 0, 0));
	caps.U8(0);			// Pad
	caps.U16LE(1);		// Version
	return _SendPdu(caps.Data());
}


bool
DynamicChannels::_SendPdu(const Bytes& pdu)
{
	return fSender.SendChannelData(pdu);
}


bool
DynamicChannels::_OpenChannels()
{
	// DYNVC_CREATE_REQ (2.2.2.1) for each wanted channel.
	for (size_t i = 0; i < fWanted.size(); i++) {
		uint32_t id = fNextId++;
		Channel& channel = fChannels[id];
		channel.name = fWanted[i].first;
		channel.handler = fWanted[i].second;
		channel.open = false;
		channel.pendingTotal = 0;

		Writer create;
		create.U8(Header(DYNVC_CREATE, 0, 0));
		WriteChannelId(create, id);
		create.Bytes((const uint8_t*)channel.name.c_str(),
			channel.name.size() + 1);
		if (!_SendPdu(create.Data()))
			return false;
	}
	return true;
}


bool
DynamicChannels::Receive(const Bytes& pdu)
{
	Reader reader(pdu);
	uint8_t header = reader.U8();
	if (!reader.Ok())
		return true;
	uint8_t cmd = header >> 4;
	uint8_t sp = (header >> 2) & 0x3;
	uint8_t cbId = header & 0x3;

	if (cmd == DYNVC_CAPABILITIES) {
		// DYNVC_CAPS_RSP (2.2.1.2)
		reader.U8();
		uint16_t version = reader.U16LE();
		if (!reader.Ok() || fReady)
			return true;
		LOG_D("dynamic channels: client version %u", version);
		fReady = true;
		return _OpenChannels();
	}

	uint32_t id;
	if (!ReadVariable(reader, cbId, id))
		return true;
	std::map<uint32_t, Channel>::iterator found = fChannels.find(id);
	if (found == fChannels.end()) {
		LOG_D("dynamic channels: PDU %u for unknown channel %u", cmd, id);
		return true;
	}
	Channel& channel = found->second;

	switch (cmd) {
		case DYNVC_CREATE:
		{
			// DYNVC_CREATE_RSP (2.2.2.2)
			int32_t status = (int32_t)reader.U32LE();
			if (!reader.Ok())
				return true;
			if (status < 0) {
				LOG_D("dynamic channels: the client did not open \"%s\" "
					"(0x%08x)", channel.name.c_str(), (uint32_t)status);
				return true;
			}
			LOG_D("dynamic channels: \"%s\" open as %u", channel.name.c_str(),
				id);
			channel.open = true;
			return channel.handler->Opened(*this, id);
		}

		case DYNVC_DATA_FIRST:
		{
			// DYNVC_DATA_FIRST (2.2.3.1); sp is the Len field size.
			uint32_t total;
			if (!ReadVariable(reader, sp, total) || total > kMaxMessage)
				return true;
			channel.pending.assign(reader.Current(),
				reader.Current() + reader.Remaining());
			channel.pendingTotal = total;
			if (channel.pending.size() < total)
				return true;
			channel.pending.resize(total);
			Bytes message;
			message.swap(channel.pending);
			channel.pendingTotal = 0;
			return channel.handler->Receive(*this, id, message);
		}

		case DYNVC_DATA:
		{
			Bytes data(reader.Current(), reader.Current() + reader.Remaining());
			if (channel.pendingTotal == 0)
				return channel.handler->Receive(*this, id, data);
			if (channel.pending.size() + data.size() > channel.pendingTotal) {
				LOG_W("dynamic channels: more data than announced on %u", id);
				channel.pending.clear();
				channel.pendingTotal = 0;
				return true;
			}
			channel.pending.insert(channel.pending.end(), data.begin(),
				data.end());
			if (channel.pending.size() < channel.pendingTotal)
				return true;
			Bytes message;
			message.swap(channel.pending);
			channel.pendingTotal = 0;
			return channel.handler->Receive(*this, id, message);
		}

		case DYNVC_CLOSE:
			LOG_D("dynamic channels: the client closed \"%s\"",
				channel.name.c_str());
			channel.open = false;
			return true;

		default:
			LOG_D("dynamic channels: ignoring command %u", cmd);
			return true;
	}
}


bool
DynamicChannels::Send(uint32_t id, const Bytes& message)
{
	std::map<uint32_t, Channel>::iterator found = fChannels.find(id);
	if (found == fChannels.end() || !found->second.open)
		return true;

	if (message.size() <= kMaxSingleData) {
		Writer data;
		data.U8(Header(DYNVC_DATA, 0, 0));
		WriteChannelId(data, id);
		data.Bytes(message);
		return _SendPdu(data.Data());
	}

	// DYNVC_DATA_FIRST with a 4-byte Length (Len 2), then DYNVC_DATA.
	size_t offset = 0;
	Writer first;
	first.U8(Header(DYNVC_DATA_FIRST, 2, 0));
	WriteChannelId(first, id);
	first.U32LE((uint32_t)message.size());
	size_t chunk = kMaxPdu - first.Size();
	if (chunk > message.size())
		chunk = message.size();
	first.Bytes(message.data(), chunk);
	offset += chunk;
	if (!_SendPdu(first.Data()))
		return false;
	while (offset < message.size()) {
		Writer data;
		data.U8(Header(DYNVC_DATA, 0, 0));
		WriteChannelId(data, id);
		chunk = kMaxPdu - data.Size();
		if (chunk > message.size() - offset)
			chunk = message.size() - offset;
		data.Bytes(message.data() + offset, chunk);
		offset += chunk;
		if (!_SendPdu(data.Data()))
			return false;
	}
	return true;
}


// #pragma mark - DisplayControl


DisplayControl::DisplayControl(DisplaySizeRequester& requester)
	:
	fRequester(requester)
{
}


const char*
DisplayControl::Name()
{
	return "Microsoft::Windows::RDS::DisplayControl";
}


bool
DisplayControl::Opened(DynamicChannels& channels, uint32_t id)
{
	// DISPLAYCONTROL_CAPS_PDU (2.2.2.1): one monitor, up to 8192 by 8192.
	Writer caps;
	caps.U32LE(DISPLAYCONTROL_PDU_TYPE_CAPS);
	caps.U32LE(20);
	caps.U32LE(1);		// MaxNumMonitors
	caps.U32LE(8192);	// MaxMonitorAreaFactorA
	caps.U32LE(8192);	// MaxMonitorAreaFactorB
	return channels.Send(id, caps.Data());
}


bool
DisplayControl::Receive(DynamicChannels& channels, uint32_t id,
	const Bytes& message)
{
	(void)channels;
	(void)id;
	Reader reader(message);
	uint32_t type = reader.U32LE();
	uint32_t length = reader.U32LE();
	if (!reader.Ok() || type != DISPLAYCONTROL_PDU_TYPE_MONITOR_LAYOUT
		|| length > message.size()) {
		return true;
	}

	// DISPLAYCONTROL_MONITOR_LAYOUT_PDU (2.2.2.2)
	uint32_t layoutSize = reader.U32LE();
	uint32_t count = reader.U32LE();
	if (!reader.Ok() || layoutSize != 40 || count == 0 || count > 16)
		return true;

	int32_t width = 0;
	int32_t height = 0;
	for (uint32_t i = 0; i < count; i++) {
		Reader monitor = reader.Sub(40);
		uint32_t flags = monitor.U32LE();
		monitor.U32LE();	// Left
		monitor.U32LE();	// Top
		uint32_t w = monitor.U32LE();
		uint32_t h = monitor.U32LE();
		if (!monitor.Ok())
			return true;
		// The primary monitor, or else the first.
		if ((flags & DISPLAYCONTROL_MONITOR_PRIMARY) != 0 || i == 0) {
			width = (int32_t)w;
			height = (int32_t)h;
		}
	}
	if (width < 200 || width > 8192 || height < 200 || height > 8192) {
		LOG_D("display control: ignoring a %dx%d layout", width, height);
		return true;
	}
	LOG_I("display control: the client's window is now %dx%d", width,
		height);
	fRequester.ClientSizeChanged(width, height);
	return true;
}


}	// namespace rrd
