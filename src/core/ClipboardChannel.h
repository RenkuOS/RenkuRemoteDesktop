/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */
#ifndef RRD_CLIPBOARD_CHANNEL_H
#define RRD_CLIPBOARD_CHANNEL_H


// The server side of the clipboard virtual channel "cliprdr"
// ([MS-RDPECLIP]): Unicode text and files, in both directions.
//
// The local clipboard has no delayed rendering. So text the client copies
// is fetched as soon as the client announces it, and files the client
// copies are downloaded into a staging folder and then put on the
// clipboard (the scope document, section 9.2). Text and files copied
// locally are announced to the client and sent when it asks.


#include <stdint.h>

#include <string>
#include <vector>

#include "Platform.h"


namespace rrd {


typedef std::vector<uint8_t> Bytes;


// Sends one complete channel message; the session splits it into chunks.
class ChannelSender {
public:
	virtual					~ChannelSender() {}
	virtual	bool			SendChannelData(const Bytes& data) = 0;
};


enum {
	// CLIPRDR_HEADER msgType (2.2.1)
	CB_MONITOR_READY = 0x0001,
	CB_FORMAT_LIST = 0x0002,
	CB_FORMAT_LIST_RESPONSE = 0x0003,
	CB_FORMAT_DATA_REQUEST = 0x0004,
	CB_FORMAT_DATA_RESPONSE = 0x0005,
	CB_TEMP_DIRECTORY = 0x0006,
	CB_CLIP_CAPS = 0x0007,
	CB_FILECONTENTS_REQUEST = 0x0008,
	CB_FILECONTENTS_RESPONSE = 0x0009,
	CB_LOCK_CLIPDATA = 0x000a,
	CB_UNLOCK_CLIPDATA = 0x000b,

	// msgFlags
	CB_RESPONSE_OK = 0x0001,
	CB_RESPONSE_FAIL = 0x0002,
	CB_ASCII_NAMES = 0x0004,

	// CLIPRDR_GENERAL_CAPABILITY (2.2.2.1.1.1)
	CB_CAPSTYPE_GENERAL = 0x0001,
	CB_CAPS_VERSION_2 = 0x00000002,
	CB_USE_LONG_FORMAT_NAMES = 0x00000002,
	CB_STREAM_FILECLIP_ENABLED = 0x00000004,
	CB_FILECLIP_NO_FILE_PATHS = 0x00000008,
	CB_HUGE_FILE_SUPPORT_ENABLED = 0x00000020,

	// File Contents Request dwFlags (2.2.5.3)
	FILECONTENTS_SIZE = 0x00000001,
	FILECONTENTS_RANGE = 0x00000002,

	// CLIPRDR_FILEDESCRIPTOR (2.2.5.2.3.1)
	FD_ATTRIBUTES = 0x00000004,
	FD_WRITESTIME = 0x00000020,
	FD_FILESIZE = 0x00000040,
	FD_SHOWPROGRESSUI = 0x00004000,
	FILE_ATTRIBUTE_DIRECTORY = 0x00000010,
	FILE_ATTRIBUTE_ARCHIVE = 0x00000020,

	// Standard clipboard format IDs
	CF_UNICODETEXT = 13
};


// Text conversions. Clipboard text on the wire is UTF-16LE with "\r\n"
// line ends and a terminating NUL.
std::string ClipboardTextFromWire(const uint8_t* data, size_t size);
Bytes ClipboardTextToWire(const std::string& text);


struct ClipboardFormat {
	uint32_t		id;
	std::string		name;
};

// Parses the formatListData of a Format List PDU (2.2.3.1), long or short
// names.
bool ParseFormatList(const uint8_t* data, size_t size, bool longNames,
	bool asciiNames, std::vector<ClipboardFormat>& formats);


// One entry of a file list.
struct ClipboardFile {
				ClipboardFile();

	// Relative, with "\" between folders, as on the wire.
	std::string	name;
	// Where the file is (sending) or goes (receiving).
	std::string	localPath;
	bool		directory;
	bool		hasSize;
	uint64_t	size;
	// FILETIME: 100 ns since 1601.
	uint64_t	writeTime;
	// The position in the list it came from: lindex in File Contents
	// Requests (2.2.5.3).
	uint32_t	listIndex;
};

// CLIPRDR_FILELIST (2.2.5.2.3)
Bytes BuildFileList(const std::vector<ClipboardFile>& files);
bool ParseFileList(const uint8_t* data, size_t size,
	std::vector<ClipboardFile>& files);

// Turns a name from the client into a relative path that stays inside the
// staging folder: "/" between parts, no "." or "..", no empty parts. Fails
// when nothing safe is left.
bool SafeRelativePath(const std::string& name, std::string& path);

// Lists local files and folders, with everything inside the folders.
// Folders come before their contents.
bool CollectLocalFiles(const std::vector<std::string>& paths,
	std::vector<ClipboardFile>& files);

// Removes the copies in folder (subfolders named like
// "2026-11-12 14.50.03") that are older than maxAgeSeconds. Nothing else
// in the folder is touched. Returns how many were removed.
int CleanUpIncomingFiles(const std::string& folder, int64_t maxAgeSeconds);


class ClipboardChannel {
public:
							// Copies from the client larger than
							// incomingLimit bytes are refused.
							ClipboardChannel(ChannelSender& sender,
								Clipboard& clipboard,
								uint64_t incomingLimit);
							~ClipboardChannel();

			// The server's side of the Initialization Sequence (1.3.2.1).
			bool			Start();
			// One reassembled clipboard PDU from the client.
			bool			Receive(const Bytes& pdu);
			// Announces text or files copied locally since the last call.
			bool			Poll();
			// Ends a file copy in progress, when the session ends.
			void			Stop();

private:
			bool			_Send(uint16_t type, uint16_t flags,
								const Bytes& body);
			bool			_SendFormatList();
			bool			_RequestFormat(uint32_t format);
			bool			_HandleCapabilities(const uint8_t* data,
								size_t size);
			bool			_HandleFormatList(uint16_t flags,
								const uint8_t* data, size_t size);
			bool			_HandleDataRequest(const uint8_t* data,
								size_t size);
			bool			_HandleDataResponse(uint16_t flags,
								const uint8_t* data, size_t size);
			bool			_HandleFileContentsRequest(const uint8_t* data,
								size_t size);
			bool			_HandleFileContentsResponse(uint16_t flags,
								const uint8_t* data, size_t size);

			bool			_StartDownload(
								const std::vector<ClipboardFile>& files);
			bool			_RequestNextPiece();
			void			_FinishDownload();
			void			_AbortDownload(const char* reason);

			ChannelSender&	fSender;
			Clipboard&		fClipboard;
			uint64_t		fIncomingLimit;
			bool			fStarted;
			bool			fLongNames;
			bool			fClientFiles;
			uint32_t		fGeneration;
			// The format of an outstanding Format Data Request, or 0.
			uint32_t		fRequestedFormat;
			// The client's ID for FileGroupDescriptorW, or 0.
			uint32_t		fClientFileFormat;
			// A refused Format Data Request is asked again: the format, the
			// time (monotonic ms) to ask, and how often it was refused.
			uint32_t		fRetryFormat;
			int64_t			fRetryAt;
			int				fRetries;

			// What we offered last: files (with their list) or text.
			std::vector<ClipboardFile> fOffered;

			struct Download {
				bool		active;
				std::vector<ClipboardFile> files;
				std::vector<std::string> topLevel;
				std::string	folder;
				size_t		index;
				uint64_t	offset;
				int			fd;
				uint32_t	streamId;
				uint32_t	requested;
				uint64_t	total;
				uint64_t	received;
			};
			Download		fDownload;
			uint32_t		fNextStreamId;
};


}	// namespace rrd


#endif	// RRD_CLIPBOARD_CHANNEL_H
