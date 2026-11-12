/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */


#include "ClipboardChannel.h"

#include <dirent.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>

#include "Auth.h"
#include "ByteStream.h"
#include "Log.h"


namespace rrd {


// Text larger than this is not taken from or offered to the client.
static const size_t kMaxText = 16 * 1024 * 1024;
static const size_t kHeaderSize = 8;

// Our IDs for the registered formats we offer. Any value from 0xc000 up
// works; the names are what identify them (3.1.1.1).
static const uint32_t kFileGroupFormat = 0xc0f1;
static const uint32_t kFileContentsFormat = 0xc0f2;
static const char* kFileGroupName = "FileGroupDescriptorW";
static const char* kFileContentsName = "FileContents";

static const size_t kFileDescriptorSize = 592;
// The fileName field holds 260 UTF-16 code units with the terminator.
static const size_t kMaxFileNameUnits = 259;
static const size_t kMaxFiles = 100000;
// File data is requested from the client in pieces of this size, and
// pieces asked of us are capped at kMaxPieceOut.
static const uint32_t kPieceSize = 512 * 1024;
static const uint32_t kMaxPieceOut = 4 * 1024 * 1024;

// A client can refuse a Format Data Request that arrives right after its
// Format List, while the application that copied still holds the Windows
// clipboard. The request is then repeated after these delays.
static const int64_t kRetryDelaysMs[] = { 250, 500, 1000 };
static const int kMaxRetries = 3;


static int64_t
MonotonicMs()
{
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}


// FILETIME: 100 ns intervals since 1601-01-01.
static const uint64_t kUnixEpochInFileTime = 116444736000000000ULL;


std::string
ClipboardTextFromWire(const uint8_t* data, size_t size)
{
	// Up to the first NUL code unit.
	size_t length = 0;
	while (length + 1 < size && (data[length] != 0 || data[length + 1] != 0))
		length += 2;
	std::string text = Utf16LeToUtf8(data, length);

	std::string result;
	result.reserve(text.size());
	for (size_t i = 0; i < text.size(); i++) {
		if (text[i] == '\r' && i + 1 < text.size() && text[i + 1] == '\n')
			continue;
		result += text[i];
	}
	return result;
}


Bytes
ClipboardTextToWire(const std::string& text)
{
	std::string crlf;
	crlf.reserve(text.size() + text.size() / 16);
	for (size_t i = 0; i < text.size(); i++) {
		if (text[i] == '\n' && (i == 0 || text[i - 1] != '\r'))
			crlf += '\r';
		crlf += text[i];
	}
	Bytes wire = Utf8ToUtf16Le(crlf);
	wire.push_back(0);
	wire.push_back(0);
	return wire;
}


bool
ParseFormatList(const uint8_t* data, size_t size, bool longNames,
	bool asciiNames, std::vector<ClipboardFormat>& formats)
{
	formats.clear();
	size_t at = 0;
	if (!longNames) {
		// CLIPRDR_SHORT_FORMAT_NAME: formatId, then 32 bytes of name.
		if (size % 36 != 0)
			return false;
		for (; at < size; at += 36) {
			ClipboardFormat format;
			format.id = data[at] | (data[at + 1] << 8) | (data[at + 2] << 16)
				| ((uint32_t)data[at + 3] << 24);
			const uint8_t* name = data + at + 4;
			if (asciiNames) {
				size_t length = strnlen((const char*)name, 32);
				format.name.assign((const char*)name, length);
			} else
				format.name = ClipboardTextFromWire(name, 32);
			formats.push_back(format);
		}
		return true;
	}

	// CLIPRDR_LONG_FORMAT_NAME: formatId, then a NUL-terminated UTF-16 name.
	while (at < size) {
		if (size - at < 6)
			return false;
		ClipboardFormat format;
		format.id = data[at] | (data[at + 1] << 8) | (data[at + 2] << 16)
			| ((uint32_t)data[at + 3] << 24);
		at += 4;
		size_t end = at;
		while (end + 1 < size && (data[end] != 0 || data[end + 1] != 0))
			end += 2;
		if (end + 1 >= size)
			return false;	// no terminator
		format.name = Utf16LeToUtf8(data + at, end - at);
		at = end + 2;
		formats.push_back(format);
	}
	return true;
}


// #pragma mark - file lists


ClipboardFile::ClipboardFile()
	:
	directory(false),
	hasSize(false),
	size(0),
	writeTime(0),
	listIndex(0)
{
}


static void
PutLE32(Bytes& out, uint32_t value)
{
	for (int i = 0; i < 4; i++)
		out.push_back((uint8_t)(value >> (8 * i)));
}


static uint32_t
GetLE32(const uint8_t* data)
{
	return (uint32_t)data[0] | ((uint32_t)data[1] << 8)
		| ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}


Bytes
BuildFileList(const std::vector<ClipboardFile>& files)
{
	Bytes out;
	PutLE32(out, (uint32_t)files.size());
	for (size_t i = 0; i < files.size(); i++) {
		const ClipboardFile& file = files[i];
		size_t start = out.size();
		out.resize(start + kFileDescriptorSize, 0);
		uint8_t* d = out.data() + start;
		uint32_t flags = FD_ATTRIBUTES | FD_FILESIZE | FD_WRITESTIME
			| FD_SHOWPROGRESSUI;
		uint32_t attributes = file.directory ? FILE_ATTRIBUTE_DIRECTORY
			: FILE_ATTRIBUTE_ARCHIVE;
		uint64_t size = file.directory ? 0 : file.size;
		for (int b = 0; b < 4; b++) {
			d[b] = (uint8_t)(flags >> (8 * b));
			d[36 + b] = (uint8_t)(attributes >> (8 * b));
			d[64 + b] = (uint8_t)(size >> (32 + 8 * b));	// fileSizeHigh
			d[68 + b] = (uint8_t)(size >> (8 * b));			// fileSizeLow
		}
		for (int b = 0; b < 8; b++)
			d[56 + b] = (uint8_t)(file.writeTime >> (8 * b));
		Bytes name = Utf8ToUtf16Le(file.name);
		if (name.size() > kMaxFileNameUnits * 2)
			name.resize(kMaxFileNameUnits * 2);
		memcpy(d + 72, name.data(), name.size());
	}
	return out;
}


bool
ParseFileList(const uint8_t* data, size_t size,
	std::vector<ClipboardFile>& files)
{
	files.clear();
	if (size < 4)
		return false;
	uint32_t count = GetLE32(data);
	if (count > kMaxFiles || size - 4 < (size_t)count * kFileDescriptorSize)
		return false;
	for (uint32_t i = 0; i < count; i++) {
		const uint8_t* d = data + 4 + (size_t)i * kFileDescriptorSize;
		ClipboardFile file;
		uint32_t flags = GetLE32(d);
		uint32_t attributes = GetLE32(d + 36);
		file.directory = (flags & FD_ATTRIBUTES) != 0
			&& (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
		if ((flags & FD_WRITESTIME) != 0) {
			for (int b = 7; b >= 0; b--)
				file.writeTime = (file.writeTime << 8) | d[56 + b];
		}
		file.hasSize = (flags & FD_FILESIZE) != 0;
		if (file.hasSize)
			file.size = ((uint64_t)GetLE32(d + 64) << 32) | GetLE32(d + 68);
		file.name = ClipboardTextFromWire(d + 72, 520);
		file.listIndex = i;
		files.push_back(file);
	}
	return true;
}


bool
SafeRelativePath(const std::string& name, std::string& path)
{
	path.clear();
	size_t start = 0;
	while (start <= name.size()) {
		size_t end = name.find_first_of("\\/", start);
		if (end == std::string::npos)
			end = name.size();
		std::string part = name.substr(start, end - start);
		start = end + 1;
		if (part.empty() || part == "." || part == "..")
			continue;
		// Names with control characters are not created.
		for (size_t i = 0; i < part.size(); i++) {
			if ((unsigned char)part[i] < 0x20)
				return false;
		}
		if (!path.empty())
			path += '/';
		path += part;
	}
	return !path.empty();
}


static void
CollectFolder(const std::string& path, const std::string& name,
	std::vector<ClipboardFile>& files)
{
	DIR* directory = opendir(path.c_str());
	if (directory == NULL)
		return;
	std::vector<std::string> entries;
	while (struct dirent* entry = readdir(directory)) {
		if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
			entries.push_back(entry->d_name);
	}
	closedir(directory);

	for (size_t i = 0; i < entries.size() && files.size() < kMaxFiles; i++) {
		std::string child = path + "/" + entries[i];
		struct stat info;
		// Links inside folders are not followed, so loops cannot happen.
		if (lstat(child.c_str(), &info) != 0
			|| (!S_ISREG(info.st_mode) && !S_ISDIR(info.st_mode))) {
			continue;
		}
		ClipboardFile file;
		file.name = name + "\\" + entries[i];
		file.localPath = child;
		file.directory = S_ISDIR(info.st_mode);
		file.hasSize = true;
		file.size = file.directory ? 0 : (uint64_t)info.st_size;
		file.writeTime = (uint64_t)info.st_mtime * 10000000ULL
			+ kUnixEpochInFileTime;
		files.push_back(file);
		if (file.directory)
			CollectFolder(child, file.name, files);
	}
}


bool
CollectLocalFiles(const std::vector<std::string>& paths,
	std::vector<ClipboardFile>& files)
{
	files.clear();
	for (size_t i = 0; i < paths.size(); i++) {
		struct stat info;
		if (stat(paths[i].c_str(), &info) != 0
			|| (!S_ISREG(info.st_mode) && !S_ISDIR(info.st_mode))) {
			continue;
		}
		size_t slash = paths[i].find_last_of('/');
		ClipboardFile file;
		file.name = slash == std::string::npos ? paths[i]
			: paths[i].substr(slash + 1);
		if (file.name.empty())
			continue;
		file.localPath = paths[i];
		file.directory = S_ISDIR(info.st_mode);
		file.hasSize = true;
		file.size = file.directory ? 0 : (uint64_t)info.st_size;
		file.writeTime = (uint64_t)info.st_mtime * 10000000ULL
			+ kUnixEpochInFileTime;
		files.push_back(file);
		if (file.directory)
			CollectFolder(paths[i], file.name, files);
	}
	return !files.empty();
}


static bool
RemoveTree(const std::string& path)
{
	struct stat info;
	if (lstat(path.c_str(), &info) != 0)
		return false;
	if (S_ISDIR(info.st_mode)) {
		DIR* directory = opendir(path.c_str());
		if (directory != NULL) {
			while (struct dirent* entry = readdir(directory)) {
				if (strcmp(entry->d_name, ".") != 0
					&& strcmp(entry->d_name, "..") != 0) {
					RemoveTree(path + "/" + entry->d_name);
				}
			}
			closedir(directory);
		}
		return rmdir(path.c_str()) == 0;
	}
	return unlink(path.c_str()) == 0;
}


static bool
IsCopyFolderName(const char* name)
{
	// "YYYY-MM-DD HH.MM.SS", maybe followed by " N".
	const char* pattern = "dddd-dd-dd dd.dd.dd";
	size_t i = 0;
	for (; pattern[i] != '\0'; i++) {
		if (pattern[i] == 'd' ? (name[i] < '0' || name[i] > '9')
				: name[i] != pattern[i]) {
			return false;
		}
	}
	if (name[i] == '\0')
		return true;
	if (name[i] != ' ' || name[i + 1] == '\0')
		return false;
	for (i++; name[i] != '\0'; i++) {
		if (name[i] < '0' || name[i] > '9')
			return false;
	}
	return true;
}


int
CleanUpIncomingFiles(const std::string& folder, int64_t maxAgeSeconds)
{
	DIR* directory = opendir(folder.c_str());
	if (directory == NULL)
		return 0;
	std::vector<std::string> old;
	time_t now = time(NULL);
	while (struct dirent* entry = readdir(directory)) {
		if (!IsCopyFolderName(entry->d_name))
			continue;
		std::string path = folder + "/" + entry->d_name;
		struct stat info;
		if (lstat(path.c_str(), &info) == 0 && S_ISDIR(info.st_mode)
			&& now - info.st_mtime > maxAgeSeconds) {
			old.push_back(path);
		}
	}
	closedir(directory);
	int removed = 0;
	for (size_t i = 0; i < old.size(); i++) {
		if (RemoveTree(old[i]))
			removed++;
	}
	return removed;
}


// #pragma mark - ClipboardChannel


ClipboardChannel::ClipboardChannel(ChannelSender& sender,
	Clipboard& clipboard, uint64_t incomingLimit, bool allowFiles)
	:
	fSender(sender),
	fClipboard(clipboard),
	fIncomingLimit(incomingLimit),
	fAllowFiles(allowFiles),
	fStarted(false),
	fLongNames(false),
	fClientFiles(false),
	fGeneration(0),
	fRequestedFormat(0),
	fClientFileFormat(0),
	fRetryFormat(0),
	fRetryAt(0),
	fRetries(0),
	fNextStreamId(1)
{
	fDownload.active = false;
	fDownload.fd = -1;
}


ClipboardChannel::~ClipboardChannel()
{
	Stop();
}


void
ClipboardChannel::Stop()
{
	if (fDownload.active)
		_AbortDownload("the session ended");
}


bool
ClipboardChannel::Start()
{
	// What is already on the local clipboard is not announced: when it
	// starts, the client sends its own clipboard, which wins.
	fGeneration = fClipboard.Generation();

	// Clipboard Capabilities PDU (2.2.2.1): one General Capability Set.
	uint32_t flags = CB_USE_LONG_FORMAT_NAMES;
	if (_FilesEnabled()) {
		flags |= CB_STREAM_FILECLIP_ENABLED | CB_FILECLIP_NO_FILE_PATHS
			| CB_HUGE_FILE_SUPPORT_ENABLED;
	}
	Writer caps;
	caps.U16LE(1);					// cCapabilitiesSets
	caps.U16LE(0);					// pad1
	caps.U16LE(CB_CAPSTYPE_GENERAL);
	caps.U16LE(12);					// lengthCapability
	caps.U32LE(CB_CAPS_VERSION_2);
	caps.U32LE(flags);
	if (!_Send(CB_CLIP_CAPS, 0, caps.Data()))
		return false;

	// Monitor Ready PDU (2.2.2.2)
	if (!_Send(CB_MONITOR_READY, 0, Bytes()))
		return false;
	fStarted = true;
	return true;
}


bool
ClipboardChannel::Receive(const Bytes& pdu)
{
	if (pdu.size() < kHeaderSize)
		return true;
	Reader reader(pdu);
	uint16_t type = reader.U16LE();
	uint16_t flags = reader.U16LE();
	uint32_t length = reader.U32LE();
	if (length > pdu.size() - kHeaderSize) {
		LOG_W("clipboard: PDU 0x%04x claims %u bytes, has %zu", type,
			length, pdu.size() - kHeaderSize);
		return true;
	}
	const uint8_t* data = pdu.data() + kHeaderSize;
	LOG_D("clipboard: PDU 0x%04x, flags 0x%x, %u bytes", type, flags, length);

	switch (type) {
		case CB_CLIP_CAPS:
			return _HandleCapabilities(data, length);
		case CB_TEMP_DIRECTORY:
			return true;
		case CB_FORMAT_LIST:
			return _HandleFormatList(flags, data, length);
		case CB_FORMAT_LIST_RESPONSE:
			if ((flags & CB_RESPONSE_OK) == 0)
				LOG_D("clipboard: the client refused our format list");
			return true;
		case CB_FORMAT_DATA_REQUEST:
			return _HandleDataRequest(data, length);
		case CB_FORMAT_DATA_RESPONSE:
			return _HandleDataResponse(flags, data, length);
		case CB_FILECONTENTS_REQUEST:
			return _HandleFileContentsRequest(data, length);
		case CB_FILECONTENTS_RESPONSE:
			return _HandleFileContentsResponse(flags, data, length);
		case CB_LOCK_CLIPDATA:
		case CB_UNLOCK_CLIPDATA:
			return true;
		default:
			LOG_D("clipboard: ignoring PDU type 0x%04x", type);
			return true;
	}
}


bool
ClipboardChannel::Poll()
{
	if (!fStarted)
		return true;
	if (fRetryFormat != 0 && fRequestedFormat == 0
		&& MonotonicMs() >= fRetryAt) {
		uint32_t format = fRetryFormat;
		fRetryFormat = 0;
		LOG_D("clipboard: asking the client again for format %u", format);
		if (!_RequestFormat(format))
			return false;
	}
	uint32_t generation = fClipboard.Generation();
	if (generation == fGeneration)
		return true;
	fGeneration = generation;
	return _SendFormatList();
}


bool
ClipboardChannel::_Send(uint16_t type, uint16_t flags, const Bytes& body)
{
	Writer writer;
	writer.U16LE(type);
	writer.U16LE(flags);
	writer.U32LE((uint32_t)body.size());
	writer.Bytes(body);
	// Older Windows versions append 4 bytes that dataLen does not count
	// (2.2.1, note 1). They are not needed, and Receive() ignores them.
	return fSender.SendChannelData(writer.Data());
}


static void
AddFormat(Writer& list, uint32_t id, const char* name, bool longNames)
{
	list.U32LE(id);
	Bytes wide = Utf8ToUtf16Le(name);
	if (longNames) {
		list.Bytes(wide);
		list.U16LE(0);
	} else {
		// 32 bytes, NUL-terminated (2.2.3.1.1.1).
		if (wide.size() > 30)
			wide.resize(30);
		wide.resize(32, 0);
		list.Bytes(wide);
	}
}


bool
ClipboardChannel::_SendFormatList()
{
	// Format List PDU (2.2.3.1): files, or text, or an empty list, which
	// empties the client's shared clipboard.
	Writer list;
	fOffered.clear();

	std::vector<std::string> paths;
	if (fClientFiles && fLongNames && fClipboard.GetFiles(paths)
		&& CollectLocalFiles(paths, fOffered)) {
		AddFormat(list, kFileGroupFormat, kFileGroupName, true);
		AddFormat(list, kFileContentsFormat, kFileContentsName, true);
		LOG_D("clipboard: offering %zu files and folders", fOffered.size());
		return _Send(CB_FORMAT_LIST, 0, list.Data());
	}

	std::string text;
	if (fClipboard.GetText(text) && !text.empty() && text.size() <= kMaxText) {
		AddFormat(list, CF_UNICODETEXT, "", fLongNames);
		LOG_D("clipboard: offering text");
	} else
		LOG_D("clipboard: nothing to offer");
	return _Send(CB_FORMAT_LIST, 0, list.Data());
}


bool
ClipboardChannel::_HandleCapabilities(const uint8_t* data, size_t size)
{
	Reader reader(data, size);
	uint16_t count = reader.U16LE();
	reader.U16LE();
	for (uint16_t i = 0; i < count && reader.Ok(); i++) {
		uint16_t type = reader.U16LE();
		uint16_t length = reader.U16LE();
		if (!reader.Ok() || length < 4)
			break;
		Reader set = reader.Sub(length - 4);
		if (type == CB_CAPSTYPE_GENERAL) {
			set.U32LE();	// version
			uint32_t flags = set.U32LE();
			if (set.Ok()) {
				fLongNames = (flags & CB_USE_LONG_FORMAT_NAMES) != 0;
				fClientFiles = (flags & CB_STREAM_FILECLIP_ENABLED) != 0
					&& _FilesEnabled();
				LOG_D("clipboard: client flags 0x%08x", flags);
			}
		}
	}
	return true;
}


bool
ClipboardChannel::_HandleFormatList(uint16_t flags, const uint8_t* data,
	size_t size)
{
	std::vector<ClipboardFormat> formats;
	bool ok = ParseFormatList(data, size, fLongNames,
		(flags & CB_ASCII_NAMES) != 0, formats);

	// Format List Response PDU (2.2.3.2)
	if (!_Send(CB_FORMAT_LIST_RESPONSE, ok ? CB_RESPONSE_OK : CB_RESPONSE_FAIL,
			Bytes())) {
		return false;
	}
	if (!ok) {
		LOG_W("clipboard: cannot parse the client's format list");
		return true;
	}

	// The client's clipboard changed: what it offered before is gone.
	if (fDownload.active)
		_AbortDownload("the remote clipboard changed");
	fClientFileFormat = 0;
	fRetryFormat = 0;
	fRetries = 0;

	LOG_I("clipboard: the client's clipboard changed (%zu formats)",
		formats.size());
	bool hasText = false;
	for (size_t i = 0; i < formats.size(); i++) {
		LOG_T("clipboard: client format %u \"%s\"", formats[i].id,
			formats[i].name.c_str());
		if (formats[i].id == CF_UNICODETEXT)
			hasText = true;
		else if (formats[i].name == kFileGroupName)
			fClientFileFormat = formats[i].id;
	}

	// The local clipboard cannot render later: fetch files or text now.
	uint32_t format = 0;
	if (fClientFileFormat != 0 && fClientFiles)
		format = fClientFileFormat;
	else if (hasText)
		format = CF_UNICODETEXT;
	if (format == 0)
		return true;
	return _RequestFormat(format);
}


bool
ClipboardChannel::_FilesEnabled()
{
	return fAllowFiles && !fClipboard.IncomingFilesFolder().empty();
}


bool
ClipboardChannel::_RequestFormat(uint32_t format)
{
	Writer request;
	request.U32LE(format);
	fRequestedFormat = format;
	return _Send(CB_FORMAT_DATA_REQUEST, 0, request.Data());
}


bool
ClipboardChannel::_HandleDataRequest(const uint8_t* data, size_t size)
{
	Reader reader(data, size);
	uint32_t format = reader.U32LE();
	if (!reader.Ok())
		return _Send(CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_FAIL, Bytes());

	if (format == kFileGroupFormat && !fOffered.empty()) {
		LOG_D("clipboard: sending the list of %zu files", fOffered.size());
		return _Send(CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK,
			BuildFileList(fOffered));
	}

	std::string text;
	if (format != CF_UNICODETEXT || !fClipboard.GetText(text)
		|| text.size() > kMaxText) {
		return _Send(CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_FAIL, Bytes());
	}
	LOG_D("clipboard: sending %zu bytes of text to the client", text.size());
	return _Send(CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK,
		ClipboardTextToWire(text));
}


bool
ClipboardChannel::_HandleDataResponse(uint16_t flags, const uint8_t* data,
	size_t size)
{
	uint32_t format = fRequestedFormat;
	fRequestedFormat = 0;
	if (format == 0)
		return true;
	if ((flags & CB_RESPONSE_OK) == 0) {
		if (fRetries < kMaxRetries) {
			LOG_D("clipboard: the client could not send format %u yet; "
				"asking again", format);
			fRetryFormat = format;
			fRetryAt = MonotonicMs() + kRetryDelaysMs[fRetries];
			fRetries++;
		} else {
			LOG_W("clipboard: the client could not send its clipboard "
				"(format %u)", format);
		}
		return true;
	}
	fRetries = 0;

	if (format == fClientFileFormat) {
		std::vector<ClipboardFile> files;
		if (!ParseFileList(data, size, files)) {
			LOG_W("clipboard: cannot parse the client's file list");
			return true;
		}
		return _StartDownload(files);
	}

	if (format != CF_UNICODETEXT)
		return true;
	if (size > kMaxText * 2) {
		LOG_W("clipboard: %zu bytes of text from the client; too large",
			size);
		return true;
	}
	std::string text = ClipboardTextFromWire(data, size);
	LOG_I("clipboard: received %zu bytes of text from the client",
		text.size());
	fClipboard.SetText(text);
	return true;
}


bool
ClipboardChannel::_HandleFileContentsRequest(const uint8_t* data, size_t size)
{
	// File Contents Request PDU (2.2.5.3)
	Reader reader(data, size);
	uint32_t streamId = reader.U32LE();
	int32_t index = (int32_t)reader.U32LE();
	uint32_t flags = reader.U32LE();
	uint32_t positionLow = reader.U32LE();
	uint32_t positionHigh = reader.U32LE();
	uint32_t requested = reader.U32LE();

	Bytes reply;
	PutLE32(reply, streamId);
	if (!reader.Ok() || index < 0 || (size_t)index >= fOffered.size()
		|| fOffered[index].directory) {
		return _Send(CB_FILECONTENTS_RESPONSE, CB_RESPONSE_FAIL, reply);
	}
	const ClipboardFile& file = fOffered[index];

	if ((flags & FILECONTENTS_SIZE) != 0) {
		struct stat info;
		if (stat(file.localPath.c_str(), &info) != 0)
			return _Send(CB_FILECONTENTS_RESPONSE, CB_RESPONSE_FAIL, reply);
		uint64_t fileSize = (uint64_t)info.st_size;
		PutLE32(reply, (uint32_t)fileSize);
		PutLE32(reply, (uint32_t)(fileSize >> 32));
		return _Send(CB_FILECONTENTS_RESPONSE, CB_RESPONSE_OK, reply);
	}

	if ((flags & FILECONTENTS_RANGE) == 0)
		return _Send(CB_FILECONTENTS_RESPONSE, CB_RESPONSE_FAIL, reply);
	if (requested > kMaxPieceOut)
		requested = kMaxPieceOut;
	uint64_t position = ((uint64_t)positionHigh << 32) | positionLow;
	int fd = open(file.localPath.c_str(), O_RDONLY);
	if (fd < 0)
		return _Send(CB_FILECONTENTS_RESPONSE, CB_RESPONSE_FAIL, reply);
	size_t start = reply.size();
	reply.resize(start + requested);
	ssize_t got = pread(fd, reply.data() + start, requested, (off_t)position);
	close(fd);
	if (got < 0) {
		reply.resize(start);
		return _Send(CB_FILECONTENTS_RESPONSE, CB_RESPONSE_FAIL, reply);
	}
	reply.resize(start + (size_t)got);
	return _Send(CB_FILECONTENTS_RESPONSE, CB_RESPONSE_OK, reply);
}


// #pragma mark - downloads from the client


static std::string
FormatSize(uint64_t bytes)
{
	char text[32];
	if (bytes >= 1024ULL * 1024 * 1024)
		snprintf(text, sizeof(text), "%.1f GB", bytes / 1073741824.0);
	else if (bytes >= 1024 * 1024)
		snprintf(text, sizeof(text), "%.1f MB", bytes / 1048576.0);
	else
		snprintf(text, sizeof(text), "%.0f KB", (bytes + 1023) / 1024.0);
	return text;
}


bool
ClipboardChannel::_StartDownload(const std::vector<ClipboardFile>& files)
{
	std::string base = fClipboard.IncomingFilesFolder();
	if (base.empty() || files.empty())
		return true;

	// Check the names and the total first.
	uint64_t total = 0;
	std::vector<ClipboardFile> safe;
	for (size_t i = 0; i < files.size(); i++) {
		ClipboardFile file = files[i];
		std::string relative;
		if (!SafeRelativePath(file.name, relative)) {
			LOG_W("clipboard: skipping a file with an unusable name");
			continue;
		}
		file.localPath = relative;
		if (!file.directory) {
			// Without wrapping: a total over the limit stays over it.
			if (file.size > UINT64_MAX - total)
				total = UINT64_MAX;
			else
				total += file.size;
		}
		safe.push_back(file);
	}
	if (safe.empty())
		return true;
	size_t fileCount = 0;
	for (size_t i = 0; i < safe.size(); i++) {
		if (!safe[i].directory)
			fileCount++;
	}
	if (total > fIncomingLimit) {
		char message[256];
		snprintf(message, sizeof(message), "%zu files (%s) were not copied "
			"from the remote computer: that is more than the limit of %s.",
			fileCount, FormatSize(total).c_str(),
			FormatSize(fIncomingLimit).c_str());
		LOG_W("clipboard: %s", message);
		fClipboard.Notify(message);
		return true;
	}

	// Each copy gets its own folder, named after the time.
	mkdir(base.c_str(), 0755);
	char stamp[64];
	time_t now = time(NULL);
	struct tm local;
	localtime_r(&now, &local);
	strftime(stamp, sizeof(stamp), "%Y-%m-%d %H.%M.%S", &local);
	std::string folder = base + "/" + stamp;
	for (int attempt = 2; mkdir(folder.c_str(), 0755) != 0; attempt++) {
		if (errno != EEXIST || attempt > 100) {
			LOG_E("clipboard: cannot create %s: %s", folder.c_str(),
				strerror(errno));
			return true;
		}
		char suffixed[96];
		snprintf(suffixed, sizeof(suffixed), "%s %d", stamp, attempt);
		folder = base + "/" + suffixed;
	}

	fDownload.active = true;
	fDownload.files.clear();
	fDownload.topLevel.clear();
	fDownload.folder = folder;
	fDownload.index = 0;
	fDownload.offset = 0;
	fDownload.fd = -1;
	fDownload.total = total;
	fDownload.received = 0;
	for (size_t i = 0; i < safe.size(); i++) {
		ClipboardFile file = safe[i];
		std::string relative = file.localPath;
		file.localPath = folder + "/" + relative;
		if (relative.find('/') == std::string::npos)
			fDownload.topLevel.push_back(file.localPath);
		fDownload.files.push_back(file);
	}
	LOG_I("clipboard: copying %zu files (%s) from the client into %s",
		fileCount, FormatSize(total).c_str(), folder.c_str());
	return _RequestNextPiece();
}


static void
MakeParents(const std::string& path)
{
	for (size_t slash = path.find('/', 1); slash != std::string::npos;
			slash = path.find('/', slash + 1)) {
		mkdir(path.substr(0, slash).c_str(), 0755);
	}
}


bool
ClipboardChannel::_RequestNextPiece()
{
	while (fDownload.index < fDownload.files.size()) {
		ClipboardFile& file = fDownload.files[fDownload.index];
		if (fDownload.fd < 0) {
			MakeParents(file.localPath);
			if (file.directory) {
				mkdir(file.localPath.c_str(), 0755);
				fDownload.index++;
				continue;
			}
			fDownload.fd = open(file.localPath.c_str(),
				O_WRONLY | O_CREAT | O_EXCL, 0644);
			if (fDownload.fd < 0) {
				LOG_W("clipboard: cannot create %s: %s",
					file.localPath.c_str(), strerror(errno));
				fDownload.index++;
				continue;
			}
			fDownload.offset = 0;
		}
		if (file.hasSize && fDownload.offset >= file.size) {
			close(fDownload.fd);
			fDownload.fd = -1;
			fDownload.index++;
			continue;
		}

		// File Contents Request PDU (2.2.5.3), a range.
		uint32_t piece = kPieceSize;
		if (file.hasSize && file.size - fDownload.offset < piece)
			piece = (uint32_t)(file.size - fDownload.offset);
		fDownload.streamId = fNextStreamId++;
		Writer request;
		fDownload.requested = piece;
		request.U32LE(fDownload.streamId);
		request.U32LE(file.listIndex);
		request.U32LE(FILECONTENTS_RANGE);
		request.U32LE((uint32_t)fDownload.offset);
		request.U32LE((uint32_t)(fDownload.offset >> 32));
		request.U32LE(piece);
		return _Send(CB_FILECONTENTS_REQUEST, 0, request.Data());
	}
	_FinishDownload();
	return true;
}


bool
ClipboardChannel::_HandleFileContentsResponse(uint16_t flags,
	const uint8_t* data, size_t size)
{
	if (!fDownload.active || size < 4)
		return true;
	uint32_t streamId = GetLE32(data);
	if (streamId != fDownload.streamId)
		return true;	// a stale answer
	if ((flags & CB_RESPONSE_OK) == 0) {
		_AbortDownload("the remote computer could not send a file");
		return true;
	}

	ClipboardFile& file = fDownload.files[fDownload.index];
	const uint8_t* bytes = data + 4;
	size_t received = size - 4;
	size_t count = received;
	// Never more than was asked for, nor past the file's size.
	if (count > fDownload.requested)
		count = fDownload.requested;
	if (file.hasSize && count > file.size - fDownload.offset)
		count = (size_t)(file.size - fDownload.offset);
	// Files without a size count against the limit as they arrive.
	if (count > fIncomingLimit - std::min(fDownload.received, fIncomingLimit)) {
		_AbortDownload("the files are larger than the limit");
		return true;
	}
	while (count > 0) {
		ssize_t written = write(fDownload.fd, bytes, count);
		if (written <= 0) {
			_AbortDownload(strerror(errno));
			return true;
		}
		bytes += written;
		count -= written;
		fDownload.offset += written;
		fDownload.received += written;
	}
	// Without a size, a short or empty piece ends the file.
	if (!file.hasSize && received < fDownload.requested) {
		file.hasSize = true;
		file.size = fDownload.offset;
	}
	return _RequestNextPiece();
}


void
ClipboardChannel::_FinishDownload()
{
	fDownload.active = false;
	if (fDownload.fd >= 0) {
		close(fDownload.fd);
		fDownload.fd = -1;
	}
	fClipboard.SetFiles(fDownload.topLevel);
	size_t fileCount = 0;
	for (size_t i = 0; i < fDownload.files.size(); i++) {
		if (!fDownload.files[i].directory)
			fileCount++;
	}
	char message[256];
	snprintf(message, sizeof(message), "%zu %s (%s) from the remote "
		"computer %s ready to paste.", fileCount,
		fileCount == 1 ? "file" : "files",
		FormatSize(fDownload.received).c_str(),
		fileCount == 1 ? "is" : "are");
	LOG_I("clipboard: %s", message);
	fClipboard.Notify(message);
}


void
ClipboardChannel::_AbortDownload(const char* reason)
{
	if (fDownload.fd >= 0) {
		close(fDownload.fd);
		fDownload.fd = -1;
		// The partial file is useless.
		if (fDownload.index < fDownload.files.size())
			unlink(fDownload.files[fDownload.index].localPath.c_str());
	}
	fDownload.active = false;
	char message[256];
	snprintf(message, sizeof(message), "Copying files from the remote "
		"computer stopped: %s.", reason);
	LOG_W("clipboard: %s", message);
	fClipboard.Notify(message);
}


}	// namespace rrd
