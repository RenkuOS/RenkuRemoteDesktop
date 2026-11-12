/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */


// A test harness for the protocol core on Linux. It serves a generated
// desktop (gradients, a test pattern, and a moving square) and logs input,
// so the protocol can be tested against RDP clients without Haiku.
// Not for real use: it does not share anything real.


#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include <mutex>

#include "Auth.h"
#include "Log.h"
#include "Server.h"
#include "Settings.h"
#include "Transport.h"


using namespace rrd;


// Reports what changed, like capture backend B: the moving square's old
// and new places. Also switches between two pointer shapes every few
// seconds, to test pointer updates.
class TestFrames : public FrameSource {
public:
	TestFrames()
		:
		fBoxX(-1)
	{
		fSize.width = 1280;
		fSize.height = 800;
		fConsole = fSize;
	}

	virtual DisplaySize Size()
	{
		std::lock_guard<std::mutex> lock(fLock);
		return fSize;
	}

	virtual bool Capture(uint8_t* pixels, size_t stride,
		const DisplaySize& size, bool full, std::vector<Rect>& changed)
	{
		std::lock_guard<std::mutex> lock(fLock);
		if (size.width != fSize.width || size.height != fSize.height
			|| (size_t)size.width * 4 > stride) {
			return false;
		}
		int boxX = (int)((NowMs() / 40) * 7 % (fSize.width - kBox));
		int boxY = fSize.height / 2 - kBox / 2;

		if (full || fBoxX < 0) {
			Rect all = { 0, 0, fSize.width, fSize.height };
			_Draw(pixels, stride, all, boxX, boxY);
			changed.push_back(all);
		} else if (boxX != fBoxX) {
			Rect old = { fBoxX, boxY, kBox, kBox };
			Rect now = { boxX, boxY, kBox, kBox };
			_Draw(pixels, stride, old, boxX, boxY);
			_Draw(pixels, stride, now, boxX, boxY);
			changed.push_back(old);
			changed.push_back(now);
		}
		fBoxX = boxX;
		return true;
	}

	virtual bool TracksChanges()
	{
		return true;
	}

	virtual bool PointerShape(uint32_t& generation, PointerImage& image)
	{
		uint32_t current = (uint32_t)(NowMs() / 5000);
		if (current == generation)
			return false;
		generation = current;

		// A 16 by 16 arrow, white with a black edge; every other shape is
		// red and has a soft (half transparent) edge.
		bool red = current % 2 != 0;
		image.width = image.height = 16;
		image.hotX = image.hotY = 0;
		image.pixels.assign(16 * 16 * 4, 0);
		for (int y = 0; y < 16; y++) {
			for (int x = 0; x <= y && x < 11; x++) {
				uint8_t* pixel = image.pixels.data() + (y * 16 + x) * 4;
				bool edge = x == 0 || x == y || x == 10 || y == 15;
				uint8_t value = edge ? 0 : 255;
				pixel[0] = red && !edge ? 0 : value;
				pixel[1] = red && !edge ? 0 : value;
				pixel[2] = value;
				pixel[3] = red && edge ? 128 : 255;
			}
		}
		return true;
	}

	virtual std::vector<DisplaySize> AvailableSizes()
	{
		static const DisplaySize kSizes[] = {
			{ 800, 600 }, { 1024, 768 }, { 1280, 720 }, { 1280, 800 },
			{ 1366, 768 }, { 1600, 900 }, { 1920, 1080 }
		};
		return std::vector<DisplaySize>(kSizes,
			kSizes + sizeof(kSizes) / sizeof(kSizes[0]));
	}

	virtual bool SetSize(const DisplaySize& size)
	{
		std::lock_guard<std::mutex> lock(fLock);
		fSize = size;
		fBoxX = -1;
		return true;
	}

	virtual void RestoreSize()
	{
		std::lock_guard<std::mutex> lock(fLock);
		fSize = fConsole;
		fBoxX = -1;
	}

	virtual DisplaySize OriginalSize()
	{
		return fConsole;
	}

private:
	static const int kBox = 96;

	static int64_t NowMs()
	{
		struct timespec now;
		clock_gettime(CLOCK_MONOTONIC, &now);
		return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
	}

	void _Draw(uint8_t* pixels, size_t stride, const Rect& area, int boxX,
		int boxY)
	{
		for (int y = area.y; y < area.y + area.height; y++) {
			uint8_t* row = pixels + (size_t)y * stride;
			for (int x = area.x; x < area.x + area.width; x++) {
				uint8_t b, g, r;
				if (y < 40) {
					// Title bar with a marker in the top-left corner, so a
					// flipped image is obvious.
					bool marker = x < 40;
					r = marker ? 255 : 40;
					g = marker ? 0 : 60;
					b = marker ? 0 : 120;
				} else if (x >= boxX && x < boxX + kBox && y >= boxY
					&& y < boxY + kBox) {
					r = 250;
					g = 200;
					b = 0;
				} else if (y > fSize.height - 120) {
					// Checkerboard: worst case for RLE.
					bool on = ((x / 8) + (y / 8)) % 2 == 0;
					r = g = b = on ? 230 : 20;
				} else {
					r = (uint8_t)(x * 255 / fSize.width);
					g = (uint8_t)(y * 255 / fSize.height);
					b = 128;
				}
				row[4 * x] = b;
				row[4 * x + 1] = g;
				row[4 * x + 2] = r;
				row[4 * x + 3] = 255;
			}
		}
	}

	std::mutex	fLock;
	DisplaySize	fSize;
	DisplaySize	fConsole;
	int			fBoxX;
};


class LoggingInput : public InputSink {
public:
	virtual void Key(uint8_t scancode, bool extended, bool extended1,
		bool down)
	{
		LOG_I("input: key 0x%02x%s%s %s", scancode, extended ? " E0" : "",
			extended1 ? " E1" : "", down ? "down" : "up");
	}

	virtual void UnicodeKey(uint16_t codeUnit, bool down)
	{
		LOG_I("input: unicode U+%04X %s", codeUnit, down ? "down" : "up");
	}

	virtual void Pointer(int32_t x, int32_t y, uint32_t buttons)
	{
		LOG_D("input: pointer %d,%d buttons 0x%x", x, y, buttons);
	}

	virtual void Wheel(int32_t delta, bool horizontal)
	{
		LOG_I("input: %s wheel %d", horizontal ? "horizontal" : "vertical",
			delta);
	}

	virtual void SyncLocks(uint32_t flags)
	{
		LOG_I("input: lock state 0x%x", flags);
	}

	virtual void ReleaseAll()
	{
		LOG_I("input: release all");
	}
};


// A clipboard in two files in the harness directory: changing
// clipboard-local.txt is a local copy; text from the client is written to
// clipboard-from-client.txt.
class FileClipboard : public Clipboard {
public:
	FileClipboard(const std::string& directory)
		:
		fLocalPath(directory + "/clipboard-local.txt"),
		fClientPath(directory + "/clipboard-from-client.txt"),
		fFilesPath(directory + "/clipboard-files.txt"),
		fIncoming(directory + "/incoming"),
		fGeneration(0),
		fLastChange(0)
	{
		fLastChange = _ChangeTime(fLocalPath) + _ChangeTime(fFilesPath);
	}

	virtual uint32_t Generation()
	{
		std::lock_guard<std::mutex> lock(fLock);
		int64_t change = _ChangeTime(fLocalPath) + _ChangeTime(fFilesPath);
		if (change != fLastChange) {
			fLastChange = change;
			fGeneration++;
		}
		return fGeneration;
	}

	virtual bool GetText(std::string& text)
	{
		FILE* file = fopen(fLocalPath.c_str(), "rb");
		if (file == NULL)
			return false;
		text.clear();
		char buffer[4096];
		size_t size;
		while ((size = fread(buffer, 1, sizeof(buffer), file)) > 0)
			text.append(buffer, size);
		fclose(file);
		return true;
	}

	// clipboard-files.txt lists local paths, one per line; when it exists
	// it is the clipboard instead of the text.
	virtual bool GetFiles(std::vector<std::string>& paths)
	{
		paths.clear();
		FILE* file = fopen(fFilesPath.c_str(), "r");
		if (file == NULL)
			return false;
		char line[4096];
		while (fgets(line, sizeof(line), file) != NULL) {
			size_t length = strcspn(line, "\r\n");
			if (length > 0)
				paths.push_back(std::string(line, length));
		}
		fclose(file);
		return !paths.empty();
	}

	virtual void SetFiles(const std::vector<std::string>& paths)
	{
		for (size_t i = 0; i < paths.size(); i++)
			LOG_I("clipboard: files from the client: %s", paths[i].c_str());
	}

	virtual std::string IncomingFilesFolder()
	{
		return fIncoming;
	}

	virtual void Notify(const std::string& message)
	{
		LOG_I("notification: %s", message.c_str());
	}

	virtual void SetText(const std::string& text)
	{
		LOG_I("clipboard from the client: %zu bytes", text.size());
		FILE* file = fopen(fClientPath.c_str(), "wb");
		if (file != NULL) {
			fwrite(text.data(), 1, text.size(), file);
			fclose(file);
		}
	}

private:
	int64_t _ChangeTime(const std::string& path)
	{
		struct stat info;
		if (stat(path.c_str(), &info) != 0)
			return 0;
		return (int64_t)info.st_mtim.tv_sec * 1000000000LL
			+ info.st_mtim.tv_nsec + info.st_size;
	}

	std::mutex	fLock;
	std::string	fLocalPath;
	std::string	fClientPath;
	std::string	fFilesPath;
	std::string	fIncoming;
	uint32_t	fGeneration;
	int64_t		fLastChange;
};


static Server* sServer;


static void
HandleSignal(int)
{
	if (sServer != NULL)
		sServer->Stop();
}


int
main(int argc, char** argv)
{
	std::string directory = ".";
	ServerConfig config;
	config.port = 3390;
	bool setPassword = false;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--dir") == 0 && i + 1 < argc)
			directory = argv[++i];
		else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
			config.port = atoi(argv[++i]);
		else if (strcmp(argv[i], "--set-password") == 0)
			setPassword = true;
		else if (strcmp(argv[i], "-v") == 0)
			SetLogLevel(kLogDebug);
		else if (strcmp(argv[i], "-vv") == 0)
			SetLogLevel(kLogTrace);
		else {
			fprintf(stderr, "usage: %s [--dir DIR] [--port N] "
				"[--set-password] [-v|-vv]\n", argv[0]);
			return 1;
		}
	}

	std::string settingsPath = directory + "/settings";
	uint16_t port = config.port;
	LoadSettings(settingsPath, config);
	config.port = port;

	if (setPassword) {
		std::string password;
		if (!ReadPassword("New password: ", password) || password.empty())
			return 1;
		config.passwordHash = HashPassword(password);
		config.ntHash = NtHashHex(password);
		WipeString(password);
		return SaveSettings(settingsPath, config) ? 0 : 1;
	}

	TlsContext tls;
	if (!tls.Init(directory + "/certificate.pem", directory + "/key.pem"))
		return 1;

	TestFrames frames;
	LoggingInput input;
	FileClipboard clipboard(directory);
	Server server(config, tls, frames, input, clipboard);
	if (!server.Listen())
		return 1;

	sServer = &server;
	signal(SIGINT, HandleSignal);
	signal(SIGTERM, HandleSignal);
	signal(SIGPIPE, SIG_IGN);
	server.Run();
	return 0;
}
