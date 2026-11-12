/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */


#include <Application.h>
#include <Clipboard.h>
#include <FindDirectory.h>
#include <Path.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <thread>

#include "Auth.h"
#include "ControlProtocol.h"
#include "ClipboardChannel.h"
#include "HaikuClipboard.h"
#include "Log.h"
#include "PortInputSink.h"
#include "ObserverFrameSource.h"
#include "ScreenFrameSource.h"
#include "Server.h"
#include "Settings.h"
#include "Transport.h"


using namespace rrd;


static const char* kSignature = RRD_SERVER_SIGNATURE;


// The server runs on its own thread. Sessions capture the screen through
// this application's app_server connection, and app_server does not answer
// ReadBitmap() while the application's looper is blocked. So quitting must
// not wait inside QuitRequested(): it asks the server to stop and finishes
// when the server thread reports that every session has ended.
static const uint32 kMsgServerStopped = 'rrSS';


class RemoteDesktopApp : public BApplication {
public:
	RemoteDesktopApp()
		:
		BApplication(kSignature),
		fServer(NULL),
		fFrames(NULL),
		fClipboard(NULL),
		fCapture(""),
		fStopped(false)
	{
	}

	void StartServer(Server* server, ScreenFrameSource* frames,
		HaikuClipboard* clipboard, const char* capture,
		const std::string& settingsPath, const ServerConfig& config)
	{
		fServer = server;
		fClipboard = clipboard;
		fClipboard->StartWatching();
		fFrames = frames;
		fCapture = capture;
		fSettingsPath = settingsPath;
		fConfig = config;
		fThread = std::thread([this]() {
			fServer->Run();
			PostMessage(kMsgServerStopped);
		});
	}

	virtual bool QuitRequested()
	{
		if (!fStopped && fServer != NULL) {
			fServer->Stop();
			return false;
		}
		return true;
	}

	virtual void MessageReceived(BMessage* message)
	{
		switch (message->what) {
			case RRD_MSG_GET_STATUS:
				_SendStatus(message);
				return;
			case RRD_MSG_DISCONNECT:
				if (fServer != NULL)
					fServer->Disconnect();
				return;
			case RRD_MSG_RELOAD_SETTINGS:
				_ReloadSettings(message);
				return;
			case B_CLIPBOARD_CHANGED:
				if (fClipboard != NULL)
					fClipboard->Changed();
				return;
			case kMsgServerStopped:
				break;
			default:
				BApplication::MessageReceived(message);
				return;
		}

		// Run() has returned and no session is left.
		if (fThread.joinable())
			fThread.join();
		fFrames->Release();
		if (fClipboard != NULL)
			fClipboard->StopWatching();
		fStopped = true;
		PostMessage(B_QUIT_REQUESTED);
	}

private:
	void _SendStatus(BMessage* request)
	{
		BMessage reply(RRD_MSG_STATUS);
		reply.AddInt32("port", fConfig.port);
		reply.AddString("bind", fConfig.bindAddress.c_str());
		reply.AddString("capture", fCapture);
		uint8 hash[16];
		reply.AddBool("nla", ParseNtHash(fConfig.ntHash, hash));
		Server::Status status;
		status.connected = false;
		if (fServer != NULL)
			status = fServer->ActiveSession();
		reply.AddBool("connected", status.connected);
		if (status.connected) {
			reply.AddString("peer", status.peer.c_str());
			reply.AddString("user", status.user.c_str());
			reply.AddBool("session_nla", status.nla);
			reply.AddInt64("since", status.since);
		}
		request->SendReply(&reply);
	}

	void _ReloadSettings(BMessage* request)
	{
		ServerConfig config;
		bool loaded = LoadSettings(fSettingsPath, config);
		bool restart = false;
		if (loaded) {
			restart = config.port != fConfig.port
				|| config.bindAddress != fConfig.bindAddress;
			// The listening socket stays as it is until a restart.
			config.port = fConfig.port;
			config.bindAddress = fConfig.bindAddress;
			fConfig = config;
			if (fServer != NULL)
				fServer->UpdateConfig(config);
			LOG_I("settings reloaded%s", restart
				? "; the new port or address needs a restart" : "");
		}
		BMessage reply(RRD_MSG_RELOADED);
		reply.AddInt32("status", loaded ? B_OK : B_ERROR);
		reply.AddBool("restart", restart);
		request->SendReply(&reply);
	}

	Server*				fServer;
	ScreenFrameSource*	fFrames;
	HaikuClipboard*		fClipboard;
	const char*			fCapture;
	std::string			fSettingsPath;
	ServerConfig		fConfig;
	std::thread			fThread;
	bool				fStopped;
};


// Under launch_daemon (--service), a server that exits is started again at
// once, without any throttle. So a server that cannot start waits a while
// before it exits, instead of being restarted in a tight loop.
static const bigtime_t kServiceFailureDelay = 30000000;


static int
StartupFailed(bool service)
{
	if (service) {
		LOG_E("cannot start; trying again in %d seconds",
			(int)(kServiceFailureDelay / 1000000));
		snooze(kServiceFailureDelay);
	}
	return 1;
}


static void
Usage(const char* name)
{
	fprintf(stderr,
		"usage: %s [options]\n"
		"  --set-password    read a new password and save it\n"
		"  --resize POLICY   fastest (default), match-client, or keep\n"
		"  --port N          listen on port N (default 3389)\n"
		"  --bind ADDRESS    listen on one IPv4 address only\n"
		"  --poll            capture by reading the whole screen, even\n"
		"                    where app_server can report changes\n"
		"  --service         started by launch_daemon: wait before exiting\n"
		"                    when the server cannot start\n"
		"  -v, -vv           more logging\n", name);
}


int
main(int argc, char** argv)
{
	BPath path;
	if (rrd_settings_directory(path) != B_OK)
		return 1;
	mkdir(path.Path(), 0700);
	std::string directory = path.Path();
	std::string settingsPath = directory + "/settings";

	ServerConfig config;
	LoadSettings(settingsPath, config);
	static const char* kLevels[] = { "error", "warning", "info", "debug",
		"trace" };
	for (int i = 0; i < 5; i++) {
		if (config.logLevel == kLevels[i])
			SetLogLevel((LogLevel)i);
	}

	bool setPassword = false;
	bool save = false;
	bool poll = false;
	bool service = false;
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--set-password") == 0)
			setPassword = true;
		else if (strcmp(argv[i], "--resize") == 0 && i + 1 < argc) {
			if (!ParseResizePolicy(argv[++i], config.resize)) {
				Usage(argv[0]);
				return 1;
			}
			save = true;
		} else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
			config.port = atoi(argv[++i]);
			save = true;
		} else if (strcmp(argv[i], "--bind") == 0 && i + 1 < argc) {
			config.bindAddress = argv[++i];
			save = true;
		} else if (strcmp(argv[i], "--poll") == 0)
			poll = true;
		else if (strcmp(argv[i], "--service") == 0)
			service = true;
		else if (strcmp(argv[i], "-v") == 0)
			SetLogLevel(kLogDebug);
		else if (strcmp(argv[i], "-vv") == 0)
			SetLogLevel(kLogTrace);
		else {
			Usage(argv[0]);
			return 1;
		}
	}

	if (setPassword) {
		std::string password;
		std::string again;
		if (!ReadPassword("New password: ", password)
			|| !ReadPassword("Again: ", again)) {
			return 1;
		}
		if (password != again || password.size() < 8) {
			fprintf(stderr, "The passwords differ or are shorter than eight "
				"characters.\n");
			WipeString(password);
			WipeString(again);
			return 1;
		}
		config.passwordHash = HashPassword(password);
		config.ntHash = NtHashHex(password);
		WipeString(password);
		WipeString(again);
		save = true;
	}

	if (save) {
		if (!SaveSettings(settingsPath, config))
			return 1;
		fprintf(stderr, "Settings saved to %s\n", settingsPath.c_str());
		if (setPassword)
			return 0;
	}

	if (config.passwordHash.empty()) {
		LOG_E("no password is set; set one in the Remote Desktop "
			"preferences or with %s --set-password", argv[0]);
		return StartupFailed(service);
	}

	signal(SIGPIPE, SIG_IGN);

	TlsContext tls;
	if (!tls.Init(directory + "/certificate.pem", directory + "/key.pem"))
		return StartupFailed(service);

	// The application first: capturing the screen needs its connection to
	// app_server.
	RemoteDesktopApp app;

	ObserverFrameSource observer;
	ScreenFrameSource polling;
	ScreenFrameSource* frames = &polling;
	const char* capture = "polling";
	if (!poll && observer.Start()) {
		frames = &observer;
		capture = "observer";
		LOG_I("capture: app_server screen observer");
	} else
		LOG_I("capture: reading the whole screen each frame");

	PortInputSink input;
	HaikuClipboard clipboard;
	// Copies from clients are kept for a week (scope document, 9.2).
	int removed = CleanUpIncomingFiles(clipboard.IncomingFilesFolder(),
		7 * 24 * 3600);
	if (removed > 0)
		LOG_I("removed %d copies older than a week from Remote files", removed);
	Server server(config, tls, *frames, input, clipboard);
	if (!server.Listen()) {
		frames->Release();
		return StartupFailed(service);
	}

	app.StartServer(&server, frames, &clipboard, capture, settingsPath,
		config);
	app.Run();
	return 0;
}
