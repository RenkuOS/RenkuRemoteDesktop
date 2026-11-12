/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */


#include <Application.h>
#include <FindDirectory.h>
#include <Path.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <thread>

#include "Auth.h"
#include "Log.h"
#include "PortInputSink.h"
#include "ObserverFrameSource.h"
#include "ScreenFrameSource.h"
#include "Server.h"
#include "Settings.h"
#include "Transport.h"


using namespace rrd;


static const char* kSignature = "application/x-vnd.RenkuOS-RemoteDesktop";


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
		fStopped(false)
	{
	}

	void StartServer(Server* server, ScreenFrameSource* frames)
	{
		fServer = server;
		fFrames = frames;
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
		if (message->what != kMsgServerStopped) {
			BApplication::MessageReceived(message);
			return;
		}
		// Run() has returned and no session is left.
		if (fThread.joinable())
			fThread.join();
		fFrames->Release();
		fStopped = true;
		PostMessage(B_QUIT_REQUESTED);
	}

private:
	Server*				fServer;
	ScreenFrameSource*	fFrames;
	std::thread			fThread;
	bool				fStopped;
};


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
		"  -v, -vv           more logging\n", name);
}


int
main(int argc, char** argv)
{
	BPath path;
	if (find_directory(B_USER_SETTINGS_DIRECTORY, &path) != B_OK)
		return 1;
	path.Append("RenkuRemoteDesktop");
	mkdir(path.Path(), 0700);
	std::string directory = path.Path();
	std::string settingsPath = directory + "/settings";

	ServerConfig config;
	LoadSettings(settingsPath, config);

	bool setPassword = false;
	bool save = false;
	bool poll = false;
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
		fprintf(stderr, "No password is set. Run %s --set-password first.\n",
			argv[0]);
		return 1;
	}

	signal(SIGPIPE, SIG_IGN);

	TlsContext tls;
	if (!tls.Init(directory + "/certificate.pem", directory + "/key.pem"))
		return 1;

	// The application first: capturing the screen needs its connection to
	// app_server.
	RemoteDesktopApp app;

	ObserverFrameSource observer;
	ScreenFrameSource polling;
	ScreenFrameSource* frames = &polling;
	if (!poll && observer.Start()) {
		frames = &observer;
		LOG_I("capture: app_server screen observer");
	} else
		LOG_I("capture: reading the whole screen each frame");

	PortInputSink input;
	Server server(config, tls, *frames, input);
	if (!server.Listen()) {
		frames->Release();
		return 1;
	}

	app.StartServer(&server, frames);
	app.Run();
	return 0;
}
