/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */


#include "ServiceControl.h"

#include <Entry.h>
#include <File.h>
#include <Messenger.h>
#include <Path.h>
#include <Roster.h>

#include <private/app/LaunchRoster.h>

#include <sys/stat.h>

#include "../ControlProtocol.h"


static status_t
EnabledPath(BPath& path)
{
	status_t status = rrd_settings_directory(path);
	if (status != B_OK)
		return status;
	mkdir(path.Path(), 0700);
	return path.Append("enabled");
}


bool
ServiceControl::IsEnabled()
{
	BPath path;
	return EnabledPath(path) == B_OK && BEntry(path.Path()).Exists();
}


status_t
ServiceControl::SetEnabled(bool enabled)
{
	BPath path;
	status_t status = EnabledPath(path);
	if (status != B_OK)
		return status;
	if (enabled) {
		BFile file(path.Path(), B_WRITE_ONLY | B_CREATE_FILE);
		return file.InitCheck();
	}
	BEntry entry(path.Path());
	if (!entry.Exists())
		return B_OK;
	return entry.Remove();
}


bool
ServiceControl::IsRunning()
{
	return be_roster->IsRunning(RRD_SERVER_SIGNATURE);
}


status_t
ServiceControl::Start()
{
	// Through launch_daemon, so that it knows the service is wanted and
	// restarts it if it crashes. It checks the "enabled" file again.
	BLaunchRoster roster;
	status_t status = roster.Start(RRD_SERVICE_NAME);
	if (status == B_OK)
		return B_OK;

	// No service installed: start the server directly.
	return be_roster->Launch(RRD_SERVER_SIGNATURE);
}


status_t
ServiceControl::Stop()
{
	// First launch_daemon disables the service, so that it does not restart
	// the server, and asks it to quit. A server started by hand gets the
	// request directly; a second request does no harm.
	BLaunchRoster roster;
	roster.Stop(RRD_SERVICE_NAME);

	BMessenger server(RRD_SERVER_SIGNATURE);
	if (!server.IsValid())
		return B_OK;
	return server.SendMessage(B_QUIT_REQUESTED);
}


status_t
ServiceControl::Restart()
{
	BMessenger server(RRD_SERVER_SIGNATURE);
	if (!server.IsValid())
		return B_OK;
	return server.SendMessage(B_QUIT_REQUESTED);
}
