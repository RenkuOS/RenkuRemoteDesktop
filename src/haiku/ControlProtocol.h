/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */
#ifndef RRD_CONTROL_PROTOCOL_H
#define RRD_CONTROL_PROTOCOL_H


// How the Remote Desktop preferences talk to the running server, and where
// both keep their files.


#include <FindDirectory.h>
#include <Path.h>
#include <SupportDefs.h>


// The server's application signature. As a launch_daemon service its job
// name is the same without "application/".
#define RRD_SERVER_SIGNATURE	"application/x-vnd.RenkuOS-RemoteDesktop"
#define RRD_SERVICE_NAME		"x-vnd.RenkuOS-RemoteDesktop"

enum {
	// Asks for the server's state. Reply: RRD_MSG_STATUS.
	RRD_MSG_GET_STATUS		= 'rrGS',
	// "port" int32, "bind" string ("" for all addresses),
	// "capture" string ("observer" or "polling"), "nla" bool (whether
	// Windows clients can log in), "connected" bool, and when connected:
	// "peer" string, "user" string, "session_nla" bool, "since" int64
	// (seconds since the epoch).
	RRD_MSG_STATUS			= 'rrST',
	// Ends the active session.
	RRD_MSG_DISCONNECT		= 'rrDC',
	// Reads the settings file again. Reply: RRD_MSG_RELOADED.
	RRD_MSG_RELOAD_SETTINGS	= 'rrRL',
	// "status" int32 (B_OK when the file was read), "restart" bool (the
	// port or address changed, which takes a restart).
	RRD_MSG_RELOADED		= 'rrRD'
};


// ~/config/settings/RenkuRemoteDesktop. It holds "settings", the
// certificate and key, and "enabled", whose presence makes launch_daemon
// start the server at login.
static inline status_t
rrd_settings_directory(BPath& path)
{
	status_t status = find_directory(B_USER_SETTINGS_DIRECTORY, &path);
	if (status == B_OK)
		status = path.Append("RenkuRemoteDesktop");
	return status;
}


#endif	// RRD_CONTROL_PROTOCOL_H
