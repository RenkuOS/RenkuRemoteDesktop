/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */
#ifndef RRD_SERVICE_CONTROL_H
#define RRD_SERVICE_CONTROL_H


// Turns the server on and off. launch_daemon starts it at login when the
// "enabled" file exists (data/user_launch/RenkuRemoteDesktop). Where that
// service is not installed, as in a development build, the server is
// launched and quit directly instead.


#include <SupportDefs.h>


namespace ServiceControl {

bool		IsEnabled();
status_t	SetEnabled(bool enabled);

bool		IsRunning();
status_t	Start();
status_t	Stop();
// Asks the server to quit without disabling its launch_daemon job, which
// then starts it again.
status_t	Restart();

}	// namespace ServiceControl


#endif	// RRD_SERVICE_CONTROL_H
