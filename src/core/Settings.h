/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */
#ifndef RRD_SETTINGS_H
#define RRD_SETTINGS_H


#include <string>

#include "Session.h"


namespace rrd {


// The settings file is plain "key = value" lines:
//
//   password_hash = pbkdf2-sha256$...
//   nt_hash = <32 hex digits>  (NTLM needs it for NLA; it is as secret as
//                               the password itself)
//   resize = fastest | match-client | keep
//   port = 3389
//   bind = 192.168.1.10        (empty: all interfaces)
//   frame_interval_ms = 40
//
// Unknown keys are ignored with a warning.
bool LoadSettings(const std::string& path, ServerConfig& config);

// Writes config back, creating the file with mode 0600.
bool SaveSettings(const std::string& path, const ServerConfig& config);

// Reads a password from the terminal without echo (or from stdin when it is
// not a terminal).
bool ReadPassword(const char* prompt, std::string& password);


}	// namespace rrd


#endif	// RRD_SETTINGS_H
