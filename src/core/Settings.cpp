/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */


#include "Settings.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "Log.h"


namespace rrd {


static std::string
Trim(const std::string& text)
{
	size_t start = text.find_first_not_of(" \t\r\n");
	if (start == std::string::npos)
		return std::string();
	size_t end = text.find_last_not_of(" \t\r\n");
	return text.substr(start, end - start + 1);
}


bool
LoadSettings(const std::string& path, ServerConfig& config)
{
	FILE* file = fopen(path.c_str(), "r");
	if (file == NULL) {
		if (errno != ENOENT)
			LOG_W("cannot read %s: %s", path.c_str(), strerror(errno));
		return false;
	}

	char line[1024];
	int lineNumber = 0;
	while (fgets(line, sizeof(line), file) != NULL) {
		lineNumber++;
		std::string text = Trim(line);
		if (text.empty() || text[0] == '#')
			continue;
		size_t equals = text.find('=');
		if (equals == std::string::npos) {
			LOG_W("%s:%d: expected key = value", path.c_str(), lineNumber);
			continue;
		}
		std::string key = Trim(text.substr(0, equals));
		std::string value = Trim(text.substr(equals + 1));

		if (key == "password_hash")
			config.passwordHash = value;
		else if (key == "nt_hash")
			config.ntHash = value;
		else if (key == "resize") {
			if (!ParseResizePolicy(value.c_str(), config.resize))
				LOG_W("%s:%d: unknown resize policy \"%s\"", path.c_str(),
					lineNumber, value.c_str());
		} else if (key == "port") {
			int port = atoi(value.c_str());
			if (port > 0 && port < 65536)
				config.port = port;
		} else if (key == "bind")
			config.bindAddress = value;
		else if (key == "frame_interval_ms") {
			int interval = atoi(value.c_str());
			if (interval >= 10 && interval <= 1000)
				config.frameIntervalMs = interval;
		} else
			LOG_W("%s:%d: unknown setting \"%s\"", path.c_str(), lineNumber,
				key.c_str());
	}
	fclose(file);
	return true;
}


bool
SaveSettings(const std::string& path, const ServerConfig& config)
{
	std::string temporary = path + ".new";
	int fd = open(temporary.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		LOG_E("cannot write %s: %s", temporary.c_str(), strerror(errno));
		return false;
	}
	FILE* file = fdopen(fd, "w");
	if (file == NULL) {
		close(fd);
		return false;
	}

	fprintf(file, "# RenkuRemoteDesktop settings\n");
	fprintf(file, "password_hash = %s\n", config.passwordHash.c_str());
	fprintf(file, "nt_hash = %s\n", config.ntHash.c_str());
	fprintf(file, "resize = %s\n", ResizePolicyName(config.resize));
	fprintf(file, "port = %u\n", config.port);
	fprintf(file, "bind = %s\n", config.bindAddress.c_str());
	fprintf(file, "frame_interval_ms = %d\n", config.frameIntervalMs);

	bool ok = fflush(file) == 0 && fsync(fd) == 0;
	ok &= fclose(file) == 0;
	if (ok && rename(temporary.c_str(), path.c_str()) != 0) {
		LOG_E("cannot replace %s: %s", path.c_str(), strerror(errno));
		ok = false;
	}
	return ok;
}


bool
ReadPassword(const char* prompt, std::string& password)
{
	bool terminal = isatty(STDIN_FILENO);
	struct termios saved;
	if (terminal) {
		fprintf(stderr, "%s", prompt);
		tcgetattr(STDIN_FILENO, &saved);
		struct termios quiet = saved;
		quiet.c_lflag &= ~ECHO;
		tcsetattr(STDIN_FILENO, TCSANOW, &quiet);
	}

	char buffer[512];
	bool ok = fgets(buffer, sizeof(buffer), stdin) != NULL;

	if (terminal) {
		tcsetattr(STDIN_FILENO, TCSANOW, &saved);
		fprintf(stderr, "\n");
	}
	if (!ok)
		return false;

	size_t length = strcspn(buffer, "\r\n");
	password.assign(buffer, length);
	memset(buffer, 0, sizeof(buffer));
	return true;
}


}	// namespace rrd
