/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */


#include "Log.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#ifdef __HAIKU__
#	include <syslog.h>
#endif


namespace rrd {


static LogLevel sLevel = kLogInfo;
static pthread_mutex_t sLock = PTHREAD_MUTEX_INITIALIZER;


void
SetLogLevel(LogLevel level)
{
	sLevel = level;
}


LogLevel
GetLogLevel()
{
	return sLevel;
}


void
Log(LogLevel level, const char* format, ...)
{
	if (level > sLevel)
		return;

	static const char* kNames[] = { "error", "warning", "info", "debug",
		"trace" };

	char message[1024];
	va_list args;
	va_start(args, format);
	vsnprintf(message, sizeof(message), format, args);
	va_end(args);

	struct timespec now;
	clock_gettime(CLOCK_REALTIME, &now);
	struct tm local;
	localtime_r(&now.tv_sec, &local);

	pthread_mutex_lock(&sLock);
	fprintf(stderr, "%02d:%02d:%02d.%03ld RenkuRemoteDesktop %s: %s\n",
		local.tm_hour, local.tm_min, local.tm_sec, now.tv_nsec / 1000000,
		kNames[level], message);
	pthread_mutex_unlock(&sLock);

#ifdef __HAIKU__
	{
		// Everything the level lets through: when the server runs as a
		// service, its stderr goes nowhere, so the system log is the only
		// place debug output can be read.
		static const int kPriorities[] = { LOG_ERR, LOG_WARNING, LOG_INFO,
			LOG_DEBUG, LOG_DEBUG };
		syslog(kPriorities[level], "RenkuRemoteDesktop: %s", message);
	}
#endif
}


void
LogHex(LogLevel level, const char* label, const void* data, unsigned long size)
{
	if (level > sLevel)
		return;

	const unsigned char* bytes = (const unsigned char*)data;
	char line[3 * 16 + 1];
	Log(level, "%s (%lu bytes)", label, size);
	for (unsigned long offset = 0; offset < size; offset += 16) {
		int length = 0;
		for (unsigned long i = offset; i < size && i < offset + 16; i++)
			length += snprintf(line + length, sizeof(line) - length, "%02x ",
				bytes[i]);
		Log(level, "  %04lx  %s", offset, line);
	}
}


}	// namespace rrd
