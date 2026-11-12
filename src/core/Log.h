/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */
#ifndef RRD_LOG_H
#define RRD_LOG_H


namespace rrd {


enum LogLevel {
	kLogError = 0,
	kLogWarning,
	kLogInfo,
	kLogDebug,
	kLogTrace
};


void SetLogLevel(LogLevel level);
LogLevel GetLogLevel();

// printf-style logging to stderr (and syslog on Haiku). Never log passwords
// or key material.
void Log(LogLevel level, const char* format, ...)
	__attribute__((format(printf, 2, 3)));

void LogHex(LogLevel level, const char* label, const void* data,
	unsigned long size);


}	// namespace rrd


#define LOG_E(...) rrd::Log(rrd::kLogError, __VA_ARGS__)
#define LOG_W(...) rrd::Log(rrd::kLogWarning, __VA_ARGS__)
#define LOG_I(...) rrd::Log(rrd::kLogInfo, __VA_ARGS__)
#define LOG_D(...) rrd::Log(rrd::kLogDebug, __VA_ARGS__)
#define LOG_T(...) rrd::Log(rrd::kLogTrace, __VA_ARGS__)


#endif	// RRD_LOG_H
