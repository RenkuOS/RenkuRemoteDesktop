/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */
#ifndef RRD_PORT_INPUT_SINK_H
#define RRD_PORT_INPUT_SINK_H


#include <OS.h>

#include "Platform.h"


// Forwards input to the RenkuRemoteDesktopInput add-on in input_server.
class PortInputSink : public rrd::InputSink {
public:
								PortInputSink();

	virtual	void				Key(uint8_t scancode, bool extended,
									bool extended1, bool down);
	virtual	void				UnicodeKey(uint16_t codeUnit, bool down);
	virtual	void				Pointer(int32_t x, int32_t y,
									uint32_t buttons);
	virtual	void				Wheel(int32_t delta, bool horizontal);
	virtual	void				SyncLocks(uint32_t flags);
	virtual	void				ReleaseAll();

private:
			void				_Send(int32 type, int32 a, int32 b, int32 c);

			port_id				fPort;
			bigtime_t			fLastLookup;
			bool				fWarned;
};


#endif	// RRD_PORT_INPUT_SINK_H
