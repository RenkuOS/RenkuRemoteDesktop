/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */
#ifndef RRD_HAIKU_CLIPBOARD_H
#define RRD_HAIKU_CLIPBOARD_H


#include <SupportDefs.h>

#include <atomic>

#include "Platform.h"


// The system clipboard (be_clipboard), as "text/plain" in UTF-8. The
// application calls Changed() on every B_CLIPBOARD_CHANGED; changes made by
// SetText() itself do not count.
class HaikuClipboard : public rrd::Clipboard {
public:
								HaikuClipboard();

			// Starts B_CLIPBOARD_CHANGED messages to the application.
			void				StartWatching();
			void				StopWatching();
			void				Changed();

	virtual	uint32_t			Generation();
	virtual	bool				GetText(std::string& text);
	virtual	void				SetText(const std::string& text);

	// Files use Tracker's clipboard format: an entry_ref named
	// "r<device>_<node>" and an int32 move mode "m<device>_<node>"
	// (src/kits/tracker/FSClipboard.cpp).
	virtual	bool				GetFiles(std::vector<std::string>& paths);
	virtual	void				SetFiles(const std::vector<std::string>& paths);
	// ~/Desktop/Remote files
	virtual	std::string			IncomingFilesFolder();
	virtual	void				Notify(const std::string& message);

private:
			std::atomic<uint32_t> fGeneration;
			// The clipboard's system count after our own last write.
			std::atomic<uint32> fOwnCount;
};


#endif	// RRD_HAIKU_CLIPBOARD_H
