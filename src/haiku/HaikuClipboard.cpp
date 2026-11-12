/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */


#include "HaikuClipboard.h"

#include <Application.h>
#include <Clipboard.h>
#include <Entry.h>
#include <FindDirectory.h>
#include <Message.h>
#include <Node.h>
#include <Notification.h>
#include <Path.h>

#include <stdio.h>
#include <string.h>

#include "Log.h"


static const char* kTextType = "text/plain";
// Tracker's move modes (src/kits/tracker/Commands.h).
static const int32 kCopySelectionTo = 'Tcsl';


HaikuClipboard::HaikuClipboard()
	:
	fGeneration(0),
	fOwnCount(0)
{
}


void
HaikuClipboard::StartWatching()
{
	be_clipboard->StartWatching(be_app_messenger);
}


void
HaikuClipboard::StopWatching()
{
	be_clipboard->StopWatching(be_app_messenger);
}


void
HaikuClipboard::Changed()
{
	// Our own write is reported too; it is not news for the client. The
	// lock waits for a SetText() in progress to record its count.
	if (!be_clipboard->Lock())
		return;
	bool own = be_clipboard->SystemCount() == fOwnCount;
	be_clipboard->Unlock();
	if (!own)
		fGeneration++;
}


uint32_t
HaikuClipboard::Generation()
{
	return fGeneration;
}


bool
HaikuClipboard::GetText(std::string& text)
{
	if (!be_clipboard->Lock())
		return false;
	bool found = false;
	BMessage* data = be_clipboard->Data();
	const void* bytes;
	ssize_t size;
	if (data != NULL && data->FindData(kTextType, B_MIME_TYPE, &bytes, &size)
			== B_OK) {
		// Some applications include a terminating NUL.
		const char* chars = (const char*)bytes;
		while (size > 0 && chars[size - 1] == '\0')
			size--;
		text.assign(chars, size);
		found = true;
	}
	be_clipboard->Unlock();
	return found;
}


void
HaikuClipboard::SetText(const std::string& text)
{
	if (!be_clipboard->Lock())
		return;
	be_clipboard->Clear();
	BMessage* data = be_clipboard->Data();
	if (data != NULL) {
		data->AddData(kTextType, B_MIME_TYPE, text.data(), text.size());
		if (be_clipboard->Commit() != B_OK)
			LOG_W("clipboard: cannot commit the client's text");
	}
	fOwnCount = be_clipboard->SystemCount();
	be_clipboard->Unlock();
}


bool
HaikuClipboard::GetFiles(std::vector<std::string>& paths)
{
	paths.clear();
	if (!be_clipboard->Lock())
		return false;
	BMessage* data = be_clipboard->Data();
	if (data != NULL) {
		char* name;
		type_code type;
		int32 count;
		for (int32 i = 0; data->GetInfo(B_REF_TYPE, i, &name, &type, &count)
				== B_OK; i++) {
			// Tracker pairs each "r..." ref with an "m..." mode.
			if (name[0] != 'r')
				continue;
			char modeName[B_FILE_NAME_LENGTH];
			snprintf(modeName, sizeof(modeName), "m%s", name + 1);
			if (!data->HasInt32(modeName))
				continue;
			entry_ref ref;
			BPath path;
			if (data->FindRef(name, &ref) == B_OK
				&& path.SetTo(&ref) == B_OK) {
				paths.push_back(path.Path());
			}
		}
	}
	be_clipboard->Unlock();
	return !paths.empty();
}


void
HaikuClipboard::SetFiles(const std::vector<std::string>& paths)
{
	if (!be_clipboard->Lock())
		return;
	be_clipboard->Clear();
	BMessage* data = be_clipboard->Data();
	if (data != NULL) {
		for (size_t i = 0; i < paths.size(); i++) {
			BEntry entry(paths[i].c_str());
			entry_ref ref;
			node_ref node;
			if (entry.GetRef(&ref) != B_OK || entry.GetNodeRef(&node) != B_OK)
				continue;
			char refName[64];
			char modeName[64];
			snprintf(refName, sizeof(refName), "r%" B_PRIdDEV "_%" B_PRIdINO,
				node.device, node.node);
			snprintf(modeName, sizeof(modeName), "m%" B_PRIdDEV "_%" B_PRIdINO,
				node.device, node.node);
			data->AddInt32(modeName, kCopySelectionTo);
			data->AddRef(refName, &ref);
		}
		if (be_clipboard->Commit() != B_OK)
			LOG_W("clipboard: cannot commit the client's files");
	}
	fOwnCount = be_clipboard->SystemCount();
	be_clipboard->Unlock();
}


std::string
HaikuClipboard::IncomingFilesFolder()
{
	BPath path;
	if (find_directory(B_DESKTOP_DIRECTORY, &path) != B_OK
		|| path.Append("Remote files") != B_OK) {
		return std::string();
	}
	return path.Path();
}


void
HaikuClipboard::Notify(const std::string& message)
{
	BNotification notification(B_INFORMATION_NOTIFICATION);
	notification.SetGroup("Remote Desktop");
	notification.SetTitle("Files from the remote computer");
	notification.SetContent(message.c_str());
	notification.Send();
}
