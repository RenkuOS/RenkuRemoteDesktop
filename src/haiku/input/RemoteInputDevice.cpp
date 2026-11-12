/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */


// input_server device add-on that turns RDP input from the
// RenkuRemoteDesktop server into Haiku input events. It registers one
// keyboard and one pointing device and reads events from a port.
//
// Key handling follows Haiku's own KeyboardInputDevice (key states,
// modifiers, B_MODIFIERS_CHANGED, B_KEY_DOWN and B_UNMAPPED_KEY_DOWN), using
// the same scancode table (ATKeymap.h) and keymap code (BKeymap). Dead keys
// are not handled yet.


#include <Autolock.h>
#include <InputServerDevice.h>
#include <InterfaceDefs.h>
#include <Message.h>
#include <OS.h>

#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <private/input/ATKeymap.h>
#include <private/shared/Keymap.h>

#include "../InputProtocol.h"


static const char* kKeyboardName = "RenkuRemoteDesktop keyboard";
static const char* kPointerName = "RenkuRemoteDesktop pointer";


class RemoteInputDevice : public BInputServerDevice {
public:
								RemoteInputDevice();
	virtual						~RemoteInputDevice();

	virtual	status_t			InitCheck();
	virtual	status_t			Start(const char* name, void* cookie);
	virtual	status_t			Stop(const char* name, void* cookie);
	virtual	status_t			Control(const char* name, void* cookie,
									uint32 command, BMessage* message);

private:
	static	int32				_ThreadEntry(void* data);
			void				_Thread();

			void				_Key(uint32 keycode, bool down);
			void				_Unicode(uint16 codeUnit, bool down);
			void				_Pointer(int32 x, int32 y, uint32 buttons);
			void				_Wheel(int32 delta, bool horizontal);
			void				_Locks(uint32 rdpFlags);
			void				_ReleaseAll();
			void				_ModifiersChanged(uint32 oldModifiers);
			void				_Enqueue(BMessage* message);

			port_id				fPort;
			thread_id			fThread;
			int32				fStarted;

			// Control() reloads the keymap on an input_server thread while
			// the reader thread uses it, as in KeyboardInputDevice.
			BLocker				fKeymapLock;
			BKeymap				fKeymap;
			uint32				fModifiers;
			uint8				fStates[16];
			uint32				fLastKeycode;
			int32				fRepeatCount;
			uint16				fHighSurrogate;

			uint32				fButtons;
			BPoint				fWhere;
			bigtime_t			fLastClick;
			uint32				fLastClickButtons;
			BPoint				fLastClickWhere;
			int32				fClicks;
};


RemoteInputDevice::RemoteInputDevice()
	:
	fPort(-1),
	fThread(-1),
	fStarted(0),
	fModifiers(0),
	fLastKeycode(0),
	fRepeatCount(0),
	fHighSurrogate(0),
	fButtons(0),
	fWhere(0, 0),
	fLastClick(0),
	fLastClickButtons(0),
	fClicks(0)
{
	memset(fStates, 0, sizeof(fStates));
}


RemoteInputDevice::~RemoteInputDevice()
{
}


status_t
RemoteInputDevice::InitCheck()
{
	static input_device_ref keyboard = { (char*)kKeyboardName,
		B_KEYBOARD_DEVICE, NULL };
	static input_device_ref pointer = { (char*)kPointerName,
		B_POINTING_DEVICE, NULL };
	static input_device_ref* devices[] = { &keyboard, &pointer, NULL };

	{
		BAutolock lock(fKeymapLock);
		fKeymap.SetToCurrent();
	}
	RegisterDevices(devices);
	return B_OK;
}


status_t
RemoteInputDevice::Start(const char* name, void* cookie)
{
	if (fStarted++ > 0)
		return B_OK;

	fPort = create_port(64, RRD_INPUT_PORT_NAME);
	if (fPort < 0) {
		fStarted--;
		return fPort;
	}
	fThread = spawn_thread(_ThreadEntry, "RenkuRemoteDesktop input",
		B_URGENT_DISPLAY_PRIORITY, this);
	if (fThread < 0) {
		delete_port(fPort);
		fPort = -1;
		fStarted--;
		return fThread;
	}
	resume_thread(fThread);
	return B_OK;
}


status_t
RemoteInputDevice::Stop(const char* name, void* cookie)
{
	if (fStarted == 0 || --fStarted > 0)
		return B_OK;

	// Deleting the port ends the reader thread.
	delete_port(fPort);
	fPort = -1;
	status_t result;
	wait_for_thread(fThread, &result);
	fThread = -1;
	return B_OK;
}


status_t
RemoteInputDevice::Control(const char* name, void* cookie, uint32 command,
	BMessage* message)
{
	if (command == B_KEY_MAP_CHANGED) {
		BAutolock lock(fKeymapLock);
		fKeymap.SetToCurrent();
	}
	return B_OK;
}


int32
RemoteInputDevice::_ThreadEntry(void* data)
{
	((RemoteInputDevice*)data)->_Thread();
	return 0;
}


void
RemoteInputDevice::_Thread()
{
	while (true) {
		remote_input_event event;
		int32 code;
		ssize_t size = read_port(fPort, &code, &event, sizeof(event));
		if (size == B_INTERRUPTED)
			continue;
		if (size < 0)
			break;
		if (size != sizeof(event) || event.version != kRemoteInputVersion)
			continue;

		switch (event.type) {
			case RRD_INPUT_KEY:
			{
				// Same index as the PS/2 driver: E0 keys have bit 7 set,
				// Pause (E1 1D 45) is 0x80 | 0x46.
				uint32 scancode = event.a & 0x7f;
				if ((event.b & RRD_KEY_EXTENDED) != 0)
					scancode |= 0x80;
				if ((event.b & RRD_KEY_EXTENDED1) != 0 && scancode == 0x1d)
					scancode = 0x80 | 0x46;
				if (scancode == 0 || scancode > sizeof(kATKeycodeMap)
						/ sizeof(kATKeycodeMap[0])) {
					break;
				}
				uint32 keycode = kATKeycodeMap[scancode - 1];
				// Entries above 0xff are HID consumer and system codes.
				if (keycode != 0 && keycode < 0x100)
					_Key(keycode, event.c != 0);
				break;
			}
			case RRD_INPUT_UNICODE:
				_Unicode((uint16)event.a, event.c != 0);
				break;
			case RRD_INPUT_POINTER:
				_Pointer(event.a, event.b, (uint32)event.c);
				break;
			case RRD_INPUT_WHEEL:
				_Wheel(event.a, event.b != 0);
				break;
			case RRD_INPUT_LOCKS:
				_Locks((uint32)event.a);
				break;
			case RRD_INPUT_RELEASE_ALL:
				_ReleaseAll();
				break;
		}
	}
}


void
RemoteInputDevice::_Enqueue(BMessage* message)
{
	if (EnqueueMessage(message) != B_OK)
		delete message;
}


void
RemoteInputDevice::_ModifiersChanged(uint32 oldModifiers)
{
	BMessage* message = new BMessage(B_MODIFIERS_CHANGED);
	message->AddInt64("when", system_time());
	message->AddInt32("be:old_modifiers", oldModifiers);
	message->AddInt32("modifiers", fModifiers);
	message->AddData("states", B_UINT8_TYPE, fStates, 16);
	_Enqueue(message);
}


void
RemoteInputDevice::_Key(uint32 keycode, bool down)
{
	bool wasDown = (fStates[keycode >> 3] & (1 << (7 - (keycode & 7)))) != 0;
	if (!down && !wasDown)
		return;

	if (down)
		fStates[keycode >> 3] |= 1 << (7 - (keycode & 7));
	else
		fStates[keycode >> 3] &= ~(1 << (7 - (keycode & 7)));

	BAutolock lock(fKeymapLock);
	uint32 modifiers = fKeymap.Modifier(keycode);
	bool isLock = (modifiers & (B_CAPS_LOCK | B_NUM_LOCK | B_SCROLL_LOCK)) != 0;
	if (modifiers != 0 && (!isLock || down)) {
		uint32 oldModifiers = fModifiers;
		if ((down && !isLock) || (down && (fModifiers & modifiers) == 0))
			fModifiers |= modifiers;
		else {
			fModifiers &= ~modifiers;
			if ((fModifiers & (B_LEFT_SHIFT_KEY | B_RIGHT_SHIFT_KEY)) != 0)
				fModifiers |= B_SHIFT_KEY;
			if ((fModifiers & (B_LEFT_COMMAND_KEY | B_RIGHT_COMMAND_KEY)) != 0)
				fModifiers |= B_COMMAND_KEY;
			if ((fModifiers & (B_LEFT_CONTROL_KEY | B_RIGHT_CONTROL_KEY)) != 0)
				fModifiers |= B_CONTROL_KEY;
			if ((fModifiers & (B_LEFT_OPTION_KEY | B_RIGHT_OPTION_KEY)) != 0)
				fModifiers |= B_OPTION_KEY;
		}
		if (fModifiers != oldModifiers)
			_ModifiersChanged(oldModifiers);
	}

	char* string = NULL;
	char* rawString = NULL;
	int32 numBytes = 0;
	int32 rawNumBytes = 0;
	fKeymap.GetChars(keycode, fModifiers, 0, &string, &numBytes);
	fKeymap.GetChars(keycode, 0, 0, &rawString, &rawNumBytes);

	BMessage* message = new BMessage(numBytes > 0
		? (down ? B_KEY_DOWN : B_KEY_UP)
		: (down ? B_UNMAPPED_KEY_DOWN : B_UNMAPPED_KEY_UP));
	message->AddInt64("when", system_time());
	message->AddInt32("key", keycode);
	message->AddInt32("modifiers", fModifiers);
	message->AddData("states", B_UINT8_TYPE, fStates, 16);
	if (numBytes > 0) {
		for (int32 i = 0; i < numBytes; i++)
			message->AddInt8("byte", (int8)string[i]);
		message->AddData("bytes", B_STRING_TYPE, string, numBytes + 1);

		if (down && fLastKeycode == keycode) {
			fRepeatCount++;
			message->AddInt32("be:key_repeat", fRepeatCount);
		} else
			fRepeatCount = 1;
	}
	if (rawNumBytes > 0)
		message->AddInt32("raw_char", (uint32)((uint8)rawString[0] & 0x7f));
	else if (numBytes > 0)
		message->AddInt32("raw_char", (uint32)((uint8)string[0] & 0x7f));

	delete[] string;
	delete[] rawString;

	fLastKeycode = down ? keycode : 0;
	_Enqueue(message);
}


void
RemoteInputDevice::_Unicode(uint16 codeUnit, bool down)
{
	uint32 c = codeUnit;
	if (c >= 0xd800 && c <= 0xdbff) {
		fHighSurrogate = codeUnit;
		return;
	}
	if (c >= 0xdc00 && c <= 0xdfff) {
		if (fHighSurrogate == 0)
			return;
		c = 0x10000 + ((fHighSurrogate - 0xd800) << 10) + (c - 0xdc00);
	}
	if (!down)
		fHighSurrogate = 0;

	char bytes[5];
	int32 length;
	if (c < 0x80) {
		bytes[0] = c;
		length = 1;
	} else if (c < 0x800) {
		bytes[0] = 0xc0 | (c >> 6);
		bytes[1] = 0x80 | (c & 0x3f);
		length = 2;
	} else if (c < 0x10000) {
		bytes[0] = 0xe0 | (c >> 12);
		bytes[1] = 0x80 | ((c >> 6) & 0x3f);
		bytes[2] = 0x80 | (c & 0x3f);
		length = 3;
	} else {
		bytes[0] = 0xf0 | (c >> 18);
		bytes[1] = 0x80 | ((c >> 12) & 0x3f);
		bytes[2] = 0x80 | ((c >> 6) & 0x3f);
		bytes[3] = 0x80 | (c & 0x3f);
		length = 4;
	}
	bytes[length] = '\0';

	BMessage* message = new BMessage(down ? B_KEY_DOWN : B_KEY_UP);
	message->AddInt64("when", system_time());
	message->AddInt32("key", 0);
	message->AddInt32("modifiers", fModifiers);
	message->AddData("states", B_UINT8_TYPE, fStates, 16);
	for (int32 i = 0; i < length; i++)
		message->AddInt8("byte", (int8)bytes[i]);
	message->AddData("bytes", B_STRING_TYPE, bytes, length + 1);
	message->AddInt32("raw_char", c < 0x80 ? c : 0);
	_Enqueue(message);
}


void
RemoteInputDevice::_Pointer(int32 x, int32 y, uint32 buttons)
{
	// Haiku: bit 0 primary (left), bit 1 secondary (right), bit 2 tertiary
	// (middle); the server uses the same order.
	uint32 changed = buttons ^ fButtons;
	BPoint where(x, y);
	bigtime_t now = system_time();

	uint32 what = B_MOUSE_MOVED;
	if ((changed & buttons) != 0)
		what = B_MOUSE_DOWN;
	else if (changed != 0)
		what = B_MOUSE_UP;
	else if (where == fWhere)
		return;

	// app_server takes the cursor position only from B_MOUSE_MOVED. It
	// reports a button event at that position, whatever the event itself
	// says (EventDispatcher). RDP clients send a move and a click as one
	// button event with the new position, so move there first.
	if (what != B_MOUSE_MOVED && where != fWhere) {
		BMessage* moved = new BMessage(B_MOUSE_MOVED);
		moved->AddInt64("when", now);
		moved->AddInt32("buttons", fButtons);
		moved->AddPoint("where", where);
		fWhere = where;
		_Enqueue(moved);
	}

	BMessage* message = new BMessage(what);
	message->AddInt64("when", now);
	message->AddInt32("buttons", buttons);
	// An absolute position; input_server takes "where" as is.
	message->AddPoint("where", where);

	if (what == B_MOUSE_DOWN) {
		bigtime_t clickSpeed = 500000;
		get_click_speed(&clickSpeed);
		if (buttons == fLastClickButtons && now - fLastClick <= clickSpeed
			&& fabs(where.x - fLastClickWhere.x) <= 4
			&& fabs(where.y - fLastClickWhere.y) <= 4) {
			fClicks++;
		} else
			fClicks = 1;
		fLastClick = now;
		fLastClickButtons = buttons;
		fLastClickWhere = where;
		message->AddInt32("clicks", fClicks);
	}

	fButtons = buttons;
	fWhere = where;
	_Enqueue(message);
}


void
RemoteInputDevice::_Wheel(int32 delta, bool horizontal)
{
	// RDP: 120 units per notch, positive away from the user (up) or to the
	// right. Haiku: positive delta_y scrolls down.
	BMessage* message = new BMessage(B_MOUSE_WHEEL_CHANGED);
	message->AddInt64("when", system_time());
	message->AddFloat("be:wheel_delta_x", horizontal ? delta / 120.0f : 0.0f);
	message->AddFloat("be:wheel_delta_y", horizontal ? 0.0f : -delta / 120.0f);
	_Enqueue(message);
}


void
RemoteInputDevice::_Locks(uint32 rdpFlags)
{
	uint32 locks = 0;
	if ((rdpFlags & 0x01) != 0)
		locks |= B_SCROLL_LOCK;
	if ((rdpFlags & 0x02) != 0)
		locks |= B_NUM_LOCK;
	if ((rdpFlags & 0x04) != 0)
		locks |= B_CAPS_LOCK;

	uint32 oldModifiers = fModifiers;
	fModifiers = (fModifiers & ~(B_SCROLL_LOCK | B_NUM_LOCK | B_CAPS_LOCK))
		| locks;
	if (fModifiers != oldModifiers)
		_ModifiersChanged(oldModifiers);
}


void
RemoteInputDevice::_ReleaseAll()
{
	for (uint32 keycode = 0; keycode < 128; keycode++) {
		if ((fStates[keycode >> 3] & (1 << (7 - (keycode & 7)))) != 0)
			_Key(keycode, false);
	}
	if (fButtons != 0)
		_Pointer((int32)fWhere.x, (int32)fWhere.y, 0);
	fHighSurrogate = 0;
}


extern "C" BInputServerDevice*
instantiate_input_device()
{
	return new(std::nothrow) RemoteInputDevice();
}
