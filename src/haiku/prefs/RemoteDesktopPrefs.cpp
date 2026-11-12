/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */


// Remote Desktop preferences: turns the RDP server on and off, sets its
// password, and shows who is connected.


#include <Application.h>

#include "PrefsWindow.h"


static const char* kSignature = "application/x-vnd.RenkuOS-RemoteDesktopPrefs";


class RemoteDesktopPrefs : public BApplication {
public:
	RemoteDesktopPrefs()
		:
		BApplication(kSignature)
	{
	}

	virtual void ReadyToRun()
	{
		(new PrefsWindow())->Show();
	}
};


int
main()
{
	RemoteDesktopPrefs app;
	app.Run();
	return 0;
}
