/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */
#ifndef RRD_PREFS_WINDOW_H
#define RRD_PREFS_WINDOW_H


#include <String.h>
#include <Window.h>

#include "Session.h"


class BButton;
class BCheckBox;
class BMenuField;
class BMessageRunner;
class BPopUpMenu;
class BStringView;
class BTextControl;
class BTextView;


class PrefsWindow : public BWindow {
public:
								PrefsWindow();
	virtual						~PrefsWindow();

	virtual	void				MessageReceived(BMessage* message);

private:
			void				_Load();
			void				_Save();
			void				_ApplyEnabled(bool enabled);
			void				_UpdateControls();
			void				_UpdateStatus(const BMessage* status);
			void				_UpdateFingerprint();
			void				_FillAddressMenu();
			void				_Pulse();

			BCheckBox*			fEnable;
			BStringView*		fStatus;
			BStringView*		fDetail;
			BButton*			fDisconnect;
			BStringView*		fPasswordState;
			BStringView*		fWindowsNote;
			BButton*			fSetPassword;
			BTextControl*		fPort;
			BPopUpMenu*			fAddressMenu;
			BMenuField*			fAddressField;
			BPopUpMenu*			fResizeMenu;
			BMenuField*			fResizeField;
			BTextView*			fFingerprint;
			BButton*			fDefaults;
			BButton*			fRevert;
			BMessageRunner*		fPulse;

			BString				fSettingsPath;
			BString				fCertificatePath;
			rrd::ServerConfig	fConfig;
			rrd::ServerConfig	fOriginal;
			bool				fOriginalEnabled;
			bool				fEnableAfterPassword;
			bool				fRestartPending;
			bool				fManualRestartNeeded;
			bigtime_t			fStartedAt;
			bigtime_t			fStoppedAt;
			bigtime_t			fRestartRequestedAt;
			bigtime_t			fStatusRequestedAt;
			bool				fHaveFingerprint;
};


#endif	// RRD_PREFS_WINDOW_H
