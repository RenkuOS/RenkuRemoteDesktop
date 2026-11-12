/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */


#include "PrefsWindow.h"

#include <Alert.h>
#include <Beep.h>
#include <Box.h>
#include <Button.h>
#include <Catalog.h>
#include <CheckBox.h>
#include <LayoutBuilder.h>
#include <MenuField.h>
#include <MenuItem.h>
#include <MessageRunner.h>
#include <Messenger.h>
#include <NetworkAddress.h>
#include <NetworkInterface.h>
#include <NetworkRoster.h>
#include <Path.h>
#include <PopUpMenu.h>
#include <StringView.h>
#include <TextControl.h>
#include <TextView.h>

#include <math.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "../ControlProtocol.h"
#include "Auth.h"
#include "PasswordWindow.h"
#include "Resize.h"
#include "ServiceControl.h"
#include "Settings.h"


#undef B_TRANSLATION_CONTEXT
#define B_TRANSLATION_CONTEXT "PrefsWindow"


using rrd::ServerConfig;


static const uint32 kMsgEnable = 'peEn';
static const uint32 kMsgDisconnect = 'peDc';
static const uint32 kMsgSetPassword = 'peSP';
static const uint32 kMsgPort = 'pePo';
static const uint32 kMsgAddress = 'peAd';
static const uint32 kMsgResize = 'peRs';
static const uint32 kMsgDefaults = 'peDf';
static const uint32 kMsgRevert = 'peRv';
static const uint32 kMsgPulse = 'pePu';

// How long "Starting…" is shown before a server that does not come up is
// reported as not running.
static const bigtime_t kStartGrace = 5000000;
// A running server that has not answered a status request for this long is
// shown as not running.
static const bigtime_t kStatusTimeout = 3000000;

static const struct {
	rrd::ResizePolicy	policy;
	const char*			label;
} kResizeChoices[] = {
	{ rrd::RESIZE_FASTEST,
		B_TRANSLATE_MARK("Smaller of this screen and the client's") },
	{ rrd::RESIZE_MATCH_CLIENT, B_TRANSLATE_MARK("Same as the client's") },
	{ rrd::RESIZE_KEEP, B_TRANSLATE_MARK("Keep this screen's size") }
};


static BString
Fingerprint(const char* path)
{
	BString text;
	FILE* file = fopen(path, "r");
	if (file == NULL)
		return text;
	X509* certificate = PEM_read_X509(file, NULL, NULL, NULL);
	fclose(file);
	if (certificate == NULL)
		return text;

	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int size = 0;
	if (X509_digest(certificate, EVP_sha256(), digest, &size) == 1) {
		// Two lines of 16 bytes, as colon-separated hex.
		for (unsigned int i = 0; i < size; i++) {
			char hex[4];
			snprintf(hex, sizeof(hex), "%02X", digest[i]);
			if (i > 0)
				text << (i == size / 2 ? "\n" : ":");
			text << hex;
		}
	}
	X509_free(certificate);
	return text;
}


static BString
FormatSince(int64 since)
{
	time_t when = (time_t)since;
	time_t now = time(NULL);
	struct tm local;
	struct tm today;
	localtime_r(&when, &local);
	localtime_r(&now, &today);
	char buffer[64];
	if (local.tm_year == today.tm_year && local.tm_yday == today.tm_yday)
		strftime(buffer, sizeof(buffer), "%H:%M", &local);
	else
		strftime(buffer, sizeof(buffer), "%b %e, %H:%M", &local);
	return BString(buffer);
}


PrefsWindow::PrefsWindow()
	:
	BWindow(BRect(0, 0, 400, 300), B_TRANSLATE_SYSTEM_NAME("Remote Desktop"),
		B_TITLED_WINDOW, B_NOT_RESIZABLE | B_NOT_ZOOMABLE
			| B_AUTO_UPDATE_SIZE_LIMITS | B_ASYNCHRONOUS_CONTROLS
			| B_QUIT_ON_WINDOW_CLOSE),
	fPulse(NULL),
	fOriginalEnabled(false),
	fEnableAfterPassword(false),
	fRestartPending(false),
	fManualRestartNeeded(false),
	fStartedAt(-kStartGrace),
	fStoppedAt(-kStartGrace),
	fRestartRequestedAt(-kStartGrace),
	fStatusRequestedAt(0),
	fHaveFingerprint(false)
{
	BPath directory;
	if (rrd_settings_directory(directory) == B_OK) {
		fSettingsPath = directory.Path();
		fSettingsPath << "/settings";
		fCertificatePath = directory.Path();
		fCertificatePath << "/certificate.pem";
	}

	fEnable = new BCheckBox("enable",
		B_TRANSLATE("Allow remote desktop connections to this computer"),
		new BMessage(kMsgEnable));
	fStatus = new BStringView("status", "");
	fDetail = new BStringView("detail", "");
	fDisconnect = new BButton("disconnect", B_TRANSLATE("Disconnect"),
		new BMessage(kMsgDisconnect));

	// Password
	fPasswordState = new BStringView("password state", "");
	fWindowsNote = new BStringView("windows note", "");
	fSetPassword = new BButton("set password",
		B_TRANSLATE("Set password" B_UTF8_ELLIPSIS),
		new BMessage(kMsgSetPassword));
	BBox* passwordBox = new BBox("password box");
	passwordBox->SetLabel(B_TRANSLATE("Password"));
	BLayoutBuilder::Group<>(passwordBox, B_VERTICAL, B_USE_SMALL_SPACING)
		.SetInsets(B_USE_DEFAULT_SPACING, B_USE_BIG_SPACING,
			B_USE_DEFAULT_SPACING, B_USE_DEFAULT_SPACING)
		.AddGroup(B_HORIZONTAL)
			.Add(fPasswordState)
			.AddGlue()
			.Add(fSetPassword)
		.End()
		.Add(fWindowsNote);

	// Connection
	fPort = new BTextControl("port", B_TRANSLATE("Port:"), "",
		new BMessage(kMsgPort));
	for (uint32 c = 0; c < 256; c++) {
		if (c < '0' || c > '9')
			fPort->TextView()->DisallowChar(c);
	}
	fPort->TextView()->SetMaxBytes(5);

	fAddressMenu = new BPopUpMenu("address");
	fAddressField = new BMenuField("address", B_TRANSLATE("Listen on:"),
		fAddressMenu);

	fResizeMenu = new BPopUpMenu("resize");
	for (size_t i = 0; i < sizeof(kResizeChoices) / sizeof(kResizeChoices[0]);
			i++) {
		BMessage* message = new BMessage(kMsgResize);
		message->AddInt32("policy", kResizeChoices[i].policy);
		fResizeMenu->AddItem(new BMenuItem(
			B_TRANSLATE_NOCOLLECT(kResizeChoices[i].label), message));
	}
	fResizeField = new BMenuField("resize", B_TRANSLATE("Screen size:"),
		fResizeMenu);

	BBox* connectionBox = new BBox("connection box");
	connectionBox->SetLabel(B_TRANSLATE("Connection"));
	BLayoutBuilder::Grid<>(connectionBox, B_USE_DEFAULT_SPACING,
			B_USE_SMALL_SPACING)
		.SetInsets(B_USE_DEFAULT_SPACING, B_USE_BIG_SPACING,
			B_USE_DEFAULT_SPACING, B_USE_DEFAULT_SPACING)
		.AddTextControl(fPort, 0, 0)
		.AddMenuField(fAddressField, 0, 1)
		.AddMenuField(fResizeField, 0, 2);

	// Certificate
	fFingerprint = new BTextView("fingerprint");
	fFingerprint->MakeEditable(false);
	fFingerprint->MakeSelectable(true);
	fFingerprint->SetViewUIColor(B_PANEL_BACKGROUND_COLOR);
	fFingerprint->SetFontAndColor(be_fixed_font);
	BString sample("00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00");
	float width = be_fixed_font->StringWidth(sample.String()) + 8;
	font_height height;
	be_fixed_font->GetHeight(&height);
	float lineHeight = ceilf(height.ascent + height.descent + height.leading);
	fFingerprint->SetExplicitMinSize(BSize(width, lineHeight * 2 + 6));
	fFingerprint->SetExplicitMaxSize(BSize(B_SIZE_UNLIMITED,
		lineHeight * 2 + 6));

	BStringView* fingerprintLabel = new BStringView("fingerprint label",
		B_TRANSLATE("Clients show this SHA-256 fingerprint when they first "
			"connect:"));
	BBox* certificateBox = new BBox("certificate box");
	certificateBox->SetLabel(B_TRANSLATE("Certificate"));
	BLayoutBuilder::Group<>(certificateBox, B_VERTICAL, B_USE_SMALL_SPACING)
		.SetInsets(B_USE_DEFAULT_SPACING, B_USE_BIG_SPACING,
			B_USE_DEFAULT_SPACING, B_USE_DEFAULT_SPACING)
		.Add(fingerprintLabel)
		.Add(fFingerprint);

	fDefaults = new BButton("defaults", B_TRANSLATE("Defaults"),
		new BMessage(kMsgDefaults));
	fRevert = new BButton("revert", B_TRANSLATE("Revert"),
		new BMessage(kMsgRevert));

	BLayoutBuilder::Group<>(this, B_VERTICAL)
		.SetInsets(B_USE_WINDOW_SPACING)
		.Add(fEnable)
		.AddGroup(B_HORIZONTAL)
			.AddGroup(B_VERTICAL, 0)
				.Add(fStatus)
				.Add(fDetail)
			.End()
			.AddGlue()
			.Add(fDisconnect)
		.End()
		.Add(passwordBox)
		.Add(connectionBox)
		.Add(certificateBox)
		.AddGroup(B_HORIZONTAL)
			.Add(fDefaults)
			.Add(fRevert)
			.AddGlue()
		.End();

	_Load();
	fOriginal = fConfig;
	fOriginalEnabled = ServiceControl::IsEnabled();
	_UpdateControls();
	_UpdateFingerprint();
	_UpdateStatus(NULL);

	BMessage pulse(kMsgPulse);
	fPulse = new BMessageRunner(BMessenger(this), &pulse, 1000000);
	_Pulse();

	CenterOnScreen();
}


PrefsWindow::~PrefsWindow()
{
	delete fPulse;
}


void
PrefsWindow::MessageReceived(BMessage* message)
{
	switch (message->what) {
		case kMsgEnable:
		{
			bool enable = fEnable->Value() == B_CONTROL_ON;
			if (enable && fConfig.passwordHash.empty()) {
				// A password first; the switch turns on once one is set.
				fEnable->SetValue(B_CONTROL_OFF);
				fEnableAfterPassword = true;
				(new PasswordWindow(this, BMessenger(this)))->Show();
				break;
			}
			_ApplyEnabled(enable);
			break;
		}

		case kMsgDisconnect:
			BMessenger(RRD_SERVER_SIGNATURE).SendMessage(RRD_MSG_DISCONNECT);
			break;

		case kMsgSetPassword:
			fEnableAfterPassword = false;
			(new PasswordWindow(this, BMessenger(this)))->Show();
			break;

		case PasswordWindow::kMsgPasswordChosen:
		{
			const char* passwordHash;
			const char* ntHash;
			if (message->FindString("password_hash", &passwordHash) != B_OK
				|| message->FindString("nt_hash", &ntHash) != B_OK) {
				break;
			}
			fConfig.passwordHash = passwordHash;
			fConfig.ntHash = ntHash;
			_Save();
			if (fEnableAfterPassword) {
				fEnableAfterPassword = false;
				_ApplyEnabled(true);
			}
			_UpdateControls();
			break;
		}

		case kMsgPort:
		{
			int port = atoi(fPort->Text());
			if (port < 1 || port > 65535) {
				BString text;
				text << fConfig.port;
				fPort->SetText(text.String());
				beep();
				break;
			}
			if (port != fConfig.port) {
				fConfig.port = port;
				_Save();
			}
			break;
		}

		case kMsgAddress:
		{
			const char* address;
			if (message->FindString("address", &address) == B_OK
				&& fConfig.bindAddress != address) {
				fConfig.bindAddress = address;
				_Save();
			}
			break;
		}

		case kMsgResize:
		{
			int32 policy;
			if (message->FindInt32("policy", &policy) == B_OK) {
				fConfig.resize = (rrd::ResizePolicy)policy;
				_Save();
			}
			break;
		}

		case kMsgDefaults:
		{
			ServerConfig defaults;
			fConfig.port = defaults.port;
			fConfig.bindAddress = defaults.bindAddress;
			fConfig.resize = defaults.resize;
			_Save();
			_UpdateControls();
			break;
		}

		case kMsgRevert:
			fConfig = fOriginal;
			_Save();
			if (ServiceControl::IsEnabled() != fOriginalEnabled)
				_ApplyEnabled(fOriginalEnabled);
			_UpdateControls();
			break;

		case kMsgPulse:
			_Pulse();
			break;

		case RRD_MSG_STATUS:
			fStatusRequestedAt = 0;
			_UpdateStatus(message);
			break;

		case RRD_MSG_RELOADED:
			if (message->GetBool("restart", false)) {
				// A new port or address takes a restart. The server is only
				// asked to quit: launch_daemon starts it again, as the job
				// stays enabled. _Pulse() starts it if nothing else does.
				if (ServiceControl::IsEnabled()) {
					fRestartPending = true;
					fRestartRequestedAt = system_time();
					ServiceControl::Restart();
				} else {
					// Started by hand: nothing would start it again.
					fManualRestartNeeded = true;
				}
			}
			break;

		default:
			BWindow::MessageReceived(message);
			break;
	}
}


void
PrefsWindow::_Load()
{
	fConfig = ServerConfig();
	rrd::LoadSettings(fSettingsPath.String(), fConfig);
}


void
PrefsWindow::_Save()
{
	if (!rrd::SaveSettings(fSettingsPath.String(), fConfig)) {
		BAlert* alert = new BAlert(B_TRANSLATE("Remote Desktop"),
			B_TRANSLATE("The settings could not be saved."),
			B_TRANSLATE("OK"), NULL, NULL, B_WIDTH_AS_USUAL, B_STOP_ALERT);
		alert->Go(NULL);
		return;
	}
	if (ServiceControl::IsRunning()) {
		BMessenger(RRD_SERVER_SIGNATURE).SendMessage(RRD_MSG_RELOAD_SETTINGS,
			this);
	}
	_UpdateControls();
}


void
PrefsWindow::_ApplyEnabled(bool enabled)
{
	if (ServiceControl::SetEnabled(enabled) != B_OK) {
		BAlert* alert = new BAlert(B_TRANSLATE("Remote Desktop"),
			B_TRANSLATE("The setting could not be saved."),
			B_TRANSLATE("OK"), NULL, NULL, B_WIDTH_AS_USUAL, B_STOP_ALERT);
		alert->Go(NULL);
		_UpdateControls();
		return;
	}
	fRestartPending = false;
	fManualRestartNeeded = false;
	if (enabled) {
		fStartedAt = system_time();
		// Also while an old server is still quitting: Start() enables the
		// launch_daemon job again, which then relaunches the server once
		// the old one is gone.
		ServiceControl::Start();
	} else {
		fStoppedAt = system_time();
		ServiceControl::Stop();
	}
	_UpdateControls();
	_UpdateStatus(NULL);
}


void
PrefsWindow::_UpdateControls()
{
	fEnable->SetValue(ServiceControl::IsEnabled()
		? B_CONTROL_ON : B_CONTROL_OFF);

	bool havePassword = !fConfig.passwordHash.empty();
	uint8 hash[16];
	bool haveNtHash = rrd::ParseNtHash(fConfig.ntHash, hash);
	fPasswordState->SetText(havePassword
		? B_TRANSLATE("A password is set.")
		: B_TRANSLATE("No password is set."));
	fSetPassword->SetLabel(havePassword
		? B_TRANSLATE("Change password" B_UTF8_ELLIPSIS)
		: B_TRANSLATE("Set password" B_UTF8_ELLIPSIS));
	// Network Level Authentication needs the NT hash, which settings from
	// before NLA do not have.
	bool needsNtHash = havePassword && !haveNtHash;
	fWindowsNote->SetText(needsNtHash
		? B_TRANSLATE("Set the password again so that Windows clients can "
			"log in.")
		: "");
	if (needsNtHash && fWindowsNote->IsHidden())
		fWindowsNote->Show();
	else if (!needsNtHash && !fWindowsNote->IsHidden())
		fWindowsNote->Hide();

	BString port;
	port << fConfig.port;
	if (port != fPort->Text())
		fPort->SetText(port.String());

	_FillAddressMenu();

	for (int32 i = 0; i < fResizeMenu->CountItems(); i++) {
		BMenuItem* item = fResizeMenu->ItemAt(i);
		item->SetMarked(item->Message()->GetInt32("policy", -1)
			== fConfig.resize);
	}

	bool sameAsOriginal = fConfig.port == fOriginal.port
		&& fConfig.bindAddress == fOriginal.bindAddress
		&& fConfig.resize == fOriginal.resize
		&& fConfig.passwordHash == fOriginal.passwordHash
		&& ServiceControl::IsEnabled() == fOriginalEnabled;
	fRevert->SetEnabled(!sameAsOriginal);
	ServerConfig defaults;
	fDefaults->SetEnabled(fConfig.port != defaults.port
		|| fConfig.bindAddress != defaults.bindAddress
		|| fConfig.resize != defaults.resize);
}


void
PrefsWindow::_FillAddressMenu()
{
	// "All networks", then each IPv4 address of this computer, and the
	// configured one even when no interface has it right now.
	while (BMenuItem* item = fAddressMenu->RemoveItem((int32)0))
		delete item;

	BMessage* all = new BMessage(kMsgAddress);
	all->AddString("address", "");
	BMenuItem* allItem = new BMenuItem(B_TRANSLATE("All networks"), all);
	fAddressMenu->AddItem(allItem);
	allItem->SetMarked(fConfig.bindAddress.empty());

	bool foundConfigured = fConfig.bindAddress.empty();
	BNetworkRoster& roster = BNetworkRoster::Default();
	BNetworkInterface interface;
	uint32 cookie = 0;
	bool separator = false;
	while (roster.GetNextInterface(&cookie, interface) == B_OK) {
		if ((interface.Flags() & IFF_LOOPBACK) != 0)
			continue;
		int32 count = interface.CountAddresses();
		for (int32 i = 0; i < count; i++) {
			BNetworkInterfaceAddress address;
			if (interface.GetAddressAt(i, address) != B_OK
				|| address.Address().Family() != AF_INET
				|| address.Address().IsEmpty()) {
				continue;
			}
			BString text = address.Address().ToString(false);
			if (!separator) {
				fAddressMenu->AddSeparatorItem();
				separator = true;
			}
			BMessage* message = new BMessage(kMsgAddress);
			message->AddString("address", text);
			BString label;
			label << text << " (" << interface.Name() << ")";
			BMenuItem* item = new BMenuItem(label.String(), message);
			fAddressMenu->AddItem(item);
			if (text == fConfig.bindAddress.c_str()) {
				item->SetMarked(true);
				foundConfigured = true;
			}
		}
	}

	if (!foundConfigured) {
		if (!separator)
			fAddressMenu->AddSeparatorItem();
		BMessage* message = new BMessage(kMsgAddress);
		message->AddString("address", fConfig.bindAddress.c_str());
		BString label(fConfig.bindAddress.c_str());
		label << " " << B_TRANSLATE("(not on this computer now)");
		BMenuItem* item = new BMenuItem(label.String(), message);
		fAddressMenu->AddItem(item);
		item->SetMarked(true);
	}
}


void
PrefsWindow::_UpdateFingerprint()
{
	BString text = Fingerprint(fCertificatePath.String());
	fHaveFingerprint = !text.IsEmpty();
	if (!fHaveFingerprint)
		text = B_TRANSLATE("Created when the server first starts.");
	if (text != fFingerprint->Text())
		fFingerprint->SetText(text.String());
}


void
PrefsWindow::_Pulse()
{
	bool running = ServiceControl::IsRunning();
	if (fRestartPending && !running) {
		fRestartPending = false;
		if (ServiceControl::IsEnabled()) {
			fStartedAt = system_time();
			ServiceControl::Start();
		}
	}

	if (running) {
		// A server that cannot start waits 30 seconds before it exits
		// (--service). It is registered but does not answer meanwhile, so
		// one that stays silent counts as not running.
		bigtime_t now = system_time();
		if (fStatusRequestedAt == 0)
			fStatusRequestedAt = now;
		else if (now - fStatusRequestedAt > kStatusTimeout)
			_UpdateStatus(NULL);
		BMessenger(RRD_SERVER_SIGNATURE).SendMessage(RRD_MSG_GET_STATUS,
			this);
	} else {
		fStatusRequestedAt = 0;
		_UpdateStatus(NULL);
	}

	if (!fHaveFingerprint)
		_UpdateFingerprint();
}


void
PrefsWindow::_UpdateStatus(const BMessage* status)
{
	bool enabled = ServiceControl::IsEnabled();
	BString text;
	BString detail;
	bool connected = false;

	if (status != NULL) {
		if (!enabled && system_time() - fStoppedAt < kStartGrace)
			text = B_TRANSLATE("Stopping" B_UTF8_ELLIPSIS);
		else if (status->GetBool("connected", false)) {
			connected = true;
			text = B_TRANSLATE("Connected: %user% from %peer% since %time%.");
			text.ReplaceFirst("%user%", status->GetString("user", "?"));
			text.ReplaceFirst("%peer%", status->GetString("peer", "?"));
			text.ReplaceFirst("%time%",
				FormatSince(status->GetInt64("since", 0)).String());
		} else {
			text = B_TRANSLATE("On. Waiting for connections on port %port%.");
			if (!enabled) {
				text = B_TRANSLATE("Started by hand. Waiting for connections "
					"on port %port%.");
			}
			BString port;
			port << status->GetInt32("port", 0);
			text.ReplaceFirst("%port%", port.String());
		}
		if (!enabled && fManualRestartNeeded) {
			detail = B_TRANSLATE("Restart the server to use the new port or "
				"address.");
		} else if (enabled && strcmp(status->GetString("capture", ""),
				"polling") == 0) {
			detail = B_TRANSLATE("Screen capture is slow: this app_server "
				"cannot report changes.");
		} else if (enabled && !status->GetBool("nla", true)) {
			detail = B_TRANSLATE("Windows clients cannot log in until the "
				"password is set again.");
		}
	} else if (fRestartPending
		|| system_time() - fRestartRequestedAt < kStartGrace) {
		text = B_TRANSLATE("Restarting" B_UTF8_ELLIPSIS);
	}
	else if (enabled) {
		if (system_time() - fStartedAt < kStartGrace)
			text = B_TRANSLATE("Starting" B_UTF8_ELLIPSIS);
		else {
			text = B_TRANSLATE("Not running.");
			detail = B_TRANSLATE("The system log (syslog) has the reason.");
		}
	} else
		text = B_TRANSLATE("Off.");

	if (text != fStatus->Text())
		fStatus->SetText(text.String());
	if (detail != fDetail->Text())
		fDetail->SetText(detail.String());
	fDisconnect->SetEnabled(connected);
}
