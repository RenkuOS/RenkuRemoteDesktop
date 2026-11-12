/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */


#include "PasswordWindow.h"

#include <Button.h>
#include <Catalog.h>
#include <LayoutBuilder.h>
#include <StringView.h>
#include <TextControl.h>

#include <string.h>

#include <string>

#include "Auth.h"


#undef B_TRANSLATION_CONTEXT
#define B_TRANSLATION_CONTEXT "PasswordWindow"


static const uint32 kMsgChanged = 'pwCh';
static const uint32 kMsgOK = 'pwOK';
static const size_t kMinimumLength = 8;


PasswordWindow::PasswordWindow(BWindow* parent, BMessenger target)
	:
	BWindow(BRect(0, 0, 300, 100), B_TRANSLATE("Set password"),
		B_TITLED_WINDOW_LOOK, B_MODAL_SUBSET_WINDOW_FEEL,
		B_NOT_RESIZABLE | B_NOT_ZOOMABLE | B_NOT_MINIMIZABLE
			| B_AUTO_UPDATE_SIZE_LIMITS | B_CLOSE_ON_ESCAPE),
	fTarget(target)
{
	if (parent != NULL)
		AddToSubset(parent);

	fPassword = new BTextControl(B_TRANSLATE("New password:"), "",
		new BMessage(kMsgChanged));
	fPassword->TextView()->HideTyping(true);
	fPassword->SetModificationMessage(new BMessage(kMsgChanged));
	fAgain = new BTextControl(B_TRANSLATE("Again:"), "",
		new BMessage(kMsgChanged));
	fAgain->TextView()->HideTyping(true);
	fAgain->SetModificationMessage(new BMessage(kMsgChanged));

	fHint = new BStringView("hint", "");
	fOK = new BButton(B_TRANSLATE("Set password"), new BMessage(kMsgOK));
	BButton* cancel = new BButton(B_TRANSLATE("Cancel"),
		new BMessage(B_QUIT_REQUESTED));

	BLayoutBuilder::Group<>(this, B_VERTICAL)
		.SetInsets(B_USE_WINDOW_SPACING)
		.AddGrid()
			.AddTextControl(fPassword, 0, 0)
			.AddTextControl(fAgain, 0, 1)
		.End()
		.Add(fHint)
		.AddGroup(B_HORIZONTAL)
			.AddGlue()
			.Add(cancel)
			.Add(fOK)
		.End();

	SetDefaultButton(fOK);
	fPassword->MakeFocus(true);
	_Check();
	if (parent != NULL)
		CenterIn(parent->Frame());
	else
		CenterOnScreen();
}


void
PasswordWindow::MessageReceived(BMessage* message)
{
	switch (message->what) {
		case kMsgChanged:
			_Check();
			break;
		case kMsgOK:
			_Accept();
			break;
		default:
			BWindow::MessageReceived(message);
			break;
	}
}


void
PasswordWindow::_Check()
{
	size_t length = strlen(fPassword->Text());
	bool same = strcmp(fPassword->Text(), fAgain->Text()) == 0;
	if (length < kMinimumLength) {
		fHint->SetText(B_TRANSLATE("Use at least eight characters."));
		fOK->SetEnabled(false);
	} else if (!same) {
		fHint->SetText(B_TRANSLATE("The two passwords differ."));
		fOK->SetEnabled(false);
	} else {
		fHint->SetText("");
		fOK->SetEnabled(true);
	}
}


void
PasswordWindow::_Accept()
{
	std::string password = fPassword->Text();
	if (password.size() < kMinimumLength
		|| password != std::string(fAgain->Text())) {
		rrd::WipeString(password);
		return;
	}

	// Hashing takes a moment (PBKDF2 with many rounds).
	fOK->SetEnabled(false);

	BMessage chosen(kMsgPasswordChosen);
	chosen.AddString("password_hash", rrd::HashPassword(password).c_str());
	chosen.AddString("nt_hash", rrd::NtHashHex(password).c_str());
	rrd::WipeString(password);
	fPassword->SetText("");
	fAgain->SetText("");

	fTarget.SendMessage(&chosen);
	PostMessage(B_QUIT_REQUESTED);
}
