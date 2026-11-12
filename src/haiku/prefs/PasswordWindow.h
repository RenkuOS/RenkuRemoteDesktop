/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */
#ifndef RRD_PASSWORD_WINDOW_H
#define RRD_PASSWORD_WINDOW_H


#include <Messenger.h>
#include <Window.h>


class BButton;
class BStringView;
class BTextControl;


// Asks for a new password twice. On success it sends the target a
// kMsgPasswordChosen message with "password_hash" and "nt_hash" strings;
// the password itself never leaves this window.
class PasswordWindow : public BWindow {
public:
								PasswordWindow(BWindow* parent,
									BMessenger target);

	virtual	void				MessageReceived(BMessage* message);

	static	const uint32		kMsgPasswordChosen = 'rpPC';

private:
			void				_Check();
			void				_Accept();

			BMessenger			fTarget;
			BTextControl*		fPassword;
			BTextControl*		fAgain;
			BStringView*		fHint;
			BButton*			fOK;
};


#endif	// RRD_PASSWORD_WINDOW_H
