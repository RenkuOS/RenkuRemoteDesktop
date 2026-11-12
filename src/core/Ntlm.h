/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */
#ifndef RRD_NTLM_H
#define RRD_NTLM_H


// The server side of NTLMv2 with extended session security ([MS-NLMP]),
// connection-oriented, as CredSSP uses it. There is one account: any user
// name is accepted with the server's password.


#include <stdint.h>

#include <string>
#include <vector>

#include "Crypto.h"


namespace rrd {


enum {
	NTLMSSP_NEGOTIATE_UNICODE = 0x00000001,
	NTLMSSP_REQUEST_TARGET = 0x00000004,
	NTLMSSP_NEGOTIATE_SIGN = 0x00000010,
	NTLMSSP_NEGOTIATE_SEAL = 0x00000020,
	NTLMSSP_NEGOTIATE_NTLM = 0x00000200,
	NTLMSSP_NEGOTIATE_ANONYMOUS = 0x00000800,
	NTLMSSP_NEGOTIATE_ALWAYS_SIGN = 0x00008000,
	NTLMSSP_TARGET_TYPE_SERVER = 0x00020000,
	NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000,
	NTLMSSP_NEGOTIATE_TARGET_INFO = 0x00800000,
	NTLMSSP_NEGOTIATE_VERSION = 0x02000000,
	NTLMSSP_NEGOTIATE_128 = 0x20000000,
	NTLMSSP_NEGOTIATE_KEY_EXCH = 0x40000000,
	NTLMSSP_NEGOTIATE_56 = 0x80000000
};


// The NT hash of a password: MD4 of its UTF-16LE encoding (NTOWFv1,
// [MS-NLMP] 3.3.1).
void NtHash(const std::string& utf8Password, uint8_t hash[16]);


class NtlmServer {
public:
	enum Result {
		kOk,
		kBadMessage,
		kWrongPassword
	};

							NtlmServer(const uint8_t ntHash[16],
								const std::string& computerName);
							~NtlmServer();

			// NEGOTIATE_MESSAGE in, CHALLENGE_MESSAGE out.
			bool			HandleNegotiate(const Bytes& negotiate,
								Bytes& challenge);
			// Checks the AUTHENTICATE_MESSAGE and, on success, sets up the
			// session keys.
			Result			HandleAuthenticate(const Bytes& authenticate);

			const std::string& UserName() const { return fUserName; }
			const std::string& DomainName() const { return fDomainName; }

			// GSS_WrapEx with one sealed buffer (3.4.6): the 16-byte
			// signature, then the sealed data. Server to client.
			Bytes			Wrap(const Bytes& message);
			// GSS_UnwrapEx, client to server. Fails on a bad signature or
			// sequence number.
			bool			Unwrap(const Bytes& wrapped, Bytes& message);

			// GSS_GetMICEx and GSS_VerifyMICEx (3.4.8, 3.4.9). With
			// keepKeyState, the RC4 state is left as it was, which SPNEGO's
			// mechListMIC needs ([MS-SPNG] 3.2.5.1).
			Bytes			GetMic(const Bytes& message, bool keepKeyState);
			bool			VerifyMic(const Bytes& message,
								const Bytes& signature, bool keepKeyState);

			// For tests: fixed values instead of random ones.
			void			SetChallengeForTest(const uint8_t challenge[8],
								uint64_t timestamp);

private:
			void			_Signature(Rc4& handle, const uint8_t* signKey,
								uint32_t sequence, const Bytes& message,
								uint8_t signature[16]);

			uint8_t			fNtHash[16];
			std::string		fComputerName;

			uint8_t			fServerChallenge[8];
			uint64_t		fTimestamp;
			bool			fFixedChallenge;
			uint32_t		fFlags;
			Bytes			fNegotiateMessage;
			Bytes			fChallengeMessage;

			std::string		fUserName;
			std::string		fDomainName;

			bool			fKeyExchange;
			uint8_t			fClientSignKey[16];
			uint8_t			fServerSignKey[16];
			Rc4				fClientSeal;
			Rc4				fServerSeal;
			uint32_t		fSendSequence;
			uint32_t		fReceiveSequence;
			bool			fAuthenticated;
};


}	// namespace rrd


#endif	// RRD_NTLM_H
