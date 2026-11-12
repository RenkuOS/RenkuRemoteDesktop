/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */
#ifndef RRD_CREDSSP_H
#define RRD_CREDSSP_H


// The server side of CredSSP ([MS-CSSP]) with NTLM, raw or inside SPNEGO
// ([MS-SPNG], [RFC4178]). This is Network Level Authentication: the client
// proves the password before any RDP data is exchanged.


#include <stdint.h>

#include <string>

#include "Crypto.h"


namespace rrd {


class Transport;


// TSRequest (2.2.1).
struct TsRequest {
				TsRequest();

	int64_t		version;
	bool		hasNegoToken;
	Bytes		negoToken;
	bool		hasAuthInfo;
	Bytes		authInfo;
	bool		hasPubKeyAuth;
	Bytes		pubKeyAuth;
	bool		hasErrorCode;
	int64_t		errorCode;
	bool		hasClientNonce;
	Bytes		clientNonce;
};

bool ParseTsRequest(const Bytes& data, TsRequest& request);
Bytes BuildTsRequest(const TsRequest& request);


// The parts of an SPNEGO token the server uses. A negTokenInit inside the
// GSS-API framing, or a negTokenResp.
struct SpnegoToken {
				SpnegoToken();

	bool		init;
	// negTokenInit: the mechTypes element as encoded (the mechListMIC is
	// computed over it), and where NTLM is in it.
	Bytes		mechTypes;
	bool		offersNtlm;
	bool		ntlmFirst;
	// mechToken (init) or responseToken (resp).
	bool		hasToken;
	Bytes		token;
	bool		hasMechListMic;
	Bytes		mechListMic;
};

bool ParseSpnego(const Bytes& data, SpnegoToken& token);

enum {
	SPNEGO_ACCEPT_COMPLETED = 0,
	SPNEGO_ACCEPT_INCOMPLETE = 1,
	SPNEGO_REJECT = 2
};

Bytes BuildSpnegoResponse(int negState, bool supportedMech,
	const Bytes* responseToken, const Bytes* mechListMic);


class CredSspServer {
public:
	enum Result {
		kAuthenticated,
		kWrongPassword,
		kFailed
	};

							// ntHash: the password's NT hash. passwordHash:
							// the PBKDF2 hash; the delegated password must
							// match it too.
							CredSspServer(Transport& transport,
								const Bytes& subjectPublicKey,
								const uint8_t ntHash[16],
								const std::string& passwordHash,
								const std::string& computerName);
							~CredSspServer();

			Result			Run();

			const std::string& UserName() const { return fUserName; }
			const std::string& DomainName() const { return fDomainName; }

private:
			bool			_Read(TsRequest& request);
			bool			_Write(const TsRequest& request);
			bool			_SendError(uint32_t status);

			Transport&		fTransport;
			const Bytes&	fSubjectPublicKey;
			uint8_t			fNtHash[16];
			const std::string& fPasswordHash;
			std::string		fComputerName;
			int64_t			fVersion;
			std::string		fUserName;
			std::string		fDomainName;
};


}	// namespace rrd


#endif	// RRD_CREDSSP_H
