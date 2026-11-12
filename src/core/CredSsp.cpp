/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */


#include "CredSsp.h"

#include <string.h>

#include "Auth.h"
#include "Der.h"
#include "Log.h"
#include "Ntlm.h"
#include "Transport.h"


namespace rrd {


// The highest CredSSP version implemented (2.2.1).
static const int64_t kCredSspVersion = 6;
// TSRequests are small; this bounds what a client can make us buffer.
static const size_t kMaxTsRequest = 64 * 1024;

// NTSTATUS codes ([MS-ERREF] 2.3.1).
static const uint32_t STATUS_LOGON_FAILURE = 0xc000006d;
static const uint32_t STATUS_INVALID_PARAMETER = 0xc000000d;

// OIDs, DER-encoded with their headers.
static const uint8_t kSpnegoOid[] = { 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05,
	0x05, 0x02 };								// 1.3.6.1.5.5.2
static const uint8_t kNtlmOid[] = { 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
	0x01, 0x82, 0x37, 0x02, 0x02, 0x0a };		// 1.3.6.1.4.1.311.2.2.10

static const char kClientServerMagic[] = "CredSSP Client-To-Server Binding Hash";
static const char kServerClientMagic[] = "CredSSP Server-To-Client Binding Hash";

static const uint8_t kNtlmSignature[8] = { 'N', 'T', 'L', 'M', 'S', 'S', 'P',
	0 };


// #pragma mark - TSRequest


TsRequest::TsRequest()
	:
	version(0),
	hasNegoToken(false),
	hasAuthInfo(false),
	hasPubKeyAuth(false),
	hasErrorCode(false),
	errorCode(0),
	hasClientNonce(false)
{
}


bool
ParseTsRequest(const Bytes& data, TsRequest& request)
{
	// Nothing from an earlier message may survive into this one.
	request = TsRequest();

	DerReader outer(data.data(), data.size());
	DerReader sequence(NULL, 0);
	if (!outer.Read(DER_SEQUENCE, sequence))
		return false;

	// [0] version is required; the rest are optional and in order.
	DerReader field(NULL, 0);
	if (!sequence.Read(DerContext(0), field)
		|| !field.ReadInteger(request.version)) {
		return false;
	}
	while (!sequence.AtEnd()) {
		int tag = sequence.PeekTag();
		if (!sequence.Read((uint8_t)tag, field))
			return false;
		switch (tag) {
			case 0xa1:
			{
				// NegoData ::= SEQUENCE OF SEQUENCE { negoToken [0] OCTET
				// STRING }. Only the first token is used.
				DerReader list(NULL, 0);
				DerReader item(NULL, 0);
				DerReader token(NULL, 0);
				if (!field.Read(DER_SEQUENCE, list)
					|| !list.Read(DER_SEQUENCE, item)
					|| !item.Read(DerContext(0), token)
					|| !token.ReadOctetString(request.negoToken)) {
					return false;
				}
				request.hasNegoToken = true;
				break;
			}
			case 0xa2:
				if (!field.ReadOctetString(request.authInfo))
					return false;
				request.hasAuthInfo = true;
				break;
			case 0xa3:
				if (!field.ReadOctetString(request.pubKeyAuth))
					return false;
				request.hasPubKeyAuth = true;
				break;
			case 0xa4:
				if (!field.ReadInteger(request.errorCode))
					return false;
				request.hasErrorCode = true;
				break;
			case 0xa5:
				if (!field.ReadOctetString(request.clientNonce))
					return false;
				request.hasClientNonce = true;
				break;
			default:
				// Unknown fields are skipped.
				break;
		}
	}
	return sequence.Ok();
}


Bytes
BuildTsRequest(const TsRequest& request)
{
	DerWriter body;

	DerWriter version;
	version.Integer(request.version);
	body.Element(DerContext(0), version.Data());

	if (request.hasNegoToken) {
		DerWriter token;
		token.OctetString(request.negoToken);
		DerWriter tagged;
		tagged.Element(DerContext(0), token.Data());
		DerWriter item;
		item.Element(DER_SEQUENCE, tagged.Data());
		DerWriter list;
		list.Element(DER_SEQUENCE, item.Data());
		body.Element(DerContext(1), list.Data());
	}
	if (request.hasAuthInfo) {
		DerWriter value;
		value.OctetString(request.authInfo);
		body.Element(DerContext(2), value.Data());
	}
	if (request.hasPubKeyAuth) {
		DerWriter value;
		value.OctetString(request.pubKeyAuth);
		body.Element(DerContext(3), value.Data());
	}
	if (request.hasErrorCode) {
		DerWriter value;
		value.Integer(request.errorCode);
		body.Element(DerContext(4), value.Data());
	}
	if (request.hasClientNonce) {
		DerWriter value;
		value.OctetString(request.clientNonce);
		body.Element(DerContext(5), value.Data());
	}

	DerWriter out;
	out.Element(DER_SEQUENCE, body.Data());
	return out.Data();
}


// #pragma mark - SPNEGO


SpnegoToken::SpnegoToken()
	:
	init(false),
	offersNtlm(false),
	ntlmFirst(false),
	hasToken(false),
	hasMechListMic(false)
{
}


static bool
ParseMechTypes(DerReader& field, SpnegoToken& token)
{
	DerReader list(NULL, 0);
	const uint8_t* element;
	size_t elementSize;
	if (!field.Read(DER_SEQUENCE, list, &element, &elementSize))
		return false;
	token.mechTypes.assign(element, element + elementSize);
	bool first = true;
	while (!list.AtEnd()) {
		const uint8_t* oid;
		size_t oidSize;
		DerReader contents(NULL, 0);
		if (!list.Read(DER_OID, contents, &oid, &oidSize))
			return false;
		if (oidSize == sizeof(kNtlmOid)
			&& memcmp(oid, kNtlmOid, oidSize) == 0) {
			token.offersNtlm = true;
			token.ntlmFirst = first;
		}
		first = false;
	}
	return true;
}


bool
ParseSpnego(const Bytes& data, SpnegoToken& token)
{
	DerReader reader(data.data(), data.size());
	DerReader body(NULL, 0);

	if (reader.PeekTag() == 0x60) {
		// InitialContextToken ([RFC2743] 3.1): the SPNEGO OID, then
		// negTokenInit [0].
		DerReader framing(NULL, 0);
		DerReader oid(NULL, 0);
		const uint8_t* oidElement;
		size_t oidSize;
		DerReader inner(NULL, 0);
		if (!reader.Read(0x60, framing)
			|| !framing.Read(DER_OID, oid, &oidElement, &oidSize)
			|| oidSize != sizeof(kSpnegoOid)
			|| memcmp(oidElement, kSpnegoOid, oidSize) != 0
			|| !framing.Read(DerContext(0), inner)
			|| !inner.Read(DER_SEQUENCE, body)) {
			return false;
		}
		token.init = true;
		while (!body.AtEnd()) {
			int tag = body.PeekTag();
			DerReader field(NULL, 0);
			if (!body.Read((uint8_t)tag, field))
				return false;
			if (tag == 0xa0) {
				if (!ParseMechTypes(field, token))
					return false;
			} else if (tag == 0xa2) {
				if (!field.ReadOctetString(token.token))
					return false;
				token.hasToken = true;
			} else if ((tag == 0xa3 || tag == 0xa4)
				&& field.PeekTag() == DER_OCTET_STRING) {
				// mechListMIC: [3] in NegTokenInit, [4] in NegTokenInit2
				// ([MS-SPNG] 2.2.1), where [3] holds negHints instead.
				if (!field.ReadOctetString(token.mechListMic))
					return false;
				token.hasMechListMic = true;
			}
		}
		return body.Ok();
	}

	// negTokenResp [1]
	if (!reader.Read(DerContext(1), body))
		return false;
	DerReader sequence(NULL, 0);
	if (!body.Read(DER_SEQUENCE, sequence))
		return false;
	while (!sequence.AtEnd()) {
		int tag = sequence.PeekTag();
		DerReader field(NULL, 0);
		if (!sequence.Read((uint8_t)tag, field))
			return false;
		if (tag == 0xa2) {
			if (!field.ReadOctetString(token.token))
				return false;
			token.hasToken = true;
		} else if (tag == 0xa3) {
			if (!field.ReadOctetString(token.mechListMic))
				return false;
			token.hasMechListMic = true;
		}
	}
	return sequence.Ok();
}


Bytes
BuildSpnegoResponse(int negState, bool supportedMech,
	const Bytes* responseToken, const Bytes* mechListMic)
{
	DerWriter body;
	DerWriter state;
	state.Enumerated(negState);
	body.Element(DerContext(0), state.Data());
	if (supportedMech) {
		body.Element(DerContext(1), Bytes(kNtlmOid,
			kNtlmOid + sizeof(kNtlmOid)));
	}
	if (responseToken != NULL) {
		DerWriter value;
		value.OctetString(*responseToken);
		body.Element(DerContext(2), value.Data());
	}
	if (mechListMic != NULL) {
		DerWriter value;
		value.OctetString(*mechListMic);
		body.Element(DerContext(3), value.Data());
	}
	DerWriter sequence;
	sequence.Element(DER_SEQUENCE, body.Data());
	DerWriter out;
	out.Element(DerContext(1), sequence.Data());
	return out.Data();
}


// #pragma mark - CredSspServer


static Bytes
BindingHash(const char* magic, const Bytes& nonce, const Bytes& publicKey)
{
	// SHA256(magic including its NUL, nonce, SubjectPublicKey) (3.1.5).
	Bytes input(magic, magic + strlen(magic) + 1);
	input.insert(input.end(), nonce.begin(), nonce.end());
	input.insert(input.end(), publicKey.begin(), publicKey.end());
	Bytes hash(32);
	Sha256(input.data(), input.size(), hash.data());
	return hash;
}


static bool
IsRawNtlm(const Bytes& token)
{
	return token.size() >= 8 && memcmp(token.data(), kNtlmSignature, 8) == 0;
}


CredSspServer::CredSspServer(Transport& transport,
	const Bytes& subjectPublicKey, const uint8_t ntHash[16],
	const std::string& passwordHash, const std::string& computerName)
	:
	fTransport(transport),
	fSubjectPublicKey(subjectPublicKey),
	fPasswordHash(passwordHash),
	fComputerName(computerName),
	fVersion(kCredSspVersion)
{
	memcpy(fNtHash, ntHash, sizeof(fNtHash));
}


CredSspServer::~CredSspServer()
{
	Wipe(fNtHash, sizeof(fNtHash));
}


bool
CredSspServer::_Read(TsRequest& request)
{
	Bytes data(2);
	if (!fTransport.ReadExact(data.data(), 2))
		return false;
	size_t needed;
	size_t total = DerElementSize(data.data(), data.size(), needed);
	if (total == 0 && needed > data.size()) {
		size_t have = data.size();
		data.resize(needed);
		if (!fTransport.ReadExact(data.data() + have, needed - have))
			return false;
		total = DerElementSize(data.data(), data.size(), needed);
	}
	if (total == 0 || total > kMaxTsRequest || data[0] != DER_SEQUENCE) {
		LOG_W("CredSSP: not a TSRequest");
		return false;
	}
	size_t have = data.size();
	data.resize(total);
	if (!fTransport.ReadExact(data.data() + have, total - have))
		return false;
	if (!ParseTsRequest(data, request)) {
		LOG_W("CredSSP: cannot parse a TSRequest");
		return false;
	}
	return true;
}


bool
CredSspServer::_Write(const TsRequest& request)
{
	return fTransport.WriteAll(BuildTsRequest(request));
}


bool
CredSspServer::_SendError(uint32_t status)
{
	// errorCode exists from version 3 on (2.2.1).
	if (fVersion < 3)
		return false;
	TsRequest reply;
	reply.version = fVersion;
	reply.hasErrorCode = true;
	reply.errorCode = (int32_t)status;
	return _Write(reply);
}


CredSspServer::Result
CredSspServer::Run()
{
	NtlmServer ntlm(fNtHash, fComputerName);

	// Step 2 of 3.1.5: the NTLM NEGOTIATE_MESSAGE, raw or in SPNEGO.
	TsRequest request;
	if (!_Read(request) || !request.hasNegoToken)
		return kFailed;
	if (request.version < 2) {
		LOG_W("CredSSP: version %lld is not supported",
			(long long)request.version);
		return kFailed;
	}
	fVersion = request.version < kCredSspVersion ? request.version
		: kCredSspVersion;

	bool spnego = !IsRawNtlm(request.negoToken);
	Bytes negotiate;
	Bytes mechTypes;
	bool mechListMicNeeded = false;
	if (spnego) {
		SpnegoToken token;
		if (!ParseSpnego(request.negoToken, token) || !token.init
			|| !token.offersNtlm) {
			LOG_W("CredSSP: the client offers neither raw NTLM nor NTLM in "
				"SPNEGO");
			_SendError(STATUS_LOGON_FAILURE);
			return kFailed;
		}
		mechTypes = token.mechTypes;
		// [RFC4178] 5: when the chosen mechanism is not the client's first
		// choice, both sides have to exchange mechListMICs.
		mechListMicNeeded = !token.ntlmFirst;
		if (token.ntlmFirst && token.hasToken)
			negotiate = token.token;
		else {
			// Ask for an NTLM token: accept-incomplete, NTLM, no response.
			TsRequest reply;
			reply.version = fVersion;
			reply.hasNegoToken = true;
			reply.negoToken = BuildSpnegoResponse(SPNEGO_ACCEPT_INCOMPLETE,
				true, NULL, NULL);
			if (!_Write(reply) || !_Read(request) || !request.hasNegoToken)
				return kFailed;
			SpnegoToken next;
			if (!ParseSpnego(request.negoToken, next) || !next.hasToken)
				return kFailed;
			negotiate = next.token;
		}
	} else
		negotiate = request.negoToken;
	LOG_D("CredSSP: version %lld, NTLM %s", (long long)fVersion,
		spnego ? "in SPNEGO" : "raw");

	Bytes challenge;
	if (!ntlm.HandleNegotiate(negotiate, challenge)) {
		_SendError(STATUS_INVALID_PARAMETER);
		return kFailed;
	}
	TsRequest reply;
	reply.version = fVersion;
	reply.hasNegoToken = true;
	reply.negoToken = spnego
		? BuildSpnegoResponse(SPNEGO_ACCEPT_INCOMPLETE, true, &challenge, NULL)
		: challenge;
	if (!_Write(reply))
		return kFailed;

	// Step 3: AUTHENTICATE_MESSAGE with pubKeyAuth (and the nonce from
	// version 5 on).
	if (!_Read(request) || !request.hasNegoToken || !request.hasPubKeyAuth)
		return kFailed;
	Bytes authenticate;
	Bytes clientMic;
	bool hasClientMic = false;
	if (spnego) {
		SpnegoToken token;
		if (!ParseSpnego(request.negoToken, token) || !token.hasToken)
			return kFailed;
		authenticate = token.token;
		hasClientMic = token.hasMechListMic;
		clientMic = token.mechListMic;
	} else
		authenticate = request.negoToken;

	NtlmServer::Result result = ntlm.HandleAuthenticate(authenticate);
	fUserName = ntlm.UserName();
	fDomainName = ntlm.DomainName();
	if (result == NtlmServer::kWrongPassword) {
		_SendError(STATUS_LOGON_FAILURE);
		return kWrongPassword;
	}
	if (result != NtlmServer::kOk) {
		_SendError(STATUS_INVALID_PARAMETER);
		return kFailed;
	}

	// The client's mechListMIC comes first in its sequence numbers. The
	// RC4 state is the same afterwards ([MS-SPNG] 3.2.5.1).
	if (spnego && (hasClientMic || mechListMicNeeded)) {
		if (!hasClientMic
			|| !ntlm.VerifyMic(mechTypes, clientMic, true)) {
			LOG_W("CredSSP: bad or missing SPNEGO mechListMIC");
			_SendError(STATUS_LOGON_FAILURE);
			return kFailed;
		}
		mechListMicNeeded = true;
	}

	Bytes clientBinding;
	if (!ntlm.Unwrap(request.pubKeyAuth, clientBinding)) {
		_SendError(STATUS_LOGON_FAILURE);
		return kFailed;
	}
	Bytes serverBinding;
	if (fVersion >= 5) {
		if (!request.hasClientNonce || request.clientNonce.size() != 32) {
			LOG_W("CredSSP: version %lld without a 32-byte nonce",
				(long long)fVersion);
			return kFailed;
		}
		Bytes expected = BindingHash(kClientServerMagic, request.clientNonce,
			fSubjectPublicKey);
		if (clientBinding.size() != expected.size()
			|| !SameBytes(clientBinding.data(), expected.data(),
				expected.size())) {
			LOG_W("CredSSP: the client's public key hash does not match; "
				"is something between us and the client?");
			return kFailed;
		}
		serverBinding = BindingHash(kServerClientMagic, request.clientNonce,
			fSubjectPublicKey);
	} else {
		if (clientBinding != fSubjectPublicKey) {
			LOG_W("CredSSP: the client saw a different public key; is "
				"something between us and the client?");
			return kFailed;
		}
		// Versions 2 to 4: the key with 1 added to its first byte (3.1.5).
		serverBinding = fSubjectPublicKey;
		serverBinding[0]++;
	}

	// Step 4: our side of the binding, with SPNEGO's final token.
	reply = TsRequest();
	reply.version = fVersion;
	if (spnego) {
		Bytes serverMic;
		if (mechListMicNeeded)
			serverMic = ntlm.GetMic(mechTypes, true);
		reply.hasNegoToken = true;
		reply.negoToken = BuildSpnegoResponse(SPNEGO_ACCEPT_COMPLETED, false,
			NULL, mechListMicNeeded ? &serverMic : NULL);
	}
	reply.hasPubKeyAuth = true;
	reply.pubKeyAuth = ntlm.Wrap(serverBinding);
	if (!_Write(reply))
		return kFailed;

	// Step 5: the delegated credentials, TSCredentials (2.2.1.2).
	if (!_Read(request) || !request.hasAuthInfo)
		return kFailed;
	Bytes credentials;
	if (!ntlm.Unwrap(request.authInfo, credentials))
		return kFailed;

	DerReader reader(credentials.data(), credentials.size());
	DerReader sequence(NULL, 0);
	DerReader field(NULL, 0);
	int64_t credType = 0;
	Bytes passwordCreds;
	bool parsed = reader.Read(DER_SEQUENCE, sequence)
		&& sequence.Read(DerContext(0), field) && field.ReadInteger(credType)
		&& sequence.Read(DerContext(1), field)
		&& field.ReadOctetString(passwordCreds);
	Wipe(credentials.data(), credentials.size());
	if (!parsed || credType != 1) {
		LOG_W("CredSSP: credentials of type %lld; only passwords (1) are "
			"supported", (long long)credType);
		Wipe(passwordCreds.data(), passwordCreds.size());
		return kFailed;
	}

	// TSPasswordCreds (2.2.1.2.1)
	DerReader creds(passwordCreds.data(), passwordCreds.size());
	Bytes domain;
	Bytes user;
	Bytes password;
	parsed = creds.Read(DER_SEQUENCE, sequence)
		&& sequence.Read(DerContext(0), field) && field.ReadOctetString(domain)
		&& sequence.Read(DerContext(1), field) && field.ReadOctetString(user)
		&& sequence.Read(DerContext(2), field)
		&& field.ReadOctetString(password);
	Wipe(passwordCreds.data(), passwordCreds.size());
	std::string plain = Utf16LeToUtf8(password.data(), password.size());
	Wipe(password.data(), password.size());
	if (!parsed) {
		WipeString(plain);
		return kFailed;
	}

	// NTLM already proved the password. The delegated copy has to match
	// the stored hash as well, so both hashes always describe one password.
	bool same = VerifyPassword(plain, fPasswordHash);
	WipeString(plain);
	if (!same) {
		LOG_W("CredSSP: the delegated password does not match the stored "
			"one; run --set-password again");
		return kWrongPassword;
	}
	return kAuthenticated;
}


}	// namespace rrd
