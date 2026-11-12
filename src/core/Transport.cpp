/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */


#include "Transport.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "Log.h"


namespace rrd {


static void
LogOpenSslErrors(const char* what)
{
	unsigned long error;
	bool any = false;
	while ((error = ERR_get_error()) != 0) {
		char text[256];
		ERR_error_string_n(error, text, sizeof(text));
		LOG_E("%s: %s", what, text);
		any = true;
	}
	if (!any)
		LOG_E("%s failed", what);
}


// #pragma mark - TlsContext


TlsContext::TlsContext()
	:
	fContext(NULL)
{
}


TlsContext::~TlsContext()
{
	SSL_CTX_free(fContext);
}


bool
TlsContext::Init(const std::string& certPath, const std::string& keyPath)
{
	if (access(certPath.c_str(), R_OK) != 0
		|| access(keyPath.c_str(), R_OK) != 0) {
		LOG_I("no certificate at %s, generating a self-signed one",
			certPath.c_str());
		if (!_Generate(certPath, keyPath))
			return false;
	}

	fContext = SSL_CTX_new(TLS_server_method());
	if (fContext == NULL) {
		LogOpenSslErrors("SSL_CTX_new");
		return false;
	}

	// [MS-RDPBCGR] 5.4.5.1 names TLS 1.0 to 1.2 for PROTOCOL_SSL. We require
	// at least 1.2 and, for now, stop there too: some RDP clients have had
	// trouble with TLS 1.3 servers. Revisit once tested with current clients.
	SSL_CTX_set_min_proto_version(fContext, TLS1_2_VERSION);
	SSL_CTX_set_max_proto_version(fContext, TLS1_2_VERSION);
	SSL_CTX_set_options(fContext, SSL_OP_NO_COMPRESSION
		| SSL_OP_NO_RENEGOTIATION | SSL_OP_CIPHER_SERVER_PREFERENCE);

	if (!_Load(certPath, keyPath)) {
		// A damaged pair (for example, emptied by a power loss) is moved
		// aside and replaced, so the service comes back on its own. The
		// fingerprint changes, and clients will warn about that.
		LogOpenSslErrors("loading the certificate");
		LOG_W("certificate or key unusable; moving them aside and generating "
			"a new pair");
		rename(certPath.c_str(), (certPath + ".bad").c_str());
		rename(keyPath.c_str(), (keyPath + ".bad").c_str());
		if (!_Generate(certPath, keyPath) || !_Load(certPath, keyPath)) {
			LogOpenSslErrors("loading the new certificate");
			return false;
		}
	}

	X509* certificate = SSL_CTX_get0_certificate(fContext);
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digestLength = 0;
	if (X509_digest(certificate, EVP_sha256(), digest, &digestLength) == 1) {
		char hex[4];
		fFingerprint.clear();
		for (unsigned int i = 0; i < digestLength; i++) {
			snprintf(hex, sizeof(hex), i == 0 ? "%02X" : ":%02X", digest[i]);
			fFingerprint += hex;
		}
	}

	// The SubjectPublicKey is the content of the BIT STRING inside
	// SubjectPublicKeyInfo, without the unused-bits byte.
	const ASN1_BIT_STRING* key = X509_get0_pubkey_bitstr(certificate);
	if (key != NULL) {
		fSubjectPublicKey.assign(ASN1_STRING_get0_data(key),
			ASN1_STRING_get0_data(key) + ASN1_STRING_length(key));
	}

	LOG_I("TLS certificate SHA-256 fingerprint %s", fFingerprint.c_str());
	return true;
}


bool
TlsContext::_Load(const std::string& certPath, const std::string& keyPath)
{
	return SSL_CTX_use_certificate_chain_file(fContext, certPath.c_str()) == 1
		&& SSL_CTX_use_PrivateKey_file(fContext, keyPath.c_str(),
			SSL_FILETYPE_PEM) == 1
		&& SSL_CTX_check_private_key(fContext) == 1;
}


// Writes a PEM file through a temporary file, fsync, and rename, so a crash
// or power loss leaves either the old file or the complete new one.
static bool
WritePemFile(const std::string& path, mode_t mode,
	int (*write)(FILE* file, void* object), void* object)
{
	std::string temporary = path + ".new";
	int fd = open(temporary.c_str(), O_WRONLY | O_CREAT | O_TRUNC, mode);
	if (fd < 0) {
		LOG_E("cannot create %s: %s", temporary.c_str(), strerror(errno));
		return false;
	}
	FILE* file = fdopen(fd, "w");
	if (file == NULL) {
		close(fd);
		return false;
	}
	bool ok = write(file, object) == 1 && fflush(file) == 0
		&& fsync(fd) == 0;
	ok &= fclose(file) == 0;
	if (ok && rename(temporary.c_str(), path.c_str()) != 0) {
		LOG_E("cannot replace %s: %s", path.c_str(), strerror(errno));
		ok = false;
	}
	if (!ok)
		unlink(temporary.c_str());
	return ok;
}


static int
WriteKey(FILE* file, void* key)
{
	return PEM_write_PrivateKey(file, (EVP_PKEY*)key, NULL, NULL, 0, NULL,
		NULL);
}


static int
WriteCertificate(FILE* file, void* certificate)
{
	return PEM_write_X509(file, (X509*)certificate);
}


bool
TlsContext::_Generate(const std::string& certPath, const std::string& keyPath)
{
	EVP_PKEY* key = EVP_RSA_gen(2048);
	X509* certificate = X509_new();
	bool ok = false;

	do {
		if (key == NULL || certificate == NULL)
			break;

		X509_set_version(certificate, 2);
		unsigned char serial[16];
		RAND_bytes(serial, sizeof(serial));
		serial[0] &= 0x7f;
		BIGNUM* serialNumber = BN_bin2bn(serial, sizeof(serial), NULL);
		BN_to_ASN1_INTEGER(serialNumber, X509_get_serialNumber(certificate));
		BN_free(serialNumber);

		X509_gmtime_adj(X509_getm_notBefore(certificate), -60 * 60);
		X509_gmtime_adj(X509_getm_notAfter(certificate),
			10L * 365 * 24 * 60 * 60);
		X509_set_pubkey(certificate, key);

		char hostName[256] = "RenkuOS";
		gethostname(hostName, sizeof(hostName) - 1);
		X509_NAME* name = X509_get_subject_name(certificate);
		X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8,
			(const unsigned char*)hostName, -1, -1, 0);
		X509_set_issuer_name(certificate, name);

		if (X509_sign(certificate, key, EVP_sha256()) == 0)
			break;

		// The key is owner-only from the start.
		bool keyWritten = WritePemFile(keyPath, 0600, WriteKey, key);
		bool certWritten = keyWritten
			&& WritePemFile(certPath, 0644, WriteCertificate, certificate);

		ok = keyWritten && certWritten;
	} while (false);

	if (!ok)
		LogOpenSslErrors("generating the certificate");

	X509_free(certificate);
	EVP_PKEY_free(key);
	return ok;
}


// #pragma mark - Transport


Transport::Transport(int fd)
	:
	fFd(fd),
	fSsl(NULL)
{
	int one = 1;
	setsockopt(fFd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

	// No read or write may block longer than this. Before login this
	// bounds how long a silent client holds a connection slot; later it
	// bounds a stalled client. Idle sessions are unaffected: the session
	// waits with poll() and reads only when data is there.
	struct timeval timeout = { 20, 0 };
	setsockopt(fFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	setsockopt(fFd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

	struct sockaddr_storage address;
	socklen_t length = sizeof(address);
	char text[INET6_ADDRSTRLEN] = "?";
	if (getpeername(fFd, (struct sockaddr*)&address, &length) == 0) {
		if (address.ss_family == AF_INET) {
			inet_ntop(AF_INET, &((struct sockaddr_in*)&address)->sin_addr,
				text, sizeof(text));
		} else if (address.ss_family == AF_INET6) {
			inet_ntop(AF_INET6, &((struct sockaddr_in6*)&address)->sin6_addr,
				text, sizeof(text));
		}
	}
	fPeer = text;
}


Transport::~Transport()
{
	if (fSsl != NULL) {
		SSL_shutdown(fSsl);
		SSL_free(fSsl);
	}
	close(fFd);
}


bool
Transport::StartTls(SSL_CTX* context)
{
	fSsl = SSL_new(context);
	if (fSsl == NULL || SSL_set_fd(fSsl, fFd) != 1) {
		LogOpenSslErrors("SSL_new");
		return false;
	}

	int result = SSL_accept(fSsl);
	if (result != 1) {
		LOG_W("TLS handshake with %s failed (%d)", fPeer.c_str(),
			SSL_get_error(fSsl, result));
		LogOpenSslErrors("SSL_accept");
		return false;
	}

	LOG_I("TLS established with %s: %s, %s", fPeer.c_str(),
		SSL_get_version(fSsl), SSL_get_cipher_name(fSsl));
	return true;
}


bool
Transport::ReadExact(void* buffer, size_t size)
{
	uint8_t* bytes = (uint8_t*)buffer;
	while (size > 0) {
		ssize_t count;
		if (fSsl != NULL) {
			int result = SSL_read(fSsl, bytes, size > 0x40000000
				? 0x40000000 : (int)size);
			if (result <= 0) {
				int error = SSL_get_error(fSsl, result);
				if (error != SSL_ERROR_ZERO_RETURN)
					LOG_D("SSL_read failed (%d)", error);
				return false;
			}
			count = result;
		} else {
			count = recv(fFd, bytes, size, 0);
			if (count < 0 && errno == EINTR)
				continue;
			if (count <= 0)
				return false;
		}
		bytes += count;
		size -= count;
	}
	return true;
}


bool
Transport::WriteAll(const void* buffer, size_t size)
{
	const uint8_t* bytes = (const uint8_t*)buffer;
	while (size > 0) {
		ssize_t count;
		if (fSsl != NULL) {
			int result = SSL_write(fSsl, bytes, size > 0x40000000
				? 0x40000000 : (int)size);
			if (result <= 0) {
				LOG_D("SSL_write failed (%d)", SSL_get_error(fSsl, result));
				return false;
			}
			count = result;
		} else {
			count = send(fFd, bytes, size, 0);
			if (count < 0 && errno == EINTR)
				continue;
			if (count <= 0)
				return false;
		}
		bytes += count;
		size -= count;
	}
	return true;
}


int
Transport::WaitReadable(int timeoutMs)
{
	if (fSsl != NULL && SSL_pending(fSsl) > 0)
		return 1;

	struct pollfd pollFd = { fFd, POLLIN, 0 };
	int result;
	do {
		result = poll(&pollFd, 1, timeoutMs);
	} while (result < 0 && errno == EINTR);

	if (result < 0)
		return -1;
	if (result == 0)
		return 0;
	if ((pollFd.revents & POLLIN) != 0)
		return 1;
	return -1;
}


void
Transport::Shutdown()
{
	shutdown(fFd, SHUT_RDWR);
}


}	// namespace rrd
