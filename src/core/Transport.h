/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */
#ifndef RRD_TRANSPORT_H
#define RRD_TRANSPORT_H


#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>


typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;


namespace rrd {


// Creates the server's TLS context. The certificate and key are read from
// certPath and keyPath; if either file is missing, a self-signed RSA
// certificate is generated and written there (the key with mode 0600).
class TlsContext {
public:
								TlsContext();
								~TlsContext();

			bool				Init(const std::string& certPath,
									const std::string& keyPath);

			SSL_CTX*			Context() const { return fContext; }

			// SHA-256 fingerprint of the certificate, as colon-separated hex.
			// Users compare this with what their RDP client shows.
			const std::string&	Fingerprint() const { return fFingerprint; }

			// DER encoding of the certificate's SubjectPublicKey (the BIT
			// STRING contents), which CredSSP binds to ([MS-CSSP] 3.1.5).
			const std::vector<uint8_t>& SubjectPublicKey() const
									{ return fSubjectPublicKey; }

private:
			bool				_Load(const std::string& certPath,
									const std::string& keyPath);
			bool				_Generate(const std::string& certPath,
									const std::string& keyPath);

			SSL_CTX*			fContext;
			std::string			fFingerprint;
			std::vector<uint8_t> fSubjectPublicKey;
};


// A TCP connection that starts in the clear (for the X.224 negotiation) and
// is upgraded to TLS in place. Reads and writes happen on one thread; only
// Shutdown() may be called from another thread.
class Transport {
public:
								Transport(int fd);
								~Transport();

			bool				StartTls(SSL_CTX* context);
			bool				IsTls() const { return fSsl != NULL; }

			bool				ReadExact(void* buffer, size_t size);
			bool				WriteAll(const void* buffer, size_t size);
			bool				WriteAll(const std::vector<uint8_t>& data)
									{ return WriteAll(data.data(),
										data.size()); }

			// Waits until data can be read, up to timeoutMs. Returns 1 when
			// readable, 0 on timeout, and -1 on error or hangup.
			int					WaitReadable(int timeoutMs);

			// Wakes any blocked read and makes further I/O fail.
			void				Shutdown();

			const std::string&	PeerAddress() const { return fPeer; }

private:
			int					fFd;
			SSL*				fSsl;
			std::string			fPeer;
};


}	// namespace rrd


#endif	// RRD_TRANSPORT_H
