/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */


#include "Server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <chrono>
#include <thread>

#include "Log.h"
#include "Protocol.h"


namespace rrd {


// Connections that have not finished logging in yet, at most. The active
// session does not count. Pending connections also have a login deadline
// (kLoginDeadlineMs), so slow or silent clients cannot hold the slots.
static const int kMaxPending = 4;
// At most this many of them from one address.
static const int kMaxPendingPerPeer = 2;
// A connection must finish logging in within this time. The socket timeouts
// only bound each single read, so a client sending one byte at a time could
// otherwise hold its slot forever.
static const int64_t kLoginDeadlineMs = 30 * 1000;
// Five failed logins from one address within ten minutes block that address
// until the ten minutes are over.
static const int kMaxFailures = 5;
static const int64_t kFailureWindowMs = 10 * 60 * 1000;


static int64_t
NowMs()
{
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}


Server::Server(const ServerConfig& config, TlsContext& tls,
	FrameSource& frames, InputSink& input)
	:
	fConfig(config),
	fTls(tls),
	fFrames(frames),
	fInput(input),
	fListenFd(-1),
	fStopping(false),
	fActive(NULL)
{
}


Server::~Server()
{
	if (fListenFd >= 0)
		close(fListenFd);
}


bool
Server::Listen()
{
	struct sockaddr_in address;
	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_port = htons(fConfig.port);
	if (fConfig.bindAddress.empty())
		address.sin_addr.s_addr = htonl(INADDR_ANY);
	else if (inet_pton(AF_INET, fConfig.bindAddress.c_str(),
			&address.sin_addr) != 1) {
		LOG_E("bad bind address %s", fConfig.bindAddress.c_str());
		return false;
	}

	fListenFd = socket(AF_INET, SOCK_STREAM, 0);
	int one = 1;
	setsockopt(fListenFd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	if (fListenFd < 0
		|| bind(fListenFd, (struct sockaddr*)&address, sizeof(address)) != 0
		|| listen(fListenFd, 8) != 0) {
		LOG_E("cannot listen on port %u: %s", fConfig.port, strerror(errno));
		return false;
	}

	// Non-blocking, so a client that resets between poll() and accept()
	// cannot leave Run() stuck in accept().
	fcntl(fListenFd, F_SETFL, fcntl(fListenFd, F_GETFL) | O_NONBLOCK);

	LOG_I("listening on %s:%u",
		fConfig.bindAddress.empty() ? "*" : fConfig.bindAddress.c_str(),
		fConfig.port);
	return true;
}


void
Server::Run()
{
	while (!fStopping) {
		// Poll instead of blocking in accept(): on Haiku, shutdown() does
		// not wake a thread in accept(), and Stop() has to be noticed.
		_AbortOverduePending();
		struct pollfd pollFd = { fListenFd, POLLIN, 0 };
		int ready = poll(&pollFd, 1, 500);
		if (ready < 0 && errno != EINTR) {
			LOG_E("poll failed: %s", strerror(errno));
			break;
		}
		if (ready <= 0 || fStopping)
			continue;

		int fd = accept(fListenFd, NULL, NULL);
		if (fd < 0) {
			if (errno == EINTR || errno == ECONNABORTED || errno == EAGAIN
				|| errno == EWOULDBLOCK) {
				continue;
			}
			if (!fStopping)
				LOG_E("accept failed: %s", strerror(errno));
			break;
		}
		// Sessions use blocking I/O with timeouts. Some systems let the
		// accepted socket inherit O_NONBLOCK from the listening one.
		fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);

		Session* session;
		{
			std::lock_guard<std::mutex> lock(fLock);
			if (fPending.size() >= (size_t)kMaxPending) {
				LOG_W("too many connections still logging in, refusing one");
				close(fd);
				continue;
			}
			session = new Session(fd, fConfig, fTls, fFrames, fInput, *this);
		}

		if (!AllowConnection(session->Peer())) {
			LOG_W("refusing %s after repeated failed logins",
				session->Peer().c_str());
			delete session;
			continue;
		}

		{
			std::lock_guard<std::mutex> lock(fLock);
			int fromPeer = 0;
			for (std::map<Session*, int64_t>::iterator i = fPending.begin();
					i != fPending.end(); i++) {
				if (i->first->Peer() == session->Peer())
					fromPeer++;
			}
			if (fromPeer >= kMaxPendingPerPeer) {
				LOG_W("%s already has %d connections logging in, refusing one",
					session->Peer().c_str(), fromPeer);
				delete session;
				continue;
			}
			fPending[session] = NowMs();
			fLive.insert(session);
		}
		std::thread([session]() {
			session->Run();
			delete session;
		}).detach();
	}

	// Shut down: end every session, and wait until none of them uses the
	// server or the platform objects any more.
	std::unique_lock<std::mutex> lock(fLock);
	for (std::set<Session*>::iterator i = fLive.begin(); i != fLive.end(); i++)
		(*i)->Abort();
	fCondition.wait(lock, [this]() { return fLive.empty(); });
}


void
Server::_AbortOverduePending()
{
	std::lock_guard<std::mutex> lock(fLock);
	int64_t now = NowMs();
	for (std::map<Session*, int64_t>::iterator i = fPending.begin();
			i != fPending.end(); i++) {
		if (i->second != INT64_MAX && now - i->second > kLoginDeadlineMs) {
			LOG_W("%s did not log in within %d seconds, closing it",
				i->first->Peer().c_str(), (int)(kLoginDeadlineMs / 1000));
			// The session leaves fPending itself once its I/O fails. Mark it
			// so it is aborted and logged only once.
			i->first->Abort();
			i->second = INT64_MAX;
		}
	}
}


// Only sets a flag, so it is safe from a signal handler. Run() notices it
// within half a second, then ends the sessions before it returns.
void
Server::Stop()
{
	fStopping = true;
}


void
Server::SessionActivating(Session* session)
{
	std::unique_lock<std::mutex> lock(fLock);
	fPending.erase(session);

	// Re-read fActive on every pass: another new session can take over in
	// the meantime. A session pointer equal to fActive under fLock is alive,
	// because a session is deleted only after SessionEnded() took the lock.
	while (fActive != NULL && fActive != session) {
		Session* previous = fActive;
		LOG_I("%s takes over the session from %s", session->Peer().c_str(),
			previous->Peer().c_str());
		previous->Kick(ERRINFO_DISCONNECTED_BY_OTHERCONNECTION);
		if (!fCondition.wait_for(lock, std::chrono::seconds(3),
				[this, previous]() { return fActive != previous; })
			&& fActive == previous) {
			// Stuck writing to a slow client: cut its socket.
			previous->Abort();
			fCondition.wait(lock,
				[this, previous]() { return fActive != previous; });
		}
	}
	fActive = session;
}


void
Server::SessionEnded(Session* session)
{
	std::lock_guard<std::mutex> lock(fLock);
	if (fActive == session)
		fActive = NULL;
	fPending.erase(session);
	fLive.erase(session);
	fCondition.notify_all();
}


bool
Server::AllowConnection(const std::string& peer)
{
	std::lock_guard<std::mutex> lock(fLock);
	std::map<std::string, Failures>::iterator found = fFailures.find(peer);
	if (found == fFailures.end())
		return true;
	if (NowMs() - found->second.firstMs > kFailureWindowMs) {
		fFailures.erase(found);
		return true;
	}
	return found->second.count < kMaxFailures;
}


void
Server::LoginFailed(const std::string& peer)
{
	std::lock_guard<std::mutex> lock(fLock);
	int64_t now = NowMs();
	Failures& failures = fFailures[peer];
	if (failures.count == 0 || now - failures.firstMs > kFailureWindowMs) {
		failures.count = 0;
		failures.firstMs = now;
	}
	failures.count++;
	if (failures.count == kMaxFailures)
		LOG_W("blocking %s for ten minutes after %d failed logins",
			peer.c_str(), kMaxFailures);
}


}	// namespace rrd
