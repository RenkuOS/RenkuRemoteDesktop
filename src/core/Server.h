/*
 * Copyright 2026, RenkuOS contributors.
 * Distributed under the terms of the MIT License.
 */
#ifndef RRD_SERVER_H
#define RRD_SERVER_H


#include <atomic>
#include <condition_variable>
#include <map>
#include <mutex>
#include <set>
#include <string>

#include "Session.h"


namespace rrd {


// Accepts connections and runs each in its own thread. One session at a
// time owns the desktop; a newly authenticated session takes it over.
class Server : public SessionHost {
public:
								Server(const ServerConfig& config,
									TlsContext& tls, FrameSource& frames,
									InputSink& input);
	virtual						~Server();

			bool				Listen();

			// Applies changed login settings (password hashes, resize policy,
			// frame rate) to new connections. The port and address stay
			// until the server is restarted.
			void				UpdateConfig(const ServerConfig& config);

			struct Status {
				bool			connected;
				std::string		peer;
				std::string		user;
				bool			nla;
				int64_t			since;
			};
			Status				ActiveSession();
			// Ends the active session, if there is one.
			void				Disconnect();
			// Accepts connections until Stop() is called, then ends all
			// sessions and returns once none is running.
			void				Run();
			void				Stop();

	virtual	void				SessionActivating(Session* session);
	virtual	void				SessionEnded(Session* session);
	virtual	bool				AllowConnection(const std::string& peer);
	virtual	void				LoginFailed(const std::string& peer);

private:
			void				_AbortOverduePending();

private:
			struct Failures {
				int		count;
				int64_t	firstMs;
			};

			ServerConfig		fConfig;
			TlsContext&			fTls;
			FrameSource&		fFrames;
			InputSink&			fInput;
			int					fListenFd;
			std::atomic<bool>	fStopping;

			std::mutex			fLock;
			std::condition_variable fCondition;
			Session*			fActive;
			// Sessions still logging in, with the time they connected.
			std::map<Session*, int64_t> fPending;
			std::set<Session*>	fLive;
			std::map<std::string, Failures> fFailures;
};


}	// namespace rrd


#endif	// RRD_SERVER_H
