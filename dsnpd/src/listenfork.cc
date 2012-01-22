/*
 * Copyright (c) 2011, Adrian Thurston <thurston@complang.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define __STDC_FORMAT_MACROS 1
#define __STDC_LIMIT_MACROS 1

#include "dsnp.h"
#include "error.h"
#include "dlist.h"
#include "keyagent.h"

#include <inttypes.h>
#include <stdint.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <pwd.h>

bool stop = false;
bool logFileReopen = false;

void sigLogFileReopen( int signum )
{
	logFileReopen = true;
}

void quit( int signum )
{
	stop = true;
}

void thatsOkay( int signum )
{
}

void dieHandler( int signum )
{
	error( "caught signal %d, exiting\n", signum );
	exit(1);
}

void workerSignalHandlers()
{
	signal( SIGHUP,  &dieHandler );
	signal( SIGINT,  &dieHandler );
	signal( SIGQUIT, &dieHandler );
	signal( SIGILL,  &dieHandler );
	signal( SIGABRT, &dieHandler );
	signal( SIGFPE,  &dieHandler );
	signal( SIGSEGV, &dieHandler );
	signal( SIGPIPE, &dieHandler );
	signal( SIGTERM, &dieHandler );
}

void listenerSignalHandlers()
{
	signal( SIGHUP,  gbl.background ? sigLogFileReopen : quit );
	signal( SIGINT,  quit );
	signal( SIGQUIT, quit );
	signal( SIGTERM, quit );
	signal( SIGILL,  quit );
	signal( SIGABRT, quit );
	signal( SIGFPE,  quit );
	signal( SIGSEGV, quit );
	signal( SIGPIPE, quit );
	signal( SIGALRM, quit );

	signal( SIGCHLD, thatsOkay );
}

void Server::runServerBare( int sockFd )
{
	/* This can throw. */
	bioWrap.makeNonBlocking();

	/* Setup the parser and run it off the server's bioWrap. */
	ServerParser parser( this );
	bioWrap.readParse( parser );

	close( sockFd );
}

void Server::runServer( int sockFd )
{
	/* Set BIOs that wrap up the input BIO to wrap stdin. */
	bioWrap.setSockFd( sockFd );

	try {
		runServerBare( sockFd );
	}
	catch ( UserError &e ) {
		e.print( bioWrap );
	}

	if ( mysql != 0 )
		mysql_close( mysql );
}

int issueCommand( Config *c, TlsContext &tlsContext, int privFd, int notifFd )
{
	/* Drop privs. */
	setgid( gbl.dsnpdGid );
	setuid( gbl.dsnpdUid );

	workerSignalHandlers();

	KeyAgent keyAgent( privFd );
	NotifAgent notifAgent( notifFd );

	Server server( c, tlsContext, keyAgent, notifAgent );

	int exitStatus = server.runCommand();

	debug( DBG_PROC, "COMAND EXITING\n" );

	/* Tell the priv and notification processes to quit. */
	notifAgent.quit();
	keyAgent.quit();

	return exitStatus;
}

int serverProcess( Config *c, TlsContext &tlsContext, int sockFd, int privFd, int notifFd )
{
	/* Drop privs. */
	setgid( gbl.dsnpdGid );
	setuid( gbl.dsnpdUid );

	workerSignalHandlers();

	KeyAgent keyAgent( privFd );
	NotifAgent notifAgent( notifFd );

	Server server( c, tlsContext, keyAgent, notifAgent );
	server.runServer( sockFd );

	message( "SERVER EXITING\n" );

	/* Tell the priv and notification processes to quit. */
	notifAgent.quit();
	keyAgent.quit();

	return 0;
}

int queueRun( Config *c, TlsContext &tlsContext, int privFd, int notifFd )
{
	/* Drop privs. */
	setgid( gbl.dsnpdGid );
	setuid( gbl.dsnpdUid );

	KeyAgent keyAgent( privFd );
	NotifAgent notifAgent( notifFd );

	Server queueRunner( c, tlsContext, keyAgent, notifAgent );
	queueRunner.runQueue();

	/* Tell the priv and notification processes to quit. */
	notifAgent.quit();
	keyAgent.quit();

	return 0;
}

int stateChange( Config *c, TlsContext &tlsContext, int privFd, int notifFd )
{
	/* Drop privs. */
	setgid( gbl.dsnpdGid );
	setuid( gbl.dsnpdUid );

	workerSignalHandlers();

	KeyAgent keyAgent( privFd );
	NotifAgent notifAgent( notifFd );

	Server server( c, tlsContext, keyAgent, notifAgent );
	server.runReceivedQueue();

	debug( DBG_PROC, "RECEIVED QUEUE RUN SERVER EXITING\n" );

	/* Tell the priv and notification processes to quit. */
	notifAgent.quit();
	keyAgent.quit();

	return 0;
}


void ListenFork::dispatch( Config *c, 
		TlsContext &tlsContext, DispatchType dispatchType,
		int listenFd, int sockFd, sockaddr_in *, socklen_t )
{
	int result, pair[2], privFd, notifFd;

	/* Make the socket pair for comm with dsnpk. Transmit it. */
	result = socketpair( PF_UNIX, SOCK_STREAM, 0, pair );
	if ( result < 0 )
		fatal( "socketpair failed: %s\n", strerror(errno) );

	debug( DBG_PROC, "sending comm socket (%d) to dsnpk\n", pair[1] );
	privFd = pair[0];
	transmitFd( gbl.privCmdFd, AC_SOCKET, pair[1] );
	close( pair[1] );

	/* Make the socket pair for comm with the notification process. Transmit
	 * it. */
	result = socketpair( PF_UNIX, SOCK_STREAM, 0, pair );
	if ( result < 0 )
		fatal( "socketpair failed: %s\n", strerror(errno) );
	notifFd = pair[0];
	debug( DBG_PROC, "sending comm socket (%d) to "
			"notif dispatcher\n", pair[1] );
	transmitFd( gbl.notifCmdFd, AC_SOCKET, pair[1] );
	close( pair[1] );

	debug( DBG_PROC, "forking server process\n" );
	pid_t pid = fork();
	if ( pid < 0 )
		fatal( "fork failed %s\n", strerror(errno) );

	if ( pid == 0 ) {
		/* child. */
		gbl.pid = getpid();
		debug( DBG_PROC, "forked server process\n" );

		/* Not used for deplay queue runs. */
		int exitVal = 250; /* just cause. */

		/* The listenFd may not be supplied if this is a command context. */
		if ( listenFd >= 0 )
			close( listenFd );

		switch ( dispatchType ) {
			case Command:
				exitVal = ::issueCommand( c, tlsContext, privFd, notifFd );
				break;
			case ServerProcess:
				exitVal = ::serverProcess( c, tlsContext, sockFd, privFd, notifFd );
				break;
			case QueueRun:
				exitVal = ::queueRun( c, tlsContext, privFd, notifFd );
				break;
			case StateChange:
				exitVal = ::stateChange( c, tlsContext, privFd, notifFd );
				break;
		}

		exit( exitVal );
	}

	Reap *reap = new Reap( pid );
	reapList.append( reap );

	result = close( privFd );
	if ( result < 0 ) 
		error( "priv fd close faild: %s\n", strerror(errno) );

	result = close( notifFd );
	if ( result < 0 )
		error( "notif fd close faild: %s\n", strerror(errno) );

	if ( sockFd >= 0 ) {
		result = close( sockFd );
		if ( result < 0 )
			error( "sock fd close faild: %s\n", strerror(errno) );
	}
}

SSL_CTX *sslClientCtx( ConfigSection *c )
{
	/* FIXME: these should not be throws. Done at startup before any
	 * connections come in. */

	/* Create the SSL_CTX. */
	SSL_CTX *ctx = SSL_CTX_new(TLSv1_client_method());
	if ( ctx == NULL )
		throw SslNewContextFailure();
	
	/* Load the CA certificates that we will use to verify. */
	int result = SSL_CTX_load_verify_locations( ctx, CA_CERT_FILE, NULL );
	if ( !result ) 
		throw SslCaCertLoadFailure( CA_CERT_FILE );
	
	return ctx;
}

SSL_CTX *sslServerCtx( ConfigSection *c )
{
	/* FIXME: these should not be throws. Done at startup before any
	 * connections come in. */
	/* Create the SSL_CTX. */
	SSL_CTX *ctx = SSL_CTX_new(SSLv23_method());
	if ( ctx == NULL )
		throw SslContextCreationFailed();

	if ( c->CFG_TLS_CRT.length == 0 )
		throw SslParamNotSet( "CFG_TLS_CRT" );
	if ( c->CFG_TLS_KEY.length == 0 )
		throw SslParamNotSet( "CFG_TLS_KEY" );

	int result = SSL_CTX_use_certificate_chain_file( ctx, c->CFG_TLS_CRT );
	if ( result != 1 ) 
		fatal( "failed to load TLS CRT file %s\n", c->CFG_TLS_CRT() );

	result = SSL_CTX_use_PrivateKey_file( ctx, c->CFG_TLS_KEY, SSL_FILETYPE_PEM );
	if ( result != 1 ) 
		fatal( "failed to load TLS KEY file %s\n", c->CFG_TLS_KEY() );

	return ctx;
}

void tlsInitialization( TlsContext &tlsContext, Config *c )
{
	/* Global initialization. */
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
	SSL_library_init(); 

	for ( ConfigSection *sect = c->hostList.head; 
			sect != 0; sect = sect->next )
	{
		/* Something strange here: doing the client load first causes problems.
		 * */
		SSL_CTX *serverCtx = sslServerCtx( sect );
		tlsContext.serverCtx.push_back( serverCtx );

		SSL_CTX *clientCtx = sslClientCtx( sect );
		tlsContext.clientCtx.push_back( clientCtx );
	}
}

void randomDataInitialization()
{
	/* FIXME: this needs improvement. */
	RAND_load_file("/dev/urandom", 1024);
}

void Server::runQueue()
{
	/*
	 * This is rather noisy.
	 * message("running queue\n");
	 */
	try {
		runMessageQueue();
		runFofMessageQueue();
		runBroadcastQueue();
	}
	catch ( UserError &e ) {
		/* We have no more output. */
		BioWrap bioWrap( BioWrap::Null );
		e.print( bioWrap );
	}
}

void TokenFlusher::flushLoginTokens()
{
	DbQuery loginTokens( mysql, 
		"SELECT user_id, login_token, session_id, expires "
		"FROM login_token"
	);

	while ( true ) {
		MYSQL_ROW row = loginTokens.fetchRow();
		if ( !row )
			break;
		long long userId = parseId( row[0] );
		const char *loginToken = row[1];
		const char *sessionId = row[2];
		const char *expires = row[3];

		User user( mysql, userId );
		String site = user.site();

		message( "expiring %lld %s %s %s\n", userId, loginToken, sessionId, expires );
		notifAgent.notifLogout( site, sessionId );
	}

	/* Clear the login tokens. */
	DbQuery ( mysql, "DELETE FROM login_token" );
}

void TokenFlusher::flushFloginTokens()
{
	DbQuery loginTokens( mysql, 
		"SELECT user_id, identity_id, login_token, session_id, expires "
		"FROM flogin_token"
	);

	while ( true ) {
		MYSQL_ROW row = loginTokens.fetchRow();
		if ( !row )
			break;
		long long userId = parseId( row[0] );
		long long identityId = parseId( row[1] );
		const char *loginToken = row[2];
		const char *sessionId = row[3];
		const char *expires = row[4];

		User user( mysql, userId );
		String site = user.site();

		message( "expiring %lld %lld %s %s %s\n", userId, identityId, loginToken, sessionId, expires );
		notifAgent.notifLogout( site, sessionId );
	}

	/* Clear the login tokens. */
	DbQuery ( mysql, "DELETE FROM flogin_token" );
}

void TokenFlusher::flush()
{
	message("flushing all tokens\n");
	mysql = dbConnect();
	flushLoginTokens();
	flushFloginTokens();
	mysql_close( mysql );
}

void initialTimerRunProcess( Config *c, int notifFd )
{
	/* Drop privs. */
	setgid( gbl.dsnpdGid );
	setuid( gbl.dsnpdUid );

	NotifAgent notifAgent( notifFd );

	if ( gbl.tokenFlush ) {
		TokenFlusher tokenFlusher( c, notifAgent );
		tokenFlusher.flush();
	}

	notifAgent.quit();
}

void ListenFork::initialTimerRun( Config *c )
{
	int result, pair[2], notifFd;

	/* Make the socket pair for comm with the notification process. Transmit
	 * it. */
	result = socketpair( PF_UNIX, SOCK_STREAM, 0, pair );
	if ( result < 0 )
		fatal( "socketpair failed: %s\n", strerror(errno) );
	notifFd = pair[0];
	debug( DBG_PROC, "sending comm socket (%d) to "
			"notif dispatcher\n", pair[1] );
	transmitFd( gbl.notifCmdFd, AC_SOCKET, pair[1] );
	close( pair[1] );

	debug( DBG_PROC, "forking initial timer run\n" );
	pid_t pid = fork();
	if ( pid < 0 )
		fatal( "fork failed %s\n", strerror(errno) );

	if ( pid == 0 ) {
		close( gbl.privCmdFd );
		close( gbl.notifCmdFd );

		/* child. */
		gbl.pid = getpid();
		debug( DBG_PROC, "forked initial timer run\n" );

		initialTimerRunProcess( c, notifFd );

		exit( 0 );
	}

	close( notifFd );

	Reap *reap = new Reap( pid );
	reapList.append( reap );
}

void ListenFork::dispatchStateChange( Config *c, TlsContext &tlsContext, int listenFd )
{
	/* Use the dispatch mechanism for dealing with deplayed brodcast . */
	dispatch( c, tlsContext, StateChange, listenFd, -1, 0, 0 );
}

void ListenFork::dispatchIssueCommand( Config *c, TlsContext &tlsContext )
{
	/* Use the dispatch mechanism for dealing with deplayed brodcast . */
	dispatch( c, tlsContext, Command, -1, -1, 0, 0 );
}

void ListenFork::dispatchQueueRun( Config *c, TlsContext &tlsContext, int listenFd )
{
	/* Use the dispatch mechanism for dealing with deplayed brodcast . */
	dispatch( c, tlsContext, QueueRun, listenFd, -1, 0, 0 );
}

void finalTimerRunProcess( Config *c, int notifFd )
{
	/* Drop privs. */
	setgid( gbl.dsnpdGid );
	setuid( gbl.dsnpdUid );

	NotifAgent notifAgent( notifFd );

	if ( gbl.tokenFlush ) {
		TokenFlusher tokenFlusher( c, notifAgent );
		tokenFlusher.flush();
	}

	notifAgent.quit();
}

void ListenFork::finalTimerRun( Config *c )
{
	int result, pair[2], notifFd;

	/* Make the socket pair for comm with the notification process. Transmit
	 * it. */
	result = socketpair( PF_UNIX, SOCK_STREAM, 0, pair );
	if ( result < 0 )
		fatal( "socketpair failed: %s\n", strerror(errno) );
	notifFd = pair[0];
	transmitFd( gbl.notifCmdFd, AC_SOCKET, pair[1] );
	close( pair[1] );

	debug( DBG_PROC, "forking final timer run\n" );
	pid_t pid = fork();
	if ( pid < 0 )
		fatal( "fork failed %s\n", strerror(errno) );

	if ( pid == 0 ) {
		close( gbl.privCmdFd );
		close( gbl.notifCmdFd );

		/* child. */
		gbl.pid = getpid();
		debug( DBG_PROC, "forked final timer run\n" );

		finalTimerRunProcess( c, notifFd );

		exit( 0 );
	}

	Reap *reap = new Reap( pid );
	reapList.append( reap );
}

int ListenFork::reapChildren( bool wait )
{
	int exitStatus = 0;
	for ( Reap *reap = reapList.head; reap != 0; ) {
		debug( DBG_PROC, "waiting on pid %d\n", reap->pid );
		Reap *next = reap->next;

		int status = 0;
		int result = waitpid( reap->pid, &status, (wait ? 0 : WNOHANG) );
		if ( result < 0 )
			fatal( "waitpid failed: %s\n", strerror(errno) );

		if ( result > 0 && ( WIFEXITED(status) || WIFSIGNALED(status) ) ) {
			debug( DBG_PROC, "pid %d exited\n", reap->pid );
			exitStatus = WEXITSTATUS(status);

			reapList.detach ( reap );
			delete reap;
		}
			
		reap = next;
	}

	return exitStatus;
}


/* Opens and transmits log files. We do this in the listener because we still
 * have root. */
void sendAgentLogFiles()
{
	int dsnpkLogFd = openLogFile( DSNPK_LOG_FILE );
	int notifLogFd = openLogFile( NOTIF_LOG_FILE );

	debug( DBG_PROC, "sending log file descriptors %d %d\n", 
			dsnpkLogFd, dsnpkLogFd );
	transmitFd( gbl.privCmdFd, AC_LOG_FD, dsnpkLogFd );
	transmitFd( gbl.notifCmdFd, AC_LOG_FD, notifLogFd );

	/* The dsnpd log file will get wrapped by gbl.logFile and closed when
	 * reopened. */
	close( dsnpkLogFd );
	close( notifLogFd );
}

void openLogFile()
{
	int dsnpdLogFd = openLogFile( DSNPD_LOG_FILE );
	setLogFd( dsnpdLogFd );
}

int ListenFork::run( int port )
{
	time_t lastTimerRun = time(0);
	long lastReapListSize = 0;
	uint64_t lastNextDelivery = UINT64_MAX;
	bool lastNextDeliveryValid = false;
	long connectionsSinceTimer = 0;

	message("STARTING\n");

	/* Read the conf file. */
	Config *c = new Config;
	ConfigParser configParser( DSNPD_CONF, SliceDaemon, c );

	listenerSignalHandlers();

	/* Open and transmit log files. */
	if ( gbl.background )
		sendAgentLogFiles();

	TlsContext tlsContext;
	randomDataInitialization();
	tlsInitialization( tlsContext, c );

	/* Before going into select we dispatch any commands. */
	if ( gbl.issueCommand )
		dispatchIssueCommand( c, tlsContext );
	else {
		/* Start with a listen loop initialization. This initialization gets a
		 * notification process. */
		initialTimerRun( c );

		/* Create the socket. */
		int listenFd = socket( PF_INET, SOCK_STREAM, 0 );
		if ( listenFd < 0 ) {
			error( "unable to allocate socket\n" );
			return -1;
		}

		/* Set its address to reusable. */
		int optionVal = 1;
		setsockopt( listenFd, SOL_SOCKET, SO_REUSEADDR,
				(char*)&optionVal, sizeof(int) );

		/* bind. */
		sockaddr_in sockName;
		sockName.sin_family = AF_INET;
		sockName.sin_port = htons(port);
		sockName.sin_addr.s_addr = htonl (INADDR_ANY);
		if ( bind(listenFd, (sockaddr*)&sockName, sizeof(sockName)) < 0 ) {
			error( "unable to bind to port %d", port );
			close( listenFd );
			return -1;
		}

		/* listen. */
		if ( listen( listenFd, 1 ) < 0 ) {
			error( "unable put socket in listen mode\n" );
			close( listenFd );
			return -1;
		}

		/* accept loop. */
		while ( true ) {
			fd_set readSet;
			FD_ZERO( &readSet );
			FD_SET( listenFd, &readSet );

			/* Wait no longer than a second. */
			timeval tv;
			tv.tv_usec = 0;
			tv.tv_sec = 1;


			int result = select( listenFd+1, &readSet, 0, 0, &tv );

			if ( result < 0 && ( errno != EAGAIN && errno != EINTR ) )
				fatal("select returned an unexpected error %s\n", strerror(errno) );

			if ( stop ) {
				message( "received signal to stop\n" );
				break;
			}

			if ( logFileReopen ) {
				message("triggering logfile reopen\n");
				logFileReopen = false;
				openLogFile();
				sendAgentLogFiles();
				message("completed logfile reopen\n");
			}

			if ( result > 0 && FD_ISSET( listenFd, &readSet ) ) {
				connectionsSinceTimer += 1;
				sockaddr_in peer;
				socklen_t len = sizeof(sockaddr_in);

				result = accept( listenFd, (sockaddr*)&peer, &len );
				if ( result < 0 ) {
					error( "failed to accept connection: %s\n",
							strerror(errno) );
				}
				else {
					dispatch( c, tlsContext, ServerProcess, listenFd, result, &peer, len );
				}
			}

			time_t now = time(0);
			if ( now - lastTimerRun > 0 ) {
				bool deliveryQueues = false;
				bool stateChange = false;
				bool skipCheck = false;

				/* If the last time we checked there were no active children, there
				 * have been no connections since the last timer (there never were
				 * any children), the next delivery time is valid, and we haven't
				 * yet reached it, then we can skip the check. */
				if ( lastReapListSize == 0 && connectionsSinceTimer == 0 && 
						lastNextDeliveryValid && (uint64_t)now < lastNextDelivery )
				{
					debug( DBG_QUEUE, "skipping check, now %"PRIu64", lastNextDelivery %"PRIu64"\n",
							(uint64_t)now, lastNextDelivery );
					skipCheck = true;
				}

				if ( ! skipCheck ) {
					debug( DBG_QUEUE, "checking delivery queues\n" );
					ConfigCtx cc( c );
					MYSQL *mysql = cc.dbConnect();
					deliveryQueues = checkDeliveryQueues( mysql );
					stateChange = checkStateChange( mysql );

					if ( deliveryQueues ) {
						/* Goig to run a delivery. The next delivery time will not be valid. */
						lastNextDelivery = UINT64_MAX;
						lastNextDeliveryValid = false;
					}
					else {
						lastNextDelivery = nextDelivery( mysql );
						lastNextDeliveryValid = true;
					}

					mysql_close( mysql );
				}

				/* Note we need to do this before the queue runs because they will
				 * fork children and populate the reap list. */
				lastReapListSize = reapList.length();

				if ( deliveryQueues )
					dispatchQueueRun( c, tlsContext, listenFd );

				if ( stateChange )
					dispatchStateChange( c, tlsContext, listenFd );

				lastTimerRun = now;
				connectionsSinceTimer = 0;
			}

			reapChildren( false );
		}

		finalTimerRun( c );
		close( listenFd );
	}

	int exitStatus = reapChildren( true );

	/* All ok. */
	return exitStatus;
}
