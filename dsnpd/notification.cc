/*
 * Copyright (c) 2008-2011, Adrian Thurston <thurston@complang.org>
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

#include "dsnp.h"
#include "encrypt.h"
#include "string.h"
#include "error.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>

#define MB (1024*1024)
#define KB (1024)

#define READSZ KB

static ReapList reapList;
static bool stop = false;

void notificationSignalHandlers()
{
	signal( SIGHUP,  thatsOkay );
	signal( SIGINT,  thatsOkay );
	signal( SIGQUIT, thatsOkay );
	signal( SIGTERM, thatsOkay );
	signal( SIGILL,  thatsOkay );
	signal( SIGABRT, thatsOkay );
	signal( SIGFPE,  thatsOkay );
	signal( SIGSEGV, thatsOkay );
	signal( SIGPIPE, thatsOkay );
	signal( SIGALRM, thatsOkay );
	signal( SIGCHLD, thatsOkay );
}

int splitParts( const char *src )
{
	/* Assume at least one. */
	int n = 1;
	for ( ; *src != 0; src++ ) {
		if ( *src == ' ' )
			n++;
	}
	return n;
}

void split( char **argv, long &dst, const char *args )
{
	const char *last = args;
	for ( const char *src = args; ; src++ ) {
		if ( *src == ' ' || *src == 0 ) {
			argv[dst] = new char[src-last+1];
			memcpy( argv[dst], last, src-last );
			argv[dst][src-last] = 0;

			dst++;
			last = src + 1;
		}

		if ( *src == 0 )
			break;
	}
}

char *const* NotifService::makeNotifiyArgv()
{
	debug( DBG_NOTIF, "notif: CFG_NOTIFICATION: %s\n", c->site->CFG_NOTIFICATION() );

	int n = splitParts( c->site->CFG_NOTIFICATION ) + 1;
	char **argv = new char*[n];
	long dst = 0;
	split( argv, dst, c->site->CFG_NOTIFICATION );
	argv[dst++] = 0;

	return argv;
}


void startNotificationService( Config *c, int notifListenFd, int serviceFd )
{
	debug( DBG_NOTIF, "notif: forking a notification service\n" );
	pid_t pid = fork();
	if ( pid < 0 ) {
		/* FIXME: need to take down the whole thing if this goes. */
		fatal( "error: fork failed %s\n", strerror(errno) );
	}

	if ( pid == 0 ) {
		/* In child. Close the other half. */
		gbl.pid = getpid();
		debug( DBG_PROC, "forked notification service\n" );
		close( notifListenFd );
		NotifService notifService( c, serviceFd );
		int status = notifService.service();
		int result = close( serviceFd );
		if ( result < 0 ) {
			error("notif service: close service fd %d failed: %s\n",
					serviceFd, strerror(errno) );
		}
		exit( status );
	}

	Reap *reap = new Reap( pid );
	reapList.append( reap );

	close( serviceFd );
}

int notificationProcess( int listenFd )
{
	debug( DBG_NOTIF, "notification manager: starting\n" );

	Config *c = new Config;
	try {
		/* Read the conf file. */
		ConfigParser configParser( DSNPD_CONF, SliceNotifAgent, c );
	}
	catch ( UserError &e ) {
		BioWrap bioWrap( BioWrap::Null );
		e.print( bioWrap );
		exit(1);
	}

	debug( DBG_NOTIF, "notification manager: dropping privs "
			"down to %d:%d\n", gbl.notifUid, gbl.notifGid );

	/* Drop privs. */
	int r1 = setgid( gbl.notifGid );
	int r2 = setuid( gbl.notifUid );
	if ( r1 < 0 || r2 < 0 ) {
		fatal( "notification manager: could not drop "
				"privs down to %d:%d\n", gbl.notifUid, gbl.notifGid );
	}

	notificationSignalHandlers();

	debug( DBG_NOTIF, "notification notification manager: "
			"entering select loop\n" );

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
			debug( DBG_NOTIF, "received signal to stop\n" );
			break;
		}

		if ( result > 0 && FD_ISSET( listenFd, &readSet ) ) {
			/* How big for control? */
			char control[READSZ+1];
			char data[1];

			iovec iov;
			iov.iov_base = data;
			iov.iov_len = 1;

			msghdr msg;
			memset( &msg, 0, sizeof(msg) );
			msg.msg_iov = &iov;
			msg.msg_iovlen = 1;
			msg.msg_control = control;
			msg.msg_controllen = READSZ;

			int n = recvmsg( listenFd, &msg, 0 );
			if ( n == 0 ) {
				debug( DBG_PROC, "notification process received EOF, exiting\n" );
				break;
			}

			if ( n < 0 ) {
				debug( DBG_PROC, "notification process received error, exiting\n" );
				break;
			}

			if ( iov.iov_len == 1 ) {
				switch ( data[0] ) {
					case AC_SOCKET: {
						/* This is an FD transfer. */
						debug( DBG_NOTIF, "notif: received socket\n" );
						int serviceFd = extractFd( listenFd, &msg );
						if ( serviceFd < 0 )
							fatal( "notif: bad socket\n" );
						startNotificationService( c, listenFd, serviceFd );
						break;
					}
					case AC_LOG_FD: {
						debug( DBG_NOTIF, "notif: received open logfile\n" );
						int logFd = extractFd( listenFd, &msg );
						if ( logFd < 0 )
							fatal("notif: received invalid logfile fd\n");
						setLogFd( logFd );
						debug( DBG_NOTIF, "notif: logging to newly received logfile\n", logFd );
						break;
					}
					case AC_QUIT:
						debug( DBG_NOTIF, "notif: exiting\n" );
						return 0;
					default:
						fatal( "notif: received unknown command\n" );
						break;
				}
			}
		}

		for ( Reap *reap = reapList.head; reap != 0; ) {
			debug( DBG_NOTIF, "notif: waiting on pid %d\n", reap->pid );

			Reap *next = reap->next;

			int status = 0;
			int result = waitpid( reap->pid, &status, WNOHANG );
			if ( result < 0 )
				fatal( "waitpid failed: %s\n", strerror(errno) );

			if ( result > 0 && ( WIFEXITED(status) || WIFSIGNALED(status) ) ) {
				debug( DBG_NOTIF, "notif: pid %d exited\n", reap->pid );

				reapList.detach ( reap );
				delete reap;
			}
			
			reap = next;
		}
	}

	return 0;
}

#define NA_NOTIFICATION 20

void notifServiceSigChild( int sig )
{
	debug( DBG_NOTIF, "notif service: received %d\n", sig );
}

int NotifService::service()
{
	signal( SIGCHLD, notifServiceSigChild );

	while ( true ) {
		debug( DBG_NOTIF, "notif service: waiting on command\n" );
		char cmd = readCommand();

		switch ( cmd ) {
			case BA_QUIT:
				debug( DBG_NOTIF, "notif service: exiting\n" );
				writeChar( 0 );
				goto done;
			case NA_NOTIFICATION:
				debug( DBG_NOTIF, "notif service: received notification\n" );
				recvNotification();
				break;
		}
	}

done:
	return 0;
}

void NotifAgent::appNotification( const String &site, const String &args )
{
	debug( DBG_NOTIF, "issuing notification %s %s\n", site(), args() );

	command( NA_NOTIFICATION );

	/* Empty body. */
	String body;

	writeData( site );
	writeData( args );
	writeData( body );
	readChar();
}

void NotifAgent::appNotification( const String &site, const String &args, const String &body )
{
	debug( DBG_NOTIF, "issuing notification %s %s\n", site(), args() );

	UserMessageParser msgParser( body );

	command( NA_NOTIFICATION );

	writeData( site );
	writeData( args );
	writeData( body );
	readChar();
}

void NotifAgent::notifMessage( const String &site, const char *user, 
		const char *friendId, const String &msg )
{
	String args( Format(), "message %s %s %ld", 
			user, friendId, msg.length );
	appNotification( site, args, msg );
}

void NotifAgent::notifBroadcast( const String &site, const char *user,
		const char *broadcaster, const String &msg )
{
	String args( Format(), "broadcast %s %s %ld", 
			user, broadcaster, msg.length );
	appNotification( site, args, msg );
}

void NotifAgent::notifFriendRequestSent( const String &site, const char *user, const char *iduri,
		const char *hash, const char *userNotifyReqid )
{
	String args( Format(), "friend_request_sent %s %s %s %s", 
			user, iduri, hash, userNotifyReqid );
	appNotification( site, args );
}

void NotifAgent::notifFriendRequestReceived( const String &site, const char *user,
		const char *iduri, const char *hash, const char *acceptReqid )
{
	String args( Format(), "friend_request_received %s %s %s %s",
			user, iduri, hash, acceptReqid );
	appNotification( site, args );
}

void NotifAgent::notifSentFriendRequestAccepted( const String &site, const char *user, 
		const char *iduri, const char *userNotifyReqid )
{
	String args( Format(), "sent_friend_request_accepted %s %s %s", 
		user, iduri, userNotifyReqid );
	appNotification( site, args );
}

void NotifAgent::notifFriendRequestAccepted( const String &site, const char *user, 
		const char *iduri, const char *acceptReqid )
{
	String args( Format(), "friend_request_accepted %s %s %s", 
			user, iduri, acceptReqid );
	appNotification( site, args );
}

void NotifAgent::notifNewUser( const String &site, const String &iduri,
		const String &hash, const String &distName )
{
	String args( Format(), "new_user %s %s %s", 
			iduri(), hash(), distName() );
	appNotification( site, args );
}

void NotifAgent::notifLogout( const String &site, const char *sessionId )
{
	String logout( Format(), "logout %s", sessionId );
	appNotification( site, logout );
}

void NotifService::sendArgsBody( int fd, const String &site, const String &args, const String &body )
{
	String cmdLine( Format(), "%s %s\n", c->site->CFG_COMM_KEY(), args() );
	writeNotif( fd, cmdLine(), cmdLine.length );

	if ( body.length > 0 ) 
		writeNotif( fd, body(), body.length );
}

void NotifService::waitNotification( pid_t pid )
{
	while ( true ) {
		int status = 0;
		int result = waitpid( pid, &status, WNOHANG );

		if ( result < 0 )
			fatal( "waitpid failed, this is abnormal: %s\n", strerror(errno) );

		if ( result > 0 && WIFEXITED( status ) ) {
			debug( DBG_NOTIF, "notification call %d returned\n", status );
			break;
		}

		/* Expect sigchild to break this. Though there is a race condition.
		 * consier without NOHANG and setting up an alarm for timeout. Or use
		 * sigtimedwait. */
		debug( DBG_NOTIF, "waiting for notification to finish ... sleeping\n" );
		sleep(1);
	}
}

void NotifService::execNotification( int stdinFd, int stdoutFd, int stderrFd )
{
	/* Lift all the file descriptors up to 3 and so we can safely set them to
	 * 0, 1, 2 */
	while ( stdinFd < 3 )
		stdinFd = dup( stdinFd );
	while ( stdoutFd < 3 )
		stdoutFd = dup( stdoutFd );
	while ( stderrFd < 3 )
		stderrFd = dup( stderrFd );

	dup2( stdinFd, 0 );
	dup2( stdoutFd, 1 );
	dup2( stderrFd, 2 );

	/* Close the 3 and up descriptors. */
	close( stdinFd );
	close( stdoutFd );
	close( stderrFd );

	char *const*argArray = makeNotifiyArgv();
	execvp( argArray[0], argArray );
	fatal( "failed to call notification %s\n", strerror(errno) );
}

FILE *NotifService::wrapPipeFd( int fd, const char *mode )
{
	FILE *file = fdopen( fd, mode );
	if ( file == 0 )
		fatal("failed to wrap pipe fd %d with a FILE: %s", fd, strerror(errno) );
	return file;
}

void NotifService::writeNotif( int fd, const char *data, long dlen )
{
	fd_set writeSet;
	int max = fd;
	int written = 0;

	/* FIXME: we assume linux, with TV modified. The harm in assuming this on
	 * other systems is that timeout can get reset on select interruptions and
	 * partial reads. Must be fixed. */
	timeval tv;
	tv.tv_usec = 0;
	tv.tv_sec = DAEMON_DAEMON_TIMEOUT;

	while ( true ) {
		FD_ZERO( &writeSet );
		FD_SET( fd, &writeSet );

		int result = select( max+1, 0, &writeSet, 0, &tv );

		if ( result == 0 )
			throw DaemonToDaemonTimeout( __FILE__, __LINE__ );

		if ( result == EBADFD )
			break;

		if ( FD_ISSET( fd, &writeSet ) ) {
			while ( true ) {
				int nbytes = ::write( fd, data + written, dlen - written );

				if ( nbytes < 0 ) {
					error( "writing to notification pipe\n" );
					goto done;
				}
				else {
					written += nbytes;
					if ( written == dlen )
						goto done;
				} 

				goto done;
			}
		}
	}
done:
	return;
}

int NotifService::readResult( int fd )
{
	int bytesRead = 0;
	const int linelen = 1024;
	char line[linelen+1];

	fd_set readSet;
	int max = fd;

	/* FIXME: we assume linux, with TV modified. The harm in assuming this on
	 * other systems is that timeout can get reset on select interruptions (eg
	 * signals). */
	timeval tv;
	tv.tv_usec = 0;
	tv.tv_sec = DAEMON_DAEMON_TIMEOUT;

	while ( true ) {
		FD_ZERO( &readSet );
		FD_SET( fd, &readSet );

		int result = select( max+1, &readSet, 0, 0, &tv );

		if ( result == 0 )
			throw DaemonToDaemonTimeout( __FILE__, __LINE__ );

		if ( result == EBADFD )
			break;

		if ( FD_ISSET( fd, &readSet ) ) {
			while ( true ) {
				int nbytes = read( fd, line + bytesRead, linelen - bytesRead );

				/* break when client closes the connection. */
				if ( nbytes < 0 ) {
					error( "reading notification pipe failed\n" );
					goto done;
				}
				else if ( nbytes == 0 ) {
					goto done;
				}
				else {
					bytesRead += nbytes;
					if ( memchr( line + bytesRead, '\n', linelen - bytesRead ) != 0 )
						goto done;
				}
			}
		}
	}

done:
	line[bytesRead] = 0;
	message( "notif returned: %s", line );
	return 0;
}

void NotifService::recvNotification()
{
	String site, args, body;
	readData( site );
	readData( args );
	readData( body );

	c->selectSiteByName( site );

	int pipe1[2], pipe2[2];
	int res = pipe( pipe1 );
	if ( res < 0 )
		fatal("pipe creation failed\n");
	res = pipe( pipe2 );
	if ( res < 0 )
		fatal("pipe creation failed\n");

	debug( DBG_NOTIF, "forking a notification process\n" );
	pid_t pid = fork();
	if ( pid < 0 ) {
		error("error forking for app notification\n");
	}
	else if ( pid == 0 ) {
		gbl.pid = getpid();
		debug( DBG_PROC, "forked a notification call process\n" );

		fflush( gbl.logFile );

		close( pipe1[1] );
		close( pipe2[0] );

		int stdinFd = pipe1[0];
		int stdoutFd = pipe2[1];
		int stderrFd = fileno(gbl.logFile);

		execNotification( stdinFd, stdoutFd, stderrFd );
	}
	
	close( pipe1[0] );
	close( pipe2[1] );

	int wFd = pipe1[1];
	int rFd = pipe2[0];

	sendArgsBody( wFd, site, args, body );

	readResult( rFd );

	close( wFd );
	close( rFd );

	/* FIXME: can put this on a list to periodically wait for. Don't need to
	 * reap it now since we got back a result. */
	waitNotification( pid );

	/* Sync with DSNPd. */
	writeChar( 0 );
}

