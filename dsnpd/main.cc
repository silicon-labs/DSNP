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
#include "error.h"

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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define READSZ 1024
#define CTRLSZ 1024
#define PID_FILE PID_DIR "/dsnpd.pid"

Global gbl;

void Config::selectHostByHostName( const String &hostName )
{
	for ( ConfigSection *h = hostList.head; h != 0; h = h->next ) {
		if ( strcmp( hostName(), h->CFG_HOST ) == 0 ) {
			host = h;
			return;
		}
	}

	throw BadHost();
}

void Config::selectSiteByCommKey( const String &key )
{
	for ( ConfigSection *s = siteList.head; s != 0; s = s->next ) {
		if ( key == s->CFG_COMM_KEY ) {
			site = s;
			return;
		}
	}

	throw InvalidCommKey();
}

void Config::selectSiteByName( const String &siteName )
{
	for ( ConfigSection *s = siteList.head; s != 0; s = s->next ) {
		if ( siteName == s->name ) {
			site = s;
			return;
		}
	}
	throw BadSite();
}

void forkPrivProcess()
{
	/* FIXME: add logfile open. */

	int pair[2];
	int res = socketpair( PF_UNIX, SOCK_STREAM, 0, pair );
	if ( res < 0 )
		fatal( "error: socketpair failed: %s\n", strerror(errno) );

	debug( DBG_PROC, "forking the key agent\n" );
	pid_t pid = fork();
	if ( pid < 0 )
		fatal( "error: fork failed %s\n", strerror(errno) );

	if ( pid == 0 ) {
		/* In child. Close the other half. */
		gbl.pid = getpid();
		debug( DBG_PROC, "forked key agent manager\n" );
		close( pair[0] );
		int status = keyAgentProcess( pair[1] );
		exit( status );
	}

	gbl.privPid = pid;
	gbl.privCmdFd = pair[0];

	/* Close the half we passed on. */
	close( pair[1] );
}

void forkNotification()
{
	int pair[2];
	int res = socketpair( PF_UNIX, SOCK_STREAM, 0, pair );
	if ( res < 0 )
		fatal( "error: socketpair failed: %s\n", strerror(errno) );

	debug( DBG_PROC, "forking the notification manager\n" );
	pid_t pid = fork();
	if ( pid < 0 )
		fatal( "error: fork failed %s\n", strerror(errno) );

	if ( pid == 0 ) {
		/* In child. Close the other half. Close the priv command fd. */
		gbl.pid = getpid();
		debug( DBG_PROC, "forked notification manager\n" );
		close( pair[0] );
		close( gbl.privCmdFd );
		int status = notificationProcess( pair[1] );
		exit( status );
	}

	gbl.notifPid = pid;
	gbl.notifCmdFd = pair[0];

	/* Close the half we passed on. */
	close( pair[1] );
}

void sendStopCommand( int fd )
{
	/* Send a quit. */
	char cmd = AC_QUIT;
	iovec iov;
	iov.iov_base = (void*) &cmd;
	iov.iov_len = 1;
	msghdr msg;
	memset( &msg, 0, sizeof(msg) );
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	if ( sendmsg( fd, &msg, 0 ) < 0 )
		error("stop command over sendmsg failed: %s\n", strerror(errno) );
}

void stopPrivProcess()
{
	sendStopCommand( gbl.privCmdFd );
	waitpid( gbl.privPid, 0, 0 );
}

void stopNotificationProcess()
{
	sendStopCommand( gbl.notifCmdFd );
	waitpid( gbl.notifPid, 0, 0 );
}

void findUids()
{
	passwd *ent = 0;
	
	/*
	 * DSNPd user
	 */
	ent = getpwnam( DSNPD_USER );
	if ( ent == 0 )
		fatal( "unable to find DSNPd user '%s'\n", DSNPD_USER );
	gbl.dsnpdUid = ent->pw_uid;
	gbl.dsnpdGid = ent->pw_gid;

	/*
	 * Key agent user
	 */
	ent = getpwnam( DSNPK_USER );
	if ( ent == 0 )
		fatal( "unable to find DSNPk user '%s'\n", DSNPK_USER );
	gbl.privUid = ent->pw_uid;
	gbl.privGid = ent->pw_gid;

	/*
	 * Notification user
	 */
	ent = getpwnam( NOTIF_USER );
	if ( ent == 0 )
		fatal( "unable to find NOTIF user '%s'\n", NOTIF_USER );
	gbl.notifUid = ent->pw_uid;
	gbl.notifGid = ent->pw_gid;
}

void usage( char *argv0 )
{
	fprintf( stderr,
		"usage:\n"
		"  -b            go to the background\n"
		"  -m cmd args   management command\n"
		"  -D realm      turn on debug realm\n"
		"                FDT -- File Descriptor Transfer\n"
		"                PROC -- Processes\n"
		"                EP -- Packets\n"
		"                NOTIF -- Notification Agent\n"
		"                PRIV -- Key Agent\n"
		"                CFG -- Config Parsing\n"
		"                QUEUE -- Queue Running\n"
	);
}

void parseArgs( int argc, char *const *argv )
{
	while ( true ) {
		int opt = getopt( argc, argv, "mbD:FhH?" );
		if ( opt < 0 )
			break;
		switch ( opt ) {
			case 'b':
				gbl.background = true;
				break;
			case 'F':
				gbl.tokenFlush = false;
				break;
			case 'm':
				gbl.issueCommand = true;
				break;
			case 'D':
				if ( strcmp( ::optarg, "FDT" ) == 0 )
					gbl.enabledRealms |= DBG_FDT;
				else if ( strcmp( ::optarg, "PROC" ) == 0 )
					gbl.enabledRealms |= DBG_PROC;
				else if ( strcmp( ::optarg, "EP" ) == 0 )
					gbl.enabledRealms |= DBG_EP;
				else if ( strcmp( ::optarg, "NOTIF" ) == 0 )
					gbl.enabledRealms |= DBG_NOTIF;
				else if ( strcmp( ::optarg, "PRIV" ) == 0 )
					gbl.enabledRealms |= DBG_PRIV;
				else if ( strcmp( ::optarg, "CFG" ) == 0 )
					gbl.enabledRealms |= DBG_CFG;
				else if ( strcmp( ::optarg, "QUEUE" ) == 0 )
					gbl.enabledRealms |= DBG_QUEUE;
				else {
					fprintf( stderr, "invalid debug realm: %s\n", ::optarg );
					exit( 1 );
				}

				break;

			case 'h':
			case 'H':
			case '?':
			default: 
				usage( argv[0] );
				exit( 1 );
		}
	}

	if ( gbl.issueCommand ) {
		gbl.numCommandArgs = argc - ::optind;
		gbl.commandArgs = argv + optind;
	}
}

void unlinkPidFile()
{
	unlink( PID_FILE );
}

void writePidFile()
{
	int fd = open( PID_FILE, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR );
	if ( fd < 0 )
		fatal( "failed to create a fresh pid file %s\n", PID_FILE );

	FILE *pidFile = fdopen( fd, "wt" );
	if ( pidFile == 0 )
		fatal( "failed to open the pid around the fd %d\n", fd );
	fprintf( pidFile, "%d\n", (int)gbl.pid );
	fclose( pidFile );
	atexit( unlinkPidFile );
}


void checkCreds()
{
	/* Verify we start with root creds. */
	uid_t uid = getuid();
	if ( uid != 0 )
		fatal( "you must be root to run dsnpd\n" );

	gid_t gid = getgid();
	if ( gid != 0 )
		fatal( "group ID must be 0 (root) to run dsnpd\n" );
}

void checkConfFile()
{
	/* The config file should be owned by root and should not have anything
	 * more than 0600 permissions. */
	struct stat s;
	int result = stat( DSNPD_CONF, &s );
	if ( result != 0 )
		fatal( "unable to stat conf file %s: %s\n", DSNPD_CONF, strerror(errno) );

	if ( ! S_ISREG(s.st_mode) )
		fatal( "conf file %s is not a regular file\n", DSNPD_CONF );
	if ( s.st_uid != 0 || s.st_gid != 0 )
		fatal( "conf file %s is not owned by root\n", DSNPD_CONF );

	unsigned int filePerms = s.st_mode & ( S_IRWXU | S_IRWXG | S_IRWXO );
	if ( filePerms != 0600 )
		fatal( "conf file %s does not have 0600 file perms, has 0%o\n", DSNPD_CONF, filePerms );
}

int main( int argc, char *const *argv )
{
	parseArgs( argc, argv );

	/* Do this early so the log functions will be ready. We don't
	 * need stdin or stdout ever. */
	close( 0 );
	close( 1 );
	gbl.pid = getpid();
	logToConsole( 2 );

	debug( DBG_PROC, "main process with pid %hu\n", gbl.pid );

	checkCreds();
	checkConfFile();

	findUids();

	/* Open the log file. */
	if ( gbl.background ) {
		daemon( 0, 0 );
		gbl.pid = getpid();
		openLogFile();
	}

	/* Must do this after backgrounding. */
	if ( !gbl.issueCommand )
		writePidFile();

	/* 
	 * Now have a config and a log file.
	 */
	
	/* Start the privileged process and the notification process. Order here
	 * matters. We need to close the priv control socket in the notification. */
	forkPrivProcess();
	forkNotification();

	/* Parent. */
	ListenFork listenFork;
	int result = listenFork.run( 7085 );

	stopPrivProcess();
	stopNotificationProcess();

	message("EXITING\n");

	/* Wait for the privileged process. */
	return result;
}
