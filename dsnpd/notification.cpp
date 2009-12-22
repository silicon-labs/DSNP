/*
 * Copyright (c) 2008-2009, Adrian Thurston <thurston@complang.org>
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
#include "disttree.h"

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

#define NOTIF_LOG_FILE LOGDIR "/notification.log"
int maxArgs( const char *src )
{
	/* Assume at least one. */
	int n = 1;
	for ( ; *src != 0; src++ ) {
		if ( *src == ' ' )
			n++;
	}
	return n;
}

void parseArgs( char **argv, long &dst, const char *args )
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

char *const*makeNotifiyArgv( const char *args )
{
	int n = maxArgs(c->CFG_NOTIFICATION) + 2 + maxArgs(args) + 1;
	char **argv = new char*[n];
	long dst = 0;
	parseArgs( argv, dst, c->CFG_NOTIFICATION );
	argv[dst++] = strdup(c->CFG_HOST);
	argv[dst++] = strdup(c->CFG_PATH);
	parseArgs( argv, dst, args );
	argv[dst++] = 0;

	return argv;
}

void appNotification( const char *args, const char *data, long length )
{
	message( "notification callout with args %s\n", args );

	int fds[2];	
	int res = pipe( fds );
	if ( res < 0 ) {
		error("pipe creation failed\n");
		return;
	}

	pid_t pid = fork();
	if ( pid < 0 ) {
		error("error forking for app notification\n");
	}
	else if ( pid == 0 ) {
		close( fds[1] );
		FILE *log = fopen(NOTIF_LOG_FILE, "at");
		if ( log == 0 ) {
			error( "could not open notification log file, using /dev/null\n" );
			log = fopen("/dev/null", "wt");
			if ( log == 0 )
				fatal( "could not open /dev/null\n" );
		}

		dup2( fds[0], 0 );
		dup2( fileno(log), 1 );
		dup2( fileno(log), 2 );
		execvp( "php", makeNotifiyArgv( args ) );
		exit(0);
	}
	
	close( fds[0] );

	FILE *p = fdopen( fds[1], "wb" );
	if ( length > 0 ) 
		fwrite( data, 1, length, p );
	fclose( p );
	wait( 0 );
}

