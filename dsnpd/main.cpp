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

BIO *bioIn = 0;
BIO *bioOut = 0;

Global gbl;

void read_rcfile( const char *confFile )
{
	FILE *rcfile = fopen( confFile, "r" );
	if ( rcfile == NULL ) {
		fprintf( stderr, "failed to open the config file \"%s\", exiting\n", confFile );
		exit(1);
	}

	/* FIXME: this must be fixed. */
	static char buf[1024*16];
	long len = fread( buf, 1, 1024*16, rcfile );
	rcfile_parse( buf, len );
}

int checkArgs( int argc, char **argv )
{
	while ( true ) {
		int opt = getopt( argc, argv, "q:tcifp" );

		if ( opt < 0 )
			break;

		switch ( opt ) {
			case 'q':
				gbl.runQueue = true;
				gbl.siteName = optarg;
				break;
			case 't':
				gbl.test = true;
				break;
			case '?':
				return -1;
		}
	}

	if ( optind < argc )
		gbl.configFile = argv[optind];
	else
		gbl.configFile = SYSCONFDIR "/dsnpd.conf";

	return 0;
}


void dieHandler( int signum )
{
	error( "caught signal %d, exiting\n", signum );
	exit(1);
}

void setupSignals()
{
	signal( SIGHUP, &dieHandler );
	signal( SIGINT, &dieHandler );
	signal( SIGQUIT, &dieHandler );
	signal( SIGILL, &dieHandler );
	signal( SIGABRT, &dieHandler );
	signal( SIGFPE, &dieHandler );
	signal( SIGSEGV, &dieHandler );
	signal( SIGPIPE, &dieHandler );
	signal( SIGTERM, &dieHandler );
}

int serverMain()
{
	message( "STARTING UP\n" );

	/* Set up the input BIO to wrap stdin. */
	BIO *bioFdIn = BIO_new_fd( 0, BIO_NOCLOSE );
	bioIn = BIO_new( BIO_f_buffer() );
	BIO_push( bioIn, bioFdIn );

	/* Set up the output bio to wrap stdout. */
	BIO *bioFdOut = BIO_new_fd( 1, BIO_NOCLOSE );
	bioOut = BIO_new( BIO_f_buffer() );
	BIO_push( bioOut, bioFdOut );

	close( 2 );

	serverParseLoop();

	close( 0 );
	close( 1 );

	message( "RUNNING QUEUE\n" );

	runBroadcastQueue();
	runMessageQueue();

	message( "EXITING\n" );
	return 0;
}

int runTest();

int main( int argc, char **argv )
{
	if ( checkArgs( argc, argv ) < 0 ) {
		fprintf( stderr, "expecting: dsnpd [options] config\n" );
		fprintf( stderr, "  options: -q<site>    don't listen, run queue\n" );
		exit(1);
	}

	gbl.pid = getpid();
	setupSignals();

	read_rcfile( gbl.configFile );

	RAND_load_file("/dev/urandom", 1024);

	openLogFile();

	if ( gbl.runQueue )
		runQueue( gbl.siteName );
	else if ( gbl.test )
		runTest();
	else 
		serverMain();
}
