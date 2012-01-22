/*
 * Copyright (c) 2009-2011, Adrian Thurston <thurston@complang.org>
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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>

#define FATAL_EXIT_CODE 1
#define TIME_STR_SZ 64

/* FIXME: should do something about this. */
static ConfigSection *c = 0;

int openLogFile( const char *fn )
{
	int fd = open( fn,
			O_WRONLY | O_APPEND | O_CREAT,
			S_IRUSR | S_IWUSR );
	if ( fd < 0 ) {
		/* This print will only be effective in some situations, when std error
		 * is still avaialable. */
		fprintf( stderr, "ERROR: could not open log file %s: %s\n", fn, strerror(errno) );
		exit( 1 );
	}
	return fd;
}

void setLogFd( int fd )
{
	if ( gbl.logFile != 0 )
		fclose( gbl.logFile );
	gbl.logFile = fdopen( fd, "at" );
}

void logToConsole( int fd )
{
	gbl.logFile = fdopen( fd, "at" );
	if ( gbl.logFile == 0 ) {
		fprintf( stderr, "ERROR: could not open FILE wrapping fd %d\n", fd );
		exit( 1 );
	}
}

void fatal( const char *fmt, ... )
{
	va_list args;
	struct tm localTm;
	char timeStr[TIME_STR_SZ];

	assert( gbl.logFile != 0 );

	time_t t = time(0);
	localtime_r( &t, &localTm );
	strftime( timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &localTm );

	va_start( args, fmt );
	fprintf( gbl.logFile, "%-5d %s %s FATAL: ", gbl.pid, timeStr, c != 0 ? c->name() : "-" );
	vfprintf( gbl.logFile, fmt, args );
	va_end( args );
	fflush( gbl.logFile );
	exit(1);
}

void error( const char *fmt, ... )
{
	va_list args;
	struct tm localTm;
	char timeStr[TIME_STR_SZ];

	assert( gbl.logFile != 0 );

	time_t t = time(0);
	localtime_r( &t, &localTm );
	strftime( timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &localTm );

	va_start( args, fmt );
	fprintf( gbl.logFile, "%-5d %s %s ERROR: ", gbl.pid, timeStr, c != 0 ? c->name() : "-" );
	vfprintf( gbl.logFile, fmt, args );
	va_end( args );
	fflush( gbl.logFile );
}

void warning( const char *fmt, ... )
{
	va_list args;
	struct tm localTm;
	char timeStr[TIME_STR_SZ];

	assert( gbl.logFile != 0 );

	time_t t = time(0);
	localtime_r( &t, &localTm );
	strftime( timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &localTm );

	va_start( args, fmt );
	fprintf( gbl.logFile, "%-5d %s %s WARNING: ", gbl.pid, timeStr, c != 0 ? c->name() : "-" );
	vfprintf( gbl.logFile, fmt, args );
	va_end( args );
	fflush( gbl.logFile );
}

void message( const char *fmt, ... )
{
	va_list args;
	struct tm localTm;
	char timeStr[TIME_STR_SZ];

	assert( gbl.logFile != 0 );

	time_t t = time(0);
	localtime_r( &t, &localTm );
	strftime( timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &localTm );

	va_start( args, fmt );
	fprintf( gbl.logFile, "%-5d %s %s message: ", gbl.pid, timeStr, c != 0 ? c->name() : "-" );
	vfprintf( gbl.logFile, fmt, args );
	va_end( args );
	fflush( gbl.logFile );
}

void _dsnpd_debug( long realm, const char *fmt, ... )
{
	va_list args;
	struct tm localTm;
	char timeStr[TIME_STR_SZ];

	assert( gbl.logFile != 0 );

	/* Ensure the realm specified in the debug statement is enabled. */
	if ( ! ( realm & gbl.enabledRealms ) )
		return;

	time_t t = time(0);
	localtime_r( &t, &localTm );
	strftime( timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", &localTm );

	va_start( args, fmt );
	fprintf( gbl.logFile, "%-5d %s %s debug: ", gbl.pid, timeStr, c != 0 ? c->name() : "-" );
	vfprintf( gbl.logFile, fmt, args );
	va_end( args );
	fflush( gbl.logFile );
}

