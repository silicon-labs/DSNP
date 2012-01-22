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

#include <unistd.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>

void Parser::parse( const String &data )
{
	/* FIXME: deal with results? */
	this->data( data.data, data.length );
}

void Parser::parse( const char *data, int length )
{
	this->data( data, length );
}

BioWrap::BioWrap( BioWrap::Type type )
:
	type(type),
	sockFd(-1),
	sockBio(0)
{
	if ( type == BioWrap::Null )
		sockBio = BIO_new( BIO_f_null() );
}

BioWrapParse::BioWrapParse( Config *c, BioWrap::Type type, TlsContext &tlsContext )
:
	ConfigCtx(c),
	BioWrap(type),
	tlsContext(tlsContext),
	linelen(4096)
{
	input = new char[linelen];
}

void BioWrapParse::setSockFd( int sfd )
{
	sockFd = sfd;
	sockBio = BIO_new_fd( sfd, BIO_NOCLOSE );
}

void BioWrapParse::makeNonBlocking()
{
	makeNonBlocking( sockFd );
}

BioWrapParse::~BioWrapParse()
{
	delete[] input;

	BIO_free_all( sockBio );
	close( sockFd );
}

void BioWrap::write( const char *data, long dlen )
{
	if ( sockBio == 0 || sockFd < 0 )
		throw WriteOnNullSocketBio();

	fd_set readSet, writeSet;
	int result, nbytes;
	int max = sockFd;

	bool needsRead = true;
	bool needsWrite = true;

	/* FIXME: we assume linux, with TV modified. The harm in assuming this on
	 * other systems is that timeout can get reset on select interruptions and
	 * partial reads. Must be fixed. */
	timeval tv;
	tv.tv_usec = 0;
	tv.tv_sec = DAEMON_DAEMON_TIMEOUT;

	while ( true ) {
		FD_ZERO( &readSet );
		FD_ZERO( &writeSet );
		if ( needsRead )
			FD_SET( sockFd, &readSet );
		if ( needsWrite )
			FD_SET( sockFd, &writeSet );

		result = select( max+1, &readSet, &writeSet, 0, &tv );

		if ( result == 0 )
			throw DaemonToDaemonTimeout( __FILE__, __LINE__ );

		if ( result == EBADFD )
			break;

		if ( FD_ISSET( sockFd, &readSet ) || FD_ISSET( sockFd, &writeSet ) ) {
			while ( true ) {
				nbytes = BIO_write( sockBio, data, dlen );

				/* break when client closes the connection. */
				if ( nbytes <= 0 ) {
					/* If the BIO is saying it we should retry later, go back into
					 * select. */
					if ( BIO_should_retry( sockBio ) ) {
						needsRead = BIO_should_read(sockBio);
						needsWrite = BIO_should_write(sockBio);
						break;
					}

					goto done;
				}

				goto done;
			}
		}
	}
done:
	return;
}

void BioWrap::writeBody( const String &msg )
{
	write( msg.data, msg.length );
	write( "\r\n", 2 );
}

void BioWrap::returnOkLocal()
{
	printf( "OK\r\n" );
}

void BioWrap::returnOkLocal( const String &r1 )
{
	printf( "OK %s\r\n", r1() );
}

void BioWrap::returnOkLocal( const String &r1, const String &r2 )
{
	printf( "OK %s %s\r\n", r1(), r2() );
}

void BioWrap::returnOkLocal( const String &r1, const String &r2, long ld3 )
{
	printf( "OK %s %s %ld\r\n", r1(), r2(), ld3 );
}

void BioWrap::returnOkLocal( const String &r1, const String &r2, const String &r3 )
{
	printf( "OK %s %s %s\r\n", r1(), r2(), r3() );
}

void BioWrap::returnOkServer()
{
	String ret0 = consRet0();
	write( ret0 );
}

void BioWrap::returnOkServer( const String &r1 )
{
	String ret1 = consRet1( r1 );
	write( ret1 );
}

/* For the error classes that are thrown. These will get written to the content
 * manager, and to other DNSP servers processes. */
void BioWrap::returnError( int errorCode )
{
	if ( type == Local ) {
		printf( "ERROR %d\r\n", errorCode );
	}
	else if ( type == Server ) {
		printf( "ERROR %d\r\n", errorCode );
	}
}

void BioWrap::returnError( int errorCode, int arg1 )
{
	if ( type == Local ) {
		printf( "ERROR %d %d\r\n", errorCode, arg1 );
	}
	else if ( type == Server ) {
		printf( "ERROR %d %d\r\n", errorCode, arg1 );
	}
}

void BioWrap::returnError( int errorCode, int arg1, int arg2 )
{
	if ( type == Local ) {
		printf( "ERROR %d %d %d\r\n", errorCode, arg1, arg2 );
	}
	else if ( type == Server ) {
		printf( "ERROR %d %s\r\n", errorCode, arg1 );
	}
}

void BioWrap::returnError( int errorCode, const char *arg1 )
{
	if ( type == Local ) {
		printf( "ERROR %d %s\r\n", errorCode, arg1 );
	}
	else if ( type == Server ) {
		printf( "ERROR %d %s\r\n", errorCode, arg1 );
	}
}

void BioWrap::returnError( int errorCode, const char *arg1, const char *arg2 )
{
	if ( type == Local ) {
		printf( "ERROR %d %s %s\r\n", errorCode, arg1, arg2 );
	}
	else if ( type == Server ) {
		printf( "ERROR %d %s %s\r\n", errorCode, arg1, arg2 );
	}
}

int BioWrap::printf( const char *fmt, ... )
{
	va_list args;
	char buf[1];

	va_start( args, fmt );
	long length = vsnprintf( buf, 0, fmt, args );
	va_end( args );

	if ( length < 0 )
		throw WriteError();

	char *data = new char[ length+1 ];
	va_start( args, fmt );
	vsnprintf( data, length+1, fmt, args );
	va_end( args );

	write( data, length );

	delete[] data;
	return length;
}

int BioWrapParse::readParse( Parser &parser )
{
	fd_set readSet, writeSet;
	int result, nbytes;
	int max = sockFd;

	bool needsRead = true;
	bool needsWrite = true;

	/* FIXME: we assume linux, with TV modified. The harm in assuming this on
	 * other systems is that timeout can get reset on select interruptions (eg
	 * signals). */
	timeval tv;
	tv.tv_usec = 0;
	tv.tv_sec = DAEMON_DAEMON_TIMEOUT;

	while ( true ) {
		/* Over SSL, there can be reads and writes just to accomplish read. */
		FD_ZERO( &readSet );
		FD_ZERO( &writeSet );
		if ( needsRead )
			FD_SET( sockFd, &readSet );
		if ( needsWrite )
			FD_SET( sockFd, &writeSet );

		result = select( max+1, &readSet, &writeSet, 0, &tv );

		if ( result == 0 )
			throw DaemonToDaemonTimeout( __FILE__, __LINE__ );

		if ( result == EBADFD )
			break;

		if ( FD_ISSET( sockFd, &readSet ) || FD_ISSET( sockFd, &writeSet ) ) {
			while ( true ) {
				nbytes = BIO_read( sockBio, input, linelen );

				/* break when client closes the connection. */
				if ( nbytes <= 0 ) {
					/* If the BIO is saying it we should retry later, go back into
					 * select. */
					if ( BIO_should_retry( sockBio ) ) {
						needsRead = BIO_should_read(sockBio);
						needsWrite = BIO_should_write(sockBio);
						break;
					}

					goto done;
				}

				Parser::Control control = parser.data( input, nbytes );
				if ( control == Parser::Stop )
					goto done;
			}
		}
	}

done:
	return 0;
}
