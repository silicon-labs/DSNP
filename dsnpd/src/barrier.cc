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

#include "dsnp.h"
#include "encrypt.h"
#include "string.h"

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

#define READSZ 1024
#define CTRLSZ 1024

int transmitFd( int channelFd, char cmd, int fd )
{
	/* The socket message. */
	iovec iov;
	iov.iov_base = (void*) &cmd;
	iov.iov_len = 1;
	msghdr msg;
	memset( &msg, 0, sizeof(msg) );
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	/* Big enough? */
	char control[CTRLSZ];
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	/* Attach the fd. */
	cmsghdr *cmsg = CMSG_FIRSTHDR( &msg );
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN( sizeof(int) );
	*(int *)CMSG_DATA(cmsg) = fd;
	msg.msg_controllen = cmsg->cmsg_len;

	/* Send the message with fd. */
	if ( sendmsg( channelFd, &msg, 0 ) < 0 ) {
		error( "fd transmit failed on sendmsg: %s\n", strerror(errno) );
		return -1;
	}

	return 0;
}

int extractFd( int channelFd, msghdr *msg )
{
	int fd = -1;
	cmsghdr *cmsg = CMSG_FIRSTHDR( msg );
	while ( cmsg != NULL ) {
		if ( cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS ) {
			/* This is an FD transfer. */
			fd = *(int *) CMSG_DATA( cmsg );
			break;
		}
		cmsg = CMSG_NXTHDR( msg, cmsg );
	}

	debug( DBG_PROC, "extraced fd %d\n", fd );

	return fd;
}


void Barrier::command( char cmd )
{
	int result = write( fd, &cmd, 1 );

	if ( result == 0 )
		fatal( "barrier command write: nothing written (0)\n" );

	if ( result < 0 )
		fatal( "barrier command write: %s\n", strerror(errno) );
}

char Barrier::readCommand()
{
	char cmd;
	int result = read( fd, &cmd, 1 );

	if ( result == 0 ) {
		debug( DBG_PROC, "received EOF on fd %d, returning BA_QUIT\n", fd );
		return BA_QUIT;
	}

	if ( result < 1 )
		fatal( "failed reading command on fd %d: %s\n", fd, strerror(errno) );

	return cmd;
}

void Barrier::quit()
{
	debug( DBG_PROC, "sending quit command\n" );
	command( BA_QUIT );
	readChar();
}

void Barrier::writeChar( char c )
{
	int result = write( fd, &c, 1 );
	if ( result < 1 )
		fatal( "failed writing character to fd %d: %s\n", fd, strerror(errno) );
}

char Barrier::readChar()
{
	char c = INVALID_THING;
	int result = read( fd, &c, 1 );
	if ( result < 0 ) {
		fatal( "barrier failed reading character on fd %d: %s\n", 
				fd, strerror(errno) );
	}
	else if ( result < 1 ) {
		error( "barrier received EOF on fd %d\n", fd );
	}
	return c;
}

void Barrier::writeData( const String &s )
{
	int result, length = s.length;
	int writeLen = sizeof(int);
	result = write( fd, &length, writeLen );
	if ( result < writeLen )
		fatal( "barrier: write data failed: %s", strerror(errno) );

	if ( length > 0 ) {
		result = write( fd, s.data, s.length );
		if ( result < s.length )
			fatal( "barrier: write data failed: %s", strerror(errno) );
	}
}

void Barrier::readData( String &s )
{
	int length = 0, readLen = sizeof(int);
	int result = read( fd, &length, readLen );

	if ( result < readLen || length < 0 || length >= 1 * MB )
		fatal( "barrier: invalid message length\n" );

	if ( length > 0 ) {
		s.allocate( length );
		result = read( fd, s.data, s.length );
		if ( result < s.length )
			fatal( "barrier: failed to read data body\n" );
	}
}

void Barrier::writeInt( int i )
{
	int writeLen = sizeof(int);
	int result = write( fd, &i, writeLen );
	if ( result < writeLen )
		fatal( "barrier: failed to write int\n" );
}

int Barrier::readInt()
{
	int readLen = sizeof(int);
	int i, result = read( fd, &i, readLen );
	if ( result < readLen )
		fatal( "barrier: failed to read int\n" );
	return i;
}

void Barrier::writeLongLong( long long ll )
{
	int writeLen = sizeof(long long);
	int result = write( fd, &ll, writeLen );
	if ( result < writeLen )
		fatal( "barrier: failed to write long long\n" );
}

long long Barrier::readLongLong()
{
	int readLen = sizeof(long long);
	long long ll;
	int result = read( fd, &ll, readLen );
	if ( result < readLen )
		fatal( "barrier: failed to read long long\n" );
	return ll;
}
