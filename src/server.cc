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
#include "keyagent.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

void checkSockLocal( int sock )
{
	in_addr expected;
	inet_aton( "127.0.0.1", &expected );

	socklen_t len = sizeof( sockaddr_in );
	sockaddr_in addr_in;
	int res = getsockname( sock, (sockaddr*)&addr_in, &len );
	if ( res < 0 )
		throw SockAddrError( errno );

	if ( len != sizeof( sockaddr_in ) )
		throw SockAddrError( EBADMSG );

	if ( addr_in.sin_addr.s_addr != expected.s_addr )
		throw SockNotLocal( sock );
}

void Server::negotiation( long versions, bool tls, const String &host, const String &key )
{
	/* Decide on a protocol version. --VERSION-- */
	if ( ! ( versions | VERSION_MASK_0_6 ) )
		throw NoCommonVersion();

	/* --VERSION-- */
	String replyVersion = Pointer( "0.6" );

	if ( tls ) {
		/* Nonlocal, find the specified host by the hostname. */
		c->selectHostByHostName( host );
	}
	else {
		/* If a local connection is requested, verify that we are indeed connected
		 * to something on this machine, then check the communication key. */
		c->selectSiteByCommKey( key );

		/* Ensure we got a connection from localhost. */
		checkSockLocal( bioWrap.sockFd );

		/* Convert the BioWrap to a local connection, which indicates to the
		 * generic error printing code that we should be using text, not binary. */
		bioWrap.type = BioWrap::Local;
	}

	bioWrap.type = ! tls ? BioWrap::Local : BioWrap::Server;
	
	if ( ! tls ) 
		bioWrap.returnOkLocal( replyVersion );
	else
		bioWrap.returnOkServer( replyVersion );

	message( "negotiation: version %s %s\n", 
			replyVersion(), ( tls ? "tls" : "local" ) );
	
	if ( tls ) {
		bioWrap.startTls();
		message("negotiation: TLS started\n");
	}

	/* Connect to the database. Either have a valid local key, or we have
	 * established SSL. */
	mysql = dbConnect();
	if ( mysql == 0 )
		throw DatabaseConnectionFailed();
}

void Server::runReceivedQueueBare()
{
	/* Connect to the database. Either have a valid local key, or we have
	 * established SSL. */
	mysql = dbConnect();
	if ( mysql == 0 )
		throw DatabaseConnectionFailed();

	while ( true ) {
		bool itemsLeft = deliverBroadcast();
		if ( !itemsLeft )
			break;
	}
}

void Server::runReceivedQueue()
{
	try {
		runReceivedQueueBare();
	}
	catch ( UserError &e ) {
		/* We have no more output. */
		BioWrap bioWrap( BioWrap::Null );
		e.print( bioWrap );
	}

	if ( mysql != 0 )
		mysql_close( mysql );
}

void Server::runCommandBare()
{
	/* Connect to the database. Either have a valid local key, or we have
	 * established SSL. */
	mysql = dbConnect();
	if ( mysql == 0 )
		throw DatabaseConnectionFailed();

	CommandParser parser( this );

	if ( gbl.numCommandArgs < 2 )
		throw ParseError(__FILE__, __LINE__);
	
	c->selectSiteByName( Pointer( gbl.commandArgs[0] ) );

	for ( int i = 1; gbl.commandArgs[i]; i++ ) {
		/* Note we are sending the null of each arg. */
		const char *arg = gbl.commandArgs[i];
		int len = strlen( arg ) + 1;

		parser.data( arg, len );
	}

	/* Send the last null. */
	char null = 0;
	parser.data( &null, 1 );
}

int Server::runCommand()
{
	int exitStatus = 0;

	try {
		runCommandBare();
	}
	catch ( UserError &e ) {
		/* We have no more output. */
		BioWrap bioWrap( BioWrap::Null );
		e.print( bioWrap );
		exitStatus = 1;
	}

	if ( mysql != 0 )
		mysql_close( mysql );

	return exitStatus;
}
