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

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <mysql/mysql.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/time.h>
#include <iostream>

#define PEER_CN_NAME_LEN 256

void BioWrapParse::sslError( int e )
{
	switch ( e ) {
		case SSL_ERROR_NONE:
			error("ssl error: SSL_ERROR_NONE\n");
			break;
		case SSL_ERROR_ZERO_RETURN:
			error("ssl error: SSL_ERROR_ZERO_RETURN\n");
			break;
		case SSL_ERROR_WANT_READ:
			error("ssl error: SSL_ERROR_WANT_READ\n");
			break;
		case SSL_ERROR_WANT_WRITE:
			error("ssl error: SSL_ERROR_WANT_WRITE\n");
			break;
		case SSL_ERROR_WANT_CONNECT:
			error("ssl error: SSL_ERROR_WANT_CONNECT\n");
			break;
		case SSL_ERROR_WANT_ACCEPT:
			error("ssl error: SSL_ERROR_WANT_ACCEPT\n");
			break;
		case SSL_ERROR_WANT_X509_LOOKUP:
			error("ssl error: SSL_ERROR_WANT_X509_LOOKUP\n");
			break;
		case SSL_ERROR_SYSCALL:
			error("ssl error: SSL_ERROR_SYSCALL\n");
			break;
		case SSL_ERROR_SSL:
			error("ssl error: SSL_ERROR_SSL\n");
			break;
	}
}

/* Wrapper that lets us use a template to implement the select loop around
 * connect and accept. */
struct SslConnectFunc
{
	static int func( SSL *ssl )
	{
		return SSL_connect( ssl );
	}
};

struct SslAcceptFunc
{
	static int func( SSL *ssl )
	{
		return SSL_accept( ssl );
	}
};

template <class Func, class Throw> void BioWrapParse::nonBlockingSslFunc( SSL *ssl )
{
	fd_set readSet;
	fd_set writeSet;
	int result;
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
		FD_ZERO( &readSet );
		FD_ZERO( &writeSet );
		if ( needsRead )
			FD_SET( sockFd, &readSet );
		if ( needsWrite )
			FD_SET( sockFd, &writeSet );

		/* Wait on read or write. */
		result = select( max+1, &readSet, &writeSet, 0, &tv );

		if ( result == 0 )
			throw DaemonToDaemonTimeout( __FILE__, __LINE__ );

		if ( result == EBADFD )
			break;

		if ( FD_ISSET( sockFd, &readSet ) || FD_ISSET( sockFd, &writeSet ) ) {
			result = Func::func( ssl );
			if ( result <= 0 ) {
				result = SSL_get_error( ssl, result );
				if ( result == SSL_ERROR_WANT_READ || result == SSL_ERROR_WANT_WRITE ) {
					needsRead = needsWrite = false;
					if ( result == SSL_ERROR_WANT_READ )
						needsRead = true;
					else if ( result == SSL_ERROR_WANT_WRITE )
						needsWrite = true;
					continue;
				}
			
				throw Throw();
			}

			/* Success. */
			break;
		}
	}
}

void BioWrapParse::makeNonBlocking( int fd )
{
	/* Make FD non-blocking. */
	int flags = fcntl( fd, F_GETFL );
	if ( flags == -1 )
		throw NonBlockingIoNotAvailable();

	int res = fcntl( fd, F_SETFL, flags | O_NONBLOCK );
	if ( res == -1 )
		throw NonBlockingIoNotAvailable();
}

void TlsConnect::openInetConnection( const String &host, unsigned short port )
{
	sockaddr_in servername;
	hostent *hostinfo;
	long connectRes;

	/* Create the socket. */
	int fd = socket( PF_INET, SOCK_STREAM, 0 );
	if ( fd < 0 )
		throw SocketConnectFailed( host );

	/* Lookup the host. */
	servername.sin_family = AF_INET;
	servername.sin_port = htons(port);
	hostinfo = gethostbyname( host );
	if ( hostinfo == NULL ) {
		::close( fd );
		throw SocketConnectFailed( host );
	}

	servername.sin_addr = *(in_addr*)hostinfo->h_addr;

	/* Connect to the listener. */
	connectRes = ::connect( fd, (sockaddr*)&servername, sizeof(servername) );
	if ( connectRes < 0 ) {
		::close( fd );
		throw SocketConnectFailed( host );
	}

	makeNonBlocking( fd );
	sockFd = fd;
}

void TlsConnect::sslStartClient( const String &remoteHost )
{
	/* FIXME: Always using the first host context for clients. Should be
	 * selecting based on who is doing the communciation. */

	SSL_CTX *ctx = tlsContext.clientCtx[0];

	/* Create the SSL object an set it in the secure BIO. */
	SSL *ssl = SSL_new( ctx );
	SSL_set_mode( ssl, SSL_MODE_AUTO_RETRY );
	SSL_set_bio( ssl, sockBio, sockBio );

	/* Start the SSL process. */
	nonBlockingSslFunc< SslConnectFunc, SslConnectFailed >( ssl );

	/* Check the verification result. */
	long verifyResult = SSL_get_verify_result(ssl);
	if ( verifyResult != X509_V_OK )
		throw SslPeerFailedVerify( remoteHost );

	/* Check the cert chain. The chain length is automatically checked by
	 * OpenSSL when we set the verify depth in the CTX */

	/* Check the common name. */
	X509 *peer = SSL_get_peer_certificate( ssl );
	char peer_CN[PEER_CN_NAME_LEN];
	X509_NAME_get_text_by_NID( X509_get_subject_name(peer),
			NID_commonName, peer_CN, PEER_CN_NAME_LEN );

	if ( strcasecmp( remoteHost, peer_CN ) != 0 )
		throw SslPeerCnHostMismatch( remoteHost, peer_CN );

	/* Create a BIO for the ssl wrapper. */
	BIO *bio = BIO_new( BIO_f_ssl() );
	BIO_set_ssl( bio, ssl, BIO_NOCLOSE );

	sockBio = bio;
}

void BioWrapParse::sslStartServer()
{
	SSL_CTX *ctx = tlsContext.serverCtx[c->host->id];

	/* Create the SSL object an set it in the secure BIO. */
	SSL *ssl = SSL_new( ctx );
	SSL_set_mode( ssl, SSL_MODE_AUTO_RETRY );
	SSL_set_bio( ssl, sockBio, sockBio );

	nonBlockingSslFunc< SslAcceptFunc, SslAcceptFailed >( ssl );

	/* Create a BIO for the ssl wrapper. */
	BIO *bio = BIO_new(BIO_f_ssl());
	BIO_set_ssl( bio, ssl, BIO_NOCLOSE );

	sockBio = bio;
}

void TlsConnect::connect( const String &remoteHost )
{
	openInetConnection( remoteHost, atoi(c->main->CFG_PORT) );

	sockBio = BIO_new_fd( sockFd, BIO_NOCLOSE );

	/* Send the request. --VERSION-- */
	printf( "DSNP 0.6 start_tls %s\r\n", remoteHost() );

	/* The version we get back must be the one we sent. */
	ResponseParser parser;
	readParse( parser );

	/* --VERSION-- */
	String expectedVersion( Pointer( "0.6" ) );
	if ( parser.body != expectedVersion )
		throw NoCommonVersion();

	sslStartClient( remoteHost );
}

void BioWrapParse::startTls()
{
	sslStartServer();
}
