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


#include <iostream>

SSL_CTX *ctx = 0;

void sslError( int e )
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

long openInetConnection( const char *hostname, unsigned short port )
{
	sockaddr_in servername;
	hostent *hostinfo;
	long socketFd, connectRes;

	/* Create the socket. */
	socketFd = socket( PF_INET, SOCK_STREAM, 0 );
	if ( socketFd < 0 )
		throw SocketConnectFailed( hostname );

	/* Lookup the host. */
	servername.sin_family = AF_INET;
	servername.sin_port = htons(port);
	hostinfo = gethostbyname (hostname);
	if ( hostinfo == NULL ) {
		::close( socketFd );
		throw SocketConnectFailed( hostname );
	}

	servername.sin_addr = *(in_addr*)hostinfo->h_addr;

	/* Connect to the listener. */
	connectRes = connect( socketFd, (sockaddr*)&servername, sizeof(servername) );
	if ( connectRes < 0 ) {
		::close( socketFd );
		throw SocketConnectFailed( hostname );
	}

	return socketFd;
}


void sslInitClient()
{
	/* Global initialization. */
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
	SSL_library_init(); 

	/* Create the SSL_CTX. */
	ctx = SSL_CTX_new(TLSv1_client_method());
	if ( ctx == NULL )
		throw SslNewContextFailure();
	
	if ( c->CFG_TLS_CA_CERTS == 0 )
		throw SslCaCertsNotSet();

	/* Load the CA certificates that we will use to verify. */
	int result = SSL_CTX_load_verify_locations( ctx, c->CFG_TLS_CA_CERTS, NULL );
	if ( !result ) 
		throw SslCaCertLoadFailure( c->CFG_TLS_CA_CERTS );
}

BIO *sslStartClient( BIO *readBio, BIO *writeBio, const char *host )
{
	/* Create the SSL object an set it in the secure BIO. */
	SSL *ssl = SSL_new( ctx );
	SSL_set_mode( ssl, SSL_MODE_AUTO_RETRY );
	SSL_set_bio( ssl, readBio, writeBio );

	/* Start the SSL process. */
	int connResult = SSL_connect( ssl );
	if ( connResult <= 0 )
		throw SslConnectFailed( host );

	/* Check the verification result. */
	long verifyResult = SSL_get_verify_result(ssl);
	if ( verifyResult != X509_V_OK )
		throw SslPeerFailedVerify( host );

	/* Check the cert chain. The chain length is automatically checked by
	 * OpenSSL when we set the verify depth in the CTX */

	/* Check the common name. */
	X509 *peer = SSL_get_peer_certificate( ssl );
	char peer_CN[256];
	X509_NAME_get_text_by_NID( X509_get_subject_name(peer),
			NID_commonName, peer_CN, 256 );

	if ( strcasecmp( host, peer_CN ) != 0 )
		throw SslPeerCnHostMismatch( host, peer_CN );

	/* Create a BIO for the ssl wrapper. */
	BIO *sbio = BIO_new( BIO_f_ssl() );
	BIO_set_ssl( sbio, ssl, BIO_NOCLOSE );

	BIO *bio = BIO_new( BIO_f_buffer());
    BIO_push( bio, sbio );

	return bio;
}

void sslInitServer()
{
	/* Global initialization. */
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
	SSL_library_init(); 

	/* Create the SSL_CTX. */
	ctx = SSL_CTX_new(SSLv23_method());
	if ( ctx == NULL )
		fatal("creating context failed\n");

	if ( c->CFG_TLS_CRT == 0 )
		fatal("CFG_TLS_CRT is not set\n");
	if ( c->CFG_TLS_KEY == 0 )
		fatal("CFG_TLS_KEY is not set\n");

	int result = SSL_CTX_use_certificate_chain_file( ctx, c->CFG_TLS_CRT );
	if ( result != 1 ) 
		fatal("failed to load %s\n", c->CFG_TLS_CRT );

	result = SSL_CTX_use_PrivateKey_file( ctx, c->CFG_TLS_KEY, SSL_FILETYPE_PEM );
	if ( result != 1 ) 
		fatal("failed to load %s\n", c->CFG_TLS_KEY );
}


BIO *sslStartServer( BIO *readBio, BIO *writeBio )
{
	/* Create the SSL object an set it in the secure BIO. */
	SSL *ssl = SSL_new( ctx );
	SSL_set_mode( ssl, SSL_MODE_AUTO_RETRY );
	SSL_set_bio( ssl, readBio, writeBio );
	int connResult;

	/* Start the SSL process. THIS IS UGLY. Need select. */
again:
	connResult = SSL_accept( ssl );
	if ( connResult <= 0 ) {
		connResult = SSL_get_error( ssl, connResult );
		if ( connResult == SSL_ERROR_WANT_READ ) 
			goto again;

		sslError( connResult );
		fatal( "SSL_accept failed: %s\n",  ERR_error_string( ERR_get_error( ), 0 ) );
	}

	/* Create a BIO for the ssl wrapper. */
    BIO *sbio = BIO_new(BIO_f_ssl());
	BIO_set_ssl( sbio, ssl, BIO_NOCLOSE );

	BIO *bio = BIO_new( BIO_f_buffer());
    BIO_push( bio, sbio );

	return bio;
}

void TlsConnect::connect( const char *host, const char *site )
{
	static char buf[8192];

	socketFd = openInetConnection( host, atoi(c->CFG_PORT) );
	if ( socketFd < 0 )
		throw SocketConnectFailed( host );

	BIO *socketBio = BIO_new_fd( socketFd, BIO_NOCLOSE );
	BIO *buffer = BIO_new( BIO_f_buffer() );
	BIO_push( buffer, socketBio );
	rbio = wbio = socketBio;

	/* FIXME: need to parse results. */

	/* Send the request. */
	printf( "DSNP 0.1 %s start_tls\r\n", site );

	/* Read the result. */
	BIO_gets( buffer, buf, 8192 );

	/* FIXME: Verify the results. */

	/* FIXME: pop the buffer'd IO off the socketBio? Seems to be just ignored. */

	sslInitClient();
	rbio = wbio = sslStartClient( socketBio, socketBio, host );
}

BIO *startTls( BIO *rbio, BIO *wbio )
{
	/* Don't need the buffering wrappers anymore. */
	rbio = BIO_pop( rbio );
	wbio = BIO_pop( wbio );

	sslInitServer();
	rbio = wbio = sslStartServer( rbio, wbio );
	return rbio;
}
