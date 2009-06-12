#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include <iostream>
#include "sppd.h"

//#define CA_CERTS "/etc/ssl/certs/ca-certificates.crt"
//#define MY_CERT "/home/thurston/xform.complang.org.crt"
//#define MY_KEY "/home/thurston/xform.complang.org.key"
//#define MY_PEM "/home/thurston/xform.complang.org.pem"

#define CA_CERTS "/home/thurston/devel/spp/sppd/localhost.crt"

#define MY_CERT "/home/thurston/devel/spp/sppd/localhost.crt"
#define MY_KEY "/home/thurston/devel/spp/sppd/localhost.key"
#define MY_PEM "/home/thurston/devel/spp/sppd/localhost.pem"

SSL_CTX *ctx = 0;

void printError( int e )
{
	switch ( e ) {
		case SSL_ERROR_NONE:
			message("SSL_ERROR_NONE\n");
			break;
		case SSL_ERROR_ZERO_RETURN:
			message("SSL_ERROR_ZERO_RETURN\n");
			break;
		case SSL_ERROR_WANT_READ:
			message("SSL_ERROR_WANT_READ\n");
			break;
		case SSL_ERROR_WANT_WRITE:
			message("SSL_ERROR_WANT_WRITE\n");
			break;
		case SSL_ERROR_WANT_CONNECT:
			message("SSL_ERROR_WANT_CONNECT\n");
			break;
		case SSL_ERROR_WANT_ACCEPT:
			message("SSL_ERROR_WANT_ACCEPT\n");
			break;
		case SSL_ERROR_WANT_X509_LOOKUP:
			message("SSL_ERROR_WANT_X509_LOOKUP\n");
			break;
		case SSL_ERROR_SYSCALL:
			message("SSL_ERROR_SYSCALL\n");
			break;
		case SSL_ERROR_SSL:
			message("SSL_ERROR_SSL\n");
			break;
	}
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
		fatal("creating context failed\n");

	/* Load the CA certificates that we will use to verify. */
	int result = SSL_CTX_load_verify_locations( ctx, CA_CERTS, NULL );
	if ( !result ) 
		fatal("failed to load " CA_CERTS "\n" );

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
		fatal( "SSL_connect failed\n" );
	message( "connected\n");

	/* Check the verification result. */
	long verifyResult = SSL_get_verify_result(ssl);
	if ( verifyResult != X509_V_OK )
		fatal( "SSL_get_verify_result\n" );

	/* Check the cert chain. The chain length
	 * is automatically checked by OpenSSL when we set the verify depth in the
	 (ctx */

	/* Check the common name. */
	X509 *peer = SSL_get_peer_certificate( ssl );
	char peer_CN[256];
	X509_NAME_get_text_by_NID( X509_get_subject_name(peer), NID_commonName, peer_CN, 256);

	message("peer CN is: %s\n", peer_CN );
	if ( strcasecmp( peer_CN, host ) != 0 )
		fatal("common name doesn't match host name\n");

	message( "client connected\n");

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
	ctx = SSL_CTX_new(TLSv1_server_method());
	if ( ctx == NULL )
		fatal("creating context failed\n");

	int result = SSL_CTX_use_certificate_file( ctx, MY_PEM, SSL_FILETYPE_PEM );
	if ( result != 1 ) 
		fatal("failed to load " MY_PEM "\n" );

	result = SSL_CTX_use_PrivateKey_file( ctx, MY_PEM, SSL_FILETYPE_PEM );
	if ( result != 1 ) 
		fatal("failed to load " MY_PEM "\n" );
}


BIO *sslStartServer( BIO *readBio, BIO *writeBio )
{
	/* Create the SSL object an set it in the secure BIO. */
	SSL *ssl = SSL_new( ctx );
	SSL_set_mode( ssl, SSL_MODE_AUTO_RETRY );
	SSL_set_bio( ssl, readBio, writeBio );

	/* Start the SSL process. */
	int connResult = SSL_accept( ssl );
	if ( connResult <= 0 ) {
		connResult = SSL_get_error( ssl, connResult );
		printError( connResult );
		fatal( "SSL_accept failed: %s\n",  ERR_error_string( ERR_get_error( ), 0 ) );
	}

	message( "server connected\n");

	/* Create a BIO for the ssl wrapper. */
    BIO *sbio = BIO_new(BIO_f_ssl());
	BIO_set_ssl( sbio, ssl, BIO_NOCLOSE );

	BIO *bio = BIO_new( BIO_f_buffer());
    BIO_push( bio, sbio );

	return bio;
}
