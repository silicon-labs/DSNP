#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include <iostream>
#include "dsnp.h"

void printError( int e );
extern SSL_CTX *ctx;

void sslInitServer3()
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

	/* Load the CA certificates that we will use to verify. */
	if ( c->CFG_TLS_CA_CERTS == 0 )
		fatal("CFG_TLS_CA_CERTS is not set\n");

	const char *CA_CERTS = "/home/thurston/tmp/tls3/bar.pem";
	int result = SSL_CTX_load_verify_locations( ctx, CA_CERTS, NULL );
	if ( !result ) 
		fatal("failed to load %s\n", CA_CERTS );
	
	SSL_CTX_set_verify( ctx, 
		SSL_VERIFY_PEER | 
		SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 
		0);

	/*
	 * Our own identity.
	 */
	c->CFG_TLS_CRT = strdup("/home/thurston/tmp/tls3/wendy.crt");
	c->CFG_TLS_KEY = strdup("/home/thurston/tmp/tls3/wendy.key");
	if ( c->CFG_TLS_CRT == 0 )
		fatal("CFG_TLS_CRT is not set\n");
	if ( c->CFG_TLS_KEY == 0 )
		fatal("CFG_TLS_KEY is not set\n");

	result = SSL_CTX_use_certificate_file( ctx, c->CFG_TLS_CRT, SSL_FILETYPE_PEM );
	if ( result != 1 ) 
		fatal("failed to load %s\n", c->CFG_TLS_CRT );

	result = SSL_CTX_use_PrivateKey_file( ctx, c->CFG_TLS_KEY, SSL_FILETYPE_PEM );
	if ( result != 1 ) 
		fatal("failed to load %s\n", c->CFG_TLS_KEY );
}

BIO *sslStartServer3( BIO *readBio, BIO *writeBio )
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

	/* Check the verification result. */
	long verifyResult = SSL_get_verify_result(ssl);
	if ( verifyResult != X509_V_OK )
		fatal( "SSL_get_verify_result\n" );

	/* Create a BIO for the ssl wrapper. */
    BIO *sbio = BIO_new(BIO_f_ssl());
	BIO_set_ssl( sbio, ssl, BIO_NOCLOSE );

	BIO *bio = BIO_new( BIO_f_buffer());
    BIO_push( bio, sbio );

	return bio;
}

void startIdExchange()
{
	BIO_printf( bioOut, "OK\r\n" );
	BIO_flush( bioOut );

	/* Don't need the buffering wrappers anymore. */
	bioIn = BIO_pop( bioIn );
	bioOut = BIO_pop( bioOut );

	sslInitServer3();
	bioIn = bioOut = sslStartServer3( bioIn, bioOut );

	message("starting ID exchange\n");
}

void sslInitClient3()
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
	if ( c->CFG_TLS_CA_CERTS == 0 )
		fatal("CFG_TLS_CA_CERTS is not set\n");
	
	//DbQuery certQuery( mysql, "SELECT x509_crt FROM user WHERE name = 'foobar'" );
	//const char *cert = fetchRow()[0];

	const char *CA_CERTS = "/home/thurston/tmp/tls3/foo.pem";
	int result = SSL_CTX_load_verify_locations( ctx, CA_CERTS, NULL );
	if ( !result ) 
		fatal("failed to load %s\n", CA_CERTS );

	/*
	 * Our own identity.
	 */
	c->CFG_TLS_CRT = strdup("/home/thurston/tmp/tls3/sandra.crt");
	c->CFG_TLS_KEY = strdup("/home/thurston/tmp/tls3/sandra.key");
	if ( c->CFG_TLS_CRT == 0 )
		fatal("CFG_TLS_CRT is not set\n");
	if ( c->CFG_TLS_KEY == 0 )
		fatal("CFG_TLS_KEY is not set\n");

	result = SSL_CTX_use_certificate_file( ctx, c->CFG_TLS_CRT, SSL_FILETYPE_PEM );
	if ( result != 1 ) 
		fatal("failed to load %s\n", c->CFG_TLS_CRT );

	result = SSL_CTX_use_PrivateKey_file( ctx, c->CFG_TLS_KEY, SSL_FILETYPE_PEM );
	if ( result != 1 ) 
		fatal("failed to load %s\n", c->CFG_TLS_KEY );
}

BIO *sslStartClient3( BIO *readBio, BIO *writeBio, const char *host )
{
	/* Create the SSL object an set it in the secure BIO. */
	SSL *ssl = SSL_new( ctx );
	SSL_set_mode( ssl, SSL_MODE_AUTO_RETRY );
	SSL_set_bio( ssl, readBio, writeBio );

	/* Start the SSL process. */
	int connResult = SSL_connect( ssl );
	if ( connResult <= 0 )
		fatal( "SSL_connect failed\n" );

	/* Check the verification result. */
	long verifyResult = SSL_get_verify_result(ssl);
	if ( verifyResult != X509_V_OK )
		fatal( "SSL_get_verify_result\n" );

	/* Check the cert chain. The chain length is automatically checked by
	 * OpenSSL when we set the verify depth in the CTX */

	/* Check the common name. */
	X509 *peer = SSL_get_peer_certificate( ssl );
	char peer_CN[256];
	X509_NAME_get_text_by_NID( X509_get_subject_name(peer), NID_commonName, peer_CN, 256);

//	if ( strcasecmp( peer_CN, host ) != 0 )
//		fatal( "common name %s, doesn't match host name %s\n", peer_CN, host );

	/* Create a BIO for the ssl wrapper. */
	BIO *sbio = BIO_new( BIO_f_ssl() );
	BIO_set_ssl( sbio, ssl, BIO_NOCLOSE );

	BIO *bio = BIO_new( BIO_f_buffer());
    BIO_push( bio, sbio );

	return bio;
}


int TlsConnect::connect3( const char *host, const char *site )
{
	static char buf[8192];

	long socketFd = open_inet_connection( host, atoi(c->CFG_PORT) );
	if ( socketFd < 0 ) {
		error( "failed to connect to %s\n", host );
		return -1;
	}

	BIO *socketBio = BIO_new_fd( socketFd, BIO_NOCLOSE );
	BIO *buffer = BIO_new( BIO_f_buffer() );
	BIO_push( buffer, socketBio );

	/* Send the request. */
	BIO_printf( buffer,
		"SPP/0.1 %s\r\n"
		"start_id_exchange\r\n",
		site );
	BIO_flush( buffer );

	/* Read the result. */
	BIO_gets( buffer, buf, 8192 );

	/* Verify the result here. */

	sslInitClient3();
	sbio = sslStartClient3( socketBio, socketBio, host );

	return 0;
}

int runIdConnect()
{
	MYSQL *mysql = dbConnect();

	fetchCertificate( mysql, "https://localhost/s1/foobar/" );
	/* There is a fork. */
	mysql = dbConnect();


	setConfigByName( "s1" );
	message( "CFG_URI %s\n", c->CFG_URI );
	TlsConnect tlsConnect;
	int result = tlsConnect.connect3( "localhost", "https://localhost/s2/" );
	if ( result < 0 ) 
		return result;

//	BIO_printf( tlsConnect.sbio, "public_key %s\r\n", user );
//	BIO_flush( tlsConnect.sbio );
//
//	/* Read the result. */
//	int readRes = BIO_gets( tlsConnect.sbio, buf, 8192 );
//	message("encrypted return to fetch_public_key_net is %s", buf );
//
//	/* If there was an error then fail the fetch. */
//	if ( readRes <= 0 )
//		return ERR_READ_ERROR;

	return 0;
}

