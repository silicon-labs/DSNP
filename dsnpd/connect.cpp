#include "dsnp.h"
#include "error.h"

void TlsConnect::publicKey( const char *user )
{
	BIO_printf( sbio, "public_key %s\r\n", user );
	(void)BIO_flush( sbio );

	/* Read the result. */
	static char buf[8192];
	int readRes = BIO_gets( sbio, buf, 8192 );

	/* If there was an error then fail the fetch. */
	if ( readRes <= 0 )
		throw ReadError();
	
	result = buf;
}
