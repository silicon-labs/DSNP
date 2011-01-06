#include "dsnp.h"
#include "error.h"

#include <unistd.h>
#include <fcntl.h>

int TlsConnect::readParse( Parser &parser )
{
	static char buf[8192];

	int readRes = BIO_gets( sbio, buf, 8192 );

	/* If there was an error then fail the fetch. */
	if ( readRes <= 0 )
		throw ReadError();

	parser.data( buf, readRes );

	return readRes;
}

int TlsConnect::printf( const char *fmt, ... )
{
	va_list args;
	va_start( args, fmt );
	long result = BIO_vprintf( sbio, fmt, args );
	va_end( args );
	(void)BIO_flush( sbio );
	return result;
}

