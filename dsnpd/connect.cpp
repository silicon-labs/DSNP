#include "dsnp.h"
#include "error.h"

#include <unistd.h>
#include <fcntl.h>

void BioSocket::write( const char *msg, long mLen )
{
	BIO_write( sbio, msg, mLen );
	(void)BIO_flush( sbio );
}

void BioSocket::closeMessage()
{
	BIO_write( sbio, "\r\n", 2 );
	(void)BIO_flush( sbio );
}

int BioSocket::printf( const char *fmt, ... )
{
	va_list args;
	va_start( args, fmt );
	long result = BIO_vprintf( sbio, fmt, args );
	va_end( args );
	(void)BIO_flush( sbio );
	return result;
}

int BioSocket::readParse( Parser &parser )
{
	int readRes = BIO_gets( sbio, input, linelen );

	/* If there was an error then fail the fetch. */
	if ( readRes <= 0 )
		throw ReadError();

	parser.data( input, readRes );

	return readRes;
}


int BioSocket::readParse2( Parser &parser )
{
	fd_set set;
	int nbytes, fd = BIO_get_fd(sbio, 0);

	/* Make FD non-blocking. */
	int flags = fcntl( fd, F_GETFL );
	fcntl( fd, F_SETFL, flags | O_NONBLOCK );

	while ( true ) {

	retry:
		FD_ZERO( &set );
		FD_SET( fd, &set );
		select( fd+1, &set, 0, 0, 0 );

		while ( true ) {
			nbytes = BIO_read( sbio, input, linelen );

			/* break when client closes the connection. */
			if ( nbytes <= 0 ) {
				if ( BIO_should_retry( sbio ) )
					goto retry;

				message( "BIO_read returned %d, breaking\n", nbytes );
				goto done;
			}

			message( "BIO_read returned %d bytes, parsing\n", nbytes );
			//message( "command: %.*s", (int)lineLen, buf );

			parser.data( input, nbytes );

			(void)BIO_flush( bioOut );
		}
	}

done:
	return 0;
}
