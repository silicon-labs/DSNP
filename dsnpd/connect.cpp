#include "dsnp.h"
#include "error.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>

void BioWrap::write( const char *msg, long mLen )
{
	BIO_write( bio, msg, mLen );
	(void)BIO_flush( bio );
}

void BioWrap::closeMessage()
{
	BIO_write( bio, "\r\n", 2 );
	(void)BIO_flush( bio );
}

int BioWrap::printf( const char *fmt, ... )
{
	va_list args;
	va_start( args, fmt );
	long result = BIO_vprintf( bio, fmt, args );
	va_end( args );
	(void)BIO_flush( bio );
	return result;
}

int BioWrap::readParse( Parser &parser )
{
	int readRes = BIO_gets( bio, input, linelen );

	/* If there was an error then fail the fetch. */
	if ( readRes <= 0 )
		throw ReadError();

	parser.data( this, input, readRes );

	return readRes;
}


int BioWrap::readParse2( Parser &parser )
{
	fd_set set;
	int res, nbytes, fd = BIO_get_fd( bio, 0 );

	/* Make FD non-blocking. */
	int flags = fcntl( fd, F_GETFL );
	fcntl( fd, F_SETFL, flags | O_NONBLOCK );

	while ( true ) {
		FD_ZERO( &set );
		FD_SET( fd, &set );
		res = select( fd+1, &set, 0, 0, 0 );

		if ( res == EBADFD )
			break;

		if ( FD_ISSET( fd, &set ) ) {
			while ( true ) {
				nbytes = BIO_read( bio, input, linelen );

				/* break when client closes the connection. */
				if ( nbytes <= 0 ) {
					/* If the BIO is saying it we should retry later, go back into
					 * select. */
					if ( BIO_should_retry( bio ) ) {
						message( "BIO_should_retry\n" );
						break;
					}

					message( "BIO_read returned %d, breaking\n", nbytes );
					goto done;
				}

				message( "BIO_read returned %d bytes, parsing\n", nbytes );
				message( "data: %.*s", (int)nbytes, input );

				parser.data( this, input, nbytes );

				(void)BIO_flush( bioOut );
			}
		}
	}

done:
	return 0;
}
