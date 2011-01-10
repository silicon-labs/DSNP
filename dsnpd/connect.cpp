#include "dsnp.h"
#include "error.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>

BioWrap::BioWrap()
:
	socketFd(-1),
	rbio(0),
	wbio(0),
	linelen(4096)
{
	input = new char[linelen];
}

BioWrap::~BioWrap()
{
	delete[] input;
}


void BioWrap::write( const char *msg, long mLen )
{
	BIO_write( wbio, msg, mLen );
	(void)BIO_flush( wbio );
}

void BioWrap::closeMessage()
{
	BIO_write( wbio, "\r\n", 2 );
	(void)BIO_flush( wbio );
}

int BioWrap::printf( const char *fmt, ... )
{
	va_list args;
	va_start( args, fmt );
	long result = BIO_vprintf( wbio, fmt, args );
	va_end( args );
	(void)BIO_flush( wbio );
	return result;
}

int BioWrap::readParse( Parser &parser )
{
	int readRes = BIO_gets( rbio, input, linelen );

	/* If there was an error then fail the fetch. */
	if ( readRes <= 0 )
		throw ReadError();

	parser.data( input, readRes );

	return readRes;
}


int BioWrap::readParse2( Parser &parser )
{
	fd_set set;
	int res, nbytes, fd = BIO_get_fd( rbio, 0 );

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
				nbytes = BIO_read( rbio, input, linelen );

				/* break when client closes the connection. */
				if ( nbytes <= 0 ) {
					/* If the BIO is saying it we should retry later, go back into
					 * select. */
					if ( BIO_should_retry( rbio ) ) {
						message( "BIO_should_retry\n" );
						break;
					}

					message( "BIO_read returned %d, breaking\n", nbytes );
					goto done;
				}

				message( "BIO_read returned %d bytes, parsing\n", nbytes );
				message( "data: %.*s", (int)nbytes, input );

				parser.data( input, nbytes );

				/* FIXME: eventually remove this. All output commands should do their own flushing. */
				(void)BIO_flush( wbio );
			}
		}
	}

done:
	return 0;
}
