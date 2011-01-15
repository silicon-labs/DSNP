#include "dsnp.h"
#include "error.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <errno.h>

void Server::negotiation( long versions, const String &site, bool tls, const String &key )
{
	/* Decide on a protocol version. */
	const char *replyVersion;
	if ( ! ( versions | VERSION_MASK_0_1 ) )
		throw NoCommonVersion();
	replyVersion = "0.1";

	/* Check the site. */
	setConfigByUri( site );

	/* If a local connection is requested, verify that we are indeed connected
	 * to something on this machine, then check the communication key. */

	/* Check the authentication. */
	if ( !tls ) {
		if ( strcmp( key, c->CFG_COMM_KEY ) != 0 )
			throw InvalidCommKey();

		gblKeySubmitted = true;
	}
	
	/* Connect to the database. */
	mysql = dbConnect();
	if ( mysql == 0 )
		throw DatabaseConnectionFailed();

	bioWrap->printf( "OK %s\r\n", replyVersion );

	message("negotiation: version %s %s %s\n", 
			replyVersion, site(), ( tls ? "tls" : "local" ) );
	
	if ( tls ) {
		bioWrap->rbio = bioWrap->wbio = 
				startTls( bioWrap->rbio, bioWrap->wbio );
		message("negotiation: TLS started\n");
	}
}
