#include "dsnp.h"
#include "disttree.h"
#include "encrypt.h"
#include <string.h>

long long addNetwork( MYSQL *mysql, long long userId, const char *name )
{
	unsigned char distName[RELID_SIZE];
	RAND_bytes( distName, RELID_SIZE );
	String distNameStr = binToBase64( distName, RELID_SIZE );

	/* Always, try to insert. Ignore failures. FIXME: need to loop on the
	 * random selection here. */
	DbQuery insert( mysql, 
		"INSERT IGNORE INTO network "
		"( user_id, private_name, dist_name, key_gen, tree_gen_low, tree_gen_high ) "
		"VALUES ( %L, %e, %e, 1, 1, 1 )",
		userId, name, distNameStr.data
	);

	long long networkId = 0;
	if ( insert.affectedRows() > 0  ) {
        /* Make the first broadcast key for the user. */
       networkId = lastInsertId( mysql );
       newBroadcastKey( mysql, networkId, 1 );
	}
	else {
		DbQuery findNetwork( mysql,
			"SELECT id FROM network WHERE user_id = %L and private_name = %e",
			userId, name );
		if ( findNetwork.rows() == 0 ) {
			fatal("could not insert or find network for user_id "
					"%lld and network name %s\n", userId, name );
		}
		else {
			MYSQL_ROW row = findNetwork.fetchRow();
			networkId = strtoll( row[0], 0, 10 );
		}
	}

	return networkId;
}

void sendAllInProofs( MYSQL *mysql, const char *user, const char *network, long long networkId, const char *friendId )
{
	message("sending all in-proofs for user %s network %s to %s\n", user, network, friendId );

	/* Send out all proofs in the group. */
	DbQuery allProofs( mysql,
		"SELECT friend_id, friend_hash, generation, friend_proof "
		"FROM friend_claim "
		"JOIN get_broadcast_key ON friend_claim.id = get_broadcast_key.friend_claim_id "
		"WHERE user = %e AND network_id = %L",
		user, networkId );
	
	/* FIXME: need to deal with specific generation. */
	for ( int r = 0; r < allProofs.rows(); r++ ) {
		MYSQL_ROW row = allProofs.fetchRow();
		const char *friendProof = row[3];

		if ( friendProof != 0 ) {
			const char *proofId = row[0];
			const char *friendHash = row[1];
			long long generation = strtoll( row[2], 0, 10 );

			message("sending in-proof for user %s network %s <- %s to %s\n", user, network, proofId, friendId );
			String msg( "friend_proof %s %s %lld %s\r\n", friendHash, network, generation, friendProof );
			queueMessage( mysql, user, friendId, msg.data, msg.length );
		}
	}
}

void sendAllOutProofs( MYSQL *mysql, const char *user, const char *network,
		long long networkId, const char *friendId )
{
	message("sending all out-proofs for user %s network %s to %s\n", user, network, friendId );

	DbQuery allProofs( mysql,
		"SELECT friend_id, friend_hash, generation, reverse_proof "
		"FROM friend_claim "
		"JOIN network_member "
		"	ON friend_claim.id = network_member.friend_claim_id "
		"JOIN get_broadcast_key ON friend_claim.id = get_broadcast_key.friend_claim_id "
		"WHERE friend_claim.user = %e AND network_member.network_id = %L AND "
		"	get_broadcast_key.network_id = %L",
		user, networkId, networkId );

	for ( int r = 0; r < allProofs.rows(); r++ ) {
		MYSQL_ROW row = allProofs.fetchRow();
		const char *friendProof = row[3];

		if ( friendProof != 0 ) {
			const char *proofId = row[0];
			const char *friendHash = row[1];
			long long generation = strtoll( row[2], 0, 10 );

			message("sending out-proof for user %s network %s -> %s to %s\n", user, network, proofId, friendId );
			String msg( "friend_proof %s %s %lld %s\r\n", friendHash, network, generation, friendProof );
			queueMessage( mysql, user, friendId, msg.data, msg.length );
		}
	}
}

/*
 * Send the current broadcast key and the friend_proof. To make group del and
 * friend del instantaneous we need to destroy the tree.
 */
void sendBkProof( MYSQL *mysql, const char *user, 
		const char *network, long long networkId, const char *friendId,
		long long friendClaimId, const char *putRelid )
{
	CurrentPutKey put( mysql, user, network );

	/* Get the current time. */
	String timeStr = timeNow();
	String proof1( "friend_proof %s%s/ %s %s\r\n", c->CFG_URI, user, friendId, timeStr.data );
	String proof2( "friend_proof %s %s%s/ %s\r\n", friendId, c->CFG_URI, user, timeStr.data );

	RSA *user_priv = loadKey( mysql, user );
	RSA *id_pub = fetchPublicKey( mysql, friendId );

	Encrypt encrypt1( id_pub, user_priv );
	int sigRes = encrypt1.bkSignEncrypt( put.broadcastKey.data,
			(u_char*)proof1.data, proof1.length );
	if ( sigRes < 0 ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_ENCRYPT_SIGN );
		return;
	}

	Encrypt encrypt2( id_pub, user_priv );
	sigRes = encrypt2.bkSignEncrypt( put.broadcastKey.data,
			(u_char*)proof2.data, proof2.length );
	if ( sigRes < 0 ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_ENCRYPT_SIGN );
		return;
	}

	/* Notify the requester. */
	String registered( "bk_proof %s %lld %s %s %s\r\n", 
			network, put.keyGen, put.broadcastKey.data, encrypt1.sym, encrypt2.sym );

	sendMessageNow( mysql, false, user, friendId, putRelid, registered.data, 0 );

	sendAllInProofs( mysql, user, network, networkId, friendId );
	sendAllOutProofs( mysql, user, network, networkId, friendId );
}

/*
 * To make group del and friend del instantaneous we need to destroy the tree.
 */

void sendBroadcastKey( MYSQL *mysql, const char *user, 
		const char *network, long long networkId, const char *friendId,
		long long friendClaimId, const char *putRelid )
{
	CurrentPutKey put( mysql, user, network );

	/* Notify the requester. */
	String registered( "broadcast_key %s %lld %s\r\n", 
			network, put.keyGen, put.broadcastKey.data );

	sendMessageNow( mysql, false, user, friendId, putRelid, registered.data, 0 );
}

void addToNetwork( MYSQL *mysql, const char *user, const char *network, const char *identity )
{
	message("adding %s to %s for %s\n", identity, network, user );

	/* Query the user. */
	DbQuery findUser( mysql, 
		"SELECT id FROM user WHERE user = %e", user );

	if ( findUser.rows() == 0 ) {
		BIO_printf( bioOut, "ERROR user not found\r\n" );
		return;
	}

	MYSQL_ROW row = findUser.fetchRow();
	long long userId = strtoll( row[0], 0, 10 );

	/* Make sure we have the network parameters for this user. */
	long long networkId = addNetwork( mysql, userId, network );

	/* Query the friend claim. */
	DbQuery findClaim( mysql, 
		"SELECT id, put_relid FROM friend_claim WHERE user = %e AND friend_id = %e", 
		user, identity );

	if ( findClaim.rows() == 0 ) {
		BIO_printf( bioOut, "ERROR not a friend\r\n" );
		return;
	}

	row = findClaim.fetchRow();
	long long friendClaimId = strtoll( row[0], 0, 10 );
	const char *putRelid = row[1];

	/* Try to insert the group member. */
	DbQuery insert( mysql, 
		"INSERT IGNORE INTO network_member "
		"( network_id, friend_claim_id  ) "
		"VALUES ( %L, %L )",
		networkId, friendClaimId
	);

	if ( insert.affectedRows() == 0 ) {
		BIO_printf( bioOut, "ERROR friend already in group\r\n" );
		return;
	}

	if ( strcmp( network, "-" ) == 0 )
		sendBroadcastKey( mysql, user, network, networkId, identity, friendClaimId, putRelid );
	else
		sendBkProof( mysql, user, network, networkId, identity, friendClaimId, putRelid );

	BIO_printf( bioOut, "OK\n" );
}

void invalidateBroadcastKey( MYSQL *mysql, const char *user, long long userId,
		const char *network, long long networkId, const char *friendId,
		long long friendClaimId, const char *putRelid )
{
}

void invalidateBkProof( MYSQL *mysql, const char *user, long long userId,
		const char *network, long long networkId, const char *friendId,
		long long friendClaimId, const char *putRelid )
{
	CurrentPutKey put( mysql, user, network );

	String command( "group_member_revocation %s %lld %s\r\n", 
		network, put.keyGen, friendId );
	queueBroadcast( mysql, user, network, command.data, command.length );
}

void removeFromNetwork( MYSQL *mysql, const char *user, const char *network, const char *identity )
{
	message("removing %s from %s for %s\n", identity, network, user );

	/* Query the user. */
	DbQuery findUser( mysql, 
		"SELECT id FROM user WHERE user = %e", user );

	if ( findUser.rows() == 0 ) {
		BIO_printf( bioOut, "ERROR user not found\r\n" );
		return;
	}

	MYSQL_ROW row = findUser.fetchRow();
	long long userId = strtoll( row[0], 0, 10 );

	/* Query the network. */
	DbQuery findNetwork( mysql, 
		"SELECT network.id FROM network "
		"WHERE user_id = %L AND network.name = %e", 
		userId, network );

	if ( findNetwork.rows() == 0 ) {
		BIO_printf( bioOut, "ERROR invalid network\r\n" );
		return;
	}

	row = findNetwork.fetchRow();
	long long networkId = strtoll( row[0], 0, 10 );

	/* Query the friend claim. */
	DbQuery findClaim( mysql, 
		"SELECT id, put_relid FROM friend_claim WHERE user = %e AND friend_id = %e", 
		user, identity );

	if ( findClaim.rows() == 0 ) {
		BIO_printf( bioOut, "ERROR not a friend\r\n" );
		return;
	}

	row = findClaim.fetchRow();
	long long friendClaimId = strtoll( row[0], 0, 10 );
	const char *putRelid = row[1];

	DbQuery del( mysql, 
		"DELETE FROM network_member "
		"WHERE network_id = %L AND friend_claim_id = %L",
		networkId, friendClaimId
	);

	if ( del.affectedRows() == 0 ) {
		BIO_printf( bioOut, "ERROR friend not in network\r\n" );
		return;
	}

	if ( strcmp( network, "-" ) == 0 ) {
		invalidateBroadcastKey( mysql, user, userId, network, networkId,
				identity, friendClaimId, putRelid );
	}
	else {
		invalidateBkProof( mysql, user, userId, network, networkId,
				identity, friendClaimId, putRelid );
	}

	BIO_printf( bioOut, "OK\n" );
}

void showNetwork( MYSQL *mysql, const char *user, const char *network )
{
	message("showing network %s for %s\n", network, user );

	/* Query the user. */
	DbQuery findUser( mysql, 
		"SELECT id FROM user WHERE user = %e", user );

	if ( findUser.rows() == 0 ) {
		BIO_printf( bioOut, "ERROR user not found\r\n" );
		return;
	}

	MYSQL_ROW row = findUser.fetchRow();
	long long userId = strtoll( row[0], 0, 10 );

	/* Make sure we have the network parameters for this user. */
	addNetwork( mysql, userId, network );

	BIO_printf( bioOut, "OK\n" );
}

void unshowNetwork( MYSQL *mysql, const char *user, const char *network )
{
	BIO_printf( bioOut, "OK\n" );
}
