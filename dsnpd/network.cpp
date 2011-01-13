#include "dsnp.h"
#include "encrypt.h"
#include "error.h"

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
			/* This should not happen. */
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
		"SELECT iduri, friend_hash, generation, friend_proof "
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
		"SELECT iduri, friend_hash, generation, reverse_proof "
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

long long findPrimaryNetworkId( MYSQL *mysql, User &user )
{
	DbQuery query( mysql,
		"SELECT id FROM network WHERE user_id = %L AND type = %l",
		user.id(), NET_TYPE_PRIMARY );

	if ( query.rows() != 1 )
		throw NoPrimaryNetwork();

	return parseId( query.fetchRow()[0] );
}

void sendBroadcastKey( MYSQL *mysql, User &user, Identity &identity, 
		FriendClaim &friendClaim, long long networkId )
{
	PutKey put( mysql, networkId );

	/* Notify the requester. */
	String result, registered( "broadcast_key %s %lld %s\r\n", 
			put.distName(), put.generation, put.broadcastKey() );

	sendMessageNow( mysql, false, user.user(), identity.iduri(),
			friendClaim.putRelid, registered.data, result );
}

void addToPrimaryNetwork( MYSQL *mysql, User &user, Identity &identity )
{
	long long networkId = findPrimaryNetworkId( mysql, user );

	FriendClaim friendClaim( mysql, user, identity );

	/* Try to insert the group member. */
	DbQuery insert( mysql, 
		"INSERT IGNORE INTO network_member "
		"( network_id, friend_claim_id  ) "
		"VALUES ( %L, %L )",
		networkId, friendClaim.id
	);

	sendBroadcastKey( mysql, user, identity, friendClaim, networkId );
}
