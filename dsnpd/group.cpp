#include "dsnp.h"
#include "disttree.h"
#include "encrypt.h"

void addGroup( MYSQL *mysql, const char *user, const char *group )
{
	/* Query the user. */
	DbQuery findUser( mysql, "SELECT id FROM user WHERE user = %e", user );

	if ( findUser.rows() == 0 ) {
		BIO_printf( bioOut, "ERROR user not found\r\n" );
		return;
	}

	MYSQL_ROW row = findUser.fetchRow();
	long long userId = strtoll( row[0], 0, 10 );

	DbQuery insert( mysql, 
		"INSERT IGNORE INTO friend_group "
		"( user_id, name, key_gen, tree_gen_low, tree_gen_high ) "
		"VALUES ( %L, %e, 1, 1, 1 )",
		userId, group
	);


	if ( insert.affectedRows() == 0 ) {
		BIO_printf( bioOut, "ERROR friend group exists\r\n" );
		return;
	}

	/* Make the first broadcast key for the user. */
	long long friendGroupId = lastInsertId( mysql );
	newBroadcastKey( mysql, friendGroupId, 1 );

	BIO_printf( bioOut, "OK\n" );
}


void sendAllProofs( MYSQL *mysql, const char *user, const char *group, const char *friendId )
{
	message("send all proofs for %s %s %s\n", user, group, friendId );

	/* Send out all proofs in the group. */
	DbQuery allProofs( mysql,
		"SELECT friend_hash, generation, friend_proof "
		"FROM friend_claim "
		"JOIN get_broadcast_key ON friend_claim.id = get_broadcast_key.friend_claim_id "
		"WHERE user = %e AND group_name = %e",
		user, group );
	
	/* FIXME: need to deal with specific generation. */
	for ( int r = 0; r < allProofs.rows(); r++ ) {
		MYSQL_ROW row = allProofs.fetchRow();

		if ( row[1] != 0 && row[2] != 0 ) {
			const char *friendHash = row[0];
			long long generation = strtoll( row[1], 0, 10 );
			const char *friendProof = row[2];

			String msg( "friend_proof %s %s %lld %s\r\n", friendHash, group, generation, friendProof );
			message("trying to send %s\n", msg.data );
			queueMessage( mysql, user, friendId, msg.data, msg.length );
		}
	}
}

void sendAllProofs2( MYSQL *mysql, const char *user, const char *group, const char *friendId )
{
	message("send all proofs (2) for %s %s %s\n", user, group, friendId );

	DbQuery findGroup( mysql, 
		"SELECT friend_group.id FROM user "
		"JOIN friend_group ON user.id = friend_group.user_id "
		"WHERE user.user = %e AND friend_group.name = %e ",
		user, group );

	if ( findGroup.rows() > 0 ) {
		long long groupId = strtoll( findGroup.fetchRow()[0], 0, 10 );

		DbQuery allProofs( mysql,
			"SELECT friend_hash, generation, reverse_proof "
			"FROM friend_claim "
			"JOIN group_member "
			"	ON friend_claim.id = group_member.friend_claim_id "
			"JOIN get_broadcast_key ON friend_claim.id = get_broadcast_key.friend_claim_id "
			"WHERE friend_claim.user = %e AND group_member.friend_group_id = %L",
			user, groupId );

		for ( int r = 0; r < allProofs.rows(); r++ ) {
			MYSQL_ROW row = allProofs.fetchRow();
			if ( row[1] != 0 && row[2] != 0 ) {
				const char *friendHash = row[0];
				long long generation = strtoll( row[1], 0, 10 );
				const char *friendProof = row[2];

				String msg( "friend_proof %s %s %lld %s\r\n", friendHash, group, generation, friendProof );
				message("trying to send %s\n", msg.data );
				queueMessage( mysql, user, friendId, msg.data, msg.length );
			}
		}
	}
}

/*
 * To make group del and friend del instantaneous we need to destroy the tree.
 */

void sendBkProof( MYSQL *mysql, const char *user, long long friendGroupId, 
		const char *group, const char *friendId,
		long long friendClaimId, const char *putRelid )
{
	/*
	 * Send the current broadcast key and the friend_proof.
	 */
	CurrentPutKey put( mysql, user, group );

	/* Get the current time. */
	String timeStr = timeNow();
	String proof1( "friend_proof %s%s/ %s %s\r\n", c->CFG_URI, user, friendId, timeStr.data );
	String proof2( "friend_proof %s %s%s/ %s\r\n", friendId, c->CFG_URI, user, timeStr.data );

	RSA *user_priv = load_key( mysql, user );
	RSA *id_pub = fetch_public_key( mysql, friendId );

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
	String registered( "broadcast_key %s %lld %s %s %s\r\n", 
			group, put.keyGen, put.broadcastKey.data, encrypt1.sym, encrypt2.sym );

	sendMessageNow( mysql, false, user, friendId, putRelid, registered.data, 0 );

	putTreeAdd( mysql, user, group, friendGroupId, friendId, putRelid );

	sendAllProofs( mysql, user, group, friendId );
	sendAllProofs2( mysql, user, group, friendId );
}

void addToGroup( MYSQL *mysql, const char *user, const char *group, const char *identity )
{
	/* Query the user. */
	DbQuery findUser( mysql, 
		"SELECT id FROM user WHERE user = %e", user );

	if ( findUser.rows() == 0 ) {
		BIO_printf( bioOut, "ERROR user not found\r\n" );
		return;
	}

	MYSQL_ROW row = findUser.fetchRow();
	long long userId = strtoll( row[0], 0, 10 );

	/* Query the group. */
	DbQuery findGroup( mysql, 
		"SELECT id FROM friend_group WHERE user_id = %L AND name = %e", userId, group );

	if ( findGroup.rows() == 0 ) {
		BIO_printf( bioOut, "ERROR invalid friend group\r\n" );
		return;
	}

	row = findGroup.fetchRow();
	long long friendGroupId = strtoll( row[0], 0, 10 );

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

	DbQuery insert( mysql, 
		"INSERT IGNORE INTO group_member "
		"( friend_group_id, friend_claim_id   ) "
		"VALUES ( %L, %L )",
		friendGroupId, friendClaimId
	);

	if ( insert.affectedRows() == 0 ) {
		BIO_printf( bioOut, "ERROR friend already in group\r\n" );
		return;
	}

	sendBkProof( mysql, user, friendGroupId, group, identity, friendClaimId, putRelid );

	BIO_printf( bioOut, "OK\n" );
}

void invalidateBkProof( MYSQL *mysql, const char *user, long long userId, long long friendGroupId, 
		const char *group, const char *friendId,
		long long friendClaimId, const char *putRelid )
{
	putTreeDel( mysql, user, userId, group, friendGroupId, friendId, putRelid );

	/*
	 * Send the current broadcast key and the friend_proof.
	 */
	CurrentPutKey put( mysql, user, group );

	String command( "group_member_revocation %s %lld %s\r\n", 
		group, put.keyGen, friendId );
	queueBroadcast( mysql, user, group, command.data, command.length );
}

void removeFromGroup( MYSQL *mysql, const char *user, const char *group, const char *identity )
{
	message("removing %s from %s for %s\n", identity, group, user );

	/* Query the user. */
	DbQuery findUser( mysql, 
		"SELECT id FROM user WHERE user = %e", user );

	if ( findUser.rows() == 0 ) {
		BIO_printf( bioOut, "ERROR user not found\r\n" );
		return;
	}

	MYSQL_ROW row = findUser.fetchRow();
	long long userId = strtoll( row[0], 0, 10 );

	/* Query the group. */
	DbQuery findGroup( mysql, 
		"SELECT id FROM friend_group WHERE user_id = %L AND name = %e", userId, group );

	if ( findGroup.rows() == 0 ) {
		BIO_printf( bioOut, "ERROR invalid friend group\r\n" );
		return;
	}

	row = findGroup.fetchRow();
	long long friendGroupId = strtoll( row[0], 0, 10 );

	/* Query the friend claim. */
	DbQuery findClaim( mysql, 
		"SELECT id, put_relid FROM friend_claim WHERE user = %e AND friend_id = %e", user, identity );

	if ( findClaim.rows() == 0 ) {
		BIO_printf( bioOut, "ERROR not a friend\r\n" );
		return;
	}

	row = findClaim.fetchRow();
	long long friendClaimId = strtoll( row[0], 0, 10 );
	const char *putRelid = row[1];

	DbQuery del( mysql, 
		"DELETE FROM group_member "
		"WHERE friend_group_id = %L AND friend_claim_id = %L",
		friendGroupId, friendClaimId
	);

	if ( del.affectedRows() == 0 ) {
		BIO_printf( bioOut, "ERROR friend not in group\r\n" );
		return;
	}

	invalidateBkProof( mysql, user, userId, friendGroupId, group, 
			identity, friendClaimId, putRelid );

	BIO_printf( bioOut, "OK\n" );
}
