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
		"( user_id, name ) "
		"VALUES ( %L, %e )",
		userId, group
	);

	if ( insert.affectedRows() == 0 ) {
		BIO_printf( bioOut, "ERROR friend group exists\r\n" );
		return;
	}

	BIO_printf( bioOut, "OK\n" );
}

void sendBkProof( MYSQL *mysql, const char *user, const char *identity,
		long long friendClaimId, const char *putRelid )
{
	/*
	 * Send the current broadcast key and the friend_proof.
	 */
	long long outGen;
	String outBroadcastKey;
	currentPutBk( mysql, user, outGen, outBroadcastKey );

	/* Get the current time. */
	String timeStr = timeNow();
	String command( "friend_proof %s\r\n", timeStr.data );

	RSA *user_priv = load_key( mysql, user );
	RSA *id_pub = fetch_public_key( mysql, identity );

	Encrypt encrypt( id_pub, user_priv );
	int sigRes = encrypt.bkSignEncrypt( outBroadcastKey.data, (u_char*)command.data, command.length );
	if ( sigRes < 0 ) {
		BIO_printf( bioOut, "ERROR %d\r\n", ERROR_ENCRYPT_SIGN );
		return;
	}

	/* Notify the requester. */
	String registered( "broadcast_key %lld %s %s\r\n", 
			outGen, outBroadcastKey.data, encrypt.sym );

	sendMessageNow( mysql, false, user, identity, putRelid, registered.data, 0 );

	forward_tree_insert( mysql, user, identity, putRelid );
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

	/* Query the group. */
	DbQuery findClaim( mysql, 
		"SELECT id, put_relid FROM friend_claim WHERE user = %e AND friend_id = %e", user, identity );

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

	sendBkProof( mysql, user, identity, friendClaimId, putRelid );

	BIO_printf( bioOut, "OK\n" );
}
