/*
 * Copyright (c) 2008-2011, Adrian Thurston <thurston@complang.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "dsnp.h"
#include "encrypt.h"
#include "error.h"
#include "keyagent.h"

#include <string.h>

long long Server::addNetwork( long long userId, const String &privateName )
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
		userId, privateName(), distNameStr.data
	);

	long long networkId = 0;
	if ( insert.affectedRows() > 0  ) {
        /* Make the first broadcast key for the user. */
       networkId = lastInsertId( mysql );
       newBroadcastKey( networkId, 1 );
	}
	else {
		DbQuery findNetwork( mysql,
			"SELECT id FROM network WHERE user_id = %L and private_name = %e",
			userId, privateName() );
		if ( findNetwork.rows() == 0 ) {
			/* This should not happen. */
			fatal("could not insert or find network for user_id "
					"%lld and network name %s\n", userId, privateName() );
		}
		else {
			MYSQL_ROW row = findNetwork.fetchRow();
			networkId = strtoll( row[0], 0, 10 );
		}
	}

	return networkId;
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

void Server::sendBroadcastKey( User &user, Identity &identity, 
		FriendClaim &friendClaim, long long networkId )
{
	PutKey put( mysql, networkId );

	keyAgent.getPutBroadcastKey( user.id(), identity.iduri, put.id );

	/* Notify the requester. */
	String registered = consBroadcastKey( put.distName, 
			put.generation, keyAgent.bk );

	queueMessage( user, identity.iduri,
			friendClaim.putRelids[KEY_PRIV3], registered );
}

void Server::addToPrimaryNetwork( User &user, Identity &identity )
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

	sendBroadcastKey( user, identity, friendClaim, networkId );
}
