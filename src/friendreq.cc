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
#include "packet.h"
#include "string.h"
#include "error.h"
#include "keyagent.h"

#include <mysql/mysql.h>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>

bool checkFriendClaimExists( MYSQL *mysql, User &user, Identity &identity )
{
	/* Check to see if there is already a friend claim. */
	DbQuery claim( mysql, 
		"SELECT id "
		"FROM friend_claim "
		"WHERE user_id = %L AND identity_id = %L",
		user.id(), identity.id() );

	if ( claim.rows() != 0 )
		return true;

	return false;
}

bool checkFriendRequestExists( MYSQL *mysql, User &user, Identity &identity )
{
	/* Check to see if there is already a friend claim. */
	DbQuery claim( mysql, 
		"SELECT id "
		"FROM friend_request "
		"WHERE user_id = %L AND identity_id = %L",
		user.id(), identity.id() );

	if ( claim.rows() != 0 )
		return true;

	return false;
}

void RelidSet::generate()
{
	priv0.allocate( RELID_SIZE );
	priv1.allocate( RELID_SIZE );
	priv2.allocate( RELID_SIZE );
	priv3.allocate( RELID_SIZE );
	priv4.allocate( RELID_SIZE );

	RAND_bytes( priv0.binary(), priv0.length );
	RAND_bytes( priv1.binary(), priv1.length );
	RAND_bytes( priv2.binary(), priv2.length );
	RAND_bytes( priv3.binary(), priv3.length );
	RAND_bytes( priv4.binary(), priv4.length );
}

long long Server::storeGetRelid( User &user, Identity &identity, long long friendClaimId,
		int keyPriv, const String &relid )
{
	String relidStr = binToBase64( relid );
	DbQuery( mysql,
		"INSERT INTO get_relid ( "
		"	user_id, identity_id, friend_claim_id, key_priv, get_relid "
		") "
		"VALUES( %L, %L, %L, %l, %e )",
		user.id(), identity.id(), friendClaimId,
		keyPriv, relidStr() );
	return lastInsertId( mysql );
}

long long Server::storePutRelid( User &user, Identity &identity, long long friendClaimId,
		int keyPriv, const String &relid )
{
	String relidStr = binToBase64( relid );
	DbQuery( mysql,
		"INSERT INTO put_relid ( "
		"	user_id, identity_id, friend_claim_id, key_priv, put_relid "
		") "
		"VALUES( %L, %L, %L, %l, %e )",
		user.id(), identity.id(), friendClaimId,
		keyPriv, relidStr() );
	return lastInsertId( mysql );
}

void Server::relidRequest( const String &_user, const String &_iduri )
{
	/* a) verifies challenge response
	 * b) fetches $URI/id.asc (using SSL)
	 * c) randomly generates a one-way relationship id ($FR-RELID)
	 * d) randomly generates a one-way request id ($FR-REQID)
	 * e) encrypts $FR-RELID to friender and signs it
	 * f) makes message available at $FR-URI/friend-request/$FR-REQID.asc
	 * g) redirects the user's browser to $URI/return-relid?uri=$FR-URI&reqid=$FR-REQID
	 */
	
	User user( mysql, _user );
	Identity identity( mysql, _iduri );

	if ( user.id() < 0 )
		throw InvalidUser( _user );

	/* Check to make sure this isn't ourselves. */
	String ourId = user.iduri;
	
	if ( strcasecmp( ourId(), identity.iduri ) == 0 )
		throw CannotFriendSelf( identity.iduri );
	
	/* FIXME: these should be presented to the user only after the bounce back
	 * that authenticates the submitter, otherwise anyone can test friendship
	 * between arbitrary users. */

	/* Check for the existence of a friend claim. */
	if ( checkFriendClaimExists( mysql, user, identity ) )
		throw FriendClaimExists( user.iduri, identity.iduri );

	/* Check for the existence of a friend request. */
	if ( checkFriendRequestExists( mysql, user, identity ) )
		throw FriendRequestExists( user.iduri, identity.iduri );

	/* Generate the request id. */
	String requestedReqidBin( REQID_SIZE );
	RAND_bytes( requestedReqidBin.binary(), requestedReqidBin.length );
	String requestedReqid = binToBase64( requestedReqidBin );

	/* Generate the relids. */
	RelidSet requestedRelidSet;
	requestedRelidSet.generate();

	/* Encrypt and sign the relationship id. */
	String requestedRelidSetPacket = consRelidSet( requestedRelidSet );

	fetchPublicKey( identity );
	String encPacket = keyAgent.signEncrypt( identity, user, requestedRelidSetPacket );
	
	/* Store the request. */

	DbQuery( mysql,
		"INSERT INTO relid_request "
		"( user_id, identity_id, requested_reqid, requested_relid_set, message ) "
		"VALUES( %L, %L, %e, %d, %d )",
		user.id(), identity.id(), requestedReqid(), 
		requestedRelidSetPacket(), requestedRelidSetPacket.length, 
		encPacket.binary(), encPacket.length );

	/* Return the request id for the requester to use. */
	bioWrap.returnOkLocal( requestedReqid );
}

void Server::fetchRequestedRelid( const String &requestedReqid )
{
	DbQuery request( mysql,
		"SELECT message "
		"FROM relid_request "
		"WHERE requested_reqid = %e",
		requestedReqid() );

	/* Check for a result. */
	if ( request.rows() == 0 )
		throw RequestIdInvalid();

	MYSQL_ROW row = request.fetchRow();
	u_long *lengths = request.fetchLengths();
	String msg = Pointer( row[0], lengths[0] );

	bioWrap.returnOkServer( msg );
}

void Server::relidResponse( const String &token, 
		const String &requestedReqid, const String &iduri )
{
	/*  a) verifies browser is logged in as owner
	 *  b) fetches $FR-URI/id.asc (using SSL)
	 *  c) fetches $FR-URI/friend-request/$FR-REQID.asc 
	 *  d) decrypts and verifies $FR-RELID
	 *  e) randomly generates $RELID
	 *  f) randomly generates $REQID
	 *  g) encrypts "$FR-RELID $RELID" to friendee and signs it
	 *  h) makes message available at $URI/request-return/$REQID.asc
	 *  i) redirects the friender to $FR-URI/friend-final?uri=$URI&reqid=$REQID
	 */
	
	User user( mysql, User::ByLoginToken(), token );
	if ( user.id() < 0 )
		throw InvalidUser( token );

	Identity identity( mysql, iduri );

	String host = Pointer( identity.host() );
	String recvEncPacket = fetchRequestedRelidNet( host, requestedReqid );

	/* Decrypt and verify the requested_relid. */
	fetchPublicKey( identity );
	String decrypted = keyAgent.decryptVerify( identity, user, recvEncPacket );

	/* Parse the requested relid. */
	PacketRelidSet epp( decrypted );

	DbQuery( mysql, 
		"INSERT INTO friend_claim "
		"( user_id, identity_id, state ) "
		"VALUES ( %L, %L, %l ) ",
		user.id(), identity.id(), FC_SENT
	);
	long long friendClaimId = lastInsertId( mysql );

	/* Generate the response request id. */
	String responseReqidBin( REQID_SIZE );
	RAND_bytes( responseReqidBin.binary(), responseReqidBin.length );
	String responseReqid = binToBase64( responseReqidBin );

	RelidSet responseRelidSet;
	responseRelidSet.generate();

	storePutRelid( user, identity, friendClaimId, KEY_PRIV0, epp.priv0 );
	storePutRelid( user, identity, friendClaimId, KEY_PRIV1, epp.priv1 );
	storePutRelid( user, identity, friendClaimId, KEY_PRIV2, epp.priv2 );
	storePutRelid( user, identity, friendClaimId, KEY_PRIV3, epp.priv3 );
	storePutRelid( user, identity, friendClaimId, KEY_PRIV4, epp.priv4 );
	
	storeGetRelid( user, identity, friendClaimId, KEY_PRIV0, responseRelidSet.priv0 );
	storeGetRelid( user, identity, friendClaimId, KEY_PRIV1, responseRelidSet.priv1 );
	storeGetRelid( user, identity, friendClaimId, KEY_PRIV2, responseRelidSet.priv2 );
	storeGetRelid( user, identity, friendClaimId, KEY_PRIV3, responseRelidSet.priv3 );
	storeGetRelid( user, identity, friendClaimId, KEY_PRIV4, responseRelidSet.priv4 );

	/* Make IDs to identify the sent request. One will be handed to the
	 * responder. The other to the user agent. */
	String peerNotifyReqidBin(REQID_SIZE);
	RAND_bytes( peerNotifyReqidBin.binary(), peerNotifyReqidBin.length );
	String peerNotifyReqid = binToBase64( peerNotifyReqidBin );

	String userNotifyReqidBin(REQID_SIZE);
	RAND_bytes( userNotifyReqidBin.binary(), userNotifyReqidBin.length );
	String userNotifyReqid = binToBase64( userNotifyReqidBin );

	/* Construct the packet we will store and provide to the peer when asked. */
	String responseRelidSetPacket = consRelidSet( responseRelidSet );
	String relidSetPairPacket = consRelidSetPair( decrypted, responseRelidSetPacket );
	String relidResponse = consRelidResponse( peerNotifyReqidBin, relidSetPairPacket );

	/* Encrypt and sign using the same credentials. */
	String encPacket = keyAgent.signEncrypt( identity, user, relidResponse );

	/* Record the response, which will be fetched. */
	DbQuery( mysql,
		"INSERT INTO relid_response "
		"( identity_id, requested_reqid, response_reqid, message ) "
		"VALUES ( %L, %e, %e, %d )",
		identity.id(), requestedReqid(), responseReqid(), 
		encPacket.binary(), encPacket.length );

	/* The GET relids (ones we generated) always come first. */
	String storedRelidSetPair = consRelidSetPair( responseRelidSetPacket, decrypted );

	/* Recored the sent request. */
	DbQuery( mysql, 
		"INSERT INTO sent_friend_request "
		"( "
		"	user_id, identity_id, "
		"	peer_notify_reqid, user_notify_reqid, "
		"	relid_set_pair "
		") "
		"VALUES ( %L, %L, %e, %e, %d );",
		user.id(), identity.id(),
		peerNotifyReqid(), userNotifyReqid(),
		storedRelidSetPair(), storedRelidSetPair.length
	);

	String hash = identity.hash();
	String userSite = user.site();

	notifAgent.notifFriendRequestSent(
			userSite, user.iduri, identity.iduri(),
			hash(), userNotifyReqid() );
	
	/* Return the request id for the requester to use. */
	bioWrap.returnOkLocal( responseReqid );
}

void Server::fetchResponseRelid( const String &responseReqid )
{
	/* Execute the query. */
	DbQuery response( mysql,
		"SELECT message "
		"FROM relid_response "
		"WHERE response_reqid = %e",
		responseReqid() );
	
	/* Check for a result. */
	if ( response.rows() == 0 )
		throw RequestIdInvalid();

	MYSQL_ROW row = response.fetchRow();
	u_long *lengths = response.fetchLengths();
	String msg = Pointer( row[0], lengths[0] );

	bioWrap.returnOkServer( msg );
}

void Server::friendFinal( const String &_user, 
		const String &reqid, const String &_iduri )
{
	/* a) fetches $URI/request-return/$REQID.asc 
	 * b) decrypts and verifies message, must contain correct $FR-RELID
	 * c) stores request for friendee to accept/deny
	 */

	/* FIXME: some checking is missing from this. */

	User user( mysql, _user );
	if ( user.id() < 0 )
		throw InvalidUser( _user );

	Identity identity( mysql, _iduri );

	String host = Pointer( identity.host() );
	String encPacket = fetchResponseRelidNet( host, reqid );

	fetchPublicKey( identity );
	String decrypted = keyAgent.decryptVerify( identity, user, encPacket );

	/* Parse the relid response. */
	PacketRelidResponse err( decrypted );

	/* Parse the pair. */
	PacketRelidSetPair epp( err.relidSetPair );

	/* Parse the requested half. */
	PacketRelidSet epp1( epp.requested );

	/* Parse the returned half. */
	PacketRelidSet epp2( epp.returned );

	/* FIXME: more verification. */

	DbQuery( mysql, 
		"INSERT INTO friend_claim "
		"( user_id, identity_id, state ) "
		"VALUES ( %L, %L, %l ) ",
		user.id(), identity.id(), FC_RECEIVED
	);

	long long friendClaimId = lastInsertId( mysql );

	storeGetRelid( user, identity, friendClaimId, KEY_PRIV0, epp1.priv0 );
	storeGetRelid( user, identity, friendClaimId, KEY_PRIV1, epp1.priv1 );
	storeGetRelid( user, identity, friendClaimId, KEY_PRIV2, epp1.priv2 );
	storeGetRelid( user, identity, friendClaimId, KEY_PRIV3, epp1.priv3 );
	storeGetRelid( user, identity, friendClaimId, KEY_PRIV4, epp1.priv4 );

	storePutRelid( user, identity, friendClaimId, KEY_PRIV0, epp2.priv0 );
	storePutRelid( user, identity, friendClaimId, KEY_PRIV1, epp2.priv1 );
	storePutRelid( user, identity, friendClaimId, KEY_PRIV2, epp2.priv2 );
	storePutRelid( user, identity, friendClaimId, KEY_PRIV3, epp2.priv3 );
	storePutRelid( user, identity, friendClaimId, KEY_PRIV4, epp2.priv4 );

	/* Make a user request id. */
	String acceptReqidBin(REQID_SIZE);
	RAND_bytes( acceptReqidBin.binary(), acceptReqidBin.length );
	String acceptReqid = binToBase64( acceptReqidBin );

	String peerNotifyReqid = binToBase64( err.peerNotifyReqid );

	DbQuery( mysql, 
		"INSERT INTO friend_request "
		"( "
		"	user_id, identity_id, "
		"	accept_reqid, peer_notify_reqid, "
		"	relid_set_pair "
		") "
		"VALUES ( %L, %L, %e, %e, %d ) ",
		user.id(), identity.id(), 
		acceptReqid(), peerNotifyReqid(),
		decrypted(), decrypted.length
	);

	String hash = identity.hash();	
	String userSite = user.site();
	notifAgent.notifFriendRequestReceived(
		userSite, user.iduri, identity.iduri(), hash(), acceptReqid() );
	
	/* Return the request id for the requester to use. */
	bioWrap.returnOkLocal();
}
