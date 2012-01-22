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

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <mysql/mysql.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>

#include "dsnp.h"
#include "encrypt.h"
#include "string.h"
#include "error.h"
#include "keyagent.h"

User::User( MYSQL *mysql, const char *iduri )
: 
	mysql(mysql),
	iduri(Pointer(iduri)),
	haveId(false),
	_id(-1)
{}

User::User( MYSQL *mysql, long long _id )
: 
	mysql(mysql),
	haveId(true),
	_id(_id)
{
	DbQuery find( mysql,
		"SELECT iduri FROM user WHERE id = %L", 
		_id );

	if ( find.rows() != 1 )
		throw UserIdInvalid();
	
	MYSQL_ROW row = find.fetchRow();
	iduri = Pointer( row[0] );
}

User::User( MYSQL *mysql, ByLoginToken, const char *loginToken )
: 
	mysql(mysql),
	haveId(false),
	_id(0)
{
	DbQuery find( mysql,
		"SELECT user.iduri, user.id "
		"FROM login_token "
		"JOIN user ON login_token.user_id = user.id "
		"WHERE login_token.login_token = %e AND NOW() < expires",
		loginToken );

	if ( find.rows() != 1 )
		throw InvalidLoginToken( loginToken );
	
	MYSQL_ROW row = find.fetchRow();
	iduri = Pointer( row[0] );
	_id = parseId( row[1] );
	haveId = true;
}

long long User::id()
{
	if ( !haveId ) {
		DbQuery find( mysql,
			"SELECT id FROM user WHERE iduri = %e", 
			iduri() );

		if ( find.rows() > 0 ) {
			_id = parseId( find.fetchRow()[0] );
			haveId = true;
		}
	}
	return _id;
}

long long User::siteId()
{
	DbQuery find( mysql,
		"SELECT site_id FROM user WHERE id = %L", 
		id() );
	
	return parseId( find.fetchRow()[0] );
}

Allocated User::site()
{
	DbQuery find( mysql,
		"SELECT site.site "
		"FROM user "
		"JOIN site ON user.site_id = site.id "
		"WHERE user.id = %L", 
		id() );
	
	String site = Pointer( find.fetchRow()[0] );
	return site.relinquish();
}

Site::Site( MYSQL *mysql, const char *_site )
: 
	mysql(mysql),
	site(Pointer(_site)),
	haveId(false),
	_id(-1)
{}

Site::Site( MYSQL *mysql, long long _id )
: 
	mysql(mysql),
	haveId(true),
	_id(_id)
{
	DbQuery find( mysql,
		"SELECT site FROM site WHERE id = %L", 
		_id );

	if ( find.rows() != 1 )
		throw UserIdInvalid();
	
	MYSQL_ROW row = find.fetchRow();
	site = Pointer( row[0] );
}

long long Site::id()
{
	if ( !haveId ) {
		DbQuery find( mysql,
			"SELECT id FROM site WHERE site = %e", 
			site() );

		if ( find.rows() > 0 ) {
			_id = parseId( find.fetchRow()[0] );
			haveId = true;
		}
	}
	return _id;
}

FriendClaim::FriendClaim( MYSQL *mysql, User &user, Identity &identity )
:
	mysql(mysql)
{
	DbQuery query( mysql,
		"SELECT id, state "
		"FROM friend_claim "
		"WHERE user_id = %L AND "
		"	identity_id = %L ",
		user.id(), identity.id() );

	if ( query.rows() == 0 ) {
		message( "%lld %lld\n", user.id(), identity.id() );
		throw FriendClaimNotFound();
	}

	userId = user.id();
	identityId = identity.id();

	MYSQL_ROW row = query.fetchRow();
	id = parseId( row[0] );
	state = atoi( row[1] );

	loadRelids();
}

FriendClaim::FriendClaim( MYSQL *mysql, const char *getRelid )
:
	mysql(mysql)
{
	DbQuery query( mysql,
		"SELECT "
		"	friend_claim.id, friend_claim.user_id, "
		"	friend_claim.identity_id, friend_claim.state "
		"FROM friend_claim "
		"JOIN get_relid ON friend_claim.id = get_relid.friend_claim_id "
		"WHERE get_relid.get_relid = %e ",
		getRelid );

	if ( query.rows() == 0 )
		throw InvalidRelid();

	MYSQL_ROW row = query.fetchRow();

	id = parseId( row[0] );
	userId = parseId( row[1] );
	identityId = parseId( row[2] );
	state = atoi( row[3] );

	loadRelids();
}

FriendClaim::FriendClaim( MYSQL *mysql, ByFloginToken, const char *floginToken )
:
	mysql(mysql)
{
	DbQuery query( mysql,
		"SELECT friend_claim.id, flogin_token.user_id, "
		"	flogin_token.identity_id, friend_claim.state "
		"FROM flogin_token "
		"JOIN friend_claim ON "
		"	flogin_token.user_id = friend_claim.user_id AND "
		"	flogin_token.identity_id = friend_claim.identity_id "
		"WHERE flogin_token.login_token = %e ",
		floginToken );
		
	if ( query.rows() == 0 )
		throw InvalidFloginToken( floginToken );

	MYSQL_ROW row = query.fetchRow();

	id = parseId( row[0] );
	userId = parseId( row[1] );
	identityId = parseId( row[2] );
	state = atoi( row[3] );

	loadRelids();
}

void FriendClaim::loadRelids()
{
	DbQuery getQuery( mysql,
		"SELECT key_priv, get_relid "
		"FROM get_relid "
		"WHERE friend_claim_id = %L ",
		id );

	while ( MYSQL_ROW row = getQuery.fetchRow() ) {
		u_long *lengths = getQuery.fetchLengths();
		int keyPriv = atoi( row[0] );
		if ( keyPriv < 0 || keyPriv >= NUM_KEY_PRIVS )
			throw WrongNumberOfRelids();
		getRelids[keyPriv].set( row[1], lengths[1] );
	}

	DbQuery putQuery( mysql,
		"SELECT key_priv, put_relid "
		"FROM put_relid "
		"WHERE friend_claim_id = %L ",
		id );

	while ( MYSQL_ROW row = putQuery.fetchRow() ) {
		u_long *lengths = putQuery.fetchLengths();
		int keyPriv = atoi( row[0] );
		if ( keyPriv < 0 || keyPriv >= NUM_KEY_PRIVS )
			throw WrongNumberOfRelids();
		putRelids[keyPriv].set( row[1], lengths[1] );
	}
}

void Server::newUser( const String &iduri, const String &privateName, const String &pass )
{
	/* Make sure the site is present. */
	DbQuery( mysql,
			"INSERT IGNORE INTO site ( site ) "
			"VALUES ( %e ) ",
			c->site->name() );
	
	Site site( mysql, c->site->name );
	
	/* Force lowercase. */
	String iduriLower = iduri;
	iduriLower.toLower();

	/*
	 * The User
	 */

	/* First try to make the new user. */
	DbQuery insert( mysql,
			"INSERT IGNORE INTO user ( iduri, site_id ) "
			"VALUES ( %e, %L ) ",
			iduriLower(), site.id() );
	if ( insert.affectedRows() == 0 )
		throw UserExists( iduriLower );

	long long userId = lastInsertId( mysql );
	message( "user_id: %lld\n", userId );

	/*
	 * The user keys.
	 */
	keyAgent.generateKey( userId, pass );

	/*
	 * Identity
	 */
	String hash = makeIduriHash( iduri );
	DbQuery( mysql,
			"INSERT IGNORE INTO identity ( iduri, hash, public_keys ) "
			"VALUES ( %e, %e, false ) ",
			iduri.data, hash.data );

	DbQuery identityQuery( mysql,
			"SELECT id FROM identity WHERE iduri = %e",
			iduri.data );
	long long identityId = strtoll( identityQuery.fetchRow()[0], 0, 10 );

	/*
	 * Network
	 */
	unsigned char distNameBin[RELID_SIZE];
	RAND_bytes( distNameBin, RELID_SIZE );
	String distName = binToBase64( distNameBin, RELID_SIZE );

	/* Always, try to insert. Ignore failures. FIXME: need to loop on the
	 * random selection here. */
	DbQuery ( mysql, 
			"INSERT IGNORE INTO network "
			"( user_id, type, private_name, dist_name, key_gen ) "
			"VALUES ( %L, %l, %e, %e, 1 )",
			userId, NET_TYPE_PRIMARY, privateName(), distName() );

	long long networkId = lastInsertId( mysql );
	newBroadcastKey( networkId, 1 );

	DbQuery( mysql,
			"UPDATE user "
			"SET identity_id = %L, network_id = %L "
			"WHERE id = %L ",
			identityId, networkId, userId );
}
