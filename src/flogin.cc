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
#include "string.h"
#include "error.h"
#include "keyagent.h"

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

void Server::ftokenRequest( const String &_user, const String &hash )
{
	/* Load user, identity and friend claim. */
	User user( mysql, _user );
	Identity identity( mysql, Identity::ByHash(), hash );
	FriendClaim friendClaim( mysql, user, identity );

	/* Generate the login request id and relationship and request ids. */
	String floginTokenBin( TOKEN_SIZE );
	String reqidBin( REQID_SIZE );

	RAND_bytes( floginTokenBin.binary(), floginTokenBin.length );
	RAND_bytes( reqidBin.binary(), reqidBin.length );

	/* Encrypt it. */
	fetchPublicKey( identity );
	String encPacket = keyAgent.signEncrypt( identity, user, floginTokenBin );

	/* Store the request. */
	String floginToken = binToBase64( floginTokenBin.binary(), floginTokenBin.length );
	String reqid = binToBase64( reqidBin.binary(), reqidBin.length );

	DbQuery( mysql,
		"INSERT INTO ftoken_request "
		"( user_id, identity_id, token, reqid, message ) "
		"VALUES ( %L, %L, %e, %e, %d ) ",
		user.id(), identity.id(), floginToken(), reqid(),
		encPacket.binary(), encPacket.length );

	String userHash = makeIduriHash( user.iduri );

	/* Return the request id for the requester to use. */
	bioWrap.returnOkLocal( identity.iduri, userHash, reqid );
}

void Server::fetchFtoken( const String &reqid )
{
	DbQuery ftoken( mysql,
		"SELECT message FROM ftoken_request WHERE reqid = %e", reqid() );

	if ( ftoken.rows() == 0 )
		throw FtokenRequestInvalid();
	
	MYSQL_ROW row = ftoken.fetchRow();
	u_long *lengths = ftoken.fetchLengths();
	String msg = Pointer( row[0], lengths[0] );

	bioWrap.returnOkServer( msg );
}

void Server::ftokenResponse( const String &loginToken,
		const String &hash, const String &reqid )
{
	/*
	 * a) checks that $FR-URI is a friend
	 * b) if browser is not logged in fails the process (no redirect).
	 * c) fetches $FR-URI/tokens/$FR-RELID.asc
	 * d) decrypts and verifies the token
	 * e) redirects the browser to $FP-URI/submit-token?uri=$URI&token=$TOK
	 */

	/* Load user, identity and friend claim. */
	User user( mysql, User::ByLoginToken(), loginToken );
	Identity identity( mysql, Identity::ByHash(), hash );
	FriendClaim friendClaim( mysql, user, identity );

	/* Fetch the ftoken. */
	String host = Pointer( identity.host() );
	String encPacket = fetchFtokenNet( host, reqid );

	/* Decrypt the flogin token. */
	fetchPublicKey( identity );
	String decrypted = keyAgent.decryptVerify( identity, user, encPacket );

	/* Check the size. */
	if ( decrypted.length != REQID_SIZE )
		throw FloginTokenWrongSize();

	String floginToken = binToBase64( decrypted.binary(), RELID_SIZE );

	DbQuery( mysql,
		"INSERT INTO remote_flogin_token "
		"( user_id, identity_id, login_token ) "
		"VALUES ( %L, %L, %e )",
		user.id(), identity.id(), floginToken() );

	/* Return the login token for the requester to use. */
	bioWrap.returnOkLocal( identity.iduri, floginToken );
}

void Server::submitFtoken( const String &token, const String &sessionId )
{
	long lasts = LOGIN_TOKEN_LASTS;

	DbQuery request( mysql,
		"SELECT user_id, identity_id "
		"FROM ftoken_request "
		"WHERE token = %e",
		token() );

	if ( request.rows() == 0 )
		throw InvalidFloginToken( token );

	MYSQL_ROW row = request.fetchRow();
	long long userId = parseId( row[0] );
	long long identityId = parseId( row[1] );

	Identity identity( mysql, identityId );

	DbQuery( mysql, 
		"INSERT INTO flogin_token ( user_id, identity_id, login_token, session_id, expires ) "
		"VALUES ( %L, %L, %e, %e, date_add( now(), interval %l second ) )", 
		userId, identityId, token(), sessionId(), lasts );

	String hash = makeIduriHash( identity.iduri() );

	bioWrap.returnOkLocal( identity.iduri, hash, lasts );
}
