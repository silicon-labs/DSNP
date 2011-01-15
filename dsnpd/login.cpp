#include "dsnp.h"
#include "error.h"

#include <string.h>
#include <openssl/rand.h>

void Server::login( const char *user, const char *pass )
{
	const long lasts = LOGIN_TOKEN_LASTS;

	DbQuery login( mysql, 
		"SELECT id, pass_salt, pass "
		"FROM user "
		"WHERE user = %e", 
		user );

	if ( login.rows() == 0 )
		throw InvalidLogin( user, pass, "bad user" );

	MYSQL_ROW row = login.fetchRow();
	long long userId = parseId( row[0] );
	char *salt_str = row[1];
	char *pass_str = row[2];

	/* Hash the password using the sale found in the DB. */
	u_char pass_salt[SALT_SIZE];
	base64ToBin( pass_salt, salt_str, strlen(salt_str) );
	String pass_hashed = passHash( pass_salt, pass );

	/* Check the login. */
	if ( strcmp( pass_hashed, pass_str ) != 0 )
		throw InvalidLogin( user, pass, "bad pass" );

	/* Login successful. Make a token. */
	u_char token[TOKEN_SIZE];
	RAND_bytes( token, TOKEN_SIZE );
	String tokenStr = binToBase64( token, TOKEN_SIZE );

	/* Record the token. */
	DbQuery loginToken( mysql, 
		"INSERT INTO login_token ( user_id, login_token, expires ) "
		"VALUES ( %L, %e, date_add( now(), interval %l second ) )", 
		userId, tokenStr.data, lasts );

	String identity( "%s%s/", c->CFG_URI, user );
	String idHashStr = makeIduriHash( identity );

	bioWrap->printf( "OK %s %s %ld\r\n", idHashStr.data, tokenStr.data, lasts );

	message("login of %s successful\n", user );
}


