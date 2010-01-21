/*
 * Copyright (c) 2008-2009, Adrian Thurston <thurston@complang.org>
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
#include "disttree.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <mysql.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>

void newUser( MYSQL *mysql, const char *user, const char *pass )
{
	/* First try to make the new user. */
	DbQuery insert( mysql, "INSERT IGNORE INTO user ( user) VALUES ( %e ) ", user );
	if ( insert.affectedRows() == 0 ) {
		BIO_printf( bioOut, "ERROR user exists\r\n" );
		return;
	}

	long long userId = lastInsertId( mysql );

	u_char passSalt[SALT_SIZE];
	RAND_bytes( passSalt, SALT_SIZE );
	String passSaltStr = binToBase64( passSalt, SALT_SIZE );

	u_char idSalt[SALT_SIZE];
	RAND_bytes( idSalt, SALT_SIZE );
	String idSaltStr = binToBase64( idSalt, SALT_SIZE );

	/* Generate a new key. */
	RSA *rsa = RSA_generate_key( 1024, RSA_F4, 0, 0 );
	if ( rsa == 0 ) {
		BIO_printf( bioOut, "ERROR key generation failed\r\n");
		return;
	}

	/* Extract the components to hex strings. */
	String n = bnToBase64( rsa->n );
	String e = bnToBase64( rsa->e );
	String d = bnToBase64( rsa->d );
	String p = bnToBase64( rsa->p );
	String q = bnToBase64( rsa->q );
	String dmp1 = bnToBase64( rsa->dmp1 );
	String dmq1 = bnToBase64( rsa->dmq1 );
	String iqmp = bnToBase64( rsa->iqmp );

	/* Hash the password. */
	String passHashed = passHash( passSalt, pass );

	DbQuery( mysql,
		"UPDATE user "
		"SET "
		"	pass_salt = %e, pass = %e, id_salt = %e, "
		"	rsa_n = %e, rsa_e = %e, rsa_d = %e, rsa_p = %e, "
		"	rsa_q = %e, rsa_dmp1 = %e, rsa_dmq1 = %e, rsa_iqmp = %e "
		"WHERE "
		"	id = %L ",
		passSaltStr.data, passHashed.data, idSaltStr.data,
		n.data, e.data, d.data, p.data, q.data, dmp1.data, dmq1.data, iqmp.data, userId );
	
	/* Add the - network for the new user. */
	long long networkNameId = findNetworkName( mysql, "-" );
	addNetwork( mysql, userId, networkNameId );

	RSA_free( rsa );

	BIO_printf( bioOut, "OK\r\n" );
}
