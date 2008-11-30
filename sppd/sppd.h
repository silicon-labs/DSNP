/*
 * Copyright (c) 2008, Adrian Thurston <thurston@cs.queensu.ca>
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

#ifndef _SPPD_H
#define _SPPD_H

struct PublicKey
{
	char *n;
	char *e;
};

int parse_loop();
int rcfile_parse( const char *data, long length );

void create_user( const char *key, const char *user, const char *pass, const char *email );
void public_key( const char *identity );
void friend_req( const char *user, const char *identity, const char *host );
long open_inet_connection( const char *hostname, unsigned short port );
long fetch_public_key( PublicKey &pub, const char *host, const char *user );

extern char *CFG_URI;
extern char *CFG_HOST;
extern char *CFG_PATH;
extern char *CFG_DB_HOST;
extern char *CFG_DB_DATABASE;
extern char *CFG_DB_USER;
extern char *CFG_ADMIN_PASS;
extern char *CFG_COMM_KEY;
extern char *CFG_PORT;

#endif
