/*
 * Copyright (c) 2011, Adrian Thurston <thurston@complang.org>
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
#include "error.h"
#include "keyagent.h"
#include "packet.h"

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <pwd.h>
#include <pthread.h>
#include <time.h>

#include "dlist.h"
#include "error.h"
#include "encrypt.h"

#define LOG_FILE LOGDIR "/dsnpd.log"
#define READSZ 1024
#define CTRLSZ 1024

typedef void * (*ThreadStart)(void*);

#define MB (1024*1024)
#define KB (1024)
#define TIME_STR_SZ 64

typedef DList<KeyThread> ThreadList;

ThreadList threadList;

void privThatsOkay( int signum )
{
}

void privSignalHandlers()
{
	signal( SIGHUP,  privThatsOkay );
	signal( SIGINT,  privThatsOkay );
	signal( SIGQUIT, privThatsOkay );
	signal( SIGTERM, privThatsOkay );
	signal( SIGILL,  privThatsOkay );
	signal( SIGABRT, privThatsOkay );
	signal( SIGFPE,  privThatsOkay );
	signal( SIGSEGV, privThatsOkay );
	signal( SIGPIPE, privThatsOkay );
	signal( SIGALRM, privThatsOkay );
	signal( SIGCHLD, privThatsOkay );
}

void startKeyAgentService( Config *c, LoginTokenMap *map, KeyAgentActivity *activity, int fd )
{
	debug( DBG_PROC, "starting key agent thread\n" );

	/* Plus one on the number of threads. */
	activity->bump();
	KeyThread *thread = new KeyThread( c, map, activity, fd );
	threadList.append( thread );
	thread->create();
}

int keyAgentProcess( int fd )
{
	Config *c = new Config;
	ConfigParser configParser( DSNPD_CONF, SliceKeyAgent, c );

	/* Drop privs. */
	setgid( gbl.privGid );
	setuid( gbl.privUid );

	LoginTokenMap *loginTokenMap = new LoginTokenMap;
	KeyAgentActivity *keyAgentActivty = new KeyAgentActivity;

	/* FIXME: this needs improvement. */
	RAND_load_file("/dev/urandom", 1024);

	privSignalHandlers();

	while ( true ) {
		/* How big for control? */
		char control[READSZ+1];
		char data[1];

		iovec iov;
		iov.iov_base = data;
		iov.iov_len = 1;

		msghdr msg;
		memset( &msg, 0, sizeof(msg) );
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = control;
		msg.msg_controllen = READSZ;

		int n = recvmsg( fd, &msg, 0 );
		if ( n < 0 )
			break;

		if ( iov.iov_len == 1 ) {
			switch ( data[0] ) {
				case AC_SOCKET: {
					debug( DBG_PRIV, "priv: received socket\n" );
					int serviceFd = extractFd( fd, &msg );
					if ( serviceFd < 0 )
						fatal("priv: received invalid socket\n");
					startKeyAgentService( c, loginTokenMap, keyAgentActivty, serviceFd );
					break;
				}
				case AC_LOG_FD: {
					debug( DBG_PRIV, "priv: received open logfile\n" );
					int logFd = extractFd( fd, &msg );
					if ( logFd < 0 )
						fatal( "priv: received invalid logfile fd\n" );
					setLogFd( logFd );
					debug( DBG_PRIV, "priv: logging to newly received logfile\n", logFd );
					break;
				}
				case AC_QUIT:
					debug( DBG_PRIV, "priv: stopping\n" );
					keyAgentActivty->waitDone();
					return 0;
			}
		}
	}


	return 0;
}


int KeyThread::_startRoutine( KeyThread *thread )
{
	return thread->startRoutine();
}

void KeyThread::create()
{
	pthread_attr_init( &attr );
	pthread_attr_setstacksize( &attr, 256 * KB );
	int result = pthread_create( &thread, &attr, (ThreadStart) _startRoutine, this );
	if ( result != 0 )
		fatal( "priv: error creating thread\n" );

	/* Once the thread is done, storage goes away. Start it up and forget about
	 * it .. */
	pthread_detach( thread );
}

void KeyThread::dbConnect()
{
	/* Connect to the database. */
	mysql = ConfigCtx::dbConnect( c->main->CFG_KEYS_HOST, c->main->CFG_KEYS_DATABASE, 
			c->main->CFG_KEYS_USER, c->main->CFG_KEYS_PASS );
	if ( mysql == 0 )
		throw DatabaseConnectionFailed();
}


#define KA_STORE_PUBLIC_KEY                   20
#define KA_GENERATE_KEY                       21
#define KA_SIGN_ENCRYPT                       22
#define KA_DECRYPT_VERIFY                     23
#define KA_BK_SIGN_ENCRYPT                    24
#define KA_BK_DECRYPT_VERIFY                  25
#define KA_BK_FOREIGN_SIGN                    26
#define KA_BK_FOREIGN_VERIFY                  27
#define KA_GET_PUBLIC_KEY                     28
#define KA_STORE_PUT_BROADCAST_KEY            29
#define KA_STORE_GET_BROADCAST_KEY            30
#define KA_GET_PUT_BROADCAST_KEY              31
#define KA_CHECK_PASS                         32
#define KA_BK_ENCRYPT                         33
#define KA_BK_DECRYPT                         34
#define KA_BK_SIGN                            35
#define KA_BK_VERIFY                          36
#define KA_BK_DETACHED_SIGN                   37
#define KA_BK_DETACHED_VERIFY                 38
#define KA_BK_DETACHED_FOREIGN_SIGN           39
#define KA_BK_DETACHED_FOREIGN_VERIFY         40
#define KA_GENERATE_FRIEND_CLAIM_KEYS         41
#define KA_STORE_FRIEND_CLAIM_PUB_KEY         42
#define KA_GET_FRIEND_CLAIM_RB_SIG_KEY        43
#define KA_BK_DETACHED_REPUB_FOREIGN_SIGN     44
#define KA_BK_DETACHED_REPUB_FOREIGN_VERIFY   45
#define KA_SIGN_ID_ENCRYPT                    46
#define KA_DECRYPT_VERIFY1                    47
#define KA_DECRYPT_VERIFY2                    48
#define KA_STORE_RB_KEY                       49

int KeyThread::startRoutine()
{
	try {
		return startRoutineBare();
	}
	catch ( UserError &e ) {
		/* We have no more output. */
		BioWrap bioWrap( BioWrap::Null );
		e.print( bioWrap );
		return 0;
	}
}

int KeyThread::startRoutineBare()
{
	dbConnect();

	while ( true ) {
		char cmd = readCommand();

		switch ( cmd ) {
			case BA_QUIT:
				debug( DBG_PRIV, "priv: exiting\n" );
				writeChar( 0 );
				goto done;
			case KA_STORE_PUBLIC_KEY:
				debug( DBG_PRIV, "priv: store public key\n" );
				recvStorePublicKey();
				break;
			case KA_GENERATE_KEY:
				debug( DBG_PRIV, "priv: generate key\n" );
				recvGenerateKey();
				break;
			case KA_SIGN_ENCRYPT:
				debug( DBG_PRIV, "priv: sign-encrypt\n" );
				recvSignEncrypt();
				break;
			case KA_SIGN_ID_ENCRYPT:
				debug( DBG_PRIV, "priv: sign-id-encrypt\n" );
				recvSignIdEncrypt();
				break;
			case KA_DECRYPT_VERIFY:
				debug( DBG_PRIV, "priv: decrypt-verify\n" );
				recvDecryptVerify();
				break;
			case KA_DECRYPT_VERIFY1:
				debug( DBG_PRIV, "priv: decrypt-verify-1\n" );
				recvDecryptVerify1();
				break;
			case KA_DECRYPT_VERIFY2:
				debug( DBG_PRIV, "priv: decrypt-verify-2\n" );
				recvDecryptVerify2();
				break;
			case KA_BK_SIGN_ENCRYPT:
				debug( DBG_PRIV, "priv: bk-sign-encrypt\n" );
				recvBkSignEncrypt();
				break;
			case KA_BK_DECRYPT_VERIFY:
				debug( DBG_PRIV, "priv: bk-decrypt-verify\n" );
				recvBkDecryptVerify();
				break;
			case KA_BK_ENCRYPT:
				debug( DBG_PRIV, "priv: bk-encrypt\n" );
				recvBkEncrypt();
				break;
			case KA_BK_DECRYPT:
				debug( DBG_PRIV, "priv: bk-decrypt\n" );
				recvBkDecrypt();
				break;
			case KA_BK_SIGN:
				debug( DBG_PRIV, "priv: bk-sign\n" );
				recvBkSign();
				break;
			case KA_BK_VERIFY:
				debug( DBG_PRIV, "priv: bk-verify\n" );
				recvBkVerify();
				break;
			case KA_BK_FOREIGN_SIGN:
				debug( DBG_PRIV, "priv: bk-foreign-sign\n" );
				recvBkForeignSign();
				break;
			case KA_BK_FOREIGN_VERIFY:
				debug( DBG_PRIV, "priv: bk-foreign-verify\n" );
				recvBkForeignVerify();
				break;
			case KA_BK_DETACHED_SIGN:
				debug( DBG_PRIV, "priv: bk-detached-sign\n" );
				recvBkDetachedSign();
				break;
			case KA_BK_DETACHED_VERIFY:
				debug( DBG_PRIV, "priv: bk-detached-verify\n" );
				recvBkDetachedVerify();
				break;
			case KA_BK_DETACHED_FOREIGN_SIGN:
				debug( DBG_PRIV, "priv: bk-detached-foreign-sign\n" );
				recvBkDetachedForeignSign();
				break;
			case KA_BK_DETACHED_FOREIGN_VERIFY:
				debug( DBG_PRIV, "priv: bk-detached-foreign-verify\n" );
				recvBkDetachedForeignVerify();
				break;
			case KA_GET_PUBLIC_KEY:
				debug( DBG_PRIV, "priv: public-key\n" );
				recvGetPublicKey();
				break;
			case KA_STORE_PUT_BROADCAST_KEY:
				debug( DBG_PRIV, "priv: store-put-broadcast-key\n" );
				recvStorePutBroadcastKey();
				break;
			case KA_STORE_GET_BROADCAST_KEY:
				debug( DBG_PRIV, "priv: store-get-broadcast-key\n" );
				recvStoreGetBroadcastKey();
				break;
			case KA_STORE_RB_KEY:
				debug( DBG_PRIV, "priv: store-rb-key\n" );
				recvStoreRbKey();
				break;
			case KA_GET_PUT_BROADCAST_KEY:
				debug( DBG_PRIV, "priv: get-put-broadcast-key\n" );
				recvGetPutBroadcastKey();
				break;
			case KA_CHECK_PASS:
				debug( DBG_PRIV, "priv: check-pass\n" );
				recvCheckPass();
				break;
			case KA_GENERATE_FRIEND_CLAIM_KEYS:
				debug( DBG_PRIV, "priv: generate-friend-claim-keys\n" );
				recvGenerateFriendClaimKeys();
				break;
			case KA_STORE_FRIEND_CLAIM_PUB_KEY:
				debug( DBG_PRIV, "priv: strore-get-broadcast-key\n" );
				recvStoreFriendClaimSigKey();
				break;
			case KA_GET_FRIEND_CLAIM_RB_SIG_KEY:
				debug( DBG_PRIV, "priv: strore-get-broadcast-key\n" );
				recvGetFriendClaimRbSigKey();
				break;
			case KA_BK_DETACHED_REPUB_FOREIGN_SIGN:
				debug( DBG_PRIV, "priv: bk-detached-repub-foreign-sign\n" );
				recvBkDetachedRepubForeignSign();
				break;
			case KA_BK_DETACHED_REPUB_FOREIGN_VERIFY:
				debug( DBG_PRIV, "priv: bk-detached-repub-foreign-verify\n" );
				recvBkDetachedRepubForeignVerify();
				break;
			default:
				fatal( "priv: invalid command: %d\n", (int)cmd );
				break;
		}
	}

done:
	mysql_close( mysql );
	keyAgentActivity->signalDone();

	/* Close the command fd. */
	int result = close( fd );
	if ( result < 0 ) {
		error( "priv: command fd %d close failed: %s\n",
				fd, strerror(errno) );
	}

	return 0;
}

void KeyAgent::storePublicKey( Identity &identity,
		const String &encPacket )
{
	command( KA_STORE_PUBLIC_KEY );
	writeLongLong( identity.id() );
	writeData( encPacket );

	readChar();
}

Keys *makeKeys( const String &n, const String e )
{
	RSA *rsa = RSA_new();
	rsa->n = binToBn( n );
	rsa->e = binToBn( e );
	Keys *keys = new Keys;
	keys->rsa = rsa;
	return keys;
}

void KeyThread::storePublicKey( long long identityId, int keyPriv, const String &key )
{
	PacketPublicKey epp( key );

	DbQuery( mysql,
		"INSERT INTO public_key ( identity_id, key_priv, key_data ) "
		"VALUES ( %L, %l, %d )",
		identityId, keyPriv, key.binary(), key.length );
}

void KeyThread::recvStorePublicKey()
{
	String encPacket;
	long long identityId = readLongLong();
	readData( encPacket );

	/* Before we can verify we need to pull out the PRIV0 key, */
	PacketSigned epp1( encPacket );

	PacketPublicKeySet epp2( epp1.msg );

	PacketPublicKey epp3( epp2.priv0 );

	Keys *priv0Keys = makeKeys( epp3.n, epp3.e );

	/* Go back to the packet and verify it after extracting the priv0 public
	 * key. */
	verify( priv0Keys, encPacket );

	DbQuery( mysql,
		"DELETE FROM public_key WHERE identity_id = %L",
		identityId );

	storePublicKey( identityId, KEY_PRIV0, epp2.priv0 );
	storePublicKey( identityId, KEY_PRIV1, epp2.priv1 );
	storePublicKey( identityId, KEY_PRIV2, epp2.priv2 );
	storePublicKey( identityId, KEY_PRIV3, epp2.priv3 );

	/* Nothing to return, but we should sync anyways. */
	writeChar( 0 );
}

void KeyAgent::generateKey( long long userId, const String &pass )
{
	command( KA_GENERATE_KEY );
	writeLongLong( userId );
	writeData( pass );

	readChar();
}

Keys *KeyThread::generateKey( long long userId, PrivateKey &key, int keyPriv,
		bool encrypt, const String &pass )
{
	/* Generate a new key. Do this first so we don't have to remove the user if
	 * it fails. */
	RSA *rsa = RSA_generate_key( 1024, RSA_F4, 0, 0 );
	if ( rsa == 0 )
		throw RsaKeyGenError( ERR_get_error() );

	/* Extract the components to hex strings. */
	key.n = bnToBin( rsa->n );
	key.e = bnToBin( rsa->e );
	key.d = bnToBin( rsa->d );
	key.p = bnToBin( rsa->p );
	key.q = bnToBin( rsa->q );
	key.dmp1 = bnToBin( rsa->dmp1 );
	key.dmq1 = bnToBin( rsa->dmq1 );
	key.iqmp = bnToBin( rsa->iqmp );
	Keys *keys = new Keys;
	keys->rsa = rsa;

	String priv = consPrivateKey( key );
	String prot;
	if ( encrypt )
		prot = pwEncrypt( pass, priv );
	else 
		prot = Pointer( priv(), priv.length );

	DbQuery( mysql,
			"INSERT INTO private_key "
			"	( user_id, key_priv, encrypted, key_data ) "
			"VALUES ( %L, %l, %b, %d ); ",
			userId, keyPriv, encrypt, prot.binary(), prot.length );
	
	return keys;
}

void KeyThread::recvGenerateKey()
{
	long long userId = readLongLong();
	String pass;
	readData( pass );

	/*
	 * Generate password salt and store the password.
	 */

	/* First set the password. */
	u_char passSalt[SALT_SIZE];
	RAND_bytes( passSalt, SALT_SIZE );
	String passSaltStr = binToBase64( passSalt, SALT_SIZE );

	/* Hash the password. */
	String passHashed = passHash( passSalt, pass );

	DbQuery insert( mysql,
			"INSERT IGNORE INTO password ( user_id, pass_salt, pass ) "
			"VALUES ( %L, %e, %e ) ",
			userId, passSaltStr.data, passHashed.data );
	
	/*
	 * The Keys
	 */

	DbQuery( mysql, "DELETE FROM private_key WHERE user_id = %L", userId );
	DbQuery( mysql, "DELETE FROM public_key_set WHERE user_id = %L", userId );

	PrivateKey priv0, priv1, priv2, priv3;

	Keys *priv0Keys = generateKey( userId, priv0, KEY_PRIV0, true, pass );
	Keys *priv1Keys = generateKey( userId, priv1, KEY_PRIV1, true, pass );
	Keys *priv2Keys = generateKey( userId, priv2, KEY_PRIV2, true, pass );
	Keys *priv3Keys = generateKey( userId, priv3, KEY_PRIV3, false, pass );

	String priv0Str = consPublicKey( priv0 );
	String priv1Str = consPublicKey( priv1 );
	String priv2Str = consPublicKey( priv2 );
	String priv3Str = consPublicKey( priv3 );

	String publicKeySet = consPublicKeySet( 
			priv0Str, priv1Str, priv2Str, priv3Str );

	String signedPublicKeySet = sign( priv0Keys, publicKeySet );

	DbQuery( mysql,
			"INSERT INTO public_key_set "
			"	( user_id, key_data ) "
			"VALUES ( %L, %d ); ",
			userId, signedPublicKeySet.binary(),
			signedPublicKeySet.length );
	
	delete priv0Keys;
	delete priv1Keys;
	delete priv2Keys;
	delete priv3Keys;

	/* Nothing to return, but we need to sync. */
	writeChar( 0 );
}

Keys *parsePubKey( const String &pubKey )
{
	PacketPublicKey epp( pubKey );

	RSA *rsa = RSA_new();
	rsa->n = binToBn( epp.n );
	rsa->e = binToBn( epp.e );

	Keys *keys = new Keys;
	keys->rsa = rsa;

	return keys;
}

Keys *KeyThread::loadKeyPub( long long identityId )
{
	DbQuery keysQuery( mysql, 
		"SELECT key_data "
		"FROM public_key "
		"WHERE identity_id = %L AND key_priv = %l",
		identityId, KEY_PRIV3 );

	Keys *keys = 0;

	/* Check for a result. */
	if ( keysQuery.rows() > 0 ) {
		MYSQL_ROW row = keysQuery.fetchRow();
		u_long *lengths = keysQuery.fetchLengths();

		String pk = Pointer( row[0], lengths[0] );

		keys = parsePubKey( pk );
	}
	else {
		throw MissingKeys();
	}

	return keys;
}

Keys *parsePrivKey( const String &priv )
{
	PacketPrivateKey epp( priv );

	RSA *rsa = RSA_new();
	rsa->n =    binToBn( epp.key.n );
	rsa->e =    binToBn( epp.key.e );
	rsa->d =    binToBn( epp.key.d );
	rsa->p =    binToBn( epp.key.p );
	rsa->q =    binToBn( epp.key.q );
	rsa->dmp1 = binToBn( epp.key.dmp1 );
	rsa->dmq1 = binToBn( epp.key.dmq1 );
	rsa->iqmp = binToBn( epp.key.iqmp );

	Keys *keys = new Keys;
	keys->rsa = rsa;
	return keys;
}

Keys *KeyThread::loadKeyPriv( long long userId, int keyPriv, const String *pass )
{
	DbQuery keyQuery( mysql,
		"SELECT encrypted, key_data "
		"FROM private_key "
		"WHERE user_id = %L AND key_priv = %l ",
		userId, keyPriv );

	if ( keyQuery.rows() < 1 )
		throw MissingKeys();

	MYSQL_ROW row = keyQuery.fetchRow();
	u_long *lengths = keyQuery.fetchLengths();

	bool encrypted = parseBoolean( row[0] );
	String priv = Pointer( row[1], lengths[1] );

	if ( encrypted ) {
		String plain = pwDecrypt( *pass, priv );
		priv = plain;
	}

	Keys *keys = parsePrivKey( priv );
	return keys;
}

Keys *KeyThread::loadKeyPriv( long long userId )
{
	return loadKeyPriv( userId, KEY_PRIV3, 0 );
}

Allocated KeyAgent::signEncrypt( Identity &pubEncVer, User &privDecSign, const String &msg )
{
	command( KA_SIGN_ENCRYPT );
	writeLongLong( pubEncVer.id() );
	writeLongLong( privDecSign.id() );
	writeData( msg );

	String result;
	readData( result );

	return result.relinquish();
}

void KeyThread::recvSignEncrypt()
{
	long long pubEncVerId = readLongLong();
	long long privDecSignId = readLongLong();

	String msg;
	readData( msg );

	Keys *pubEncVer = loadKeyPub( pubEncVerId );
	Keys *privDecSign = loadKeyPriv( privDecSignId );

	String encPacket = signEncrypt( pubEncVer, privDecSign, 0, msg );
	writeData( encPacket );
}

Allocated KeyAgent::signIdEncrypt( Identity &pubEncVer, User &privDecSign,
		const String &iduri, long long bkId, const String &distName, 
		long long generation )
{
	command( KA_SIGN_ID_ENCRYPT );
	writeLongLong( pubEncVer.id() );
	writeLongLong( privDecSign.id() );
	writeData( iduri );
	writeLongLong( bkId );
	writeData( distName );
	writeLongLong( generation );

	String result;
	readData( result );

	return result.relinquish();
}

void KeyThread::recvSignIdEncrypt()
{
	long long pubEncVerId = readLongLong();
	long long privDecSignId = readLongLong();

	String iduri;
	String msg;
	String distName;

	readData( iduri );
	long long bkId = readLongLong();
	readData( distName );
	long long generation = readLongLong();

	Keys *pubEncVer = loadKeyPub( pubEncVerId );
	Keys *privDecSign = loadKeyPriv( privDecSignId );

	DbQuery findBk( mysql,
		"SELECT member_proof FROM get_broadcast_key "
		"WHERE id = %L ", bkId );

	if ( findBk.rows() != 1 )
		fatal("bk-decrypt-verify: invalid broadcast_key id %lld\n", bkId );

	MYSQL_ROW row = findBk.fetchRow();
	u_long *lengths = findBk.fetchLengths();
	String memberProof = Pointer( row[0], lengths[0] );

	String rbBroadcastKey = consFetchRbBroadcastKey( distName, generation, memberProof );

	String encPacket = signEncrypt( pubEncVer, privDecSign, &iduri, rbBroadcastKey );
	writeData( encPacket );
}

Allocated KeyAgent::decryptVerify( Identity &pubEncVer, User &privDecSign, const String &msg )
{
	command( KA_DECRYPT_VERIFY );
	writeLongLong( pubEncVer.id() );
	writeLongLong( privDecSign.id() );
	writeData( msg );

	String result;
	readData( result );

	return result.relinquish();
}

void KeyThread::recvDecryptVerify()
{
	long long pubEncVerId = readLongLong();
	long long privDecSignId = readLongLong();

	String msg;
	readData( msg );

	Keys *pubEncVer = loadKeyPub( pubEncVerId );
	Keys *privDecSign = loadKeyPriv( privDecSignId );

	String decrypted = decryptVerify( pubEncVer, privDecSign, msg );
	writeData( decrypted );
}

Allocated KeyAgent::decryptVerify1( User &privDecSign, const String &msg )
{
	command( KA_DECRYPT_VERIFY1 );
	writeLongLong( privDecSign.id() );
	writeData( msg );

	String result;
	readData( result );

	return result.relinquish();
}

void KeyThread::recvDecryptVerify1()
{
	long long privDecSignId = readLongLong();

	String msg;
	readData( msg );

	Keys *privDecSign = loadKeyPriv( privDecSignId );

	String decrypted = decryptVerify1( privDecSign, msg );
	writeData( decrypted );
}

Allocated KeyAgent::decryptVerify2( Identity &pubEncVer, User &privDecSign, const String &msg )
{
	command( KA_DECRYPT_VERIFY2 );
	writeLongLong( pubEncVer.id() );
	writeLongLong( privDecSign.id() );
	writeData( msg );

	String result;
	readData( result );

	return result.relinquish();
}

void KeyThread::recvDecryptVerify2()
{
	long long pubEncVerId = readLongLong();
	long long privDecSignId = readLongLong();

	String msg;
	readData( msg );

	Keys *pubEncVer = loadKeyPub( pubEncVerId );
	Keys *privDecSign = loadKeyPriv( privDecSignId );

	String decrypted = decryptVerify2( pubEncVer, privDecSign, msg );
	writeData( decrypted );
}

Allocated KeyAgent::bkSign( User &privDecSign, long long bkId, const String &msg )
{
	command( KA_BK_SIGN );
	writeLongLong( privDecSign.id() );
	writeLongLong( bkId );
	writeData( msg );

	String result;
	readData( result );

	return result.relinquish();
}

void KeyThread::recvBkSign()
{
	long long privDecSignId = readLongLong();
	long long bkId = readLongLong();
	String msg;
	readData( msg );

	DbQuery findBk( mysql,
		"SELECT broadcast_key "
		"FROM put_broadcast_key "
		"WHERE id = %L ",
		bkId );

	if ( findBk.rows() != 1 )
		fatal("bk-sign-encrypt: invalid broadcast_key id %lld\n", bkId );

	MYSQL_ROW row = findBk.fetchRow();
	String bk = Pointer( row[0] );

	Keys *privDecSign = loadKeyPriv( privDecSignId );

	String encPacket = bkSign( privDecSign, bk, msg ); 
	writeData( encPacket );
}

Allocated KeyAgent::bkVerify( Identity &pubEncVer, long long bkId, const String &msg )
{
	command( KA_BK_VERIFY );
	writeLongLong( pubEncVer.id() );
	writeLongLong( bkId );
	writeData( msg );

	String result;
	readData( result );

	return result.relinquish();
}

void KeyThread::recvBkVerify()
{
	long long pubEncVerId = readLongLong();
	long long bkId = readLongLong();
	String msg;
	readData( msg );

	DbQuery findBk( mysql,
		"SELECT broadcast_key FROM get_broadcast_key "
		"WHERE id = %L ",
		bkId );

	if ( findBk.rows() != 1 )
		fatal("bk-decrypt-verify: invalid broadcast_key id %lld\n", bkId );

	MYSQL_ROW row = findBk.fetchRow();
	String bk = Pointer( row[0] );

	Keys *pubEncVer = loadKeyPub( pubEncVerId );
	String decrypted = bkVerify( pubEncVer, bk, msg );
	writeData( decrypted );
}


Allocated KeyAgent::bkSignEncrypt( User &privDecSign, long long bkId, const String &msg )
{
	command( KA_BK_SIGN_ENCRYPT );
	writeLongLong( privDecSign.id() );
	writeLongLong( bkId );
	writeData( msg );

	String result;
	readData( result );

	return result.relinquish();
}

void KeyThread::recvBkSignEncrypt()
{
	long long privDecSignId = readLongLong();
	long long bkId = readLongLong();
	String msg;
	readData( msg );

	DbQuery findBk( mysql,
		"SELECT broadcast_key "
		"FROM put_broadcast_key "
		"WHERE id = %L ",
		bkId );

	if ( findBk.rows() != 1 )
		fatal("bk-sign-encrypt: invalid broadcast_key id %lld\n", bkId );

	MYSQL_ROW row = findBk.fetchRow();
	String bk = Pointer( row[0] );

	Keys *privDecSign = loadKeyPriv( privDecSignId );

	String encPacket = bkSignEncrypt( privDecSign, bk, msg ); 
	writeData( encPacket );
}

Allocated KeyAgent::bkDecryptVerify( Identity &pubEncVer, long long bkId, const String &msg )
{
	command( KA_BK_DECRYPT_VERIFY );
	writeLongLong( pubEncVer.id() );
	writeLongLong( bkId );
	writeData( msg );

	String result;
	readData( result );

	return result.relinquish();
}

void KeyThread::recvBkDecryptVerify()
{
	long long pubEncVerId = readLongLong();
	long long bkId = readLongLong();
	String msg;
	readData( msg );

	DbQuery findBk( mysql,
		"SELECT broadcast_key FROM get_broadcast_key "
		"WHERE id = %L ",
		bkId );

	if ( findBk.rows() != 1 )
		fatal("bk-decrypt-verify: invalid broadcast_key id %lld\n", bkId );

	MYSQL_ROW row = findBk.fetchRow();
	String bk = Pointer( row[0] );

	Keys *pubEncVer = loadKeyPub( pubEncVerId );
	String decrypted = bkDecryptVerify( pubEncVer, bk, msg );
	writeData( decrypted );
}

Allocated KeyAgent::bkEncrypt( long long bkId, const String &msg )
{
	command( KA_BK_ENCRYPT );
	writeLongLong( bkId );
	writeData( msg );

	String result;
	readData( result );

	return result.relinquish();
}

void KeyThread::recvBkEncrypt()
{
	long long bkId = readLongLong();
	String msg;
	readData( msg );

	DbQuery findBk( mysql,
		"SELECT broadcast_key "
		"FROM put_broadcast_key "
		"WHERE id = %L ",
		bkId );

	if ( findBk.rows() != 1 )
		fatal("bk-sign-encrypt: invalid broadcast_key id %lld\n", bkId );

	MYSQL_ROW row = findBk.fetchRow();
	String bk = Pointer( row[0] );

	String encPacket = bkEncrypt( bk, msg ); 
	writeData( encPacket );
}

Allocated KeyAgent::bkDecrypt( long long bkId, const String &msg )
{
	command( KA_BK_DECRYPT );
	writeLongLong( bkId );
	writeData( msg );

	String result;
	readData( result );

	return result.relinquish();
}

void KeyThread::recvBkDecrypt()
{
	long long bkId = readLongLong();
	String msg;
	readData( msg );

	DbQuery findBk( mysql,
		"SELECT broadcast_key FROM get_broadcast_key "
		"WHERE id = %L ",
		bkId );

	if ( findBk.rows() != 1 )
		fatal("bk-decrypt-verify: invalid broadcast_key id %lld\n", bkId );

	MYSQL_ROW row = findBk.fetchRow();
	String bk = Pointer( row[0] );

	String decrypted = bkDecrypt( bk, msg );
	writeData( decrypted );
}

/* Just sign a messaging using some get broadcast key (foreign) that belongs to
 * somone else. This is for the inner signature in remote broadcasts. */
Allocated KeyAgent::bkForeignSign( User &privDecSign, long long bkId, const String &msg )
{
	command( KA_BK_FOREIGN_SIGN );
	writeLongLong( privDecSign.id() );
	writeLongLong( bkId );
	writeData( msg );

	String result;
	readData( result );

	return result.relinquish();
}

void KeyThread::recvBkForeignSign()
{
	long long privDecSignId = readLongLong();
	long long bkId = readLongLong();
	String msg;
	readData( msg );

	DbQuery findBk( mysql,
		"SELECT broadcast_key FROM get_broadcast_key "
		"WHERE id = %L ",
		bkId );

	if ( findBk.rows() != 1 )
		fatal("bk-foreign-sign: invalid broadcast_key id %lld\n", bkId );

	MYSQL_ROW row = findBk.fetchRow();
	String bk = Pointer( row[0] );

	Keys *privDecSign = loadKeyPriv( privDecSignId );

	String encPacket = bkSign( privDecSign, bk, msg ); 
	writeData( encPacket );
}

Allocated KeyAgent::bkForeignVerify( Identity &pubEncVer, long long bkId, const String &msg )
{
	command( KA_BK_FOREIGN_VERIFY );
	writeLongLong( pubEncVer.id() );
	writeLongLong( bkId );
	writeData( msg );

	String result;
	readData( result );

	return result.relinquish();
}

void KeyThread::recvBkForeignVerify()
{
	long long pubEncVerId = readLongLong();
	long long bkId = readLongLong();
	String msg;
	readData( msg );

	DbQuery findBk( mysql,
		"SELECT broadcast_key FROM get_broadcast_key "
		"WHERE id = %L ",
		bkId );

	if ( findBk.rows() != 1 )
		fatal("bk-foreign-verify: invalid broadcast_key id %lld\n", bkId );

	MYSQL_ROW row = findBk.fetchRow();
	String bk = Pointer( row[0] );

	Keys *pubEncVer = loadKeyPub( pubEncVerId );
	String decrypted = bkVerify( pubEncVer, bk, msg );
	writeData( decrypted );
}

void KeyAgent::publicKey( User &user )
{
	command( KA_GET_PUBLIC_KEY );
	writeLongLong( user.id() );
	
	readData( pubSet );
}

void KeyThread::recvGetPublicKey()
{
	long long userId = readLongLong();

	DbQuery query( mysql,
		"SELECT key_data "
		"FROM public_key_set "
		"WHERE user_id = %L ",
		userId );

	if ( query.rows() == 0 )
		throw InvalidUser( "user" );

	/* Everythings okay. */
	MYSQL_ROW row = query.fetchRow();
	u_long *lengths = query.fetchLengths();

	String packet = Pointer( row[0], lengths[0] );

	writeData( packet );
}

void KeyAgent::storePutBroadcastKey( long long id, const char *_broadcastKey )
{
	String broadcastKey = Pointer( _broadcastKey );

	/* FIXME: should be generated in the key agent. */
	command( KA_STORE_PUT_BROADCAST_KEY );
	writeLongLong( id );
	writeData( broadcastKey );

	readChar();
}

void KeyThread::recvStorePutBroadcastKey()
{
	long long id = readLongLong();
	String broadcastKey;
	readData( broadcastKey );

	/* Generate a new key. Do this first so we don't have to remove the user if
	 * it fails. */
	RSA *rsa = RSA_generate_key( 1024, RSA_F4, 0, 0 );
	if ( rsa == 0 )
		throw RsaKeyGenError( ERR_get_error() );

	/* FIXME: Hack here! Extract the components to hex strings. */
	PrivateKey key;
	key.n = bnToBin( rsa->n );
	key.e = bnToBin( rsa->e );
	key.d = bnToBin( rsa->d );
	key.p = bnToBin( rsa->p );
	key.q = bnToBin( rsa->q );
	key.dmp1 = bnToBin( rsa->dmp1 );
	key.dmq1 = bnToBin( rsa->dmq1 );
	key.iqmp = bnToBin( rsa->iqmp );

	String priv = consPrivateKey( key );
	String pub = consPublicKey( key );

	DbQuery( mysql,
		"INSERT IGNORE INTO put_broadcast_key "
		"( id, broadcast_key, priv_key, pub_key ) "
		"VALUES ( %L, %e, %d, %d ) ",
		id, broadcastKey(), 
		priv.binary(), priv.length,
		pub.binary(), pub.length );

	/* Nothing to return, but we need to sync. */
	writeChar( 0 );
}

void KeyAgent::storeGetBroadcastKey( long long id, const String &bkKeys )
{
	command( KA_STORE_GET_BROADCAST_KEY );
	writeLongLong( id );
	writeData( bkKeys );

	readChar();
}

void KeyThread::recvStoreGetBroadcastKey()
{
	long long id = readLongLong();
	String bkKeys;
	readData( bkKeys );

	PacketBkKeys epp( bkKeys );
	PacketPublicKey epp2( epp.pubKey );

	DbQuery( mysql,
		"INSERT IGNORE INTO get_broadcast_key "
		"( id, broadcast_key, pub_key, member_proof ) "
		"VALUES ( %L, %e, %d, %d ) ",
		id, epp.bk(), 
		epp.pubKey.binary(), epp.pubKey.length,
		epp.memberProof.binary(), epp.memberProof.length 
		);

	/* Nothing to return, but we need to sync. */
	writeChar( 0 );
}

void KeyAgent::storeRbKey( long long bkId, long long identityId, const String &hash, const String &keyData )
{
	command( KA_STORE_RB_KEY );
	writeLongLong( bkId );
	writeLongLong( identityId );
	writeData( hash );
	writeData( keyData );

	readChar();
}

void KeyThread::recvStoreRbKey()
{
	String hash, keyData;

	long long bkId = readLongLong();
	long long identityId = readLongLong();
	readData( hash );
	readData( keyData );

	DbQuery( mysql,
		"INSERT IGNORE INTO rb_key "
		"( get_broadcast_key_id, identity_id, hash, key_data ) "
		"VALUES ( %L, %L, %d, %d )",
		bkId, identityId, hash.binary(), hash.length,
		keyData.binary(), keyData.length
	);

	/* Nothing to return, but we need to sync. */
	writeChar( 0 );
}

void KeyAgent::getPutBroadcastKey( long long userId, const String &forIduri, long long id )
{
	command( KA_GET_PUT_BROADCAST_KEY );	

	writeLongLong( userId );
	writeData( forIduri );
	writeLongLong( id );

	readData( bk );
}

void KeyThread::recvGetPutBroadcastKey()
{
	String forIduri;

	long long userId = readLongLong();
	readData( forIduri );
	long long id = readLongLong();

	DbQuery keyQuery( mysql, 
		"SELECT broadcast_key, pub_key "
		"FROM put_broadcast_key "
		"WHERE id = %L",
		id );

	/* Check for a result. */
	MYSQL_ROW row = keyQuery.fetchRow();
	u_long *lengths = keyQuery.fetchLengths();

	String bk = Pointer( row[0] );
	String pubKey = Pointer( row[1], lengths[1] );

	/* Make the member proof that the friend can use to proove they have this
	 * key. */
	Keys *privDecSign = loadKeyPriv( userId, KEY_PRIV3, 0 );
	String memberProof = bkDetachedSign( privDecSign, bk, forIduri );

	String packet = consBkKeys( bk, pubKey, memberProof );
	writeData( packet );
}

int KeyAgent::checkPass( long long userId, const String &pass, const String &token )
{
	command( KA_CHECK_PASS );
	writeLongLong( userId );
	writeData( pass );
	writeData( token );
	return readInt();
}

/* This is under OpenKey::mutex. */
void OpenKey::mutexOpen( KeyThread *keyThread, long long userId, const String &pass )
{
	/* Don't touch priv0. */

	/*
	 * Load priv1, produce the login sig, then delete it.
	 */
	Keys *priv1 = keyThread->loadKeyPriv( userId, KEY_PRIV1, &pass );

	/* Get the time. */
	time_t t = time(0);
	struct tm localTm;
	localtime_r( &t, &localTm );

	/* Format it. */
	String timeStr( TIME_STR_SZ );
	strftime( timeStr.data, timeStr.length, "%Y-%m-%d %H:%M:%S", &localTm );

	/* Sign it and destroy it. */
	priv1Sig = sign( priv1, timeStr );
	delete priv1;

	/* Load the priv2 key and decrypt it. */
	priv2 = keyThread->loadKeyPriv( userId, KEY_PRIV2, &pass );

	/* Leave the priv3 key in the DB. It will be fetched on demand. */
}

void OpenKey::open( KeyThread *keyThread, long long userId, const String &pass )
{
	pthread_mutex_lock( &mutex );
	if ( !isOpen ) {
		isOpen = true;
		mutexOpen( keyThread, userId, pass );
	}
	pthread_mutex_unlock( &mutex );
}

OpenKey *LoginTokenMap::addToken( const String &token )
{
	pthread_mutex_lock( &mutex );

	pair<TokenMap::iterator, bool> ret =
		tokenMap.insert( TokenMapPair( token, 0 ) );

	if ( ret.second ) {
		/* Successful insert. */
		ret.first->second = new OpenKey;
	}

	OpenKey *openKeys = ret.first->second;

	pthread_mutex_unlock( &mutex );

	return openKeys;
}

void KeyAgentActivity::bump()
{
	pthread_mutex_lock( &mutex );

	activeAgents += 1;
	debug( DBG_PRIV, "bump: active agents %d\n", activeAgents );

	pthread_mutex_unlock( &mutex );
}

void KeyAgentActivity::signalDone()
{
	pthread_mutex_lock( &mutex );

	activeAgents -= 1;
	debug( DBG_PRIV, "signal done: active agents %d\n", activeAgents );

	if ( activeAgents == 0 )
		pthread_cond_broadcast( &cond );

	pthread_mutex_unlock( &mutex );
}

void KeyAgentActivity::waitDone()
{
	/* Grab the lock. */
	pthread_mutex_lock( &mutex );

	while ( activeAgents > 0 )
		pthread_cond_wait( &cond, &mutex );

	debug( DBG_PRIV, "wait done: active agents %d\n", activeAgents );

	pthread_mutex_unlock( &mutex );
}

void KeyThread::test( long long userId )
{
	Keys *keys = loadKeyPriv( userId, KEY_PRIV3, 0 );
	PrivateKey key;
	key.n = bnToBin( keys->rsa->n );
	key.e = bnToBin( keys->rsa->e );

	String pKey = consPublicKey( key );
	PacketPublicKey epp( pKey );
}

void KeyThread::recvCheckPass()
{
	long long userId = readLongLong();

//	test( userId );

	String pass, token;
	readData( pass );
	readData( token );

	DbQuery login( mysql, 
		"SELECT pass_salt, pass "
		"FROM password "
		"WHERE user_id = %L", 
		userId );

	if ( login.rows() == 0 ) {
		/* not much point in this since the UI reports non-existent users. */
		sleep( 2 );
		writeInt( CHECK_PASS_BAD_USER );
	}
	else {
		MYSQL_ROW row = login.fetchRow();
		char *saltStr = row[0];
		char *passStr = row[1];

		/* Hash the password using the sale found in the DB. */
		String passSalt = base64ToBin( saltStr, strlen(saltStr) );
		String passHashed = passHash( (u_char*)passSalt.data, pass );

		/* Check the login. */
		if ( strcmp( passHashed, passStr ) != 0 ) {
			sleep( 2 );
			writeInt( CHECK_PASS_BAD_PASS );
		}
		else {
			OpenKey *openKey = loginTokenMap->addToken( token );
			openKey->open( this, userId, pass );
			writeInt( CHECK_PASS_OK );
		}
	}
}

Allocated KeyAgent::bkDetachedSign( User &privDecSign, long long bkId, const String &msg )
{
	command( KA_BK_DETACHED_SIGN );
	writeLongLong( privDecSign.id() );
	writeLongLong( bkId );
	writeData( msg );

	String result;
	readData( result );

	return result.relinquish();
}

void KeyThread::recvBkDetachedSign()
{
	/*long long privDecSignId =*/ readLongLong();
	long long bkId = readLongLong();
	String msg;
	readData( msg );

	DbQuery findBk( mysql,
		"SELECT broadcast_key, priv_key "
		"FROM put_broadcast_key "
		"WHERE id = %L ",
		bkId );

	if ( findBk.rows() != 1 )
		fatal("bk-sign-encrypt: invalid broadcast_key id %lld\n", bkId );

	MYSQL_ROW row = findBk.fetchRow();
	u_long *lengths = findBk.fetchLengths();

	String bk = Pointer( row[0], lengths[0] );
	String privKey = Pointer( row[1], lengths[1] );

	Keys *privDecSign = parsePrivKey( privKey );

	String encPacket = bkDetachedSign( privDecSign, bk, msg ); 
	writeData( encPacket );
}

bool KeyAgent::bkDetachedVerify( Identity &pubEncVer, long long bkId,
		const String &sig, const String &plainMsg )
{
	command( KA_BK_DETACHED_VERIFY );
	writeLongLong( pubEncVer.id() );
	writeLongLong( bkId );
	writeData( sig );
	writeData( plainMsg );

	char result = readChar();
	return result != 0;
}

void KeyThread::recvBkDetachedVerify()
{
	long long pubEncVerId = readLongLong();
	long long bkId = readLongLong();
	String sig, plainMsg;
	readData( sig );
	readData( plainMsg );

	DbQuery findBk( mysql,
		"SELECT broadcast_key FROM get_broadcast_key "
		"WHERE id = %L ",
		bkId );

	if ( findBk.rows() != 1 )
		fatal("bk-decrypt-verify: invalid broadcast_key id %lld\n", bkId );

	MYSQL_ROW row = findBk.fetchRow();
	String bk = Pointer( row[0] );

	Keys *pubEncVer = loadKeyPub( pubEncVerId );
	bkDetachedVerify( pubEncVer, bk, sig, plainMsg );
	writeChar( true );
}

/* Just sign a messaging using some get broadcast key (foreign) that belongs to
 * somone else. This is for the inner signature in remote broadcasts. */
Allocated KeyAgent::bkDetachedForeignSign( User &privDecSign, long long bkId, const String &msg )
{
	command( KA_BK_DETACHED_FOREIGN_SIGN );
	writeLongLong( privDecSign.id() );
	writeLongLong( bkId );
	writeData( msg );

	String result;
	readData( result );

	return result.relinquish();
}

void KeyThread::recvBkDetachedForeignSign()
{
	long long privDecSignId = readLongLong();
	long long bkId = readLongLong();
	String msg;
	readData( msg );

	DbQuery findBk( mysql,
		"SELECT broadcast_key FROM get_broadcast_key "
		"WHERE id = %L ",
		bkId );

	if ( findBk.rows() != 1 )
		fatal("bk-foreign-sign: invalid broadcast_key id %lld\n", bkId );

	MYSQL_ROW row = findBk.fetchRow();
	String bk = Pointer( row[0] );

	Keys *privDecSign = loadKeyPriv( privDecSignId );

	String encPacket = bkDetachedSign( privDecSign, bk, msg ); 
	writeData( encPacket );
}

bool KeyAgent::bkDetachedForeignVerify( Identity &pubEncVer, long long bkId,
		const String &sig, const String &plainMsg )
{
	command( KA_BK_DETACHED_FOREIGN_VERIFY );
	writeLongLong( pubEncVer.id() );
	writeLongLong( bkId );
	writeData( sig );
	writeData( plainMsg );

	char result = readChar();
	return result != 0;
}

void KeyThread::recvBkDetachedForeignVerify()
{
	/* UNUSED long long pubEncVerId = */ readLongLong();
	long long bkId = readLongLong();
	String sig;
	String plainMsg;
	readData( sig );
	readData( plainMsg );

	DbQuery findBk( mysql,
		"SELECT broadcast_key, pub_key "
		"FROM get_broadcast_key "
		"WHERE id = %L ",
		bkId );

	if ( findBk.rows() != 1 )
		fatal("bk-foreign-verify: invalid broadcast_key id %lld\n", bkId );

	MYSQL_ROW row = findBk.fetchRow();
	u_long *lengths = findBk.fetchLengths();

	String bk = Pointer( row[0], lengths[0] );
	String pubKey = Pointer( row[1], lengths[1] );

	Keys *pubEncVer = parsePubKey( pubKey );
	bkDetachedVerify( pubEncVer, bk, sig, plainMsg );
	writeChar( true );
}

void KeyAgent::generateFriendClaimKeys( long long friendClaimId )
{
	command( KA_GENERATE_FRIEND_CLAIM_KEYS );
	writeLongLong( friendClaimId );
	
	/* result */
	readData( pub1 );
	readData( pub2 );
}

void KeyThread::recvGenerateFriendClaimKeys()
{
	long long friendClaimId = readLongLong();

	/* Generate a new key. Do this first so we don't have to remove the user if
	 * it fails. */
	RSA *rsa = RSA_generate_key( 1024, RSA_F4, 0, 0 );
	if ( rsa == 0 )
		throw RsaKeyGenError( ERR_get_error() );

	/* Extract the components to hex strings. */
	PrivateKey key;
	key.n = bnToBin( rsa->n );
	key.e = bnToBin( rsa->e );
	key.d = bnToBin( rsa->d );
	key.p = bnToBin( rsa->p );
	key.q = bnToBin( rsa->q );
	key.dmp1 = bnToBin( rsa->dmp1 );
	key.dmq1 = bnToBin( rsa->dmq1 );
	key.iqmp = bnToBin( rsa->iqmp );

	String priv1 = consPrivateKey( key );
	String pub1 = consPublicKey( key );

	/* Generate a new key. Do this first so we don't have to remove the user if
	 * it fails. */
	rsa = RSA_generate_key( 1024, RSA_F4, 0, 0 );
	if ( rsa == 0 )
		throw RsaKeyGenError( ERR_get_error() );

	/* Extract the components to hex strings. */
	key.n = bnToBin( rsa->n );
	key.e = bnToBin( rsa->e );
	key.d = bnToBin( rsa->d );
	key.p = bnToBin( rsa->p );
	key.q = bnToBin( rsa->q );
	key.dmp1 = bnToBin( rsa->dmp1 );
	key.dmq1 = bnToBin( rsa->dmq1 );
	key.iqmp = bnToBin( rsa->iqmp );

	String priv2 = consPrivateKey( key );
	String pub2 = consPublicKey( key );

	DbQuery( mysql,
		"INSERT IGNORE INTO friend_claim "
		"( id, direct_key_data, rb_key_data ) "
		"VALUES ( %L, %d, %d ) ",
		friendClaimId, 
		priv1.binary(), priv1.length,
		priv2.binary(), priv2.length );

	writeData( pub1 );
	writeData( pub2 );
}

void KeyAgent::storeFriendClaimSigKey( long long friendClaimId,
		const String &friendClaimSigKey )
{
	command( KA_STORE_FRIEND_CLAIM_PUB_KEY );
	writeLongLong( friendClaimId );
	writeData( friendClaimSigKey );

	readChar();
}

void KeyThread::recvStoreFriendClaimSigKey()
{
	long long friendClaimId = readLongLong();
	String friendClaimSigKey;
	readData( friendClaimSigKey );

	DbQuery( mysql,
		"UPDATE friend_claim "
		"SET recv_pub_key = %d "
		"WHERE id = %L ",
		friendClaimSigKey.binary(),
		friendClaimSigKey.length,
		friendClaimId );

	writeChar( 0 );
}

Allocated KeyAgent::getFriendClaimRbSigKey( long long friendClaimId,
		long long friendIdentityId, const String &senderId,
		long long bkId, const String &memberProof )
{
	command( KA_GET_FRIEND_CLAIM_RB_SIG_KEY );
	writeLongLong( friendClaimId );
	writeLongLong( friendIdentityId );
	writeData( senderId );
	writeLongLong( bkId );
	writeData( memberProof );

	String rbSigKey;
	readData( rbSigKey );
	return rbSigKey.relinquish();
}

void KeyThread::recvGetFriendClaimRbSigKey()
{
	long long friendClaimId = readLongLong();
	long long friendIdentityId = readLongLong();

	String senderId;
	String memberProof;

	readData( senderId );
	long long bkId = readLongLong();
	readData( memberProof );

	Keys *pubEncVer = loadKeyPub( friendIdentityId );

	/* Broadcast key, need for verification. */
	DbQuery findBk( mysql,
		"SELECT broadcast_key FROM get_broadcast_key "
		"WHERE id = %L ",
		bkId );

	if ( findBk.rows() != 1 )
		fatal("recv-get-friend-claim-rb-sig-key: invalid broadcast_key id %lld\n", bkId );

	MYSQL_ROW row = findBk.fetchRow();
	String bk = Pointer( row[0] );

	bkDetachedVerify( pubEncVer, bk, memberProof, senderId );

	DbQuery fc( mysql,
		"SELECT rb_key_data "
		"FROM friend_claim "
		"WHERE id = %L ",
		friendClaimId );

	if ( fc.rows() == 0 )
		throw MissingKeys();
	
	row = fc.fetchRow();
	u_long *lengths = fc.fetchLengths();

	String pk = Pointer( row[0], lengths[0] );

	Keys *privDecSign = parsePrivKey( pk );
	PrivateKey key;
	key.n = bnToBin( privDecSign->rsa->n );
	key.e = bnToBin( privDecSign->rsa->e );
	key.d = bnToBin( privDecSign->rsa->d );
	key.p = bnToBin( privDecSign->rsa->p );
	key.q = bnToBin( privDecSign->rsa->q );
	key.dmp1 = bnToBin( privDecSign->rsa->dmp1 );
	key.dmq1 = bnToBin( privDecSign->rsa->dmq1 );
	key.iqmp = bnToBin( privDecSign->rsa->iqmp );
	String pubRbKey = consPublicKey( key );

	writeData( pubRbKey );
}

Allocated KeyAgent::bkDetachedRepubForeignSign( User &privDecSign, long long friendClaimId,
		long long bkId, const String &msg )
{
	command( KA_BK_DETACHED_REPUB_FOREIGN_SIGN );
	writeLongLong( privDecSign.id() );
	writeLongLong( friendClaimId );
	writeLongLong( bkId );
	writeData( msg );

	String result;
	readData( result );

	return result.relinquish();
}

void KeyThread::recvBkDetachedRepubForeignSign()
{
	/* long long privDecSignId = */ readLongLong();
	long long friendClaimId = readLongLong();
	long long bkId = readLongLong();
	String msg;
	readData( msg );

	DbQuery findBk( mysql,
		"SELECT broadcast_key FROM get_broadcast_key "
		"WHERE id = %L ",
		bkId );

	if ( findBk.rows() != 1 )
		fatal("bk-foreign-sign: invalid broadcast_key id %lld\n", bkId );

	MYSQL_ROW row = findBk.fetchRow();
	String bk = Pointer( row[0] );

	DbQuery findFc( mysql,
		"SELECT rb_key_data FROM friend_claim "
		"WHERE id = %L ",
		friendClaimId );

	if ( findFc.rows() != 1 )
		fatal("bk-foreign-verify: invalid friend claim id %lld\n", bkId );

	row = findFc.fetchRow();
	u_long *lengths = findFc.fetchLengths();
	String rbKey = Pointer( row[0], lengths[0] );

	Keys *privDecSign = parsePrivKey( rbKey );

	/* FIXME: Hack here! */
	PrivateKey key;
	key.n = bnToBin( privDecSign->rsa->n );
	key.e = bnToBin( privDecSign->rsa->e );
	key.d = bnToBin( privDecSign->rsa->d );
	key.p = bnToBin( privDecSign->rsa->p );
	key.q = bnToBin( privDecSign->rsa->q );
	key.dmp1 = bnToBin( privDecSign->rsa->dmp1 );
	key.dmq1 = bnToBin( privDecSign->rsa->dmq1 );
	key.iqmp = bnToBin( privDecSign->rsa->iqmp );
	String pubRbKey = consPublicKey( key );

	String pubRbKeyHash = sha1( pubRbKey );

	String detachedSig = bkDetachedSign( privDecSign, bk, msg ); 
	String fullPacket = consDetachedSigKey( pubRbKeyHash, detachedSig );
	writeData( fullPacket );
}

bool KeyAgent::bkDetachedRepubForeignVerify( Identity &actorId,
		long long bkId, const String &sig, const String &plainMsg )
{
	command( KA_BK_DETACHED_REPUB_FOREIGN_VERIFY );
	writeLongLong( actorId.id() );
	writeLongLong( bkId );
	writeData( sig );
	writeData( plainMsg );

	char result = readChar();
	return result != 0;
}

void KeyThread::recvBkDetachedRepubForeignVerify()
{
	long long actorId = readLongLong();
	long long bkId = readLongLong();
	String sig;
	String plainMsg;
	readData( sig );
	readData( plainMsg );

	DbQuery findBk( mysql,
		"SELECT broadcast_key FROM get_broadcast_key "
		"WHERE id = %L ",
		bkId );

	if ( findBk.rows() != 1 )
		fatal("bk-foreign-verify: invalid broadcast_key id %lld\n", bkId );

	MYSQL_ROW row = findBk.fetchRow();
	String bk = Pointer( row[0] );

	DbQuery findKey( mysql,
		"SELECT key_data "
		"FROM rb_key "
		"WHERE get_broadcast_key_id = %L AND identity_id = %L ",
		bkId, actorId );

	if ( findKey.rows() == 0 )
		fatal("bk-foreign-verify: invalid rb_key %lld %lld\n", bkId, actorId );

	row = findKey.fetchRow();
	u_long *lengths = findKey.fetchLengths();
	String keyData = Pointer( row[0], lengths[0] );

	Keys *pubEncVer1 = parsePubKey( keyData );

	PacketDetachedSigKey epp( sig );

	bkDetachedVerify( pubEncVer1, bk, epp.sig, plainMsg );

	writeChar( true );
}
