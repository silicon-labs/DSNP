/*
 * Copyright (c) 2009-2011, Adrian Thurston <thurston@complang.org>
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

#ifndef _KEYAGENT_H
#define _KEYAGENT_H

#include <pthread.h>
#include <string>
#include <map>
#include <list>

#include "encrypt.h"

using std::map;
using std::pair;
using std::string;

struct Key;
struct KeyThread;
struct PrivateKey;


struct OpenKey
{
	OpenKey()
		: isOpen(false), priv2(0)
	{
		pthread_mutex_init( &mutex, 0 );
	}

	void mutexOpen( KeyThread *keyThread, long long userId, const String &pass );
	void open( KeyThread *keyThread, long long userId, const String &pass );
	pthread_mutex_t mutex;

	bool isOpen;
	String priv1Sig;
	Keys *priv2;
};

struct LoginTokenMap
{
	LoginTokenMap()
	{
		pthread_mutex_init( &mutex, 0 );
	}

	pthread_mutex_t mutex;
	typedef map<String, OpenKey*> TokenMap;
	typedef pair<String, OpenKey*> TokenMapPair;
	TokenMap tokenMap;

	OpenKey *addToken( const String &token );
};

struct KeyAgentActivity
{
	KeyAgentActivity()
		: activeAgents(0)
	{
		pthread_cond_init( &cond, 0 );
		pthread_mutex_init( &mutex, 0 );
	}

	void bump();
	void signalDone();
	void waitDone();

	pthread_mutex_t mutex;
	pthread_cond_t cond;

	int activeAgents;
};

struct KeyAgent
	: public Barrier
{
	KeyAgent( int fd )
		: Barrier(fd) {}

	void storePublicKey( Identity &identity, const String &encPacket );
	void generateKey( long long userId, const String &pass );
	void storePutBroadcastKey( long long id, const char *broadcastKey );
	void storeGetBroadcastKey( long long id, const String &bkKeys );
	void getPutBroadcastKey( long long userId, const String &forIduri, long long id );
	int checkPass( long long userId, const String &pass, const String &token );
	void generateFriendClaimKeys( long long friendClaimId );
	void storeFriendClaimSigKey( long long friendClaimId, const String &friendClaimPubKey );
	Allocated getFriendClaimRbSigKey( long long friendClaimId, long long friendIdentityId, 
			const String &senderId, long long bkId, const String &memberProof );

	void storeRbKey( long long bkId, long long identityId, const String &hash, const String &keyData );

	String pubSet;
	String bk;
	String pub1;
	String pub2;

	Allocated signEncrypt( Identity &pubEncVer, User &privDecSign, const String &msg );
	Allocated signIdEncrypt( Identity &pubEncVer, User &privDecSign,
			const String &iduri, long long bkId, const String &distName, 
			long long generation );
	Allocated decryptVerify( Identity &pubEncVer, User &privDecSign, const String &msg );
	Allocated decryptVerify1( User &privDecSign, const String &msg );
	Allocated decryptVerify2( Identity &pubEncVer, User &privDecSign, const String &msg );

	Allocated bkSignEncrypt( User &privDecSign, long long bkId, const String &msg );
	Allocated bkDecryptVerify( Identity &pubEncVer, long long bkId, const String &msg );

	Allocated bkSign( User &privDecSign, long long bkId, const String &msg );
	Allocated bkVerify( Identity &pubEncVer, long long bkId, const String &msg );

	Allocated bkEncrypt( long long bkId, const String &msg );
	Allocated bkDecrypt( long long bkId, const String &msg );

	/* Just sign a messaging using some get broadcast key (foreign) that
	 * belongs to somone else. This is for the inner signature in remote
	 * broadcasts. */
	Allocated bkForeignSign( User &privDecSign, long long bkId, const String &msg );
	Allocated bkForeignVerify( Identity &pubEncVer, long long bkId, const String &msg );

	Allocated bkDetachedSign( User &privDecSign, long long bkId, const String &msg );
	bool bkDetachedVerify( Identity &pubEncVer, long long bkId, const String &sig, const String &plainMsg );

	Allocated bkDetachedForeignSign( User &privDecSign, long long bkId, const String &msg );
	bool bkDetachedForeignVerify( Identity &pubEncVer, long long bkId, const String &sig, const String &plainMsg );

	Allocated bkDetachedRepubForeignSign( User &privDecSign, long long friendClaimId,
			long long bkId, const String &msg );
	bool bkDetachedRepubForeignVerify( Identity &pubEncVer,
			long long bkId, const String &sig, const String &plainMsg );

	void publicKey( User &user );
};


struct KeyThread
:
	public ConfigCtx,
	public Barrier
{
	KeyThread( Config *c, LoginTokenMap *loginTokenMap,
			KeyAgentActivity *keyAgentActivity, int fd ) 
	:
		ConfigCtx(c),
		Barrier(fd),
		loginTokenMap(loginTokenMap),
		keyAgentActivity(keyAgentActivity)
	{}

	LoginTokenMap *loginTokenMap;
	KeyAgentActivity *keyAgentActivity;

	pthread_t thread;
	pthread_attr_t attr;

	void create();
	static int _startRoutine( KeyThread *thread );
	int startRoutine();
	int startRoutineBare();
	void dbConnect();

	Keys *loadKeyPub( long long identityId );

	Keys *loadKeyPriv( long long userId, int keyPriv, const String *pass );
	Keys *loadKeyPriv( long long userId );

	Keys *generateKey( long long userId, PrivateKey &key,
			int keyPriv, bool encrypt, const String &pass );
	void recvConfig();

	void storePublicKey( long long identityId, int keyPriv, const String &key );
	void recvStorePublicKey();
	void recvGenerateKey();
	void recvSignEncrypt();
	void recvSignIdEncrypt();
	void recvDecryptVerify();
	void recvDecryptVerify1();
	void recvDecryptVerify2();
	void recvBkSignEncrypt();
	void recvBkDecryptVerify();
	void recvBkForeignSign();
	void recvBkForeignVerify();
	void recvGetPublicKey();
	void recvStorePutBroadcastKey();
	void recvStoreGetBroadcastKey();
	void recvGetPutBroadcastKey();
	void recvCheckPass();
	void recvBkEncrypt();
	void recvBkDecrypt();
	void recvBkSign();
	void recvBkVerify();
	void recvBkDetachedSign();
	void recvBkDetachedVerify();
	void recvBkDetachedForeignSign();
	void recvBkDetachedForeignVerify();
	void recvGenerateFriendClaimKeys();
	void recvStoreFriendClaimSigKey();
	void recvGetFriendClaimRbSigKey();
	void recvBkDetachedRepubForeignSign();
	void recvBkDetachedRepubForeignVerify();
	void recvStoreRbKey();

	void test( long long userId );

	MYSQL *mysql;

	KeyThread *next, *prev;
};

#endif
