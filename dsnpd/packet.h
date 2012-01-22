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

#ifndef _PACKET_H
#define _PACKET_H

#include "encrypt.h"


/*
 * Public Key Packets.
 */

Allocated consPublicKey( const PrivateKey &key );

struct PacketPublicKey
:
	public Parser
{
	PacketPublicKey( const String &encPacket )
	{
		parse( encPacket );
	}

	long cs;
	u_long val, counter;
	Buffer buf;
	u_char *dest;

	String n, e;

	virtual Control data( const char *data, int dlen );
};

/*
 * Public Key Set
 */

Allocated consPublicKeySet( const String &priv0, const String &priv1,
		const String &priv2, const String &priv3 );

struct PacketPublicKeySet
:
	public Parser
{
	PacketPublicKeySet( const String &encPacket )
	{
		parse( encPacket );
	}

	long cs;
	u_long val, counter;
	Buffer buf;
	u_char *dest;

	virtual Control data( const char *data, int dlen );

	String priv0;
	String priv1;
	String priv2;
	String priv3;
};

/*
 * Relid Set
 */

Allocated consRelidSet( const RelidSet &relidSet );

struct PacketRelidSet
:
	public Parser
{
	PacketRelidSet( const String &encPacket )
	{
		parse( encPacket );
	}

	long cs;
	u_long val, counter;
	Buffer buf;
	u_char *dest;

	virtual Control data( const char *data, int dlen );

	String priv0;
	String priv1;
	String priv2;
	String priv3;
	String priv4;
};

/*
 * Relid Set Pair
 */

Allocated consRelidSetPair( const String &requested, const String &returned );

struct PacketRelidSetPair
:
	public Parser
{
	PacketRelidSetPair( const String &encPacket )
	{
		parse( encPacket );
	}

	long cs;
	u_long val, counter;
	Buffer buf;
	u_char *dest;

	virtual Control data( const char *data, int dlen );

	String requested;
	String returned;
};

/*
 * Relid Response 
 */

Allocated consRelidResponse( const String &peerNotifyReqid, const String &relidSetPair );

struct PacketRelidResponse
:
	public Parser
{
	PacketRelidResponse( const String &encPacket )
	{
		parse( encPacket );
	}

	long cs;
	u_long val, counter;
	Buffer buf;
	u_char *dest;

	virtual Control data( const char *data, int dlen );

	String peerNotifyReqid, relidSetPair;
};


/*
 * Private Key Packets
 */

Allocated consPrivateKey( const PrivateKey &key );

struct PacketPrivateKey
:
	public Parser
{
	PacketPrivateKey( const String &encPacket )
	{
		parse( encPacket );
	}

	long cs;
	u_long val, counter;
	Buffer buf;
	u_char *dest;

	virtual Control data( const char *data, int dlen );

	PrivateKey key;
};

/*
 * PW-Encrypted Packets
 */

Allocated consPwEncrypted( const String &encryptedBin );

struct PacketPwEncrypted
:
	public Parser
{
	PacketPwEncrypted( const String &encPacket )
	{
		parse( encPacket );
	}

	long cs;
	u_long val, counter;
	Buffer buf;
	u_char *dest;

	virtual Control data( const char *data, int dlen );

	String enc;
};

/*
 * Signed Data Packets
 */

Allocated consSigned( const String &sig, const String &msg );

struct PacketSigned
:
	public Parser
{
	PacketSigned( const String &encPacket )
	{
		parse( encPacket );
	}

	long cs;
	u_long val, counter;
	Buffer buf;
	u_char *dest;

	virtual Control data( const char *data, int dlen );

	String sig, msg;
};

/*
 * Signed-Id Data Packets
 *
 * Has the the identity of the signer, the sig, and the msg. 
 */

Allocated consSignedId( const String &iduri, const String &sig, const String &msg );

struct PacketSignedId
:
	public Parser
{
	PacketSignedId( const String &encPacket )
	{
		parse( encPacket );
	}

	long cs;
	u_long val, counter;
	Buffer buf;
	u_char *dest;

	virtual Control data( const char *data, int dlen );

	String iduri, sig, msg;
};

/*
 * Detached Signatures
 */

Allocated consDetachedSig( const String &sig );

struct PacketDetachedSig
:
	public Parser
{
	PacketDetachedSig( const String &encPacket )
	{
		parse( encPacket );
	}

	long cs;
	u_long val, counter;
	Buffer buf;
	u_char *dest;

	virtual Control data( const char *data, int dlen );

	String sig;
};

/*
 * Detached PubKey Signatures
 *
 * Detached sig that includes the key.
 */

Allocated consDetachedSigKey( const String &pubKeyHash, const String &sig );

struct PacketDetachedSigKey
:
	public Parser
{
	PacketDetachedSigKey( const String &encPacket )
	{
		parse( encPacket );
	}

	long cs;
	u_long val, counter;
	Buffer buf;
	u_char *dest;

	virtual Control data( const char *data, int dlen );

	String pubKeyHash;
	String sig;
};

/*
 * Signed-Encrypted Packets.
 */

Allocated consSignedEncrypted( const String &protKey, const String &enc );

struct PacketSignedEncrypted
:
	public Parser
{
	PacketSignedEncrypted( const String &encPacket )
	{
		parse( encPacket );
	}

	long cs;
	u_long val, counter;
	Buffer buf;
	u_char *dest;

	virtual Control data( const char *data, int dlen );

	String protKey, enc;
};

/*
 * Broadcast Keys
 */

Allocated consBkKeys( const String &bk, const String &pubKey, const String &memberProof );

struct PacketBkKeys
:
	public Parser
{
	PacketBkKeys( const String &encPacket )
	{
		parse( encPacket );
	}

	long cs;
	u_long val, counter;
	Buffer buf;
	u_char *dest;

	virtual Control data( const char *data, int dlen );

	String bk;
	String pubKey;
	String memberProof;
};


/*
 * Bk Encrypted Packets
 */

Allocated consBkEncrypted( const String &enc );

struct PacketBkEncrypted
:
	public Parser
{
	PacketBkEncrypted( const String &encPacket )
	{
		parse( encPacket );
	}

	long cs;
	u_long val, counter;
	Buffer buf;
	u_char *dest;

	virtual Control data( const char *data, int dlen );

	String enc;
};

/*
 * BK-Signed-Encrypted Packets
 */

Allocated consBkSignedEncrypted( const String &enc );

struct PacketBkSignedEncrypted
:
	public Parser
{
	PacketBkSignedEncrypted( const String &encPacket )
	{
		parse( encPacket );
	}

	long cs;
	u_long val, counter;
	Buffer buf;
	u_char *dest;

	virtual Control data( const char *data, int dlen );

	String enc;
};


/*
 * Relid Response 
 */

Allocated consBroadcast( const Broadcast &broadcast );

struct PacketBroadcast
:
	public Parser
{
	PacketBroadcast( Broadcast &b, const String &encPacket )
	:
		b(b)
	{
		parse( encPacket );
	}

	long cs;
	u_long val, counter;
	Buffer buf;
	u_char *dest;

	virtual Control data( const char *data, int dlen );

	BroadcastSubject bs;
	Broadcast &b;
};

/*
 * Recipient List
 */

Allocated consRecipientList( const RecipientList2 &recipientList );

struct PacketRecipientList
:
	public Parser
{
	PacketRecipientList( const String &encPacket )
	{
		parse( encPacket );
	}

	long cs;
	u_long val, counter;
	Buffer buf;
	u_char *dest;
	String relid;
	String iduri;

	virtual Control data( const char *data, int dlen );

	RecipientList2 rl;
};

#endif
