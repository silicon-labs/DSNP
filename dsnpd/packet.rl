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
#include "packet.h"
#include "keyagent.h"
#include "error.h"

/* 
 * Common Stuff.
 */

%%{
	machine packet_common;
	include common "common.rl";

	public_key             = 1;
	public_key_set         = 2;
	relid_set              = 3;
	relid_set_pair         = 4;
	relid_response         = 5;
	private_key            = 6;
	pw_encrypted           = 7;
	signed                 = 8;
	signed_id              = 9;
	detached_sig           = 10;
	detached_sig_key       = 11;
	signed_encrypted       = 12;
	bk_keys                = 13;
	bk_encrypted           = 14;
	bk_signed_encrypted    = 15;
	broadcast              = 16;
	recipient_list         = 17;

}%%

#define EP_PUBLIC_KEY            1
#define EP_PUBLIC_KEY_SET        2
#define EP_RELID_SET             3
#define EP_RELID_SET_PAIR        4
#define EP_RELID_RESPONSE        5
#define EP_PRIVATE_KEY           6
#define EP_PW_ENCRYPTED          7
#define EP_SIGNED                8
#define EP_SIGNED_ID             9
#define EP_DETACHED_SIG          10
#define EP_DETACHED_SIG_KEY      11
#define EP_SIGNED_ENCRYPTED      12
#define EP_BK_KEYS               13
#define EP_BK_ENCRYPTED          14
#define EP_BK_SIGNED_ENCRYPTED   15
#define EP_BROADCAST             16
#define EP_RECIPIENT_LIST        17

long binLength( const String &bin )
{
	/* FIXME: check for overflow (2 byte length). */
	return 2 + bin.length;
}

long stringLength( const String &s )
{
	return s.length + 1;
}

long sixtyFourBitLength()
	{ return 8; }

u_char *writeBin( u_char *dest, const String &bin )
{
	dest[0] = ( (u_long)bin.length >> 8 ) & 0xff;
	dest[1] = (u_long)bin.length & 0xff;
	memcpy( dest + 2, bin.binary(), bin.length );
	dest += 2 + bin.length;
	return dest;
}

u_char *writeString( u_char *dest, const String &s )
{
	memcpy( dest, s(), s.length );
	dest += s.length;
	*dest++ = 0;
	return dest;
}

u_char *write64Bit( u_char *dest, u_int64_t i )
{
	for ( int shift = 56; shift >= 0; shift -= 8 )
		*dest++ = ( i >> shift ) & 0xff;
	return dest;
}

u_char *writeType( u_char *dest, u_char type )
{
	dest[0] = type;
	dest += 1;
	return dest;
}

/*
 * Public Key
 */

Allocated consPublicKey( const PrivateKey &key )
{
	long length = 1 + binLength(key.n) + binLength(key.e);
	String encPacket( length );
	u_char *dest = (u_char*)encPacket.data;

	dest = writeType( dest, EP_PUBLIC_KEY );
	dest = writeBin( dest, key.n );
	dest = writeBin( dest, key.e );

	return encPacket.relinquish();
}

%%{
	machine packet_public_keys;
	include packet_common;

	main := (
		public_key
		bin16 @{ n.set( buf ); }
		bin16 @{ e.set( buf ); }
	)
	@{
		debug( DBG_EP, "encryption packet: public_key: %ld %ld\n", 
				n.length, e.length );
	};
}%%

%% write data;

Parser::Control PacketPublicKey::data( const char *data, int dlen )
{
	%% write init;

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	%% write exec;

	if ( cs < %%{ write first_final; }%% )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

/*
 * Public Key Set
 */

Allocated consPublicKeySet( const String &priv0, const String &priv1,
		const String &priv2, const String &priv3 )
{
	long length = 1 + 
			binLength(priv0) + binLength(priv1) + 
			binLength(priv2) + binLength(priv3);

	String encPacket( length );
	u_char *dest = (u_char*)encPacket.data;

	dest = writeType( dest, EP_PUBLIC_KEY_SET );
	dest = writeBin( dest, priv0 );
	dest = writeBin( dest, priv1 );
	dest = writeBin( dest, priv2 );
	dest = writeBin( dest, priv3 );

	return encPacket.relinquish();
}

%%{
	machine packet_public_key_set;
	include packet_common;

	main := (
		public_key_set
		bin16 @{ priv0.set( buf ); }
		bin16 @{ priv1.set( buf ); }
		bin16 @{ priv2.set( buf ); }
		bin16 @{ priv3.set( buf ); }
	)
	@{
		debug( DBG_EP, "encryption packet: public_key_set: %ld %ld %ld %ld\n", 
				priv0.length, priv1.length, priv2.length, priv3.length );
	};
}%%

%% write data;

Parser::Control PacketPublicKeySet::data( const char *data, int dlen )
{
	%% write init;

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	%% write exec;

	if ( cs < %%{ write first_final; }%% )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

/*
 * Relid Set
 */

Allocated consRelidSet( const RelidSet &relidSet )
{
	long length = 1 + 
			binLength(relidSet.priv0) + binLength(relidSet.priv1) + 
			binLength(relidSet.priv2) + binLength(relidSet.priv3) +
			binLength(relidSet.priv4);

	String encPacket( length );
	u_char *dest = (u_char*)encPacket.data;

	dest = writeType( dest, EP_RELID_SET );
	dest = writeBin( dest, relidSet.priv0 );
	dest = writeBin( dest, relidSet.priv1 );
	dest = writeBin( dest, relidSet.priv2 );
	dest = writeBin( dest, relidSet.priv3 );
	dest = writeBin( dest, relidSet.priv4 );

	return encPacket.relinquish();
}

%%{
	machine packet_relid_set;
	include packet_common;

	main := (
		relid_set
		bin16 @{ priv0.set( buf ); }
		bin16 @{ priv1.set( buf ); }
		bin16 @{ priv2.set( buf ); }
		bin16 @{ priv3.set( buf ); }
		bin16 @{ priv4.set( buf ); }
	)
	@{
		debug( DBG_EP, "encryption packet: relid_set: %ld %ld %ld %ld %ld\n", 
				priv0.length, priv1.length, priv2.length, priv3.length, priv4.length );
	};
}%%

%% write data;

Parser::Control PacketRelidSet::data( const char *data, int dlen )
{
	%% write init;

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	%% write exec;

	if ( cs < %%{ write first_final; }%% )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

/*
 * Relid Set Pair
 */

Allocated consRelidSetPair( const String &requested, const String &returned )
{
	long length = 1 + binLength(requested) + binLength(returned);

	String encPacket( length );
	u_char *dest = (u_char*)encPacket.data;

	dest = writeType( dest, EP_RELID_SET_PAIR );
	dest = writeBin( dest, requested );
	dest = writeBin( dest, returned );

	return encPacket.relinquish();
}

%%{
	machine packet_relid_set_pair;
	include packet_common;

	main := (
		relid_set_pair
		bin16 @{ requested.set( buf ); }
		bin16 @{ returned.set( buf ); }
	)
	@{
		debug( DBG_EP, "encryption packet: relid_set_pair: %ld %ld\n", 
				requested.length, returned.length );
	};
}%%

%% write data;

Parser::Control PacketRelidSetPair::data( const char *data, int dlen )
{
	%% write init;

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	%% write exec;

	if ( cs < %%{ write first_final; }%% )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

/*
 * Relid Response
 */

Allocated consRelidResponse( const String &peerNotifyReqid, const String &relidSetPair )
{
	long length = 1 + binLength(peerNotifyReqid) + binLength(relidSetPair);
	String encPacket( length );
	u_char *dest = (u_char*)encPacket.data;

	dest = writeType( dest, EP_RELID_RESPONSE );
	dest = writeBin( dest, peerNotifyReqid );
	dest = writeBin( dest, relidSetPair );

	return encPacket.relinquish();
}

%%{
	machine packet_relid_response;
	include packet_common;

	main := (
		relid_response
		bin16 @{ peerNotifyReqid.set( buf ); }
		bin16 @{ relidSetPair.set( buf ); }
	)
	@{
		debug( DBG_EP, "encryption packet: relid_response: %ld %ld\n", 
				peerNotifyReqid.length, relidSetPair.length );
	};
}%%

%% write data;

Parser::Control PacketRelidResponse::data( const char *data, int dlen )
{
	%% write init;

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	%% write exec;

	if ( cs < %%{ write first_final; }%% )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}


/*
 * Private Key
 */

Allocated consPrivateKey( const PrivateKey &key )
{
	long length = 1 + 
			binLength( key.n ) + binLength( key.e ) + 
			binLength( key.d ) + binLength( key.p ) +
			binLength( key.q ) + binLength( key.dmp1 ) +
			binLength( key.dmq1 ) + binLength( key.iqmp );

	String encPacket( length );
	u_char *dest = (u_char*)encPacket.data;

	dest = writeType( dest, EP_PRIVATE_KEY );
	dest = writeBin( dest, key.n );
	dest = writeBin( dest, key.e );
	dest = writeBin( dest, key.d );
	dest = writeBin( dest, key.p );
	dest = writeBin( dest, key.q );
	dest = writeBin( dest, key.dmp1 );
	dest = writeBin( dest, key.dmq1 );
	dest = writeBin( dest, key.iqmp );

	return encPacket.relinquish();
}

%%{
	machine packet_private_keys;
	include packet_common;

	main := (
		private_key
		bin16 @{ key.n.set( buf ); }
		bin16 @{ key.e.set( buf ); }
		bin16 @{ key.d.set( buf ); }
		bin16 @{ key.p.set( buf ); }
		bin16 @{ key.q.set( buf ); }
		bin16 @{ key.dmp1.set( buf ); }
		bin16 @{ key.dmq1.set( buf ); }
		bin16 @{ key.iqmp.set( buf ); }
	)
	@{
		debug( DBG_EP, "encryption packet: private_key: %ld %ld %ld %ld %ld %ld %ld %ld\n", 
				key.n.length, key.e.length, key.d.length, key.p.length ,
				key.q.length, key.dmp1.length, key.dmq1.length, key.iqmp.length );
	};
}%%

%% write data;

Parser::Control PacketPrivateKey::data( const char *data, int dlen )
{
	%% write init;

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	%% write exec;

	if ( cs < %%{ write first_final; }%% )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

/*
 * PW Encrypted
 */

Allocated consPwEncrypted( const String &enc )
{
	long length = 1 + binLength(enc);
	String encPacket( length );
	u_char *dest = (u_char*)encPacket.data;

	dest = writeType( dest, EP_PW_ENCRYPTED );
	dest = writeBin( dest, enc );

	return encPacket.relinquish();
}

%%{
	machine packet_pw_encrypted;
	include packet_common;

	main := (
		pw_encrypted
		bin16 @{ enc.set( buf ); }
	)
	@{
		debug( DBG_EP, "encryption packet: pw_encrypted: %ld\n", enc.length );
	};
}%%

%% write data;

Parser::Control PacketPwEncrypted::data( const char *data, int dlen )
{
	%% write init;

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	%% write exec;

	if ( cs < %%{ write first_final; }%% )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

/*
 * Signed
 */

Allocated consSigned( const String &sig, const String &msg )
{
	long length = 1 + binLength(sig) + binLength(msg);
	String encPacket( length );
	u_char *dest = (u_char*)encPacket.data;

	dest = writeType( dest, EP_SIGNED );
	dest = writeBin( dest, sig );
	dest = writeBin( dest, msg );

	return encPacket.relinquish();
}

%%{
	machine packet_signed;
	include packet_common;

	main := (
		signed
		bin16 @{ sig.set( buf ); }
		bin16 @{ msg.set( buf ); }
	)
	@{
		debug( DBG_EP, "encryption packet: signed: %ld %ld\n", 
				sig.length, msg.length );
	};
}%%

%% write data;

Parser::Control PacketSigned::data( const char *data, int dlen )
{
	%% write init;

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	%% write exec;

	if ( cs < %%{ write first_final; }%% )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

/*
 * SignedId
 */

Allocated consSignedId( const String &iduri, const String &sig, const String &msg )
{
	long length = 1 +
			stringLength(iduri) +
			binLength(sig) +
			binLength(msg);

	String encPacket(length);
	u_char *dest = (u_char*)encPacket.data;

	dest = writeType( dest, EP_SIGNED_ID );
	dest = writeString( dest, iduri );
	dest = writeBin( dest, sig );
	dest = writeBin( dest, msg );

	return encPacket.relinquish();
}

%%{
	machine packet_signed_id;
	include packet_common;

	main := (
		signed_id
		iduri0 
		bin16 @{ sig.set( buf ); }
		bin16 @{ msg.set( buf ); }
	)
	@{
		debug( DBG_EP, "encryption packet: signed: %ld %ld\n", 
				sig.length, msg.length );
	};
}%%

%% write data;

Parser::Control PacketSignedId::data( const char *data, int dlen )
{
	%% write init;

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	%% write exec;

	if ( cs < %%{ write first_final; }%% )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}


/*
 * Detached Signed
 */

Allocated consDetachedSig( const String &sig )
{
	long length = 1 + binLength( sig );
	String encPacket( length );
	u_char *dest = (u_char*)encPacket.data;

	dest = writeType( dest, EP_DETACHED_SIG );
	dest = writeBin( dest, sig );

	return encPacket.relinquish();
}

%%{
	machine packet_detached_sig;
	include packet_common;

	main := (
		detached_sig
		bin16 @{ sig.set( buf ); }
	)
	@{
		debug( DBG_EP, 
				"encryption packet: detached sig: %ld\n", 
				sig.length );
	};
}%%

%% write data;

Parser::Control PacketDetachedSig::data( const char *data, int dlen )
{
	%% write init;

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	%% write exec;

	if ( cs < %%{ write first_final; }%% )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

/*
 * Detached Signed with Key.
 */

Allocated consDetachedSigKey( const String &pubKeyHash, const String &sig )
{
	long length = 1 + 
		binLength( pubKeyHash ) +
		binLength( sig );
	String encPacket( length );
	u_char *dest = (u_char*)encPacket.data;

	dest = writeType( dest, EP_DETACHED_SIG_KEY );
	dest = writeBin( dest, pubKeyHash );
	dest = writeBin( dest, sig );

	return encPacket.relinquish();
}

%%{
	machine packet_pub_key_detached_sig;
	include packet_common;

	main := (
		detached_sig_key
		bin16 @{ pubKeyHash.set( buf ); }
		bin16 @{ sig.set( buf ); }
	)
	@{
		debug( DBG_EP, 
				"encryption packet: detached sig: %ld\n", 
				sig.length );
	};
}%%

%% write data;

Parser::Control PacketDetachedSigKey::data( const char *data, int dlen )
{
	%% write init;

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	%% write exec;

	if ( cs < %%{ write first_final; }%% )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

/*
 * Signed Encrypted
 */

Allocated consSignedEncrypted( const String &protKey, const String &enc )
{
	long length = 1 + binLength(protKey) + binLength(enc);
	String encPacket( length );
	u_char *dest = (u_char*)encPacket.data;

	dest = writeType( dest, EP_SIGNED_ENCRYPTED );
	dest = writeBin( dest, protKey );
	dest = writeBin( dest, enc );

	return encPacket.relinquish();
}

%%{
	machine packet_signed_encrypted;
	include packet_common;

	main := (
		signed_encrypted
		bin16 @{ protKey.set( buf ); }
		bin16 @{ enc.set( buf ); }
	)
	@{
		debug( DBG_EP, "encryption packet: signed_encrypted: %ld %ld\n", 
				protKey.length, enc.length );
	};
}%%

%% write data;

Parser::Control PacketSignedEncrypted::data( const char *data, int dlen )
{
	%% write init;

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	%% write exec;

	if ( cs < %%{ write first_final; }%% )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

/*
 * Broadcast Keys
 */

Allocated consBkKeys( const String &bk, const String &pubKey, const String &memberProof )
{
	long length = 1 + binLength(bk) + binLength(pubKey) + binLength( memberProof );
	String encPacket( length );
	u_char *dest = (u_char*)encPacket.data;

	dest = writeType( dest, EP_BK_KEYS );
	dest = writeBin( dest, bk );
	dest = writeBin( dest, pubKey );
	dest = writeBin( dest, memberProof );

	return encPacket.relinquish();
}

%%{
	machine packet_bk_keys;
	include packet_common;

	main :=
		bk_keys
		bin16 @{ bk.set( buf ); }
		bin16 @{ pubKey.set( buf ); }
		bin16 @{ memberProof.set( buf ); }
	@{
		debug( DBG_EP, "encryption packet: bk_keys\n" );
	};
}%%

%% write data;

Parser::Control PacketBkKeys::data( const char *data, int dlen )
{
	%% write init;

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	%% write exec;

	if ( cs < %%{ write first_final; }%% )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

/*
 * BK Encrypted
 */

Allocated consBkEncrypted( const String &enc )
{
	long length = 1 + binLength(enc);
	String encPacket( length );
	u_char *dest = (u_char*)encPacket.data;

	dest = writeType( dest, EP_BK_ENCRYPTED );
	dest = writeBin( dest, enc );

	return encPacket.relinquish();
}

%%{
	machine packet_bk_encrypted;
	include packet_common;

	main := (
		bk_encrypted
		bin16 @{ enc.set( buf ); }
	)
	@{
		debug( DBG_EP, "encryption packet: bk_encrypted: %ld\n", enc.length );
	};
}%%

%% write data;

Parser::Control PacketBkEncrypted::data( const char *data, int dlen )
{
	%% write init;

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	%% write exec;

	if ( cs < %%{ write first_final; }%% )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

/*
 * BK Signed Encrypted
 */

Allocated consBkSignedEncrypted( const String &enc )
{
	long length = 1 + binLength(enc);
	String encPacket( length );
	u_char *dest = (u_char*)encPacket.data;

	dest = writeType( dest, EP_BK_SIGNED_ENCRYPTED );
	dest = writeBin( dest, enc );

	return encPacket.relinquish();
}

%%{
	machine packet_bk_signed_encrypted;
	include packet_common;

	main := (
		bk_signed_encrypted
		bin16 @{ enc.set( buf ); }
	)
	@{
		debug( DBG_EP, "encryption packet: bk_signed_encrypted: %ld\n", enc.length );
	};
}%%

%% write data;

Parser::Control PacketBkSignedEncrypted::data( const char *data, int dlen )
{
	%% write init;

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	%% write exec;

	if ( cs < %%{ write first_final; }%% )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}


/*
 * Broadcast
 */

#define EP_BKT_PUBLISHER  1
#define EP_BKT_AUTHOR     2
#define EP_BKT_SUBJECT    3
#define EP_BKT_BODY       4

Allocated consBroadcast( const Broadcast &broadcast )
{
	/*
	 * Compute the length.
	 */
	long length = 1;
	if ( broadcast.publisher.length != 0 ) {
		length += 1;
		length += binLength( broadcast.publisher);
		length += binLength( broadcast.publisherSig );
		length += binLength( broadcast.publisherRelid );
	}

	if ( broadcast.author.length != 0 ) {
		length += 1;
		length += binLength( broadcast.author);
		length += binLength( broadcast.authorSig );
		length += binLength( broadcast.authorRelid );
	}

	for ( BroadcastSubject *bs = broadcast.subjectList.head; 
			bs != 0; bs = bs->next )
	{
		length += 1;
		length += binLength( bs->subject );
		length += binLength( bs->subjectSig );
		length += binLength( bs->subjectRelid );
	}

	length += 1;
	length += binLength( broadcast.plainMsg );

	/*
	 * Write the packet.
	 */
	
	String encPacket( length );
	u_char *dest = (u_char*)encPacket.data;

	dest = writeType( dest, EP_BROADCAST );

	if ( broadcast.publisher.length != 0 ) {
		dest = writeType( dest, EP_BKT_PUBLISHER );
		dest = writeBin( dest, broadcast.publisher );
		dest = writeBin( dest, broadcast.publisherSig );
		dest = writeBin( dest, broadcast.publisherRelid );
	}

	if ( broadcast.author.length != 0 ) {
		dest = writeType( dest, EP_BKT_AUTHOR );
		dest = writeBin( dest, broadcast.author );
		dest = writeBin( dest, broadcast.authorSig );
		dest = writeBin( dest, broadcast.authorRelid );
	}

	for ( BroadcastSubject *bs = broadcast.subjectList.head; 
			bs != 0; bs = bs->next )
	{
		dest = writeType( dest, EP_BKT_SUBJECT );
		dest = writeBin( dest, bs->subject );
		dest = writeBin( dest, bs->subjectSig );
		dest = writeBin( dest, bs->subjectRelid );
	}

	dest = writeType( dest, EP_BKT_BODY );
	dest = writeBin( dest, broadcast.plainMsg );

	return encPacket.relinquish();
}

%%{
	machine packet_broadcast;
	include packet_common;

	bp_publisher = 1;
	bp_author    = 2;
	bp_subject   = 3;
	bp_body      = 4;

	main := (
		broadcast
		( 
			bp_publisher
			bin16 @{ b.publisher.set( buf ); }
			bin16 @{ b.publisherSig.set( buf ); }
			bin16empty @{ b.publisherRelid.set( buf ); }
		)?

		( 
			bp_author
			bin16 @{ b.author.set( buf ); }
			bin16 @{ b.authorSig.set( buf ); }
			bin16empty @{ b.authorRelid.set( buf ); }
		)?

		( 
			bp_subject @{
				bs.subject.clear();
				bs.subjectSig.clear();
				bs.subjectRelid.clear();
			}
			bin16 @{ bs.subject.set( buf );  }   
			bin16 @{ bs.subjectSig.set( buf ); }   
			bin16empty @{ 
				bs.subjectRelid.set( buf );

				BroadcastSubject *nbs = new BroadcastSubject;
				nbs->subject = bs.subject.relinquish();
				nbs->subjectSig = bs.subjectSig.relinquish();
				nbs->subjectRelid = bs.subjectRelid.relinquish();
				b.subjectList.append( nbs );
			}
		)*

		bp_body 
		bin16 @{ b.plainMsg.set( buf ); }
	)
	@{
		debug( DBG_EP, "encryption packet: broadcast\n" );
	};
}%%

%% write data;

Parser::Control PacketBroadcast::data( const char *data, int dlen )
{
	%% write init;

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	%% write exec;

	if ( cs < %%{ write first_final; }%% )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

/*
 * Recipient List
 */

Allocated consRecipientList( const RecipientList2 &recipientList )
{
	long length = 1;

	for ( Recipient *r = recipientList.head; r != 0; r = r->next ) {
		length += r->relid.length + 1;
		length += r->iduri.length + 1;
	}
	
	length += 1;

	String packet( length );
	u_char *dest = (u_char*)packet.data;

	dest = writeType( dest, EP_RECIPIENT_LIST );

	for ( Recipient *r = recipientList.head; r != 0; r = r->next ) {
		dest = writeString( dest, r->relid );
		dest = writeString( dest, r->iduri );
	}
	
	dest = writeType( dest, 0 );
	
	return packet.relinquish();
}

%%{
	machine packet_recipient_list;
	include packet_common;

	action recipient {
		Recipient *r = new Recipient;
		r->relid.set( relid );
		r->iduri.set( buf );
		rl.append( r );
	}

	main := (
		recipient_list
		( 
			relid0 
			iduri0 @recipient
		)*
		# This really needed?
		0
	)
	@{
		debug( DBG_EP, "encryption packet: recipeint_list\n" );
	};
}%%

%% write data;

Parser::Control PacketRecipientList::data( const char *data, int dlen )
{
	%% write init;

	const u_char *p = (u_char*)data;
	const u_char *pe = (u_char*)data + dlen;

	%% write exec;

	if ( cs < %%{ write first_final; }%% )
		throw ParseError( __FILE__, __LINE__ );

	return Continue;
}

