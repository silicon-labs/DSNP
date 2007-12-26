<?php

/* 
 * Copyright (c) 2007, Adrian Thurston <thurston@cs.queensu.ca>
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

include('config.php');
include('lib/iduri.php');

iduriSessionStart();

requireOwner();

$furi = $_GET['uri'];

# Get the public key of the friend.
$gnupg = new gnupg();
$fp = importId( $gnupg, $furi, $HTTP_GET_TIMEOUT );

# Fetch and decrypt the relid from the potential friend.
$asc = $furi . 'getrelid.php?fp=' . $FINGERPRINT;
$response = http_get( $asc, array("timeout"=>$HTTP_GET_TIMEOUT), $info );
$message = http_parse_message( $response );
$gnupg->setsignmode( gnupg::SIG_MODE_NORMAL );
$gnupg->adddecryptkey( $FINGERPRINT, "" );
$getrelid = "";
$res = $gnupg->decryptverify( $message->body, $getrelid );

# Create a relationship id for the friend to use.
$putrelid = sha1( uniqid( mt_rand() ) );

# Store the fingerprint and the relids. 
$data = readData();
$data['getrelids'][$fp] = $getrelid;
$data['putrelids'][$fp] = $putrelid;
$data['fingerprints'][$furi] = $fp;

# We consider them a friend at this point, though it is only a one-way link. We
# can't prove it.
$data['friends'][$furi] = $fp;

writeData( $data );

# Create the message containing the relid echo and the relid for the friend to
# use.
$gnupg->setsignmode( gnupg::SIG_MODE_NORMAL );
$gnupg->addencryptkey( $fp );
$gnupg->addsignkey( $FINGERPRINT, '' );
$enc = $gnupg->encryptsign( $getrelid . ' ' . $putrelid );
$fn = 'relid/' . $fp . '.asc';
$fd = fopen( $fn, 'wt' );
fwrite( $fd, $enc );
fclose( $fd );
chmod( $fn, 0644 );

//header( 'Content-type: text/plain' );
//print $enc;
header('Location: ' . $furi . 'submitrelid.php?uri=' . urlencode( $IDENTITY ) );
