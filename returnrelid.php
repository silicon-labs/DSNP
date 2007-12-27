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
$reqid = $_GET['reqid'];

# Get the public key of the friend.
$gnupg = new gnupg();
$fp = importId( $gnupg, $furi );

# Fetch and decrypt the relid from the potential friend.
$message = fetchMessage( $furi, 'relids', $reqid );
$getrelid = decryptVerify( $gnupg, $message );

# Create a relationship id for the friend to use.
$putrelid = sha1( uniqid( mt_rand() ) );

# Create a request id for posting the relationship id.
$reqid = sha1( uniqid( mt_rand() ) );

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
$plain = $getrelid . ' ' . $putrelid;
$enc = encryptSign( $gnupg, $fp, $plain );
publishMessage( 'relids', $reqid, $enc );

# URI and request id arguments for the redirect.
$arg_uri = 'uri=' . urlencode( $CFG_IDENTITY );
$arg_reqid = 'reqid=' . urlencode( $reqid );

header('Location: ' . $furi . 'submitrelid.php?' . $arg_uri . '&' . $arg_reqid );
