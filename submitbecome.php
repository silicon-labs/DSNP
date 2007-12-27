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

$furi = $_POST['uri'];
$data = readData();
$gnupg = new gnupg();

# Get the public key.
$fp = importId( $gnupg, $furi );

# Create a relationship id for the friend to use.
$putrelid = sha1( uniqid( mt_rand() ) );

# Store the fingerprint and relid. 
$data = readData();
$data['putrelids'][$fp] = $putrelid;
$data['fingerprints'][$furi] = $fp;
writeData( $data );

# Create a request id for posting the relationship id.
$reqid = sha1( uniqid( mt_rand() ) );

# Create the relid message for the identity requesting friendship.
$enc = encryptSign( $gnupg, $fp, $putrelid );
publishMessage( 'relid', $reqid, $enc );

# URI and request id arguments for the redirect.
$arg_uri = 'uri=' . urlencode( $CFG_IDENTITY );
$arg_reqid = 'reqid=' . urlencode( $reqid );

header('Location: ' . $furi . 'returnrelid.php?' . $arg_uri . '&' . $arg_reqid );
