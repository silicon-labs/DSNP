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

iduri_session_start( $IDENTITY );

$furi = $_POST['uri'];
$data = read_data( );
$gnupg = new gnupg();

# Get the public key.
$fp = import_id( $gnupg, $furi, $HTTP_GET_TIMEOUT );

# Create a relationship id for the friend to use.
$putrelid = sha1( uniqid( mt_rand() ) );

# Store the fingerprint and relid. 
$data = read_data();
$data['putrelids'][$fp] = $putrelid;
$data['fingerprints'][$furi] = $fp;
write_data( $data );

# Create the relid message for the identity requesting friendship.
$enc = encrypt_sign( $gnupg, $fp, $putrelid );
publish_message( 'relid', $fp, $enc );

header('Location: ' . $furi . 'returnrelid.php?uri=' . urlencode( $IDENTITY ) );
