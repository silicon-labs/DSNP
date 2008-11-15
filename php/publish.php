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

include( 'config.php' );
include( 'lib/iduri.php' );

iduriSessionStart();

requireOwner();

$data = readData();

$friends = $data['friends'];
$putrelids = $data['putrelids'];

$gnupg = new gnupg();
foreach ( $friends as $uri => $fp ) {
	$enc = encryptSign( $gnupg, $fp, serialize($friends) );
	publishMessage( 'feeds', $putrelids[$fp], $enc );
}

header('Location: ' . $CFG_IDENTITY );
?>
