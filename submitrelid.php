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

$furi = $_GET['uri'];

# Fetch and decrypt the get and put relids.
$asc = $furi . 'getrelid.php?fp=' . $FINGERPRINT;
$response = http_get( $asc, array("timeout"=>$HTTP_GET_TIMEOUT), $info );
$message = http_parse_message( $response );
$gnupg = new gnupg();
$gnupg->setsignmode( gnupg::SIG_MODE_NORMAL );
$gnupg->adddecryptkey( $FINGERPRINT, "" );
$relids = "";
$res = $gnupg->decryptverify( $message->body, $relids );

# Get individual relids.
$s = split(' ', $relids);
$putrelid = $s[0];
$getrelid = $s[1];

# Store getrelid.
$data = readData();
$fp = $data['fingerprints'][$furi];
$data['getrelids'][$fp] = $getrelid;

if ( $putrelid == $data['putrelids'][$fp] ) {
	echo "friend request submitted<br>\n";
	echo "<a href=\"$IDENTITY\">back to profile</a>";

	/* Store the request for review. */
	$data['requests'][$furi] = 1;
}
else {
	echo "<center>\n";
	echo "FRIEND REQUEST FAILED<br>\n";
	echo "</center>\n";
}

writeData( $data );
