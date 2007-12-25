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
$friends = $data['friends'];
$putrelids = $data['putrelids'];

if ( !isset( $friends[$furi] ) ) {
	echo "<center>\n";
	echo "Not a friend of mine<br><br>\n";
	friendLoginForm();
	echo "</center>\n";
}
else {
	$gnupg = new gnupg();
	$gnupg->setsignmode( gnupg::SIG_MODE_NORMAL );
	$gnupg->addencryptkey( $friends[$furi] );
	$gnupg->addsignkey( $FINGERPRINT, '' );
	$token = sha1( uniqid( mt_rand() ) );
	$_SESSION['tok'] = $token;
	$enc = $gnupg->encryptsign( $token );
	$fn = 'tokens/' . $putrelids[$friends[$furi]] . '.asc';
	$fd = fopen( $fn, 'wt' );
	fwrite( $fd, $enc );
	fclose( $fd );
	chmod( $fn, 0644 );


	header('Location: ' . $furi . 'returnftok.php?uri=' . urlencode( $IDENTITY ) );
}
