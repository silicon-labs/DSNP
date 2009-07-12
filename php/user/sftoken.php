<?php

/* 
 * Copyright (c) 2007-2009, Adrian Thurston <thurston@complang.org>
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

include('../config.php');

# No session yet. Maybe going to set it up.

$ftoken = $_GET['ftoken'];

$fp = fsockopen( 'localhost', $CFG_PORT );
if ( !$fp )
	exit(1);

$send = 
	"SPP/0.1 $CFG_URI\r\n" . 
	"comm_key $CFG_COMM_KEY\r\n" .
	"submit_ftoken $ftoken\r\n";
fwrite($fp, $send);

$res = fgets($fp);

# If there is a result then the login is successful. 
if ( ereg("^OK ([-A-Za-z0-9_]+) ([0-9a-f]+) ([^ \t\r\n]*)", $res, $regs) ) {
	session_name("SPPSESSID");
	session_set_cookie_params( $regs[1], $USER_PATH );
	session_start();

	# Login successful.
	$_SESSION['auth']     = 'friend';
	$_SESSION['token']    = $ftoken;
	$_SESSION['hash']     = $regs[1]; 
	$_SESSION['identity'] = $regs[3];

	if ( isset( $_GET['d'] ) )
		header( "Location: " . $_GET['d'] );
	else
		header( "Location: $USER_PATH" );
}
else {
	echo "<center>\n";
	echo "FRIEND LOGIN FAILED<br>\n";
	echo "</center>\n";
}
