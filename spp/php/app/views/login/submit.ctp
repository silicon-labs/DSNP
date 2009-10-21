<?php

/* 
 * Copyright (c) 2007, 2009 Adrian Thurston <thurston@complang.org>
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

# No session yet. Maybe going to set it up.

global $CFG_PORT;
global $CFG_URI;
global $CFG_COMM_KEY;
global $USER_NAME;
global $USER_PATH;

$pass = $_POST['pass'];

$fp = fsockopen( 'localhost', $CFG_PORT );
if ( !$fp )
	exit(1);

$send = 
	"SPP/0.1 $CFG_URI\r\n" . 
	"comm_key $CFG_COMM_KEY\r\n" .
	"login $USER_NAME $pass\r\n";
fwrite($fp, $send);

$res = fgets($fp);
#echo $res;
#exit;
if ( !ereg("^OK ([-A-Za-z0-9_]+) ([-A-Za-z0-9_]+) ([0-9]+)", $res, $regs) ) {
	include('lib/loginfailed.php');
}
else {
	session_name("SPPSESSID");
	session_set_cookie_params( $regs[3], $USER_PATH );
	session_start();

	# Login successful.
	$_SESSION['auth'] = 'owner';
	$_SESSION['hash'] = $regs[1];
	$_SESSION['token'] = $regs[2];
	header( "Location: $USER_PATH" );
}

?>
