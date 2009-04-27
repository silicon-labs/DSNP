<?php

/* 
 * Copyright (c) 2007, Adrian Thurston <thurston@complang.org>
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
include('lib/session.php');

$furi = $_REQUEST['uri'];

if ( !$furi )
	die('no uri given');

$hash = md5($furi);

/* Maybe we are already logged in as this friend. */
if ( $_SESSION['auth'] == 'friend' && $_SESSION['hash'] == $hash ) {
	header( "Location: $USER_PATH" );
}
else {
	/* Not logged in as the hashed user. */
	$fp = fsockopen( 'localhost', $CFG_PORT );
	if ( !$fp )
		exit(1);

	$send = 
		"SPP/0.1 $CFG_URI\r\n" . 
		"comm_key $CFG_COMM_KEY\r\n" .
		"flogin $USER_NAME $hash\r\n";
	fwrite($fp, $send);

	$res = fgets($fp);

	if ( ereg("^OK ([0-9a-f]+)", $res, $regs) ) {
		$arg_uri = 'uri=' . urlencode( $USER_URI );
		$arg_reqid = 'reqid=' . urlencode( $regs[1] );
		header("Location: ${furi}retftok.php?${arg_uri}&${arg_reqid}" );
	}
}
