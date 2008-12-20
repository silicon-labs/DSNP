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

include('../config.php');
include('lib/session.php');

$furi = $_POST['uri'];

# Connect to the database.
$conn = mysql_connect($CFG_DB_HOST, $CFG_DB_USER, $CFG_ADMIN_PASS) or die 
	('Could not connect to database');
mysql_select_db($CFG_DB_DATABASE) or die
	('Could not select database ' . $CFG_DB_DATABASE);

$query = sprintf(
		"SELECT put_relid, get_relid FROM friend_claim " . 
		"WHERE user='%s' AND friend_id='%s'",
    mysql_real_escape_string($USER_NAME),
    mysql_real_escape_string($furi)
);

$result = mysql_query($query) or die('Query failed: ' . mysql_error());

# If there is a result then the login is successful. 
$line = mysql_fetch_array($result, MYSQL_ASSOC);

$fp = fsockopen( 'localhost', $CFG_PORT );
if ( !$fp )
	exit(1);

$send = 
	"SPP/0.1\r\n" . 
	"flogin $USER_NAME $furi\r\n";
fwrite($fp, $send);

$res = fgets($fp);

if ( ereg("^OK ([0-9a-f]+)", $res, $regs) ) {
	$arg_uri = 'uri=' . urlencode( $USER_URI ) . '/';
	$arg_reqid = 'reqid=' . urlencode( $regs[1] );
	header("Location: ${furi}retftok.php?${arg_uri}&${arg_reqid}" );
}
