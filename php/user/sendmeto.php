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

requireOwner();

$uri = $_GET['uri'];

# Connect to the database.
$conn = mysql_connect($CFG_DB_HOST, $CFG_DB_USER, $CFG_ADMIN_PASS) or die 
	('Could not connect to database');
mysql_select_db($CFG_DB_DATABASE) or die
	('Could not select database ' . $CFG_DB_DATABASE);

$query = sprintf("SELECT friend_hash FROM friend_claim WHERE user='%s' AND friend_id='%s'",
    mysql_real_escape_string($USER_NAME),
    mysql_real_escape_string($uri)
);

$result = mysql_query($query) or die('Query failed: ' . mysql_error());

# If there is a result then the login is successful. 
$row = mysql_fetch_array($result, MYSQL_ASSOC);
if ( $row ) {
	# Is a friend. Send to the submit friend login page.
	header( "Location: ${uri}sflogin.php?uri=" . urlencode( $USER_URI ) );
}
else {
	# Not a friend. Just go to the home page.
	header( "Location: $uri" );
}
?>
