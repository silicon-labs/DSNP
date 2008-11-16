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
include('lib/iduri.php');

iduriSessionStart();

$spp_login = $_GET['u'];
$spp_pass = $_POST['password'];
$spp_md5pass = md5( $login . ':iduri:' . $pass );

$db_host = 'localhost';
$db_user = 'iduri';
$db_pass = $CFG_DB_PASS;

$conn = mysql_connect($db_host, $db_user, $db_pass) or die 
	('Could not connect to database');
mysql_select_db('iduri') or die
	('Could not select database \'iduri\'');

$query = 'select * from user;';
$result = mysql_query($query) or die('Query failed: ' . mysql_error());

$line = mysql_fetch_array($result, MYSQL_ASSOC);
if ( $line ) {
	# Login successful.
	$_SESSION['auth'] = 'owner';
	header( "Location: ${CFG_INSTALLATION}id/$spp_login/" );
}
else {
	echo "<center>\n";
	echo "LOGIN FAILED<br><br>\n";
	loginForm();
	echo "</center>\n";
}
?>
