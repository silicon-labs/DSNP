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

include('lib/functions.php');

$browser_id = $_SESSION['identity'];

?>

<html>
<head>
<title><?php print $USER_NAME;?> </title>
</head>

<body>

<table width="100%" cellpadding=12 cellspacing=0>

<tr>
<td valign="top">

<h1>SPP: <?php print $USER_NAME;?></h1>

<p>Installation: <a href="../"><small><?php print $CFG_URI;?></small></a>

<p>You are logged in as a <a href="<?php echo $browser_id;?>"><b>friend</b></a> (<a href="logout.php">logout</a>)<br>

<h1>Friend List</h1>

<?php

# Connect to the database.
$conn = mysql_connect($CFG_DB_HOST, $CFG_DB_USER, $CFG_ADMIN_PASS) or die 
	('Could not connect to database');
mysql_select_db($CFG_DB_DATABASE) or die
	('Could not select database ' . $CFG_DB_DATABASE);

# Look for the user/pass combination.
$query = sprintf("SELECT friend_id FROM friend_claim WHERE user = '%s';",
    mysql_real_escape_string($USER_NAME)
);

$result = mysql_query($query) or die('Query failed: ' . mysql_error());

while ( $row = mysql_fetch_assoc($result) ) {
	$dest_id = $row['friend_id'];
	if ( $dest_id == $browser_id ) {
		echo "you: <a href=\"${dest_id}\"><small>$dest_id</small></a> <br>\n";
	}
	else {
		echo "<a href=\"${browser_id}sendmeto.php?uri=" . 
			urlencode($dest_id) . 
			"\"><small>$dest_id</small></a> <br>\n";
	}
}

?>

</td>
<td width="%70" valign="top">

<h1>Stories about <?php print $USER_NAME;?></h1>

<?
$query = sprintf(
	"SELECT time_published, message " .
	"FROM published " .
	"WHERE user = '%s' " .
	"ORDER BY seq_id DESC",
    mysql_real_escape_string($USER_NAME)
);

$result = mysql_query($query) or die('Query failed: ' . mysql_error());

$mehash = MD5( $USER_URI );

while ( $row = mysql_fetch_assoc($result) ) {
	$browser_id = $USER_URI;
	$time_published = $row['time_published'];
	$message = $row['message'];

	echo "<p>\n";
	printMessage( $USER_NAME, null, $message, $time_published );
}
?>

</td>
</tr>
</table>

</body>

</html>
