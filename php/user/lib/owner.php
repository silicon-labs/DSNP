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

include( "lib/functions.php" );

# Connect to the database.
$conn = mysql_connect($CFG_DB_HOST, $CFG_DB_USER, $CFG_ADMIN_PASS) or die 
	('Could not connect to database');
mysql_select_db($CFG_DB_DATABASE) or die
	('Could not select database ' . $CFG_DB_DATABASE);

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

<p>You are logged in as <b><?php echo $USER_NAME;?></b> (<a href="logout.php">logout</a>)

<p>
<?php

/* Display friend requests. */
$query = sprintf("SELECT from_id, reqid FROM friend_request WHERE for_user = '%s';",
    mysql_real_escape_string($USER_NAME)
);
$result = mysql_query($query) or die('Query failed: ' . mysql_error());

if ( mysql_num_rows( $result ) > 0 ) {
	echo "<h1>Friend Requests</h1>";
	while ( $row = mysql_fetch_assoc($result) ) {
		$from_id = $row['from_id'];
		$reqid = $row['reqid'];
		echo "friend request: <a href=\"$from_id\">$from_id</a>&nbsp;&nbsp;&nbsp;\n";
		echo "<a href=\"answer.php?reqid=" . urlencode($reqid) . 
				"&a=yes\">yes</a>&nbsp;&nbsp;\n";
		echo "<a href=\"answer.php?reqid=" . urlencode($reqid) . 
				"&a=no\">no</a><br>\n";
	}
}
?>


<h1>Friend List</h1>

<?php

# Look for the user/pass combination.
$query = sprintf("SELECT friend_id, acknowledged FROM friend_claim WHERE user = '%s';",
    mysql_real_escape_string($USER_NAME)
);

$result = mysql_query($query) or die('Query failed: ' . mysql_error());

$mehash = MD5( $USER_URI );

while ( $row = mysql_fetch_assoc($result) ) {
	$browser_id = $USER_URI;
	$dest_id = $row['friend_id'];
	$acknowledged = $row['acknowledged'];

	if ( $acknowledged ) {
		echo "<a href=\"${dest_id}sflogin.php?uri=" . 
			urlencode($browser_id) . "\"><small>$dest_id</small></a> ";
	}
	else {
		echo "<a href=\"${dest_id}\"><small>$dest_id</small></a> ";
		echo "<small>(awaiting confirmation)</small>";
	}

	echo "<br>\n";
}

?>
</td>
<td width="70%" valign="top">

<h1>Broadcast</h1>

<small> Messages typed here are sent to all of your friends. At present, only
text messages are supported. However, one can imagine many different types of
notifications being implemented, including picutre uploads, tag notifications,
status changes, and contact information changes.</small>
<hr>
<p>

<form method="post" action="broadcast.php">
<table>
<tr><td>Message:</td></tr>
<!--<input type="text" name="message" size="50">-->
<tr><td>
<textarea rows="5" cols="65" name="message" wrap="physical"></textarea>
</td></tr>
<tr><td>
<input value="Submit Message" type="submit">
</td></tr>


</table>
</form>

<?

$query = sprintf(
	"SELECT friend_id, time_published, message " .
	"FROM friend_claim " .
	"JOIN received ON friend_claim.get_relid = received.get_relid " .
	"WHERE user = '%s' " .
	"UNION select user, time_published, message from published where user = '%s' " .
	"ORDER BY time_published DESC",
    mysql_real_escape_string($USER_NAME),
    mysql_real_escape_string($USER_NAME)
);

$result = mysql_query($query) or die('Query failed: ' . mysql_error());

$mehash = MD5( $USER_URI );

while ( $row = mysql_fetch_assoc($result) ) {
	$friend_id = $row['friend_id'];
	$time_published = $row['time_published'];
	$message = $row['message'];

	echo "<p>\n";
	printMessage( null, $friend_id, $message, $time_published );
}

?>

</td>
</tr>
</table>

</body>
</html>

