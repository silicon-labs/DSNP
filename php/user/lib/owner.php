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
<h1>SPP: <?php print $USER_NAME;?></h1>

<p>Installation: <a href="../"><?php print $CFG_URI;?></a>

<p>You are logged in as <b><?php echo $USER_NAME;?></b> (<a href="logout.php">logout</a>)

<p>
<?php

/* Display friend requests. */
$query = sprintf("SELECT from_id, user_reqid FROM user_friend_request WHERE user = '%s';",
    mysql_real_escape_string($USER_NAME)
);
$result = mysql_query($query) or die('Query failed: ' . mysql_error());

while ( $row = mysql_fetch_assoc($result) ) {
	$from_id = $row['from_id'];
	$user_reqid = $row['user_reqid'];
    echo "friend request: <a href=\"$from_id\">$from_id</a>&nbsp;&nbsp;&nbsp;\n";
	echo "<a href=\"answer.php?user_reqid=" . urlencode($user_reqid) . 
			"&a=yes\">yes</a>&nbsp;&nbsp;\n";
	echo "<a href=\"answer.php?user_reqid=" . urlencode($user_reqid) . 
			"&a=no\">no</a><br>\n";
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
		echo "friend: <a href=\"${dest_id}sflogin.php?uri=" . 
			urlencode($browser_id) . "\">$dest_id</a> ";
	}
	else {
		echo "friend: <a href=\"${dest_id}\">$dest_id</a> ";
		echo "<small>(awaiting confirmation)</small>";
	}

	echo "<br>\n";
}

?>

<h1>Broadcast</h1>

<form method="post" action="broadcast.php">
<table>
<tr><td>Message:</td><td> <input type="text" name="message"></td></tr>
</table>
</form>

</html>

<h1>Messages</h1>
<?php

# Look for the user/pass combination.
$query = sprintf(
	"SELECT friend_id, message " .
	"FROM friend_claim " .
	"JOIN received ON friend_claim.get_relid = received.get_relid " .
	"WHERE user = '%s' ",
    mysql_real_escape_string($USER_NAME)
);

$result = mysql_query($query) or die('Query failed: ' . mysql_error());

$mehash = MD5( $USER_URI );

while ( $row = mysql_fetch_assoc($result) ) {
	$browser_id = $USER_URI;
	$friend_id = $row['friend_id'];
	$message = $row['message'];

	echo "<p>\n";
	echo "<a href=\"${dest_id}sflogin.php?uri=" . 
			urlencode($browser_id) . "\">$dest_id</a> says:<br>";
	echo $message . "<br>";
}

?>
