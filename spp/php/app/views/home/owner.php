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

include( ROOT . '/../orig/user/lib/functions.php' );

global $CFG_DB_HOST;
global $CFG_DB_USER;
global $CFG_ADMIN_PASS;
global $CFG_DB_DATABASE;
global $CFG_URI;
global $CFG_PATH;
global $USER_NAME;
global $USER_URI;

# Connect to the database.
$conn = mysql_connect($CFG_DB_HOST, $CFG_DB_USER, $CFG_ADMIN_PASS) or die 
	('Could not connect to database');
mysql_select_db($CFG_DB_DATABASE) or die
	('Could not select database ' . $CFG_DB_DATABASE);

?>

<html>
<head>
	<title><?php print $USER_NAME;?> </title>
	<link rel="stylesheet" type="text/css" href="<?php print $CFG_PATH;?>style.css"/>
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
		echo "<a href=\"$from_id\">$from_id</a>&nbsp;&nbsp;&nbsp;\n";
		echo "<a href=\"answer.php?reqid=" . urlencode($reqid) . 
				"&a=yes\">yes</a>&nbsp;&nbsp;\n";
		echo "<a href=\"answer.php?reqid=" . urlencode($reqid) . 
				"&a=no\">no</a><br>\n";
	}
}

/* Display friend requests made to others. */
$query = sprintf("SELECT for_id FROM sent_friend_request WHERE from_user = '%s';",
	mysql_real_escape_string($USER_NAME)
);
$result = mysql_query($query) or die('Query failed: ' . mysql_error());

if ( mysql_num_rows( $result ) > 0 ) {
	echo "<h1>Sent Friend Requests</h1>";
	while ( $row = mysql_fetch_assoc($result) ) {
		$for_id = $row['for_id'];
		//$reqid = $row['reqid'];
		echo "<a class=\"idlink\" href=\"$for_id\">$for_id</a>&nbsp;&nbsp;&nbsp;\n";
		echo "<a href=\"abandon.php?reqid=" . /*urlencode($reqid) . */
				"\">cancel</a><br>\n";
	}
}
?>


<h1>Friend List</h1>

<?php

# Look for the user/pass combination.
$query = sprintf("SELECT friend_id FROM friend_claim WHERE user = '%s';",
	mysql_real_escape_string($USER_NAME)
);

$result = mysql_query($query) or die('Query failed: ' . mysql_error());

while ( $row = mysql_fetch_assoc($result) ) {
	$dest_id = $row['friend_id'];

	echo "<a class=\"idlink\" href=\"${dest_id}sflogin.php?h=" . 
		urlencode( $_SESSION['hash'] ) . "\">$dest_id</a> ";

	echo "<br>\n";
}

?>

<h1>Photo Stream</h1>

<?php

# Look for the user/pass combination.
$query = sprintf("SELECT seq_num FROM image WHERE user = '%s' ORDER BY seq_num DESC LIMIT 20;",
	mysql_real_escape_string($USER_NAME)
);

$result = mysql_query($query) or die('Query failed: ' . mysql_error());

while ( $row = mysql_fetch_assoc($result) ) {
	$seq_num = $row['seq_num'];
	echo "<a href=\"${USER_URI}img/img-$seq_num.jpg\">";
	echo "<img src=\"${USER_URI}img/thm-$seq_num.jpg\" alt=\"$seq_num\"></a><br>\n";
}

?>
</td>
<td width="70%" valign="top">

<hr>

<!--
<h1>Broadcast</h1>
<small> Messages typed here are sent to all of your friends. At present, only
text messages are supported. However, one can imagine many different types of
notifications being implemented, including picutre uploads, tag notifications,
status changes, and contact information changes.</small>
<p>
-->

<form method="post" action="broadcast.php">
<table>
<tr><td>Broadcast a Message:</td></tr>
<!--<input type="text" name="message" size="50">-->
<tr><td>
<textarea rows="3" cols="65" name="message" wrap="physical"></textarea>
</td></tr>
<tr><td>
<input value="Submit Message" type="submit">
</td></tr>


</table>
</form>

<hr>

<form method="post" enctype="multipart/form-data" action="upload.php">
Photo Upload: <input name="photo" type="file" />
<input type="submit" value="Upload" />
</form> 

<hr>

<?

$query = sprintf(
	"SELECT author_id, subject_id, time_published, type, resource_id, message " .
	"FROM received " .
	"WHERE for_user = '%s' " .
	"UNION " .
	"SELECT author_id, subject_id, time_published, type, resource_id, message " .
	"FROM published " . 
	"WHERE user = '%s' " .
	"UNION " .
	"SELECT author_id, subject_id, time_published, type, resource_id, message " .
	"FROM remote_published " .
	"WHERE user = '%s' " .
	"ORDER BY time_published DESC",
	mysql_real_escape_string($USER_NAME),
	mysql_real_escape_string($USER_NAME),
	mysql_real_escape_string($USER_NAME)
);

$result = mysql_query($query) or die('Query failed: ' . mysql_error());

while ( $row = mysql_fetch_assoc($result) ) {
	$author_id = $row['author_id'];
	$subject_id = $row['subject_id'];
	$time_published = $row['time_published'];
	$type = $row['type'];
	$resource_id = $row['resource_id'];
	$message = $row['message'];

	echo "<p>\n";
	printMessage( $author_id, $subject_id, $type, $resource_id, $message, $time_published );
}

?>

</td>
</tr>
</table>

</body>
</html>

