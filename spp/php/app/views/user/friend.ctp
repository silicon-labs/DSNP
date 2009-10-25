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

include('functions.php');

$BROWSER_ID = $_SESSION['identity'];

global $CFG_DB_DATABASE;
global $CFG_DB_USER;
global $CFG_DB_HOST;
global $CFG_ADMIN_PASS;
global $CFG_URI;
global $CFG_PORT;
global $CFG_COMM_KEY;
global $CFG_PATH;
global $USER_NAME;
global $USER_URI;
global $USER_PATH;


?>

<table width="100%" cellpadding=12 cellspacing=0>

<tr>
<td valign="top">

<h2>SPP: <?php print $USER_NAME;?></h2>

<p>Installation: <a href="../"><small><?php print $CFG_URI;?></small></a>

<p>You are logged in as a <a href="<?php echo $BROWSER_ID;?>"><b>friend</b></a> (<a href="logout">logout</a>)<br>

<h2>Friend List</h2>

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
	if ( $dest_id == $BROWSER_ID ) {
		echo "you: <a href=\"${dest_id}\"><small>$dest_id</small></a> <br>\n";
	}
	else {
		echo "<a href=\"${dest_id}sflogin.php?h=" . 
			urlencode( $_SESSION['hash'] ) .
			"\"><small>$dest_id</small></a> <br>\n";
	}
}

?>

<h2>Photo Stream</h2>

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
<td width="%70" valign="top">

<!--
<h2>Stories</h2>

<small> Messages typed here are sent to all of <?php print $USER_NAME;?>'s friends. 
</small>
<p>
-->

<hr>
<form method="post" action="wall">
<table>
<tr><td>Write on <?php print $USER_NAME;?>'s message board:</td></tr>
<!--<input type="text" name="message" size="50">-->
<tr><td>
<textarea rows="3" cols="65" name="message" wrap="physical"></textarea>
</td></tr>
<tr><td>
<input value="Submit" type="submit">
</td></tr>


</table>
</form>

<?

$query = sprintf(
	"SELECT author_id, subject_id, time_published, type, message " .
	"FROM published " . 
	"WHERE user = '%s' " .
	"UNION " .
	"SELECT author_id, subject_id, time_published, type, message " .
	"FROM remote_published " .
	"WHERE user = '%s' " .
	"ORDER BY time_published DESC",
	mysql_real_escape_string($USER_NAME),
	mysql_real_escape_string($USER_NAME)
);

$result = mysql_query($query) or die('Query failed: ' . mysql_error());

while ( $row = mysql_fetch_assoc($result) ) {
	$author_id = $row['author_id'];
	$subject_id = $row['subject_id'];
	$time_published = $row['time_published'];
	$type = $row['type'];
	$message = $row['message'];

	echo "<p>\n";
	
	printMessage( $author_id, $subject_id, $type, 0, $message, $time_published );
}
?>

</td>
</tr>
</table>

