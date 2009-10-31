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

include( 'functions.php' );

global $CFG_URI;
global $CFG_PATH;
global $USER_NAME;
global $USER_URI;

?>

<html>
<head>
	<title><?php print $USER_NAME;?> </title>
	<link rel="stylesheet" type="text/css" href="<?php print $CFG_PATH;?>style.css"/>
</head>

<body>


<div id="leftcol">

<div id="details">

<a id="edit" href="edit">edit</a>
<h2><?php print $USER_NAME;?></h2>


</div>

<?php
if ( count( $friendRequests ) ) {
	echo '<div id="friend_requests">';
	echo "<h3>Friend Requests</h3>";
	foreach ( $friendRequests as $row ) {
		$from_id = $row['FriendRequest']['from_id'];
		$reqid = $row['FriendRequest']['reqid'];
		echo "<a href=\"$from_id\">$from_id</a>&nbsp;&nbsp;&nbsp;\n";
		echo "<a href=\"answer?reqid=" . urlencode($reqid) . 
				"&a=yes\">yes</a>&nbsp;&nbsp;\n";
		echo "<a href=\"answer?reqid=" . urlencode($reqid) . 
				"&a=no\">no</a><br>\n";
	}
	echo "</div>";
}
?>

<?php

if ( count( $sentFriendRequests ) > 0 ) {
	echo '<div id="sent_friend_requests">';
	echo "<h3>Sent Friend Requests</h3>";
	foreach ( $sentFriendRequests as $row ) {
		$for_id = $row['SentFriendRequest']['for_id'];

		//$reqid = $row['reqid'];
		echo "<a class=\"idlink\" href=\"$for_id\">$for_id</a>&nbsp;&nbsp;&nbsp;\n";
		echo "<a href=\"abandon.php?reqid=" . /*urlencode($reqid) . */
				"\">cancel</a><br>\n";
	}
	echo "</div>";
}
?>

<div id="friend_list">
<h3>Friend List</h3>

<?php

foreach ( $friendClaims as $row ) {
	$dest_id = $row['FriendClaim']['friend_id'];

	echo "<a class=\"idlink\" href=\"${dest_id}sflogin?h=" . 
		urlencode( $_SESSION['hash'] ) . "\">$dest_id</a> ";

	echo "<br>\n";
}
?>
</div>

<div id="photo_stream">

<h3>Photo Stream</h3>

<div id="photo_upload">
<form method="post" enctype="multipart/form-data" action="upload">
<input name="photo" type="file"/>
<input type="submit" value="Upload"/>
</form> 
</div>

<table class="photos">
<?php
$count = 0;
foreach ( $images as $row ) {
	$seq_num = $row['Image']['seq_num'];
	if ( $count % 2 == 0 ) {
		echo "<tr div class=\"photorow\">";
		echo "<td class=\"photo0\">";
	}
	else
		echo "<td class=\"photo1\">";

	echo "<a href=\"" . USER_URI . "image/img-$seq_num.jpg\">";
	echo "<img src=\"" . USER_URI . "image/thm-$seq_num.jpg\" alt=\"$seq_num\"></a>\n";
	echo "</td>";

	if ( $count % 2 == 1 )
		echo "</tr>";
	$count += 1;
}

if ( $count % 2 == 1 )
	echo "</tr>";
?>
</table>
</div>
</div>

<div id="activity">

<div id="broadcast">
<form method="post" action="broadcast">
Broadcast a Message to all Friends
<textarea rows="3" cols="65" name="message" wrap="physical"></textarea>
<input value="Submit Message" type="submit">
</form>
</div>

<div id="activity_stream">
<?
foreach ( $activity as $row ) {
	$author_id = $row[0]['author_id'];
	$subject_id = $row[0]['subject_id'];
	$time_published = $row[0]['time_published'];
	$type = $row[0]['type'];
	$resource_id = $row[0]['resource_id'];
	$message = $row[0]['message'];

	echo "<p>\n";
	printMessage( $author_id, $subject_id, $type, $resource_id, $message, $time_published );
}
?>

</div>

</div>

