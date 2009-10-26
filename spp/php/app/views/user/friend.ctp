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

?>

<div id="leftcol">

<div id="details">

<h2>SPP: <?php print USER_NAME;?></h2>

<p>Installation: <a href="../"><?php print CFG_URI;?></a>

<p>You are logged in as a <a href="<?php echo $BROWSER_ID;?>"><b>friend</b></a> (<a href="logout">logout</a>)<br>

</div>

<div id="friend_list">

<h2>Friend List</h2>

<?php

foreach ( $friendClaims as $row ) {
	$dest_id = $row['FriendClaim']['friend_id'];
	if ( $dest_id == $BROWSER_ID ) {
		echo "you: <a href=\"${dest_id}\">$dest_id</a> <br>\n";
	}
	else {
		echo "<a href=\"${dest_id}sflogin.php?h=" . 
			urlencode( $_SESSION['hash'] ) .
			"\">$dest_id</a> <br>\n";
	}
}

?>

</div>
<div id="photo_stream">

<h2>Photo Stream</h2>

<?php

foreach ( $images as $row ) {
	$seq_num = $row['Image']['seq_num'];
	echo "<a href=\"". USER_URI . "img/img-$seq_num.jpg\">";
	echo "<img src=\"" . USER_URI . "img/thm-$seq_num.jpg\" alt=\"$seq_num\"></a><br>\n";
}

?>
</div>

<!--
<h2>Stories</h2>

<small> Messages typed here are sent to all of <?php print USER_NAME;?>'s friends. 
</small>
<p>
-->

</div>
<div id="activity">

<div id="broadcast">

<form method="post" action="wall">

Write on <?php print USER_NAME;?>'s message board:
<!--<input type="text" name="message" size="50">-->
<textarea rows="3" cols="65" name="message" wrap="physical"></textarea>
<input value="Submit" type="submit">


</form>
</div>
<div id="activity_stream">

<?

foreach ( $activity as $row ) {
	$author_id = $row[0]['author_id'];
	$subject_id = $row[0]['subject_id'];
	$time_published = $row[0]['time_published'];
	$type = $row[0]['type'];
	$message = $row[0]['message'];

	echo "<p>\n";
	
	printMessage( $author_id, $subject_id, $type, 0, $message, $time_published );
}
?>
</div>

</div>
