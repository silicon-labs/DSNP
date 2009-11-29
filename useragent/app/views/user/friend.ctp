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

<h2><?php print $USER['display_short'];?></h2>

</div>

<div id="friend_list">

<h3>Friend List</h3>

<?php

foreach ( $friendClaims as $row ) {
	$name = $row['FriendClaim']['name'];
	$dest_id = $row['FriendClaim']['identity'];

	if ( $dest_id == $BROWSER['identity'] ) {
		echo "you: <a href=\"${dest_id}\">";
		if ( isset( $name ) )
			echo $name;
		else
			echo $dest_id;
		echo "</a> <br>\n";
	}
	else {
		echo "<a href=\"${dest_id}cred/sflogin?h=" . 
			urlencode( $_SESSION['hash'] ) . "\">";
		if ( isset( $name ) )
			echo $name;
		else
			echo $dest_id;
		echo "</a> <br>\n";
	}
}

?>

</div>
<div id="photo_stream">

<h3>Photo Stream</h3>

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

	echo "<a href=\"". $USER_URI . "image/view/img-$seq_num.jpg\">";
	echo "<img src=\"" . $USER_URI . "image/view/thm-$seq_num.jpg\" alt=\"$seq_num\"></a><br>\n";
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

<form method="post" action="<?php echo $html->url("/$USER_NAME/user/board");?>">

Write on <?php print $USER_NAME;?>'s message board:
<!--<input type="text" name="message" size="50">-->
<textarea rows="3" cols="65" name="message" wrap="physical"></textarea>
<input value="Submit" type="submit">


</form>
</div>
<div id="activity_stream">

<?

$activity_size = Configure::read('activity_size');
$limit = $start + $activity_size < count( $activity ) ? $start + $activity_size : count( $activity );
for ( $i = $start; $i < $limit; $i++ ) {
	$row = $activity[$i];

	$author = $row['AuthorFC'];
	$subject = $row['SubjectFC'];
	$item = $row['Activity'];

	echo "<p>\n";
	printMessage( $html, $USER, $BROWSER, $author, $subject, $item );
}

if ( $start > 0 ) 
	echo $html->link( 'newer', "/$USER_NAME/user/index?start=" . ( $start - $activity_size ) ) . "&nbsp;&nbsp;";

if ( count( $activity ) == $start + $activity_size )
	echo $html->link( 'older', "/$USER_NAME/user/index?start=" . ( $start + $activity_size ) );
?>

</div>

</div>
