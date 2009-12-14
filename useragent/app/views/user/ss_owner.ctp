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

?>


<table><tr>
<td id="leftcol">

<div id="details">

<a id="edit" href="<?php echo $html->url( "/$USER_NAME/user/edit" );?>">edit</a>
<h2><?php echo $USER['display_short'];?></h2>

</div>

<?php
if ( count( $friendRequests ) ) {
	echo '<div class="content">';
	echo "<h3>Friend Requests</h3>";
	foreach ( $friendRequests as $row ) {
		$from_id = $row['FriendRequest']['from_id'];
		$reqid = $row['FriendRequest']['reqid'];
		echo $html->link( $from_id, $from_id );
		echo "&nbsp;&nbsp;&nbsp;\n";
		echo $html->link( 'yes', "/$USER_NAME/freq/answer?reqid=" . urlencode($reqid) . "&a=yes" );
		echo "&nbsp;&nbsp;\n";
		echo $html->link( 'no', "/$USER_NAME/freq/answer?reqid=" . urlencode($reqid) . "&a=no" );
		echo "<br>\n";
	}
	echo "</div>";
}
?>

<?php

if ( count( $sentFriendRequests ) > 0 ) {
	echo '<div class="content">';
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

<div class="content">
<h3>Friend List</h3>

<?php

foreach ( $friendClaims as $row ) {
	$name = $row['FriendClaim']['name'];
	$dest_id = $row['FriendClaim']['identity'];

	echo "<a class=\"idlink\" href=\"${dest_id}cred/sflogin?h=" . 
		urlencode( $_SESSION['hash'] ) . "\">";

	if ( isset( $name ) )
		echo $name;
	else
		echo $dest_id;

	echo "</a>";

	echo "<br>\n";
}
?>
</div>

<div class="content">
</div>

</td>

<td id="activity">

<?
#echo '<div>'; print_r( $activity ); echo '</div>';
?>

<div class="content">

<form method="post" action="<?echo $html->url( "/$USER_NAME/user/broadcast" ); ?>">
Broadcast a Message to all Friends
<textarea rows="3" cols="65" name="message" wrap="physical"></textarea>
<input value="Submit Message" type="submit">
</form>
</div>

<div class="content">

<h3>Wish Lists</h3>

<?php
echo "<pre>";
print_r ($USER );
echo " </pre>";

foreach ( $friendClaims as $row ) {
	$name = $row['FriendClaim']['name'];
	$dest_id = $row['FriendClaim']['identity'];
	$id = $row['FriendClaim']['id'];

	echo $html->link( $name, "/$USER_NAME/wish/edit/$id" );

	echo "</a>";

	echo "<br>\n";
}
?>
</div>

</div>

</td>
</tr></table>
