<?php

/* 
 * Copyright (c) 2007-2011 Adrian Thurston <thurston@complang.org>
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

require( ROOT . DS . 'view' . DS . 'functions.php' );

?>

<table><tr>

<td id="leftcol">

<div id="details">
	<?php echo $this->userLink( 'edit', '/user/edit', 'edit' );?>
    <h2><?php print $USER['NAME'];?></h2>
</div>

<?php
if ( count( $friendRequests ) ) {
	echo '<div class="content">';
	echo "<h3>" . $this->userLink("Friend Requests", "/friend/requests") . "</h3>";
	foreach ( $friendRequests as $row ) {
		$name = $row['name'];
		$iduri = $row['iduri'];
		$reqid = $row['accept_reqid'];
		echo $this->absLink( $name, $iduri, 'idlink' );
		echo "&nbsp;&nbsp;&nbsp;\n";
		echo $this->userLink( '<small>yes</small>', 
			"/freq/answer?reqid=" . 
			urlencode($reqid) . "&a=yes" );
		echo "&nbsp;&nbsp;\n";
		echo $this->userLink( '<small>no</small>',
			"/freq/answer?reqid=" .
			urlencode($reqid) . "&a=no" );
		echo "<br>\n";
	}
	echo "</div>";
}
?>

<?php

if ( count( $sentFriendRequests ) > 0 ) {
	echo '<div class="content">';
	echo "<h3>" . $this->userLink("Sent Friend Requests", "/friend/sent") . "</h3>";
	foreach ( $sentFriendRequests as $row ) {
		$name = $row['name'];
		$iduri = $row['iduri'];

		#$reqid = $row['requested_reqid'];
		echo $this->absLink( $name, $iduri, 'idlink' );
		echo "&nbsp;&nbsp;&nbsp;\n";
		echo $this->userLink( '<small>cancel</small>', "/freq/abandon?reqid=$reqid" );
		echo "<br>";
	}
	echo "</div>";
}
?>

<div class="content">

<h3><?php echo $this->userLink("Friend List", "/friend/list");?></h3>

<?php

foreach ( $friendClaims as $row ) {
	$name = $row['name'];
	$iduri = $row['iduri'];

	$arg_dsnp  = 'dsnp=ftoken_request';
	$arg_hash  = 'dsnp_hash=' . urlencode( $_SESSION['hash'] );

	$dest = addArgs( iduriToIdurl($iduri), "{$arg_dsnp}&{$arg_hash}" );

	echo "<a class=\"idlink\" href=\"${dest}\">";

	if ( isset( $name ) )
		echo $name;
	else
		echo $iduri;

	echo "</a>";

	echo "<br>\n";
}
?>
</div>

<div class="content">

<div id="photo_header">
<h3><?php echo $this->userLink("Photo Stream", "/image/stream");?></h3>
</div>

<table class="photo_sidebar">
<?php
$count = 0;
$perRow = 2;
foreach ( $images as $row ) {
	$seqNum = $row['seq_num'];
	if ( $count % $perRow == 0 ) {
		echo "<tr div class=\"photorow\">";
		echo "<td class=\"photo0\">";
	}
	else {
		echo "<td class=\"photo1\">";
	}

	$img = $this->userImg( "/image/view/thm-$seqNum.jpg", $seqNum );
	echo $this->userLink( $img, "/image/display/img-$seqNum.jpg" );

	echo "</td>";

	if ( $count % $perRow == ($perRow - 1) )
		echo "</tr>";
	$count += 1;
}

if ( $count % $perRow == ($perRow - 1) )
	echo "</tr>";
?>
</table>
</div>
</td>

<td id="activity">

<div class="content">
<form method="post" action="<?echo $this->userLoc( "/user/broadcast" ); ?>">
Broadcast a Message to all Friends<br>
<textarea rows="3" cols="65" name="message" wrap="physical"></textarea><br>
<input value="Submit Message" type="submit">
</form>
</div>

<div class="content">
<?

$activity_size = ACTIVITY_SIZE;
$limit = $start + $activity_size < count( $activity ) ? 
		$start + $activity_size : count( $activity );
for ( $i = $start; $i < $limit; $i++ ) {
	$row = $activity[$i];

	$author = $row;
	$subject = $row;
	$item = $row;

	echo "<p>\n";
	printMessage( $this, $text, $USER, $USER, $author, $subject, $item );
}

if ( $start > 0 ) 
	echo $this->userLink( 'newer', "/user/index?start=" . ( $start - $activity_size ) ) . "&nbsp;&nbsp;";

if ( count( $activity ) == $start + $activity_size )
	echo $this->userLink( 'older', "/user/index?start=" . ( $start + $activity_size ) );
?>

</div>

</td>

</tr></table>
