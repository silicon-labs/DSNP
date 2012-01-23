<?php

/* 
 * Copyright (c) 2007-2011, Adrian Thurston <thurston@complang.org>
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
    <h2><?php print $USER['NAME'];?></h2>
</div>

<div class="content">

<?php

echo '<h3>' . $this->userLink("Friend List", "/friend/list") . '</h3>';

foreach ( $friendClaims as $row ) {
	$name = $row['name'];
	$iduri = $row['iduri'];

	echo "<a href=\"${iduri}\">";
	if ( isset( $name ) )
		echo $name;
	else
		echo $iduri;
	echo "</a> <br>\n";
}

?>

</div>

<div class="content">

<div id="photo_header">
<?php echo '<h3>' . $this->userLink("Photo Stream", "/image/stream") . '</h3>'; ?>
</div>

<table class="photo_sidebar">
<?php
$count = 0;
$perRow = 2;
foreach ( $images as $row ) {
	$seqNum = $row['seq_num'];
	if ( ($count % $perRow) == 0 ) {
		echo "<tr div class=\"photorow\">\n";
		echo "<td class=\"photo0\">";
	}
	else
		echo "<td class=\"photo1\">";

	$img = $this->userImg( "/image/view/thm-$seqNum.jpg", $seqNum );
	echo $this->userLink( $img, "/image/display/img-$seqNum.jpg" );

	echo "</td>\n";

	if ( ($count % $perRow) == ($perRow-1) )
		echo "</tr>\n";
	$count += 1;
}

if ( ($count % $perRow) == ($perRow-1) )
	echo "</tr>";
?>
</table>
</div>

</td>

<td id="activity">

<div class="content">

<form method="post" action="<?php echo $this->userLoc("/user/board");?>">

Write on <?php print $USER['NAME'];?>'s message board:
<p>
<!--<input type="text" name="message" size="50">-->
<textarea rows="3" cols="65" name="message" wrap="physical"></textarea>
<p><input value="Submit" type="submit">

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
	printMessage( $this, $text, $USER, $BROWSER, $author, $subject, $item );
}

if ( $start > 0 ) 
	echo $html->link( 'newer', "/$USER_NAME/user/index?start=" . ( $start - $activity_size ) ) . "&nbsp;&nbsp;";

if ( count( $activity ) == $start + $activity_size )
	echo $html->link( 'older', "/$USER_NAME/user/index?start=" . ( $start + $activity_size ) );
?>

</div>

</td>
</tr></table>

