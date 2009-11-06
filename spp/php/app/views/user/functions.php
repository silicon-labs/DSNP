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


function printName( $USER_NAME, $USER_URI, $BROWSER_ID, $identity, $name, $possessive )
{
	if ( !$identity || !isset($BROWSER_ID) && $identity == $USER_URI || 
			isset($BROWSER_ID) && $BROWSER_ID == $identity )
	{
		if ( $possessive )
			echo "<font class=\"msgwho\"> your </font>";
		else
			echo "<font class=\"msgwho\"> you </font>";
	}
	else if ( isset( $BROWSER_ID ) && $identity == $USER_URI ) {
		echo "<font class=\"msgwho\">";
		echo $USER_NAME;
		if ( $possessive )
			echo "'s";
		echo "</font>";
	}
	else {
		echo "<a href=\"${identity}cred/sflogin?h=" . urlencode($_SESSION['hash']);
		echo "\"> <font class=\"msgwho\">";
		if ( isset( $name ) )
			echo $name;
		else
			echo $identity;
		echo "</font></a>";
		if ( $possessive )
			echo "<font class=\"msgwho\">'s</font>";
	}
}

function printMessage( $USER_NAME, $USER_URI, $BROWSER_ID,
		$author_id, $author_name, $subject_id, $subject_name,
		$type, $resource_id, $message, $time_published )
{
	echo '<div class="msgdisp">';
	if ( $type == 'PHT' ) {
		echo '<div class="msgabout">';
		echo "<font class=\"msgtime\">$time_published</font><br>";
		printName( $USER_NAME, $USER_URI, $BROWSER_ID, $author_id, $author_name, false );
		echo "<font class=\"msgaction\"> uploaded a photo </font>";
		echo '</div>';

		echo '<div class="msgphoto">';
		if ( $resource_id > 0 ) {
			echo "<a href=\"${author_id}image/view/img-$resource_id.jpg?h=" . 
				urlencode($_SESSION['hash']) . "\">";
		}
		else {
			echo "<a href=\"image/view/$message\">";
		}
		echo "<img src=\"image/view/$message\" alt=\"$message\"></a>\n";
		echo '</div>';
	}
	else if ( $type == 'MSG' ) {
		echo '<div class="msgabout">';
		echo "<font class=\"msgtime\">$time_published</font><br>";
		printName( $USER_NAME, $USER_URI, $BROWSER_ID, $author_id, $author_name, false );
		echo "<font class=\"msgaction\"> posted </font>";
		echo '</div>';

		echo htmlspecialchars($message);
	}
	else if ( $type == 'BRD' ) {
		echo '<div class="msgabout">';
		echo "<font class=\"msgtime\">$time_published</font><br>";
		printName( $USER_NAME, $USER_URI, $BROWSER_ID, $author_id, $author_name, false );
		echo "<font class=\"msgaction\"> wrote on ";
		printName( $USER_NAME, $USER_URI, $BROWSER_ID, $subject_id, $subject_name, true );
		echo " board</font>";
		echo '</div>';

		echo htmlspecialchars($message);
	}
	echo '</div>';
}

?>
