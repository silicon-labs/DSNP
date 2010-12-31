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

function printName( $USER, $BROWSER, $identity, $name, $possessive )
{
	if ( !isset($identity) && isset($BROWSER) ) {
		echo "<font class=\"msgwho\">";
		echo $USER['display_short'];
		if ( $possessive )
			echo "'s";
		echo "</font>";
	}
	else if ( !isset($identity) || 
			!isset($BROWSER) && $identity == $USER['identity'] || 
			isset($BROWSER) && $identity == $BROWSER['identity'] )
	{
		if ( $possessive )
			echo "<font class=\"msgwho\"> your </font>";
		else
			echo "<font class=\"msgwho\"> you </font>";
	}
	else {
		echo "<a href=\"${identity}cred/sflogin?h=" . urlencode($_SESSION['hash']) . "\">";
		echo "<font class=\"msgwho\">";
		if ( isset( $name ) )
			echo $name;
		else
			echo $identity;
		echo "</font></a>";
		if ( $possessive )
			echo "<font class=\"msgwho\">'s</font>";
	}
}

function printMessage( $view, $text, $USER, $BROWSER, $author, $subject, $item )
{
	$USER_NAME = $USER['user'];

	$author_id = $author['author_identity'];
	$author_name = $author['author_name'];

	$subject_id = $subject['subject_identity'];
	$subject_name = $subject['subject_name'];

	$time_published = $item['time_published'];
	$type = $item['type'];
	$local_resid = $item['local_resid'];
	$remote_resid = $item['remote_resid'];
	$message = $item['message'];
	$published = $item['published'];

	echo '<div class="msgdisp">';
	echo '<table><tr>';
	if ( $type == 'PHT' ) {
		echo '<td class="msgleft">';
		echo '<div class="msgabout">';
		echo "<font class=\"msgtime\">" . str_replace( ' ', ' &nbsp; ', $time_published ) . "</font><br>";
		printName( $USER, $BROWSER, $author_id, $author_name, false );
		echo "<font class=\"msgaction\"> uploaded a photo </font>";
		echo '</div>';
		echo '</td>';

		echo '<td class="msgbody">';
		echo '<div class="msgphoto">';
		if ( isset( $remote_resid ) ) {
			echo "<a href=\"${author_id}image/view/img-$remote_resid.jpg?h=" . 
				urlencode($_SESSION['hash']) . "\">";
			echo "<img src=\"" . $view->userLoc( "/$USER_NAME/image/view/pub-$local_resid.jpg" ) . 
				"\" alt=\"$message\"></a>\n";
		}
		else {
			echo "<a href=\"" . $view->userLoc( "/$USER_NAME/image/view/img-$local_resid.jpg" ) . "\">";
			echo "<img src=\"" . $view->userLoc( "/$USER_NAME/image/view/thm-$local_resid.jpg" ) . 
					"\" alt=\"$message\"></a>\n";
		}
		echo '</div>';
		echo '</td>';
	}
	else if ( $type == 'MSG' ) {
		echo '<td class="msgleft">';
		echo '<div class="msgabout">';
		echo "<font class=\"msgtime\">" . str_replace( ' ', ' &nbsp; ', $time_published ) . "</font><br>";
		printName( $USER, $BROWSER, $author_id, $author_name, false );
		echo "<font class=\"msgaction\"> posted </font>";
		echo '</div>';
		echo '</td>';

		echo '<td class="msgbody">';
		$message = htmlspecialchars($message);
		$message = autoLinkUrls($message);
		echo $message;
		echo '</td>';
	}
	else if ( $type == 'BRD' ) {
		echo '<td class="msgleft">';
		echo '<div class="msgabout">';
		echo "<font class=\"msgtime\">" . str_replace( ' ', ' &nbsp; ', $time_published ) . "</font><br>";
		printName( $USER, $BROWSER, $author_id, $author_name, false );
		echo "<font class=\"msgaction\"> wrote on ";
		if ( $published ) {
			echo "your";
		}
		else {
			printName( $USER, $BROWSER, $subject_id, $subject_name, true );
		}
		echo " board</font>";
		echo '</div>';
		echo '</td>';

		echo '<td class="msgbody">';
		$message = htmlspecialchars($message);
		$message = autoLinkUrls($message);
		echo $message;
		echo '</td>';
	}
	echo '</tr></table>';
	echo '</div>';
}

?>
