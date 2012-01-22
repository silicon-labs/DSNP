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

function displayName( $USER, $BROWSER, $iduri, $name, $possessive )
{
	if ( $iduri === $BROWSER['IDURI'] )
		$dest = iduriToIdurl($iduri);
	else {
		$arg_dsnp  = 'dsnp=ftoken_request';
		$arg_hash  = 'dsnp_hash=' . urlencode( $_SESSION['hash'] );

		$dest = addArgs( iduriToIdurl($iduri), "{$arg_dsnp}&{$arg_hash}" );
	}

	$result = "<a href=\"${dest}\">";
	$result .= "<font class=\"msgwho\">";
	if ( isset( $name ) )
		$result .= $name;
	else
		$result .= $iduri;
	$result .= "</font></a>";
	if ( $possessive )
		$result .= "<font class=\"msgwho\">'s</font>";
	return $result;
}

function hostPart( $uri )
{
	return preg_replace( '/([a-z]+:\/\/[^\/]+)\/.*/', '\1', $uri );
}

function printMessage( $view, $text, $USER, $BROWSER, $author, $subject, $item )
{
	$pub_type = $item['pub_type'];

	$publisher_iduri = $author['publisher_iduri'];
	$publisher_name = $author['publisher_name'];

	$author_iduri = $author['author_iduri'];
	$author_name = $author['author_name'];

	$subject_iduri = $subject['subject_iduri'];
	$subject_name = $subject['subject_name'];

	$time_published = $item['time_published'];
	$time_received = $item['time_received'];

	$remote_resource = $item['remote_resource'];
	$remote_presentation = $item['remote_presentation'];

	$local_resource = $item['local_resource'];
	$local_presentation = $item['local_presentation'];
	$local_thumbnail = $item['local_thumbnail'];

	$message = $item['message'];

	echo '<div class="msgdisp">';
	echo '<table><tr>';
	switch ( $pub_type ) {
	case PUB_TYPE_PHOTO:
		echo '<td class="msgleft">';
		echo '<div class="msgabout">';
		echo "<font class=\"msgtime\">" . str_replace( ' ', ' &nbsp; ', $time_published ) . "</font><br>";
		echo displayName( $USER, $BROWSER, $publisher_iduri, $publisher_name, false );
		echo "<font class=\"msgaction\"> uploaded a photo </font>";
		echo '</div>';
		echo '</td>';

		echo '<td class="msgbody">';
		echo '<div class="msgphoto">';
		if ( isset( $remote_presentation ) ) {
			echo $view->absLink(
				$view->userImg( $local_thumbnail, "alt" ),
				hostPart( iduriToIdurl( $publisher_iduri ) ) . "$remote_presentation?h=" . $_SESSION['hash'] );
		}
		else {
			echo $view->userLink(
				$view->userImg( $local_thumbnail, "alt" ), 
				$local_presentation );
		}
		echo '</div>';
		echo '</td>';
		break;

	case PUB_TYPE_PHOTO_TAG:
		echo '<td class="msgleft">';
		echo '<div class="msgabout">';
		echo "<font class=\"msgtime\">" . str_replace( ' ', ' &nbsp; ', $time_published ) . "</font><br>";
		echo displayName( $USER, $BROWSER, $subject_iduri, $subject_name, false );
		echo "<font class=\"msgaction\"> was tagged by </font>";
		echo displayName( $USER, $BROWSER, $author_iduri, $author_name, false );
		echo "<font class=\"msgaction\"> in a photo belonging to </font>";
		echo displayName( $USER, $BROWSER, $publisher_iduri, $publisher_name, false );

		echo '</div>';
		echo '</td>';

		echo '<td class="msgbody">';
		echo '<div class="msgphoto">';
		if ( isset( $remote_presentation ) ) {
			echo $view->absLink(
				$view->userImg( $local_thumbnail, "alt" ),
				hostPart( iduriToIdurl( $publisher_iduri ) ) . "$remote_presentation?h=" . $_SESSION['hash'] );
		}
		else {
			echo $view->userLink(
				$view->userImg( $local_thumbnail, "alt" ), 
				$local_presentation );
		}
		echo '</div>';
		echo '</td>';
		break;

	case PUB_TYPE_POST:
		echo '<td class="msgleft">';
		echo '<div class="msgabout">';
		echo "<font class=\"msgtime\">" . str_replace( ' ', ' &nbsp; ', $time_published ) . "</font><br>";
		echo displayName( $USER, $BROWSER, $publisher_iduri, $publisher_name, false );
		echo "<font class=\"msgaction\"> posted </font>";
		echo '</div>';
		echo '</td>';

		echo '<td class="msgbody">';
		$message = htmlspecialchars($message);
		$message = autoLinkUrls($message);
		echo $message;
		echo '</td>';
		break;

	case PUB_TYPE_REMOTE_POST:
		echo '<td class="msgleft">';
		echo '<div class="msgabout">';
		echo "<font class=\"msgtime\">" . str_replace( ' ', ' &nbsp; ', $time_published ) . "</font><br>";
		echo displayName( $USER, $BROWSER, $author_iduri, $author_name, false );
		echo "<font class=\"msgaction\"> wrote on ";
		echo displayName( $USER, $BROWSER, $publisher_iduri, $publisher_name, true );
		echo " board</font>";
		echo '</div>';
		echo '</td>';

		echo '<td class="msgbody">';
		$message = htmlspecialchars($message);
		$message = autoLinkUrls($message);
		echo $message;
		echo '</td>';
		break;
	}
	echo '</tr></table>';
	echo '</div>';
}

?>
