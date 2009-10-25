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


function printName( $identity, $possessive )
{
	global $USER_URI;
	global $USER_NAME;
	global $BROWSER_ID;

	if ( !$identity || !isset($BROWSER_ID) && $identity == $USER_URI || 
			isset($BROWSER_ID) && $BROWSER_ID == $identity )
	{
		if ( $possessive )
			echo "your";
		else
			echo "you";
	}
	else if ( isset($BROWSER_ID) && $identity == $USER_URI ) {
		echo $USER_NAME;
		if ( $possessive )
			echo "'s";
	}
	else {
		echo "<a href=\"${identity}sflogin?h=" . urlencode($_SESSION['hash']);

		echo "\">$identity</a>";
		if ( $possessive )
			echo "'s";
	}
}

function printMessage( $author_id, $subject_id, $type, $resource_id, $message, $time_published )
{
	global $USER_NAME;
	global $USER_URI;

	if ( $type == 'PHT' ) {
		echo "$time_published ";
		printName( $author_id, false );
		echo " uploaded a photo:<br>";
		if ( $resource_id > 0 ) {
			echo "<a href=\"${author_id}img/img-$resource_id.jpg?h=" . 
				urlencode($_SESSION['hash']) . "\">";
		}
		else {
			echo "<a href=\"img/$message\">";
		}
		echo "<img src=\"img/$message\" alt=\"$message\"></a><br>\n";
	}
	else if ( $type == 'MSG' ) {
		echo "$time_published ";
		printName( $author_id, false );
		echo " said:<br>";
		echo "&nbsp;&nbsp;" . htmlspecialchars($message) . "<br>";
	}
	else if ( $type == 'BRD' ) {
		echo "$time_published ";

		printName( $author_id, false );

		echo " wrote on ";

		printName( $subject_id, true );

		echo " wall:<br>";
		echo "&nbsp;&nbsp;" . htmlspecialchars($message) . "<br>";
	}
}

?>
