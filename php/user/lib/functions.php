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


function printName( $identity, $possessive, $known_friend )
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
		if ( $known_friend )
			echo "<a href=\"${identity}sflogin.php?uri=" . urlencode($USER_URI);
		else
			echo "<a href=\"${BROWSER_ID}sendmeto.php?uri=" . urlencode($identity);

		echo "\">$identity</a>";
		if ( $possessive )
			echo "'s";
	}
}

function printMessage( $author_id, $subject_id, $message, $time_published )
{
	global $USER_NAME;
	global $USER_URI;

	$r = new XMLReader();
	$r->xml( $message );
	if ( $r->read() ) {

		if ( $r->name == "text" ) {
			if ( $r->read() )
				$text = $r->value;

			if ( isset( $text ) ) {
				echo "<small>$time_published ";
				printName( $author_id, false, true );
				echo " said:</small><br>";
				echo "&nbsp;&nbsp;" . htmlspecialchars($text) . "<br>";
			}
		}
		else if ( $r->name == "wall" ) {
			if ( $r->read() )
				$wall = $r->value;

			if ( isset( $wall ) ) {
				echo "<small>$time_published ";

				printName( $author_id, false, true );

				echo " wrote on ";

				printName( $subject_id, true, true );

				echo " wall:</small><br>";
				echo "&nbsp;&nbsp;" . htmlspecialchars($wall) . "<br>";
			}
		}
	}
}

?>
