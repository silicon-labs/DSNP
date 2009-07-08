<?php

/* 
 * Copyright (c) 2009, Adrian Thurston <thurston@complang.org>
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

include('../config.php');
include('lib/session.php');

requireOwner();

$message = $_POST['message'];

$fp = fsockopen( 'localhost', $CFG_PORT );
if ( !$fp )
	exit(1);

$w = new XMLWriter();
$w->openMemory();
$w->startDocument();
$w->startElement("text");
$w->text($message);
$w->endElement();
$w->endDocument();
$encoded = $w->outputMemory();

/* Remove the XML header part and the trailing newline. */
$pos = strpos( $encoded, "\n" );
$encoded = substr( $encoded, $pos+1 );
$encoded = substr( $encoded, 0, strlen($encoded) - 1 );

/* Length of the encoded string. */
$len = strlen( $encoded );

$send = 
	"SPP/0.1 $CFG_URI\r\n" . 
	"comm_key $CFG_COMM_KEY\r\n" .
	"submit_broadcast $USER_NAME MSG 0 $len\r\n";

fwrite( $fp, $send );
fwrite( $fp, $encoded, $len );

$res = fgets($fp);

if ( ereg("^OK", $res, $regs) )
	header("Location: ${USER_URI}" );
else
	echo $res;
