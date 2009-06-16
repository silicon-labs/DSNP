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

include('../config.php');
include('lib/session.php');

$identity = $_POST['identity'];

//require_once('../recaptcha-php-1.10/recaptchalib.php');
//$resp = recaptcha_check_answer ($CFG_RC_PRIVATE_KEY,
//		$_SERVER["REMOTE_ADDR"],
//		$_POST["recaptcha_challenge_field"],
//		$_POST["recaptcha_response_field"]);
//
//if (!$resp->is_valid) {
//	die ("The reCAPTCHA wasn't entered correctly. Go back and try it again." .
//			"(reCAPTCHA said: " . $resp->error . ")");
//}

$fp = fsockopen( 'localhost', $CFG_PORT );
if ( !$fp )
	die( "!!! There was a problem connecting to the local SPP server.");

$send = 
	"SPP/0.1 $CFG_URI\r\n" . 
	"comm_key $CFG_COMM_KEY\r\n" .
	"relid_request $USER_NAME $identity\r\n";
fwrite($fp, $send);

$res = fgets($fp);

if ( ereg("^OK ([0-9a-f]+)", $res, $regs) ) {
	$arg_identity = 'identity=' . urlencode( $USER_URI );
	$arg_reqid = 'fr_reqid=' . urlencode( $regs[1] );

	header("Location: ${identity}retrelid.php?${arg_identity}&${arg_reqid}" );
}
else if ( ereg("^ERROR ([0-9]+)", $res, $regs) ) {
	die( "!!! There was an error:<br>" .
		$ERROR[$regs[1]] . "<br>" .
		"Check that the URI you submitted is correct.");
}
else {
	die( "!!! The local SPP server did not respond. How rude.<br>" . 
		"Check that the URI you submitted is correct.");
}

?>
