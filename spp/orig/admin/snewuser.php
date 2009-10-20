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
#include('lib/session.php');

if ( $CFG_USE_RECAPTCHA ) {
	require_once('../recaptcha-php-1.10/recaptchalib.php');
	$resp = recaptcha_check_answer ($CFG_RC_PRIVATE_KEY,
			$_SERVER["REMOTE_ADDR"],
			$_POST["recaptcha_challenge_field"],
			$_POST["recaptcha_response_field"]);

	if (!$resp->is_valid) {
		die ("The reCAPTCHA wasn't entered correctly. Go back and try it again." .
				"(reCAPTCHA said: " . $resp->error . ")");
	}
}

$user = $_POST['user'];
$pass1 = $_POST['pass1'];
$pass2 = $_POST['pass2'];
#$email = $_POST['email'];

if ( $pass1 != $pass2 )
	die("password mismatch");

# Connect to the database.
$conn = mysql_connect($CFG_DB_HOST, $CFG_DB_USER, $CFG_ADMIN_PASS) or die 
	('Could not connect to database');
mysql_select_db($CFG_DB_DATABASE) or die
	('Could not select database ' . $CFG_DB_DATABASE);

$query = sprintf( "INSERT INTO user ( user ) VALUES ( '%s') ", $user );
$result = mysql_query($query) or die('Query failed: ' . mysql_error());

$fp = fsockopen( 'localhost', $CFG_PORT );
if ( !$fp )
	exit(1);

$send = 
	"SPP/0.1 $CFG_URI\r\n" . 
	"comm_key $CFG_COMM_KEY\r\n" .
	"new_user $user $pass1 unused\r\n";
fwrite($fp, $send);

$photoDirCmd =  "umask 0002; mkdir $CFG_PHOTO_DIR/$user";
system( $photoDirCmd );

$res = fgets($fp);
if ( ereg("^OK", $res) ) {
	header("Location: ${CFG_PATH}" );
}
else
{
	echo "FAILURE *** New user creation failed with: <br>";
	echo $res;
}

