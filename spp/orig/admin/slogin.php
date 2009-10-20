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

$pass = $_POST['password'];

if ( $pass == $CFG_ADMIN_PASS ) {
	# Login successful.
	$_SESSION['auth'] = 'admin';
	header( "Location: ${CFG_PATH}admin/" );
}
else {
	?>

	<center>
	ADMIN LOGIN FAILED<br><br>

	<form method="post" action="slogin.php">
	Admin Login:
	<input type="password" name="password">
	<input type="submit">
	</form>
	</center>

	<?php
}
?>
