<?php
/* 
 * Copyright (c) 2007, Adrian Thurston <thurston@cs.queensu.ca>
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

?>

<html>

<head>
<title>Create User</title>
</head>

<body>

<br>
<center>
	<form method="post" action="snewuser.php">
	<table>
	<tr>
	<td>Desired User:</td>   <td> <input type="text"     name="user"></td></tr>
	<td>Password:</td>       <td> <input type="password" name="pass1"></td></tr>
	<td>Again:</td>          <td> <input type="password" name="pass2"></td></tr>
	<td>Email:</td>          <td> <input type="text"     name="email"></td></tr>
	</table>
	<input type="submit">
	</form>
</center>
<body>

</html>
