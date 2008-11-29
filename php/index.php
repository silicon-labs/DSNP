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

include('config.php');
include('user/lib/iduri.php');

iduriSessionStart();

# Connect to the database.
$conn = mysql_connect($CFG_DB_HOST, $CFG_DB_USER, $CFG_ADMIN_PASS) or die 
	('Could not connect to database');
mysql_select_db($CFG_DB_DATABASE) or die
	('Could not select database ' . $CFG_DB_DATABASE);

# Look for the user/pass combination.
$query = "SELECT user FROM user";
$result = mysql_query($query) or die('Query failed: ' . mysql_error());

?>

<html>
<head>
<title><?php print $data['name']?> </title>
</head>

<h1>Secure Personal Publishing</h1>

<p>
<?php
if ( $_SESSION['auth'] == 'admin' ) {
	echo 'you are admin<br>';
	echo '<a href="admlogout.php">logout</a>';
}
else
	echo '<a href="admlogin.php">login</a>'
?>

<p>Installation: <?php print $CFG_INSTALLATION;?>

<p>

<?php

while ( $row = mysql_fetch_assoc($result) )
    echo '<a href="u/' . $row['user'] . '/"/>' . $row['user'] . '</a><br>';

?>

</html>
