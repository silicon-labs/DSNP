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

global $CFG_URI;
global $CFG_PATH;

?>

<table><tr>

<td id="leftcol">

<div class="content">

<h3>DSNP User-Agent One</h3>

<p>
<a href="admin/newuser">create new user</a>

</div>
</td>

<td id="activity">

<div class="content">
<h2>Users</h2>
<p>
<?php

foreach ( $users as $row ) {
	$user = $row['user'];
	echo '<a href="' . $CFG_PATH . $user . '/"/>' . $user . '</a><br>';
}
?>
</div>
</td>
</tr>
</table>
