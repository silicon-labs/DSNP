<?php

/* 
 * Copyright (c) 2009-2011, Adrian Thurston <thurston@complang.org>
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

?>


<table><tr>
<td id="leftcol">

<div id="details">
	<h2><?php print $USER['USER'];?></h2>
</div>

</td>

<td id="activity">

<div class="content">

<h2>Become Friend</h2>

<form method="post" action="sbecome">
Please submit your IDURI. Make sure you are logged into it first.<br><br>

<input type="text" size=70 name="dsnp_iduri">

<?php
if ( $this->CFG['USE_RECAPTCHA'] ) {
	require_once( RECAPTCHA_LIB );
	echo "<p>";
	echo recaptcha_get_html($this->CFG['RC_PUBLIC_KEY']);
}
?>
<p>
<input type="submit">

<p>

Example: <code>dsnp://www.example.com/path</code><br><br>

Note:<br>
&nbsp;1. It is case-insensitive.<br>
&nbsp;2. It is the same as the URL for access, except with <code>dsnp</code> as the scheme.<br>
&nbsp;3. There may be no path (i.e. <code>dsnp://www.example.com/</code> is valid).<br>

</form>
</div>

</td>

</tr></table>
