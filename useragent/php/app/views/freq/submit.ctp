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

?>


<div id="leftcol">

<div id="details">
<h2><?php print $USER_NAME;?></h2>
</div>

</div>

<div id="activity">

<div class="content">

<h2>Become Friend</h2>

<form method="post" action="sbecome">
Please submit your identity. <br><br>

Identities are normally of the form <code>https://www.example.com/path/user/</code>. Some notes:<br><br>

1. They are case-sensitive.<br>
2. The <code>https://</code> at the beginning is required.<br>
3. The exact hostname must be used.<br>
4. There may be no path in your identity.<br>
5. The trailing <code>/</code> at the end is required.<br><br>

<big>The <b>easiest</b> way to do this is to <b>copy</b> your identity from the address bar of
your browser after logging in and then <b>paste</b> it here.</big><br><br>

Here is an example: <code>https://www.iduri.ca/thurston/</code><br><br>
<input type="text" size=70 name="identity">

<p>

<?php
//require_once('../recaptcha-php-1.10/recaptchalib.php');
//echo recaptcha_get_html($CFG_RC_PUBLIC_KEY);
?>

<p>

<input type="submit">
</form>
</div>

</div>
