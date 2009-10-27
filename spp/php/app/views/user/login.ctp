<div id="leftcol">

<div id="details">
<h2><?php print USER_NAME;?></h2>
</div>

</div>

<div id="activity">

<div class="item">
<h3>Login</h3>

<form method="post" action="slogin">
<table>
<tbody>
<tr><td>Login:</td> <td><input type="text" name="user" value="<?php echo USER_NAME?>"></td></tr>
<tr><td>Pass:</td> <td><input type="password" name="pass"></td></tr>
</tbody>
</table>
<input type="submit">
</form>
</div>

</div>
