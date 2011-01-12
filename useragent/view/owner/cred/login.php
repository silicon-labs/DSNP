<table><tr>
<td id="leftcol">

<div id="details">
	<h2><?php print $USER['USER'];?></h2>
</div>

</td>

<td id="activity">

<div class="content">
<h3>Login</h3>

<form method="post" action="<?echo $this->userLoc( '/cred/slogin' );?>">
<table>
<tr>
	<td>
		User
	</td>
	<td>
	<input name="user" type="text" value="<?echo $USER['USER'];?>"/>
	</td>
</tr>


<tr>
	<td>
		Password
	</td>
	<td>
	<input name="pass" type="password"/>
	</td>
</tr>

<tr>
	<td>
		<input type="submit">
	</td>
	<td>
		&nbsp;
	</td>
</tr>
</table>

<?php
	if ( isset( $dest ) )
		echo '<input type="hidden" name="d" value="' . $dest . '">';
?>

</form>

<?php
if ( isset( $dest ) )
	echo "<br>you will be taken to:<br> $dest"
?>

</div>

Note: you are already logged in.

</td>
</tr></table>


