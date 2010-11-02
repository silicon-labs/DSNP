<table><tr>
<td id="leftcol">

<div id="details">
<h2><?php print $USER[USER];?></h2>
</div>

</td>

<td id="activity">

<div class="content">
<h3>Login</h3>

<?php 
#echo $form->create( null, array( 'url' => "/$USER_NAME/cred/slogin"));
#
#echo $form->input('user', array( 'value' => $USER_NAME));
#echo $form->input('pass', array( 'type' => 'password'));
#
#echo $form->end('Login');
?>
<form method="post" action="<?echo $this->userLoc( '/cred/slogin' );?>">
<table>
<tr>
	<td>
		User
	</td>
	<td>
	<input name="user" type="text" value="<?echo $USER[USER];?>"/>
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
</form>

<?php
if ( isset( $dest ) )
	echo "<br>you will be taken to:<br> $dest"
?>

</div>

</td>
</tr></table>

