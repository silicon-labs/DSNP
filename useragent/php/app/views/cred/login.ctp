<div id="leftcol">

<div id="details">
<h2><?php print $USER_NAME;?></h2>
</div>

</div>

<div id="activity">

<div class="content">
<h3>Login</h3>



<?php 
echo $form->create( null, array( 'url' => "/$USER_NAME/cred/slogin"));

echo $form->input('user', array( 'value' => $USER_NAME));
echo $form->input('pass', array( 'type' => 'password'));

echo $form->end('Login');

?>

<?php
if ( isset( $dest ) )
	echo "<br>you will be taken to:<br> $dest"
?>

</div>

</div>
