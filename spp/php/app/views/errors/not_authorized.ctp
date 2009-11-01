<?php 
header("HTTP/ 403 Not Authorized");
?>

<div class="content">

<h2>Not Authorized</h2>
<p class="error"><strong>Error:</strong> 
You are not currently authorized to access <?php echo( $url ); ?>.</p>

<div class="content">

<?php if ( strchr( $cred, 'o' ) ) { ?>

	<p>If you are the owner of <?php echo $html->link( $USER_URI, $USER_URI );?> then please 
	<?php echo $html->link('login', "/$USER_NAME/cred/login?d=" . urlencode($url) );?></p>

<?php } ?>

<?php if ( strchr( $cred, 'f' ) ) { ?>

	<p> If you are a friend of <?php echo $html->link( $USER_URI, $USER_URI );?> 
	then you can login to your identity and click on a link to this resource
	from within your home.</p>

	<p>Alternatively, you can enter your user identity here and we'll send you home
	to login (if you are not already logged in), then send you back to this
	resource with the appropriate credentials.

	<div class="content">

	<form method="post" action="<? echo $html->url( "/$USER_NAME/sflogin" );?>">
	<input type="text" size=70 name="identity">
	<input type="hidden" size=70 name="d" value="<?php echo $html->url( null, true );?>">

	</div>

<?php } ?>



</div>

</div>
