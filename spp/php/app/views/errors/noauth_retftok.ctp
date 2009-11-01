<?php 
header("HTTP/ 403 Not Authorized");
?>

<div class="content">

<h2>Not Authorized</h2>
<p class="error"><strong>Error:</strong> 
You are not currently authorized to access <?php echo( $url ); ?>.</p>

<div class="content">

<p>It looks like you tried to access a friend's page or file, but you are not logged
in to your home site. Please 
<?php echo $html->link('login', "/$USER_NAME/cred/login?d=" . urlencode($backto) );?> 
to complete the process.

</div>

</div>

