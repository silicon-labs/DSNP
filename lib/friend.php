<?php

$data = read_data();

?>

<html>
<head>
<title><?php $data['name']?> </title>
</head>

<h1>Friend Page -- <?php print $IDENTITY;?></h1>
<a href="<?php print $IDENTITY . 'logout.php';?>">logout</a>

<h1>Friend List</h1>

<?php friendList( $data ); ?>

</html>

