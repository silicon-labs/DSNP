<?php

$data = read_data();

?>

<html>
<head>
<title><?php print $data['name']?> </title>
</head>
<h1>Owner Page -- <?php print $IDENTITY;?></h1>
<a href="<?php print $IDENTITY . 'logout.php';?>">logout</a><br>
<a href="<?php print $IDENTITY . 'addfriend.php';?>">add friend</a><br>

<h1>Friend List</h1>

<?php friendList( $data ); ?>

</html>
