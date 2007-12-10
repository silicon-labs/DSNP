<?php

$data = read_data();

?>

<html>
<head>
<title><?php print $data['name']?> </title>
</head>
<h1>Owner Page -- <?php print $IDENTITY;?></h1>

<a href="logout.php">logout</a><br>
<a href="publish.php">publish to friends</a><br>

<?php showFriendRequests( $data ); ?>

<h1>Friend List</h1>

<?php friendList( $data ); ?>

</html>
