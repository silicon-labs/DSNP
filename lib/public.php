<?php

$data = read_data();

?>

<html>
<head>
<title><?php print $data['name']?> </title>
</head>

<h1>Public Page -- <?php print $IDENTITY;?></h1>

<a href="<?php print $IDENTITY . 'login.php';?>">owner login</a><br>
<a href="<?php print $IDENTITY . 'flogin.php';?>">friend login</a><br>
<a href="<?php print $IDENTITY . 'becomefriend.php';?>">become friend</a>

</html>

