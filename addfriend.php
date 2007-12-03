<?php

include('config.php');
include('lib/iduri.php');

iduri_session_start( $IDENTITY );

requireOwner();

$data = read_data( );

write_data( $data );

?>
<html>

<head>
<title>Iduri Friend Login</title>
</head>

<body>

<br>
<center>
<form method="post" action="submitfriend.php">
Friend to add:
<input type="text" size=70 name="uri">
<input type="submit">
</form>

</center>
<body>

</html>
