<?php

include('config.php');
include('lib/iduri.php');

iduri_session_start( $IDENTITY );

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
First please answer a challenge (TODO).
<p>
<form method="post" action="submitbecome.php">
Please submit your identity:
<input type="text" size=70 name="uri">
<input type="submit">
</form>

</center>
<body>

</html>
