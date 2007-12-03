<?php

include('config.php');
include('lib/iduri.php');

iduri_session_start( $IDENTITY );

?>
<html>

<head>
<title>Iduri Friend Login</title>
</head>

<body>

<br>
<center>
<?php friendLoginForm();?>
</center>
<body>

</html>
