<?php

include('config.php');
include('lib/iduri.php');

iduri_session_start( $IDENTITY );

?>
<html>

<head>
<title>Iduri Owner Login</title>
</head>

<body>

<br>
<center>
<?php loginForm();?>
</center>
<body>

</html>
