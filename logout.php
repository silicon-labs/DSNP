<?php

include('config.php');
include('lib/iduri.php');

iduri_session_start( $IDENTITY );

unset($_SESSION['auth']);

header( "Location: $IDENTITY" );

?>
