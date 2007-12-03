<?php

include('config.php');
include('lib/iduri.php');

iduri_session_start( $IDENTITY );

if ( $_SESSION['auth'] == 'owner' )
	include('lib/owner.php');
else if ( $_SESSION['auth'] == 'friend' )
	include('lib/friend.php');
else
	include('lib/public.php');

?>
