<?php

include('config.php');
include('lib/iduri.php');

iduri_session_start( $IDENTITY );

$fp = $_GET['fp'];

$fn = 'relid/' . $fp . '.asc';

$asc = file( $fn );
unlink( $asc );

header( 'Content-Type: text/plain' );
print( $asc );
