<?php

include('config.php');
include('lib/iduri.php');

iduri_session_start( $IDENTITY );

$fp = $_GET['fp'];

$fn = 'relid/' . $fp . '.asc';

$asc = file_get_contents( $fn );
unlink( $fn );

header( 'Content-Type: text/plain' );
print( $asc );
