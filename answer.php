<?php

include('config.php');
include('lib/iduri.php');

iduri_session_start( $IDENTITY );

requireOwner();

$furi = $_GET['uri'];

$data = read_data();
$fp = $data['fingerprints'][$furi];

if ( $_GET['a'] == 'yes' )
	$data['friends'][$furi] = $fp;

# Remove the request.
unset( $data['requests'][$furi] );

write_data( $data );

header( "Location: $IDENTITY" );
