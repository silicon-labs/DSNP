<?php

include('config.php');
include('lib/iduri.php');

iduri_session_start( $IDENTITY );

requireOwner();

$furi = $_POST['uri'];

$data = read_data( );

$gnupg = new gnupg();

$fp = import_id( $gnupg, $furi );

$data['friends'][$furi] = $fp;
write_data( $data );

header('Location: ' . $IDENTITY );
