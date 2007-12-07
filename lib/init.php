<?php
include( 'config.php' );
include( 'lib/iduri.php' );

$data = Array(
		'name' => '',
		'friends' => Array(),
		'getrelids' => Array(),
		'putrelids' => Array(),
		'fingerprints' => Array(),
		'requests' => Array()
		);

write_data( $data );
?>
