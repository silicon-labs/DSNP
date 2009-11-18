<?php

if ( !isset( $CFG_URI ) )
	die("config.php: could not select installation\n");

if ( get_magic_quotes_gpc() )
	die("the SPP software assumes PHP magic quotes to be off\n");

Configure::write( 'CFG_URI', $CFG_URI );
Configure::write( 'CFG_HOST', $CFG_HOST );
Configure::write( 'CFG_PATH', $CFG_PATH );
Configure::write( 'CFG_DB_HOST', $CFG_DB_HOST );
Configure::write( 'CFG_DB_USER', $CFG_DB_USER );
Configure::write( 'CFG_DB_DATABASE', $CFG_DB_DATABASE );
Configure::write( 'CFG_ADMIN_PASS', $CFG_ADMIN_PASS );
Configure::write( 'CFG_COMM_KEY', $CFG_COMM_KEY );
Configure::write( 'CFG_PORT', $CFG_PORT );
Configure::write( 'CFG_USE_RECAPTCHA', $CFG_USE_RECAPTCHA );
Configure::write( 'CFG_RC_PUBLIC_KEY', $CFG_RC_PUBLIC_KEY );
Configure::write( 'CFG_RC_PRIVATE_KEY', $CFG_RC_PRIVATE_KEY );
Configure::write( 'CFG_PHOTO_DIR', $CFG_PHOTO_DIR );
Configure::write( 'CFG_IM_CONVERT', $CFG_IM_CONVERT );
Configure::write( 'CFG_SITE_NAME', $CFG_SITE_NAME );

?>
