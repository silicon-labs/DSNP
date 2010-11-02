<?php

function setCookieParams()
{
	global $CFG;
	global $USER;

	# If there is a user, then the cookie is restricted to it, Otherwise it is
	# active only for the admin controller (currently is site because that is
	# where new users are created.
	if ( isset( $USER[USER] ) )
		$path = $CFG[PATH] . '/' . $USER[USER] . '/';
	else
		$path = $CFG[PATH] . '/site/';
	
	# 30 days.
	$lifetime =
		60 * 60 * 24 * 30;

	# Always set the cookie params so we are ready 
	session_set_cookie_params( 
		$lifetime,
		$path
	);
}

if ( isset( $_COOKIE['PHPSESSID'] ) ) {
	setCookieParams();
	session_start();
}

$ROLE = null;
if ( $_SESSION[ROLE] == 'owner' )
	$ROLE = 'owner';
else if ( $_SESSION[ROLE] == 'friend' )
	$ROLE = 'friend';
else
	$ROLE = 'public';


?>
