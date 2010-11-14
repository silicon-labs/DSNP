<?php

if ( isset( $_GET['url'] ) )
	$url = $_GET['url'];

$USER[USER] = null;
$USER[NAME] = null;
$USER[ID] = null;
$USER[URI] = null;

$BROWSER[USER] = null;
$BROWSER[NAME] = null;
$BROWSER[ID] = null;
$BROWSER[URI] = null;

function checkUserDb()
{
	global $CFG;
	global $USER;
	$result = dbQuery( 
		"SELECT id, user, identity, name FROM user WHERE user = %e",
		$USER[USER] );

	if ( count( $result ) != 1 )
		die("ERROR: user $USER[USER] not found in database");

	# Turn result int first row.
	$result = $result[0];

	$USER[ID] = $result['id'];
	$USER[URI] =  "$CFG[URI]$USER[USER]/";

#	$this->USER_NAME = $user['user'];
#	$this->USER_URI =  "$this->CFG_URI$this->USER_NAME/";
#	$this->USER_ID = $result['id'];
#	$this->USER = $user;
#
#	/* Default these to something not too revealing. At session activation
#	 * time we will upgrade if the role allows it. */
#	$this->USER['display_short'] = $this->USER['user'];
#	$this->USER['display_long'] = $this->USER['identity'];
}

function checkUser()
{
	# FIXME: do the session check first.
	checkUserDb();
}

if ( !isset( $url ) ) {
	# If there is no URL then default to site/index.
	# No username.
	$route = array( 'index', 'index' );
}
else {
	# Split on '/'.
	$route = explode( '/', $url );

	# Validate the component names.
	$normalizedRoute = array();
	foreach ( $route as $component ) {
		if ( $component === "" )
			continue;
		else if	( ! preg_match( '/^[a-zA-Z][a-zA-Z0-9_\-]*$/', $component ) )
			die( "route component '$component' does not validate" );
		else {
			$normalizedRoute[] = $component;
		}
	}
	$route = $normalizedRoute;

	# If the first element of the route is anything but 'site', then it is a
	# user. Shift the array to get the controller at the head.
	if ( $route[0] === 'site' ) {
		# Controller is under site.
		array_shift( $route );
	}
	else {
		$USER[USER] = array_shift( $route );
		checkUser();
	}

	# If there is no function then default it to index.
	if ( !isset( $route[0] ) )
		$route[0] = 'index';

	# If there is no function then default it to index.
	if ( !isset( $route[1] ) )
		$route[1] = 'index';
}

foreach ( $route as $component ) {
	# Derive a class name by stripping out underscores and dashes. We can
	# expect this to be non-empty because the above regex requires alpha as the
	# first character.
	$className[$component] = preg_replace( '/[_\-]+/', '', $component );
}

?>
