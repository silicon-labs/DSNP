<?php

if ( isset( $_GET['url'] ) )
	$url = $_GET['url'];

$USER['USER'] = null;
$USER['NAME'] = null;
$USER['ID'] = null;
$USER['IDURI'] = null;

# ID is the id of the friend_claim row.
$BROWSER['ID'] = null;
$BROWSER['IDURI'] = null;

function checkUserDb()
{
	global $CFG;
	global $USER;
	$result = dbQuery( 
		"SELECT user.id, user.user, user.iduri, user.name, friend_claim.id AS rel_id_self " .
		"FROM user " .
		"JOIN friend_claim ON user.id = friend_claim.user_id " .
		"WHERE user.user = %e AND friend_claim.type = %l",
		$USER['USER'], REL_TYPE_SELF );

	if ( count( $result ) != 1 )
		userError( EC_USER_NOT_FOUND, array( $USER['USER'] ) );

	# Turn result int first row.
	$result = $result[0];

	$USER['ID'] = $result['id'];
	$USER['IDURI'] =  "{$CFG['URI']}{$USER['USER']}/";
	$USER['NAME'] = $result['name'];
	$USER['FRIEND_CLAIM_SELF_ID'] = $result['rel_id_self'];

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

	# Validate the component names. The first two are strict identifiers. Three
	# and up can have some symbols.
	$normalizedRoute = array();
	foreach ( $route as $component ) {
		if ( $component === "" )
			continue;
		else if	( ! preg_match( '/^[a-zA-Z][a-zA-Z0-9_\-\.]*$/', $component ) )
			userError( EC_INVALID_ROUTE, array( $component ) );
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
	$className[$component] = preg_replace( '/[_\-\.]+/', '', $component );
}

?>
