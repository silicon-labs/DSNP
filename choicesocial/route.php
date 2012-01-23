<?php

if ( isset( $_GET['url'] ) )
	$url = $_GET['url'];

$USER['USER'] = null;
$USER['USER_ID'] = null;
$USER['IDURI'] = null;
$USER['IDURL'] = null;
$USER['NAME'] = null;
$USER['RELATIONSHIP_ID'] = null;

# ID is the id of the friend_claim row.
$BROWSER['IDURI'] = null;
$BROWSER['IDURL'] = null;
$BROWSER['RELATIONSHIP_ID'] = null;

function addArgs( $uri, $args )
{
	if ( strstr( $uri, '?' ) === false )
		return $uri . '?' . $args;
	else
		return $uri . '&' . $args;
}

function checkUserDb()
{
	global $CFG;
	global $USER;
	$result = dbQuery( 
		"SELECT user.id, user.user, " .
		"	identity.iduri, " .
		" 	user.relationship_id, relationship.name " .
		"FROM user " .
		"JOIN identity ON user.identity_id = identity.id " .
		"JOIN relationship ON user.relationship_id = relationship.id " .
		"WHERE user.user = %e ",
		$USER['USER'], REL_TYPE_SELF );

	if ( count( $result ) != 1 )
		userError( EC_USER_NOT_FOUND, array( $USER['USER'] ) );

	# Turn result int first row.
	$result = $result[0];

	$USER['USER_ID'] = $result['id'];
	$USER['IDURL'] =  "{$CFG['URI']}{$USER['USER']}/";
	$USER['IDURI'] = idurlToIduri( $USER['IDURL'] );
	$USER['NAME'] = $result['name'];
	$USER['RELATIONSHIP_ID'] = $result['relationship_id'];
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
	# Usual case, parse the path into route components.
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
		$USER['USER'] = array_shift( $route );
		checkUser();
	}

	# If the DSNP arg is present, then this overrides all routes. This arg
	# indicates a function that must be handled. We map it to certain routes.
	if ( isset( $_GET['dsnp'] ) ) {
		$dsnp = $_GET['dsnp'];
		unset( $_GET['dsnp'] );

		switch ( $dsnp ) {
			case 'relid_request':
				$route = array( 'freq', 'sbecome' );
				break;
			case 'relid_response':
				$route = array( 'freq', 'retrelid' );
				break;
			case 'friend_final':
				$route = array( 'freq', 'frfinal' );
				break;
			case 'ftoken_request':
				$route = array( 'cred', 'sflogin' );
				break;
			case 'ftoken_response':
				$route = array( 'cred', 'retftok' );
				break;
			case 'submit_ftoken':
				$route = array( 'cred', 'sftoken' );
				break;
			case 'remote_broadcast_response':
				$route = array( 'user', 'flush' );
				break;
			case 'remote_broadcast_final':
				$route = array( 'user', 'finish' );
				break;
			default:
				userError( EC_INVALID_ROUTE, array( $_GET_component ) );
				break;
		}
	}
	else {
		# If there is no function then default it to index.
		if ( !isset( $route[0] ) )
			$route[0] = 'index';

		# If there is no function then default it to index.
		if ( !isset( $route[1] ) )
			$route[1] = 'index';
	}
}

foreach ( $route as $component ) {
	# Derive a class name by stripping out underscores and dashes. We can
	# expect this to be non-empty because the above regex requires alpha as the
	# first character.
	$className[$component] = preg_replace( '/[_\-\.]+/', '', $component );
}

?>
