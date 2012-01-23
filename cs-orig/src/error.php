<?php

/*
 * This file is included into a function.
 */

function sslPeerFailedVerify( $host )
{
	echo "We failed to verify the identity of {$host}! ";
	echo "<p>This could mean that {$host} is not properly configured, ";
	echo "that {$host}'s security certificate is invalid or expired, ";
	echo "or that this server is not properly configured. Please ";
	echo "consult the operator of this server.";
}

function sslConnectFailed( )
{
	echo "We failed to initiate a secure connection to the peer. ";
	echo "<p>This could mean that the peer is not properly configured, ";
	echo "or that this server is not properly configured. Please ";
	echo "consult the operator of this server.";
}

function sslWrongHost( $expected, $got )
{
	echo "We failed to verify the identity of {$expected}! ";
	echo "<p>We got a cert that verfies, but it belongs to {$got} ";
	echo "and not {$expected} as expected.";
}

function sslCaCertLoadFailure( $file )
{
	echo "There is an SSL configuration error. ";
	echo "<p>We could not load the CA cert file {$file} ";
}

function socketConnectFailed( $host )
{
	echo "We failed to connect to {$host}";
	echo "<p> Please double check the identitiy you entered.";
}

function friendRequestExists( $user, $identity )
{
	echo "A friend request from <code>$identity</code> " .
		"to user <code>$user</code> already exists.";
}

function friendClaimExists( $user, $identity )
{
	echo "User <code>$user</code> already has <code>$identity</code> " .
		"in its friend list.";
}

function dsnpdNoResponse()
{
	echo "There was no response from the dsnpd server. It most " .
		"likely crashed. ";
}

function dsnpdTimeout()
{
	echo "The connection to the dsnpd server timed out. " .
		"Something is amiss. It is supposed to always get back to us. Please report this if you can.";
}

function cannotFriendSelf( $identity )
{
	echo "The identity submitted <code>$identity</code> belongs to this user.";
	echo "It is not possible to friend oneself.";
}

function userNotFound( $user )
{
	echo "User <code>{$user}</code> not found.";
}

function userExists( $user )
{
	echo "User <code>{$user}</code> already exists.";
}

function invalidRoute( $component )
{
	echo "Route component <code>$component</code> contains an invalid character.";
}

function rsaKeyGenFailed( $code )
{
	echo "There was an error generating the security key.";
	echo "<p>Please contact the site administrator.";
}

function invalidLogin( $code )
{
	echo "Invalid Login";
	echo "<p> Please press the back button to try again.\n";
}

function databaseError( $reason )
{
	echo "There was an internal database error. If you can, please report this.";
	echo "<p> $reason";
}

function invalidUserName( $arg, $value, $string )
{
	echo "The user name supplied $value is not valid. ";
	echo "<p>The user name must start with a letter or number.";
	echo "It can contain (but not start with) dot, dash, or underscore.";
}

function friendClaimNotFound()
{
	echo "A friendship was not found.";
	echo "<p>For some reason an expected relationship was not found. If you ";
	echo "think this may be a software error, please contact your system ";
	echo "administrator.";
}

function confFileOpenFailed()
{
	echo "The DSNP server failed to open its conf file.";
	echo "<p>The local system is not properly configured. Please inform your system administrator.";
}

function logFileOpenFailed()
{
	echo "The DSNP server failed to open its log file.";
	echo "<p>The local system is not properly configured. Please inform your system administrator.";
}

function dsnpdDbQueryFailed()
{
	echo "The DSNP server encountered a database error.";
	echo "<p>This is not normal, please report this if you can.";
}

function schemaVersionMismatch( $databaseVersion, $softwareVersion )
{
	echo "There was a mismatch in the database schema version. The database is at ";
	echo "schema version $databaseVersion, but the the Choice Social software ";
	echo "was expecting version $softwareVersion.";
	echo "<p>This needs to be fixed, please report this if you can.";
}

function mustLogin()
{
	echo "Sorry, you must login to take this action.";
	echo "<p>Please use your bookmarks or your location bar ";
	echo "to go home and login, then revisit the request that brought you here. ";
	echo "We purposefully don't redirect you to your login page to make it harder ";
	echo "for sites to trick you into giving them your password. Remember that ";
	echo "you should never be prompted for your password by a site other than ";
	echo "your own. ";
}


switch ( $code ) {
	case EC_SSL_PEER_FAILED_VERIFY:
		sslPeerFailedVerify( $args[0] );
		break;
	case EC_SSL_CONNECT_FAILED:
		sslConnectFailed();
		break;
	case EC_SSL_WRONG_HOST:
		sslWrongHost( $args[0], $args[1] );
		break;
	case EC_SSL_CA_CERT_LOAD_FAILURE:
		sslCaCertLoadFailure( $args[0] );
		break;
	case EC_FRIEND_REQUEST_EXISTS:
		friendRequestExists( $args[0], $args[1] );
		break;
	case EC_FRIEND_CLAIM_EXISTS:
		friendClaimExists( $args[0], $args[1] );
		break;
	case EC_DSNPD_NO_RESPONSE:
		dsnpdNoResponse();
		break;
	case EC_DSNPD_TIMEOUT:
		dsnpdTimeout();
		break;
	case EC_SOCKET_CONNECT_FAILED:
		socketConnectFailed( $args[0] );
		break;
	case EC_CANNOT_FRIEND_SELF:
		cannotFriendSelf( $args[0] );
		break;
	case EC_USER_NOT_FOUND:
		userNotFound( $args[0] );
		break;
	case EC_INVALID_ROUTE:
		invalidRoute( $args[0] );
		break;
	case EC_USER_EXISTS:
		userExists( $args[0] );
		break;
	case EC_RSA_KEY_GEN_FAILED:
		rsaKeyGenFailed( $args[0] );
		break;
	case EC_INVALID_LOGIN:
		invalidLogin();
		break;
	case EC_DATABASE_ERROR:
		databaseError( $args[0] );
		break;
	case EC_INVALID_USER_NAME:
		invalidUserName( $args[0], $args[1], $args[2] );
		break;
	case EC_FRIEND_CLAIM_NOT_FOUND:
		friendClaimNotFound();
		break;
	case EC_CONF_FILE_OPEN_FAILED:
		confFileOpenFailed();
		break;
	case EC_LOG_FILE_OPEN_FAILED:
		logFileOpenFailed();
		break;
	case EC_DSNPD_DB_QUERY_FAILED:
		dsnpdDbQueryFailed();
		break;
	case EC_SCHEMA_VERSION_MISMATCH:
		schemaVersionMismatch( $args[0], $args[1] );
		break;
	case EC_MUST_LOGIN:
		mustLogin();
		break;
	default:
		echo "Sorry, I don't have any information about " .
			"the nature of this error.";
		echo "<p>Error Code: $code";
		echo "<p>Args:";
		print_r( $args );
		break;
}

?>
