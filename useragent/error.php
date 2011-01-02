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

function sslConnectFailed( $host )
{
	echo "We failed to initiate a secure connection to {$host}! ";
	echo "<p>This could mean that {$host} is not properly configured ";
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


switch ( $code ) {
	case EC_SSL_PEER_FAILED_VERIFY:
		sslPeerFailedVerify( $args[0] );
		break;
	case EC_SSL_CONNECT_FAILED:
		sslConnectFailed( $args[0] );
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
	default:
		echo "Sorry, I don't have any information about " .
			"the nature of this error.";
		echo "<p>Error Code: $code";
		echo "<p>Args:";
		print_r( $args );
		break;
}

?>
