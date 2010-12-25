<?php

function peerFailedSslVerify( $host )
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

function dsnpdNoResponse()
{
	echo "There was no response from the dsnpd server. It most " .
		"likely crashed. ";
}

function dsnpdTimeout()
{
	echo "The connection to the dsnpd server timed out. " .
		"Something is amiss. ";
}

switch ( $code ) {
	case EC_PEER_FAILED_SSL_VERIFY:
		peerFailedSslVerify( $args[0] );
		break;
	case EC_SSL_CONNECT_FAILED:
		sslConnectFailed( $args[0] );
		break;
	case EC_FRIEND_REQUEST_EXISTS:
		friendRequestExists( $args[0], $args[1] );
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
	default:
		echo "Sorry, I don't have any information about " .
			"the nature of this error.";
		break;
}

?>
