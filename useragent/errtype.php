<?php

function peerFailedSsl( $host )
{
	echo "We failed to make a secure connection to {$host}! ";
	echo "<p>This could mean that {$host} is not properly configured, ";
	echo "that {$host}'s security certificate is invalid or expired, ";
	echo "or that this server is not properly configured. Please ";
	echo "consult the operator of this server.";
}

function friendRequestExists( $user, $identity )
{
	echo "A friend request from <code>$identity</code> " .
		"to user <code>$user</code> already exists.";
}

switch ( $code ) {
	case EC_PEER_FAILED_SSL:
		peerFailedSsl( $args[0] );
		break;
	case EC_FRIEND_REQUEST_EXISTS:
		friendRequestExists( $args[0], $args[1] );
		break;
}

?>
