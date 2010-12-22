<?php

switch ( $code ) {
	case EC_PEER_FAILED_SSL:
		peerFailedSsl( $args );
		break;
	case EC_FRIEND_REQUEST_EXISTS:
		friendRequestExists( $args );
		break;
}

?>
