<?php

require( ROOT . DS . 'controller/cred.php' );

class FriendCredController extends CredController
{
	var $function = array(
		'logout' => array(),
		'sflogin' => array(
			array( 
				get => 'dsnp_hash',
				type => 'base64', 
				length => HASH_BASE64_SIZE 
			)
		),
	);

	function logout()
	{
		$this->destroySession();
		$this->userRedirect('/');
	}

	function sflogin()
	{
		/* Already logged in as a friend. If it is the same friend we can keep
		 * the login active. If not we need to restart the whole login again. */
		$hash = $this->args['dsnp_hash'];
		if ( isset( $_SESSION['hash'] ) && $_SESSION['hash'] === $hash ) {
			$this->userRedirect( "/" );
		}
		else {
			$this->destroySession();
			$this->submitFriendLogin( $hash );
		}
	}
}
?>
