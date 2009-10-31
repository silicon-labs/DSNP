<?php

class AppController extends Controller
{
	var $uses = array('User');

	function activateSession()
	{
		$this->Session->activate( '/spp/' . USER_NAME . '/' );
	}

	function maybeActivateSession()
	{
		# Only resume sessions or start a new one when *a* session variable is provided
		# Note that it might not be the right one.
		if ( isset( $_COOKIE['CAKEPHP'] ) ) {
			$this->activateSession();
		}
	}

	function checkUser()
	{
		$user = $this->User->find( 'first', array('conditions' => 
				array('user' => USER_NAME)));

		if ( $user == null )
			$this->cakeError("userNotFound", array('user' => USER_NAME));

		$this->set( 'user', USER_NAME );
	}

	function requireOwner()
	{
		if ( !$this->Session->valid() || $this->Session->read('auth') !== 'owner' )
			$this->cakeError("error403");

	}

	function requireFriend()
	{
		if ( !$this->Session->valid() || $this->Session->read('auth') !== 'friend' )
			$this->cakeError("error403");
	}

	function isOwnerOrFriend()
	{
		return ( $this->Session->valid() && ( 
				$this->Session->read('auth') === 'owner' ||
				$this->Session->read('auth') === 'friend' ) );
	}
}

?>
