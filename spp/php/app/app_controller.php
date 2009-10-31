<?php

class AppController extends Controller
{
	var $uses = array('User');

	var $CFG_URI = null;
	var $CFG_COMM_KEY = null;
	var $CFG_COMM_PORT = null;
	var $CFG_PHOTO_DIR = null;

	var $USER_NAME = null;
	var $USER_PATH = null;
	var $USER_URI = null;


	function __construct() 
	{
		$this->CFG_URI = CFG_URI;
		$this->CFG_PORT = CFG_PORT;
		$this->CFG_COMM_KEY = CFG_COMM_KEY;
		$this->CFG_PHOTO_DIR = CFG_PHOTO_DIR;
		parent::__construct();
	}

	function activateSession()
	{
		$this->Session->activate( '/spp/' . $this->USER_NAME . '/' );
	}

	function maybeActivateSession()
	{
		# Only resume sessions or start a new one when *a* session variable is provided
		# Note that it might not be the right one.
		if ( isset( $_COOKIE['CAKEPHP'] ) )
			$this->activateSession();
	}

	function checkUser()
	{
		$this->USER_NAME = $this->params['user'];
		$this->USER_PATH = CFG_PATH . $this->USER_NAME . '/';
		$this->USER_URI =  CFG_URI . $this->USER_NAME . '/';

		$user = $this->User->find( 'first', array('conditions' => 
				array('user' => $this->USER_NAME)));

		if ( $user == null )
			$this->cakeError("userNotFound");

		$this->set( 'USER_NAME', $this->USER_NAME );
		$this->set( 'USER_PATH', $this->USER_PATH );
		$this->set( 'USER_URI', $this->USER_URI );
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
