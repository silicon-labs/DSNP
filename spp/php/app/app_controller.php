<?php

class AppController extends Controller
{
	var $uses = array('User');

	var $CFG_URI = null;
	var $CFG_HOST = null;
	var $CFG_PATH = null;
	var $CFG_DB_HOST = null;
	var $CFG_DB_USER = null;
	var $CFG_DB_DATABASE = null;
	var $CFG_ADMIN_PASS = null;
	var $CFG_COMM_KEY = null;
	var $CFG_PORT = null;
	var $CFG_USE_RECAPTCHA = null;
	var $CFG_RC_PUBLIC_KEY = null;
	var $CFG_RC_PRIVATE_KEY = null;
	var $CFG_PHOTO_DIR = null;
	var $CFG_IM_CONVERT = null;

	var $USER_ID = null;
	var $USER_NAME = null;
	var $USER_PATH = null;
	var $USER_URI = null;
	var $USER_DISPLAY_NAME = null;
	var $USER_DISPLAY_SHORT = null;
	var $USER_DISPLAY_LONG = null;

	function hereFull()
	{
		/* Make the full url for sending back here in if the user does get authorized. */
		$params = $this->params['url'];
		unset( $params['url'] );
		return Router::url( null, true ) . Router::queryString( $params );
	}

	function __construct() 
	{
		$this->CFG_URI = Configure::read('CFG_URI');
		$this->CFG_HOST = Configure::read('CFG_HOST');
		$this->CFG_PATH = Configure::read('CFG_PATH');
		$this->CFG_DB_HOST = Configure::read('CFG_DB_HOST');
		$this->CFG_DB_USER = Configure::read('CFG_DB_USER');
		$this->CFG_DB_DATABASE = Configure::read('CFG_DB_DATABASE');
		$this->CFG_ADMIN_PASS = Configure::read('CFG_ADMIN_PASS');
		$this->CFG_COMM_KEY = Configure::read('CFG_COMM_KEY');
		$this->CFG_PORT = Configure::read('CFG_PORT');
		$this->CFG_USE_RECAPTCHA = Configure::read('CFG_USE_RECAPTCHA');
		$this->CFG_RC_PUBLIC_KEY = Configure::read('CFG_RC_PUBLIC_KEY');
		$this->CFG_RC_PRIVATE_KEY = Configure::read('CFG_RC_PRIVATE_KEY');
		$this->CFG_PHOTO_DIR = Configure::read('CFG_PHOTO_DIR');
		$this->CFG_IM_CONVERT = Configure::read('CFG_IM_CONVERT');

		$this->set('CFG_URI', $this->CFG_URI);
		$this->set('CFG_PATH', $this->CFG_PATH);
		parent::__construct();
	}

	function userError( $error, $params = array() )
	{
		$params['USER_ID'] = $this->USER_ID;
		$params['USER_NAME'] = $this->USER_NAME;
		$params['USER_PATH'] = $this->USER_PATH;
		$params['USER_URI'] = $this->USER_URI;
		$params['USER_DISPLAY_SHORT'] = $this->USER_DISPLAY_SHORT;
		$params['USER_DISPLAY_LONG'] = $this->USER_DISPLAY_LONG;
		$this->cakeError( $error, $params );
	}

	function activateSession()
	{
		$this->Session->activate( "/spp/$this->USER_NAME/" );
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
		$this->USER_PATH = $this->CFG_PATH . $this->USER_NAME . '/';
		$this->USER_URI =  $this->CFG_URI . $this->USER_NAME . '/';

		$user = $this->User->find( 'first', array('conditions' => 
				array('user' => $this->USER_NAME)));

		if ( $user == null )
			$this->userError("userNotFound");

		$this->USER_ID = $user['User']['id'];

		if ( isset( $user['User']['name'] ) )
			$this->USER_DISPLAY_NAME = $user['User']['name'];

		$this->USER_DISPLAY_SHORT = $this->USER_NAME;
		$this->USER_DISPLAY_LONG = $this->USER_URI;

		$this->set( 'USER_ID', $this->USER_ID );
		$this->set( 'USER_NAME', $this->USER_NAME );
		$this->set( 'USER_PATH', $this->USER_PATH );
		$this->set( 'USER_URI', $this->USER_URI );
		$this->set( 'USER_DISPLAY_SHORT', $this->USER_DISPLAY_SHORT );
		$this->set( 'USER_DISPLAY_LONG', $this->USER_DISPLAY_LONG );
	}

	function privName()
	{
		if ( isset( $this->USER_DISPLAY_NAME ) ) {
			$this->USER_DISPLAY_SHORT = $this->USER_DISPLAY_NAME;
			$this->USER_DISPLAY_LONG = $this->USER_DISPLAY_NAME;

			$this->set( 'USER_DISPLAY_SHORT', $this->USER_DISPLAY_SHORT );
			$this->set( 'USER_DISPLAY_LONG', $this->USER_DISPLAY_LONG );
		}
	}

	function requireOwner()
	{
		if ( !$this->Session->valid() || $this->Session->read('auth') !== 'owner' )
			$this->userError('notAuthorized', array( 'cred' => 'o' ));
		$this->privName();
	}

	function requireFriend()
	{
		if ( !$this->Session->valid() || $this->Session->read('auth') !== 'friend' )
			$this->userError('notAuthorized', array( 'cred' => 'f' ));
		$this->privName();
	}

	function requireOwnerOrFriend()
	{
		if ( !$this->Session->valid() || ( 
				$this->Session->read('auth') !== 'owner' &&
				$this->Session->read('auth') !== 'friend' ) )
		{
			$this->userError('notAuthorized', array( 'cred' => 'of' ));
		}

		$this->privName();
	}

	function isOwnerOrFriend()
	{
		return ( $this->Session->valid() && ( 
				$this->Session->read('auth') === 'owner' ||
				$this->Session->read('auth') === 'friend' ) );
	}

	function isOwner()
	{
		return $this->Session->valid() && 
			$this->Session->read('auth') === 'owner';

	}

	function isFriend()
	{
		return $this->Session->valid() &&
			$this->Session->read('auth') === 'friend';
	}
}

?>
