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

	var $USER = NULL;
	var $USER_ID = null;
	var $USER_NAME = null;
	var $USER_URI = null;
	var $ROLE = null;
	var $NETWORK_NAME = null;
	var $NETWORK_ID = null;
	var $BROWSWER = null;

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
		$params['USER_URI'] = $this->USER_URI;
		$params['USER'] = $this->USER;
		$this->cakeError( $error, $params );
	}

	function checkUser()
	{
		$user = $this->User->find( 'first', array('conditions' => 
				array('user' => $this->params['user'])));

		if ( $user == null )
			$this->userError("userNotFound");

		$this->USER_NAME = $this->params['user'];
		$this->USER_URI =  "$this->CFG_URI$this->USER_NAME/";
		$this->USER_ID = $user['User']['id'];
		$this->USER = $user['User'];

		/* Default these to something not too revealing. At session activation
		 * time we will upgrade if the role allows it. */
		$this->USER['display_short'] = $this->USER['user'];
		$this->USER['display_long'] = $this->USER['identity'];

		$this->set( 'USER_ID', $this->USER_ID );
		$this->set( 'USER_NAME', $this->USER_NAME );
		$this->set( 'USER_URI', $this->USER_URI );
		$this->set( 'USER', $this->USER );
	}

	function activateSession()
	{
		$this->Session->activate( Router::url( "/$this->USER_NAME/" ) );
	}

	/* Try to activate the session if a session variable has been provided. If
	 * activation is successful then load authorization/identity data from the
	 * session. */
	function maybeActivateSession()
	{
		if ( isset( $_COOKIE['CAKEPHP'] ) ) {
			$this->activateSession();
			if ( $this->Session->valid() ) {
				/* Role. */
				$this->ROLE = $this->Session->read('ROLE');
				$this->set('ROLE', $this->ROLE );

				/* Browser if this is a friend. */
				if ( $this->ROLE === 'friend' ) {
					$this->BROWSER = $this->Session->read('BROWSER');
					$this->set( 'BROWSER', $this->BROWSER );
				}

				/* Upgrade the display names if trusted. */
				if ( ( $this->ROLE === 'owner' || $this->ROLE === 'friend' ) && 
						isset( $this->USER['name'] ) )
				{
					$this->USER['display_short'] = $this->USER['name'];
					$this->USER['display_long'] = $this->USER['name'];
					$this->set( 'USER', $this->USER );
				}

				/* Network. */
				$this->NETWORK_NAME = $this->Session->read('NETWORK_NAME');
				$this->NETWORK_ID = $this->Session->read('NETWORK_ID');
				$this->set('NETWORK_NAME', $this->NETWORK_NAME );
				$this->set('NETWORK_ID', $this->NETWORK_ID );
			}
		}
	}

	function requireOwner()
	{
		if ( !$this->Session->valid() || $this->Session->read('ROLE') !== 'owner' )
			$this->userError('notAuthorized', array( 'cred' => 'o' ));
	}

	function requireFriend()
	{
		if ( !$this->Session->valid() || $this->Session->read('ROLE') !== 'friend' )
			$this->userError('notAuthorized', array( 'cred' => 'f' ));
	}

	function requireOwnerOrFriend()
	{
		if ( !$this->Session->valid() || ( 
				$this->Session->read('ROLE') !== 'owner' &&
				$this->Session->read('ROLE') !== 'friend' ) )
		{
			$this->userError('notAuthorized', array( 'cred' => 'of' ));
		}
	}

	function isOwnerOrFriend()
	{
		return ( $this->Session->valid() && ( 
				$this->Session->read('ROLE') === 'owner' ||
				$this->Session->read('ROLE') === 'friend' ) );
	}

	function isOwner()
	{
		return $this->Session->valid() && 
			$this->Session->read('ROLE') === 'owner';

	}

	function isFriend()
	{
		return $this->Session->valid() &&
			$this->Session->read('ROLE') === 'friend';
	}

	function findNetworkId( $networkName )
	{
		$this->loadModel( 'Network' );
		$networks = $this->Network->find( 'first', array( 
			'conditions' => array( 
				'Network.user_id' => $this->USER_ID,
				'NetworkName.name' => $networkName ),
			'order' => 'NetworkName.id' 
		));

		return $networks['Network']['id'];
	}
}
?>
