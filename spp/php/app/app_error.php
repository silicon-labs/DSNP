<?php

class AppError extends ErrorHandler
{
	function __construct($method, $messages)
	{
		/* In this class but not in the parent. */
		if ( method_exists( $this, $method ) && 
				!method_exists( get_parent_class($this), $method ) )
		{
			Configure::write('debug', 1);
		}

		parent::__construct($method, $messages);
	}

	function collectUserData( $params )
	{
		if ( isset( $params['USER_NAME'] ) ) {
			$this->controller->set( 'USER_NAME', $params['USER_NAME'] );
			$this->controller->set( 'USER_PATH', $params['USER_PATH'] );
			$this->controller->set( 'USER_URI', $params['USER_URI'] );
		}
	}
	
	function userNotFound( $params ) {
		$this->collectUserData( $params );
		$this->_outputMessage('user_not_found');
	}

	function notAuthorized( $params )
	{
		$this->collectUserData( $params );

		if ( isset( $params['cred'] ) )
			$this->controller->set( 'cred', $params['cred'] );
		else
			$this->controller->set( 'cred', 'o' );

		/* The url for displaying what was not authorized. */
		$this->controller->set( 'url', h(Router::normalize($this->controller->here)) );

		/* Make the full url for sending back here in if the user does get authorized. */
		$params = $this->controller->params['url'];
		unset( $params['url'] );
		$foo = Router::url( null, true ) . Router::queryString( $params );
		$this->controller->set( 'backto',  $foo );

		$this->_outputMessage('not_authorized');
	}

	# We can override this so we can use a different layout.
	# function _outputMessage($template)
	# {
	# 	$this->controller->render( $template, 'error' );
	# 	$this->controller->afterFilter();
	# 	echo $this->controller->output;
	# }
}
?>
