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
	
	function userNotFound($params) {
		if ( defined( 'USER_NAME' ) )
			$this->controller->set('user', USER_NAME );

		$this->_outputMessage('user_not_found');
	}

	function notAuthorized($params) {
		if ( defined( 'USER_NAME' ) )
			$this->controller->set('user', USER_NAME );

		$this->controller->set('url', h(Router::normalize($this->controller->here)) );
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
