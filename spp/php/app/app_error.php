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
		$this->controller->set('user', $params['user']);
		$this->_outputMessage('user_not_found');
	}

	function notAuthorized($params) {
		//$this->controller->set( 'methods', get_class_methods($this) );
		$this->controller->set('url', $params['url']);
		$this->_outputMessage('not_authorized');
	}

	# We can override this if we want to use a different layout.
	# function _outputMessage($template)
	# {
	#	$this->controller->render( $template, 'error' );
	#	$this->controller->afterFilter();
	#	echo $this->controller->output;
	# }
}

?>
