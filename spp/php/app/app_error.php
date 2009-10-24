<?php

class AppError extends ErrorHandler
{
	function userNotFound($params) {
		$this->controller->set('user', $params['user']);
		$this->_outputMessage('user_not_found');
	}
}

?>
