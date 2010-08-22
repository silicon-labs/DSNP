<?php

# Invoke the controller.
$controller->$methodName();

# Invoke the view.
$viewFile = ROOT . DS . 'view' . DS . $controller->controller . DS . $controller->method . '.php';
if ( ! file_exists( $viewFile ) )
	die("internal error: view file $viewFile not found");

require( $viewFile );

?>
