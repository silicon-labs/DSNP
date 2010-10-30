<?php

# Invoke the controller.
$controller->$methodName();

# Invoke the view.
$viewFile = ROOT . DS . 'view' . DS . 
		$controller->controller . DS .
		$controller->method . '.php';
if ( ! file_exists( $viewFile ) )
	die("internal error: view file $viewFile not found");

if ( !isset( $controller->hasView ) ) {
	die("internal error: controller '$controllerClassName' does not have a <br>" .
		"specific variable that indicates it extends the Controller class" );
}

if ( $controller->hasView ) {
	$view = new View( $controller, $viewFile );
	$view->dispatch();
}
	
?>
