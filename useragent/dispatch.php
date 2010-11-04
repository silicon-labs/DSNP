<?php

# Foo.
$CONTROLLER_TYPE = null;
if ( isset( $USER[USER] ) )
	$CONTROLLER_TYPE = $ROLE;
else
	$CONTROLLER_TYPE = 'site';
	
# Check for the controller file.
$controllerFile = ROOT . DS . 'controller' . DS . $CONTROLLER_TYPE . 
		DS . $route[0] . '.php';
if ( !file_exists( $controllerFile ) )
	die( "invalid URL: controller file '$controllerFile' does not exist" );

function upperFirst( $name )
{
	return strtoupper( substr( $name, 0, 1 ) ) . 
			substr( $name, 1, strlen($name)-1 );
}

# Make sure the controller class does not exist already.
$controllerName = $className[$route[0]];
$controllerClassName = upperFirst($CONTROLLER_TYPE) . 
		upperFirst($controllerName) . "Controller";
if ( class_exists( $controllerClassName ) )
	die("ERROR: controller '$controllerClassName' is prexisting");

# Include the file and make sure we have the class now.
include( $controllerFile );

if ( ! class_exists( $controllerClassName ) ) {
	die( "ERROR: controller '$controllerClassName' class " . 
		"not defined in $controllerFile" );
}

# Allocate controller.
$controller = new $controllerClassName;
if ( !is_object( $controller ) )
	die("ERROR: failed to allocate controller");
$controller->controllerName = $controllerName;

# The functionName is the route component after the controller. This must be
# mapped to a set of arg definitions if it is to be handled. 
$functionName = $className[$route[1]];
$functionDef = $controller->function[$functionName];
$controller->functionName = $functionName;
$controller->functionDef = $functionDef;

if ( !method_exists( $controller, $functionName ) ||
		!isset( $functionDef ) || 
		!is_array( $functionDef ) )
{
	die( "ERROR: invalid URL: function $functionName not " .
		"handled in $controllerClassName " . 
		"(role is $CONTROLLER_TYPE)" );
}

# Invoke the controller.
$controller->$functionName();

# Invoke the view.
$viewFile = ROOT . DS . 'view' . DS . 
		$CONTROLLER_TYPE . DS .
		$controller->controllerName . DS .
		$controller->functionName . '.php';
if ( ! file_exists( $viewFile ) )
	die("ERROR: view file $viewFile not found");

if ( !isset( $controller->hasView ) ) {
	die("ERROR: controller '$controllerClassName' does not have a <br>" .
		"specific variable that indicates it extends the Controller class" );
}

if ( $controller->hasView ) {
	$view = new View( $controller, $viewFile );
	$view->dispatch();
}
	
?>
