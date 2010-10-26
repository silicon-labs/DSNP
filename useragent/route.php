<?php

if ( isset( $_GET['url'] ) )
	$url = $_GET['url'];

if ( !isset( $url ) ) {
	# If there is no URL then default to index/cindex
	$route = array( 'main', 'index' );
}
else {
	# Split on '/'.
	$route = explode( '/', $url );

	# Validate the component names.
	foreach ( $route as $component ) {
		if ( ! preg_match( '/^[a-zA-Z][a-zA-Z0-9_\-]*$/', $component ) )
			die( "route component $component does not validate" );
	}

	# If the first element of the route is anything but 'admin', then it is a
	# user. Shift the array to get the controller at the head.
	if ( $route[0] !== 'admin' )
		$user = array_shift( $route );

	# If there is no function then default it to cindex.
	if ( !isset( $route[1] ) )
		$route[1] = 'index';

}

foreach ( $route as $component ) {
	# Derive a class name by stripping out underscores and dashes. We can
	# expect this to be non-empty because the above regex requires alpha as the
	# first character.
	$className[$component] = preg_replace( '/[_\-]+/', '', $component );
}

# Check for the controller file.
$controllerFile = ROOT . DS . 'controller' . DS . $route[0] . '.php';
if ( !file_exists( $controllerFile ) )
	die( "invalid URL: controller file '$controllerFile' does not exist" );

# Make sure the controller class does not exist already.
$controllerName = $className[$route[0]];
if ( class_exists( $controllerName ) )
	die("internal error: controller '$controllerName' is prexisting");

# Include the file and make sure we have the class now.
include( $controllerFile );

if ( ! class_exists( $controllerName ) )
	die("internal error: controller '$controllerName' class not defined in $controllerFile");

# Allocate controller.
$controller = new $controllerName;
if ( !is_object( $controller ) )
	die("internal error: failed to allocate controller");

# Find method
$methodName = $className[$route[1]];
if ( !method_exists( $controller, $methodName ) )
	die("invalid URL: method $methodName not present in $controllerName");

$controller->controller = $controllerName;
$controller->method = $methodName

?>
