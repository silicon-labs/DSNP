<?php

echo "<div>";

if ( isset( $_GET['url'] ) )
	$url = $_GET['url'];

if ( !isset( $url ) )
	$url = 'index';

$route = explode( '/', $url );
if ( !isset( $route[1] ) )
	$route[1] = 'index';

foreach ( $route as $component ) {
	# Validate.
	if ( ! preg_match( '/^[a-zA-Z][a-zA-Z0-9_\-]*$/', $component ) )
		die( "route component $component does not validate" );

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
$controllerClass = $className[$route[0]];
if ( class_exists( $controllerClass ) )
	die("internal error: controller '$controllerClass' is prexisting");

# Include the file and make sure we have the class now.
include( $controllerFile );
if ( ! class_exists( $controllerClass ) )
	die("internal error: controller '$controllerClass' class not defined in $controllerFile");

# Allocate controller.
$controller = new $controllerClass;
if ( !is_object( $controller ) )
	die("internal error: failed to allocate controller");

# Find method
$methodName = $className[$route[1]];
if ( !method_exists( $controller, $methodName) )
	die("invalid URL: method $methodName not present in $controllerClass");

?>
