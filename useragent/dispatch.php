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

#
#      post => name            arg 'name' needs to come from post
# or   get => name             arg 'name' needs to come from get
# or   route => name           arg 'name' comes from a component of 
#                              the route. N must be supplied
#
#      N => value              if this is a route arg, it is component N.
#      regex => '^[a-z]+$'     must match given regex
#      nonEmpty => true        arg nust not be empty
#      optional => true        arg is optional
#      def => value            default value if arg is optional and not given
#      type => ( int, base64 ) specify a predetermined type.
#      length => value         specify an exact length required
#
# Cleaned arguments get placed in the the 'args' field in the controller
#

function checkArgs( $functionDef, $route )
{
	$clean = array();

	foreach ( $functionDef as $arg ) {
		# Extract the name and value from either _GET or _POST.
		if ( isset( $arg[post] ) ) {
			$name = $arg[post];
			$value = $_POST[$name];
		}
		elseif ( isset( $arg[get] ) ) {
			$name = $arg[get];
			$value = $_GET[$name];
		}
		elseif ( isset( $arg[route] ) ) {
			$name = $arg[route];
			$value = $route[$arg[N]];
		}
		

		# Deal with the case that it is not set.
		if ( !isset($value) ) {
			if ( $arg[optional] ) {
				# Maybe give it the default value
				if ( isset( $arg[def] ) )
					$value = $arg[def];

				$clean[$name] = $value;
				continue;
			}
			else {
				die( "required argument $name not given" );
			}
		}

		if ( isset($arg[regex]) ) {
			$match = preg_match( $arg[regex], $value );
			if ( $match === false ) {
				die("<br><br>there was an error checking " . 
					"$name against {$arg[regex]}");
			}
			else if ( $match === 0 ) {
				die("arg $name does not validate {$arg[regex]}");
			}
		}

		if ( isset($arg[nonEmpty]) && $arg[nonEmpty] && strlen( $value ) == 0 )
			die("arg $name is not allowed to be empty");

		if ( isset($arg[type] ) ) {
			switch ( $arg[type] ) {
				case 'identity': {
					$match = preg_match( '|^https://.*/$|', $value );
					if ( $match === false ) {
						die("<br><br>there was an error checking " . 
							"$name regex for identity type");
					}
					else if ( $match === 0 ) {
						die("arg $name is not identity type");
						$value = (int)$value;
					}
					break;
				}
				case 'base64': {
					$match = preg_match( '/^[0-9a-zA-Z_\-]+$/', $value );
					if ( $match === false ) {
						die("<br><br>there was an error checking " . 
							"$name regex for base64 type");
					}
					else if ( $match === 0 ) {
						die("arg $name is not base64 type");
						$value = (int)$value;
					}
					break;
				}
				case 'int': {
					$match = preg_match( '/^[0-9]+$/', $value );
					if ( $match === false ) {
						die("<br><br>there was an error checking " . 
							"$name regex for integer");
					}
					else if ( $match === 0 ) {
						die("arg $name is not integer type");
						$value = (int)$value;
					}
					break;
				}
			}
		}

		if ( isset($arg[length] ) ) {
			if ( strlen($value) != $arg[length] )
				die("arg $name is is not of length {$arg[length]}");
		}

		$clean[$name] = $value;
	}
	return $clean;
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
		"handled in $controllerClassName " );
}

$clean = checkArgs( $functionDef, $route );

# Invoke the controller.
$controller->args = $clean;
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
