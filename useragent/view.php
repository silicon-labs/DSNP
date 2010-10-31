<?
class View
{
	var $viewFile = null;
	var $controller = null;
	var $CFG = null;
	var $USER = null;

	function View($controller, $viewFile)
	{
		$this->controller = $controller;
		$this->viewFile = $viewFile;
	}

	function dispatch()
	{
		global $CFG;
		global $USER;

		foreach ( $this->controller->vars as $name => $value )
			${$name} = $value;

		$this->CFG = $CFG;
		$this->USER = $USER;

		require( ROOT . DS . 'header.php' );
		require( $this->viewFile );
		require( ROOT . DS . 'footer.php' );
	}

	function link( $text, $location )
	{
		global $CFG;
		return "<a href=" . $CFG[PATH] . $location . ">" . $text . "</a>";
	}

	function siteLoc( $location )
	{
		return $this->CFG[PATH] . $location;
	}

	function userLoc( $location )
	{
		return $this->CFG[PATH] . '/' . $this->USER[USER] . $location;
	}
}
?>
