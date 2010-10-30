<?
class View
{
	var $viewFile = null;
	var $controller = null;

	function View($controller, $viewFile)
	{
		$this->controller = $controller;
		$this->viewFile = $viewFile;
	}

	function dispatch()
	{
		foreach ( $this->controller->vars as $name => $value ) {
			${$name} = $value;
		}

		global $CFG;
		global $USER_NAME;

		require( ROOT . DS . 'header.php' );
		require( $this->viewFile );
		require( ROOT . DS . 'footer.php' );
	}

	function link( $text, $location )
	{
		global $CFG;
		print "<a href=" . $CFG[PATH] . $location . ">" . $text . "</a>";
	}
}
?>
