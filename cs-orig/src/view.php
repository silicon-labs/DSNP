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
		global $ROLE;
		global $BROWSER;

		foreach ( $this->controller->vars as $name => $value )
			${$name} = $value;

		$this->CFG = $CFG;
		$this->USER = $USER;

		$headerFooterPrefix = ROOT . DS . 'view' . DS . $ROLE . DS;

		if ( $this->controller->plainView )
			require( $this->viewFile );
		else {
			require( $headerFooterPrefix . DS . 'header.php' );
			require( $this->viewFile );
			require( $headerFooterPrefix . DS . 'footer.php' );
		}
	}

	function absLink( $text, $location, $class = null )
	{
		$link = '<a';
		if ( isset( $class ) )
			$link .= " class=\"$class\"";
		$link .= ' href="' . $location . '">' . $text . '</a>';
		return $link;
	}

	function siteLink( $text, $location, $class = null )
	{
		$link = '<a';
		if ( isset( $class ) )
			$link .= " class=\"$class\"";
		$link .= ' href="' . $this->CFG['PATH'] . $location . '">' . $text . '</a>';
		return $link;
	}

	function userLink( $text, $location, $class = null )
	{
		$link = "<a";
		if ( isset( $class ) )
			$link .= " class=\"$class\"";
		$link .= ' href="' . $this->CFG['PATH'] . '/' . $this->USER['USER'] . 
				$location . '">' . $text . '</a>';
		return $link;
	}

	function siteLoc( $location )
	{
		return $this->CFG['PATH'] . $location;
	}

	function userLoc( $location )
	{
		return $this->CFG['PATH'] . '/' . $this->USER['USER'] . $location;
	}

	function userImg( $location, $alt )
	{
		return "<img src=\"{$this->CFG['PATH']}/{$this->USER['USER']}$location\" alt=\"$alt\">";
	}

}

function autoLinkUrls( $text )
{
	/* FIXME: implement this */
	return $text;
}

?>
