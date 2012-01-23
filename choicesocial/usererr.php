<?php

require( ROOT . '/errdef.php' );

function userError( $code, $args )
{
	print '<html xmlns="http://www.w3.org/1999/xhtml">';
	print '<head>';
	print '<title>OOPS</title>';
	print '</head>';
	print '<body>';
	print '<p>';
	print '<h1> Ooops, there was an error!</h1>';
	print '<big><div style="width: 50%">';
	include( ROOT . '/error.php' );
	print '</div></big>';
	print '<div style="width: 50%; topmargin: 1em;">';
	print "code: $code<br>";
	print '</div>';
	print '</body>';
	print '</html>';

	exit;
}

?>
