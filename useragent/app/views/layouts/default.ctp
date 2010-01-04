<?php
/* SVN FILE: $Id$ */
/**
 *
 * PHP versions 4 and 5
 *
 * CakePHP(tm) :  Rapid Development Framework (http://www.cakephp.org)
 * Copyright 2005-2008, Cake Software Foundation, Inc. (http://www.cakefoundation.org)
 *
 * Licensed under The MIT License
 * Redistributions of files must retain the above copyright notice.
 *
 * @filesource
 * @copyright     Copyright 2005-2008, Cake Software Foundation, Inc. (http://www.cakefoundation.org)
 * @link          http://www.cakefoundation.org/projects/info/cakephp CakePHP(tm) Project
 * @package       cake
 * @subpackage    cake.cake.libs.view.templates.layouts
 * @since         CakePHP(tm) v 0.10.0.1076
 * @version       $Revision$
 * @modifiedby    $LastChangedBy$
 * @lastmodified  $Date$
 * @license       http://www.opensource.org/licenses/mit-license.php The MIT License
 */
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
	<?php echo $html->charset(); ?>
	<title>
		<?php 
			echo Configure::read('CFG_SITE_NAME');
			if ( isset( $USER_NAME ) )
				echo ": $USER_NAME";
		?>
	</title>
	<?php
		echo $html->meta('icon');
		echo $html->css('duao');
		echo $scripts_for_layout;
	?>
</head>
<body>
	<div id="header"><tr>
	<table><tr>
		<td id="header_left"><div class="header_content">
		<h1>
		<?php 
			echo $html->link( Configure::read('CFG_SITE_NAME'), 
					Configure::read('CFG_URI') );
		?>
		</h1>
		</div></td>

		<td id="header_middle"><div class="header_content">
		<h1>
		<?php
			if ( isset( $USER['display_long'] ) )
				echo $html->link( $USER['display_long'], $USER['identity'] );
		?>
		</h1>
		</div></td>

		<td id="header_right"><div class="header_content">
		<h1>
		<?php 
		if ( isset( $ROLE ) && $ROLE == 'friend' )
		{
			echo $html->link( isset( $BROWSER['name'] ) ? $BROWSER['name'] : 
					$BROWSER['identity'], $BROWSER['identity'] );
			echo " - ";
			if ( isset( $NETWORK ) )
				echo $NETWORK;
			echo " - ";
			echo $html->link( 'logout', "/$USER_NAME/cred/logout" );
		}
		else if ( isset( $ROLE ) && $ROLE == 'owner' )
		{
			echo $html->link( $USER['name'], $USER['identity'] );
			echo " - ";
			if ( isset( $NETWORK ) )
				echo $html->link( $NETWORK, "/$USER_NAME/user/cnet" );
			echo " - ";
			echo $html->link( 'logout', "/$USER_NAME/cred/logout" );
		}
		else if ( isset( $USER_NAME ) )
		{
			echo $html->link( 'login', "/$USER_NAME/cred/login" );
		}
		?>
		</h1>
		</div></td>

	</tr></table>
	</div>

	<div id="page_body">
		<?php $session->flash(); ?>
		<?php echo $content_for_layout; ?>
	</div>

	<div id="footer">
	<table><tr>
		<td id="footer_left"><div class="footer_content">
		</div></td>

		<td id="footer_middle"><div class="footer_content">
		<h1>
		<?php echo $html->link(__('DSNP User-Agent One', true), 
			'http://www.complang.org/dsnp/'); ?>
		</h1>
		</div></td>

		<td id="footer_right"><div class="footer_content">
		</div></td>
	</tr><table>
	</div>
</body>
</html>
