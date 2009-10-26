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
		<?php __('DSNP User Agent One:'); ?>
		<?php echo USER_NAME; ?>
	</title>
	<?php
		echo $html->meta('icon');
		echo $html->css('cake.generic');
		echo $scripts_for_layout;
	?>
</head>
<body>
	<div id="container">
		<div id="header">
			<div id="header_left">
			<h1><?php echo $html->link(__('DSNP User Agent One', true), 
				'http://www.complang.org/dsnp/'); ?>
				<a href="<?php echo CFG_URI; ?>">(site)</a>
				</h1>
			</div>
			<div id="header_middle">
			<h1><?php
				if ( defined('USER_URI') )
					echo '<a href="' . USER_URI . '">' . USER_URI . '</a>';
			?></h1>
			</div>
			<div id="header_right">
			<h1><?php 
			if ( isset( $auth ) && $auth == 'friend' ) {
				echo "<a href=\"" . BROWSER_ID . "\">" . BROWSER_ID . "</a>";
				echo "<a href=\"logout\">logout</a>";
			}
			else if ( isset( $auth ) && $auth == 'owner' ) {
				echo "<a href=\"" . USER_URI . "\">" . USER_URI . "</a>";
				echo "<a href=\"logout\">logout</a>";
			}
			?></h1>
			</div>
		</div>
		<div id="content">
			<?php $session->flash(); ?>
			<?php echo $content_for_layout; ?>
		</div>
		<div id="footer">
			<?php echo $html->link(
					$html->image('cake.power.gif', array(
						'alt'=> __("CakePHP: the rapid development php framework", true), 
						'border'=>"0")),
					'http://www.cakephp.org/',
					array('target'=>'_blank'), null, false
				);
			?>
		</div>
	</div>
	<?php echo $cakeDebug; ?>
</body>
</html>
