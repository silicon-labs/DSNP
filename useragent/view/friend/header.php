<html xmlns="http://www.w3.org/1999/xhtml">
<head>
	<?php /*echo $html->charset(); */?>
	<title>
		<?php 
			echo $CFG[SITE_NAME];
			if ( isset( $USER_NAME ) )
				echo ": $USER_NAME";
		?>
	</title>
	<link href="<?echo $this->siteLoc( '/css/duao.css' ); ?>"
		rel="stylesheet" type="text/css"/>
</head>
<body>
	<div id="header">
	<table><tr>
		<td id="header_left"><div class="header_content">
		<h1>
				<?php echo $this->link( $CFG[SITE_NAME], '/' ); ?>
		</h1>
		</div></td>

		<td id="header_middle"><div class="header_content">
		<h1>
		<?php
			echo $this->absLink( $USER[USER], $USER[URI] );
		?>
		</h1>
		</div></td>

		<td id="header_right"><div class="header_content">
		<h1>
		<?php 
			echo $this->link( $BROWSER[URI], $BROWSER[URI] );
			echo " - ";
			echo $this->userLink( 'logout', "/cred/logout" );
		?>
		</h1>
		</div></td>

	</tr></table>
	</div>

	<div id="page_body">
