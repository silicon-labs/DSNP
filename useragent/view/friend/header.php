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
//			if ( isset( $USER['display_long'] ) )
//				echo $html->link( $USER['display_long'], $USER['identity'] );
		?>
		</h1>
		</div></td>

		<td id="header_right"><div class="header_content">
		<h1>
		<?php 
		if ( isset( $ROLE ) && $ROLE == 'friend' )
		{
//			echo $html->link( isset( $BROWSER['name'] ) ? $BROWSER['name'] : 
//					$BROWSER['identity'], $BROWSER['identity'] );
//			echo " - ";
//			echo $html->link( 'logout', "/$USER_NAME/cred/logout" );
		}
		else if ( isset( $ROLE ) && $ROLE == 'owner' )
		{
//			echo $html->link( $USER['name'], $USER['identity'] );
//			echo " - ";
//			echo $html->link( 'logout', "/$USER_NAME/cred/logout" );
		}
		else if ( isset( $USER_NAME ) )
		{
//			echo $html->link( 'login', "/$USER_NAME/cred/login" );
		}
		?>
		</h1>
		</div></td>

	</tr></table>
	</div>

	<div id="page_body">
