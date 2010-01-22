<table><tr>

<td id="leftcol">
<div id="details">
<h2><?php echo $USER['display_short'];?></h2>
</div>
</td>

<td id="activity">

<div class="content">

<?php 

function networkNameChoice( $name )
{
	if ( $name == '-' )
		$name = 'No Network';
	return $name;
}

echo $form->create( null, array( 'url' => "/$USER_NAME/cred/nnet"));

$options = array();

foreach ( $networks as $net ) {
	$options[ $net['NetworkName']['name'] ] = networkNameChoice( $net['NetworkName']['name'] );
}

echo $form->radio( 'network', $options );
echo $form->end('Update');

?>

</div>

</td>

</tr></table>

