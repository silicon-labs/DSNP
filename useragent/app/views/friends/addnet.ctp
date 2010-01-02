<table><tr>

<td id="leftcol">
<div id="details">
<h2><?php echo $USER['display_short'];?></h2>
</div>
</td>

<td id="activity">

<div class="content">

<h3>Show Networks</h3>

<?php 
echo $form->create( 'NetworkUsage', array( 'url' => "/$USER_NAME/friends/saddnet"));
?>

<table class="network_usage">
<? 

foreach ( $networkNames as $nn ) {
	echo "<tr><td>";
	echo "<td>" . $nn['NetworkName']['name'] . "</td>";
	echo "<td>";

	$checkboxName = 'v' . $nn['NetworkName']['id'];

	$checked = false;
	foreach ( $networks as $net ) {
		if ( isset( $net['NetworkName']['name'] ) && 
				$net['NetworkName']['id'] == $nn['NetworkName']['id'] )
		{
			$checked = true;
			break;
		}
	}

	echo $form->checkbox($checkboxName, array ( 'checked' => $checked ) );
	echo "</td>";
	echo "</tr>";
}
?>

</table>

<?php
echo $form->end('Update');
?>

</div>

</td>

</tr></table>


