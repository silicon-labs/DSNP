<table><tr>

<td id="leftcol">
<div id="details">
<h2><?php echo $USER['display_short'];?></h2>
</div>
</td>

<td id="activity">

<div class="content">

<h1>Add Group</h1>

<?php 

echo $form->create( 'FriendGroup', array( 'url' => "/$USER_NAME/friends/saddgroup"));
echo $form->input('name');
echo $form->end('Add Group');

?>

Current Groups:<br>
<? 
foreach ( $friendGroups as $group ) {
	echo $group['FriendGroup']['name'] . "<br>";
}
?>

</div>

</td>

</tr></table>


