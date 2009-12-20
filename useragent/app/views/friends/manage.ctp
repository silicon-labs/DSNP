<table><tr>

<td id="leftcol">
<div id="details">
<h2><?php echo $USER['display_short'];?></h2>
</div>
</td>

<td id="activity">

<div class="content">

<?
echo $form->create( 'Membership', array( 'url' => "/$USER_NAME/friends/smanage"));
?>

<table class="group_membership">
<thead class=>
<tr class="head1">
	<td>Person</td> 
	<td colspan="<? echo count( $friendGroups ); ?>">
		Groups 
		<font class="mod_link">
			<? echo $html->link('add', "/$USER_NAME/friends/addgroup/"); ?>
		</font>
		
	</td> 
</tr>
<tr class="head2">
	<td></td> 
	<? 
	foreach ( $friendGroups as $group ) {
		echo "<td>" . $group['FriendGroup']['name'] . "</td>";
	}
	?>
</tr>
</thead>

<?

function isMember( $groupMembers, $groupId )
{
	foreach ( $groupMembers as $member ) {
		if ( $groupId == $member['friend_group_id'] )
			return true;
	}
	return false;
}

foreach ( $friendClaims as $claim ) {
	echo "<tr>";

	echo "<td>";
	echo $claim['FriendClaim']['name'];
	echo "</td>";

	foreach ( $friendGroups as $group ) {
		echo "<td class='member'>";
		$checked = false;
		if ( isMember( $claim['GroupMember'], $group['FriendGroup']['id'] ) )
			$checked = true;

		$checkboxName = 'v_' . $group['FriendGroup']['id'] . '_' . $claim['FriendClaim']['id'];

		echo $form->checkbox($checkboxName, array (
				'checked' => $checked ) );
		echo "</td>";
	}

	echo "</tr>";
}


?>
</table>

<?

echo $form->end('Update');

#echo "<pre>"; print_r( $friendGroups ); echo "</pre>";
#echo "<pre>"; print_r( $friendClaims ); echo "</pre>";
?>

</div>

</td>

</tr></table>

