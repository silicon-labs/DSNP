<div id="leftcol">

<div id="details">
<h2><?php echo $USER['display_short'];?></h2>
</div>

</div>

<div id="activity">

<div class="content">
<h3>Wish List for <?echo $this->data['FriendClaim']['name']; ?></h3>

<?php
$id = $this->data['FriendClaim']['id'];
echo $form->create( null, array( 'url' => "/$USER_NAME/wish/sedit"));
echo $form->textarea('list', array('rows' => 20));
echo $form->hidden('friend_claim_id');
echo $form->end('Update');
?>

</div>
</div>
