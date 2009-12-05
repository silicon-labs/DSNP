<div id="leftcol">

<div id="details">
<h2><?php echo $USER['display_short'];?></h2>
</div>

</div>

<div id="activity">

<div class="content">
<h3>Wish List for <?echo $this->data['FriendClaim']['name']; ?></h3>

<div style="width: 80%;">
<p>
<?php 
if ( isset( $this->data['Wish'] ) ) {
	$list = htmlspecialchars($this->data['Wish']['list']);
	$list = preg_replace( '/\r?\n/', '<br>', $list );
	$list = $text->autoLinkUrls( $list );
	echo $list;
}
else
	echo "<em>This user has not yet given a wishlist</em>";
?>
</div>

<?php
$id = $this->data['FriendClaim']['id'];
if ( $id == $BROWSER['id'] )
	echo $html->link( 'edit', "/$USER_NAME/wish/edit/$id" );
?>

</div>
</div>
