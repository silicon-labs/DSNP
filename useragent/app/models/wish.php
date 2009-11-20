<?php
	class Wish extends AppModel
	{
		var $useTable = 'wish';
		var $name = 'Wish';

		var $belongsTo = array( 'FriendClaim' );
		var $primaryKey = 'friend_claim_id';
	}
?>
