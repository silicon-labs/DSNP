<?php
	class Activity extends AppModel
	{
		var $useTable = 'activity';
		var $name = 'Activity';

		var $belongsTo = array (
			'AuthorFC' => array(
				'className' => 'FriendClaim',
				'foreignKey' => 'author_id'
			),
			'SubjectFC' => array(
				'className' => 'FriendClaim',
				'foreignKey' => 'subject_id'
			)
		);
	}
?>
