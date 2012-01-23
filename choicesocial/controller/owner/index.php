<?
class OwnerIndexController extends Controller
{
	var $vars = array();

	var $function = array(
		'index' => array(
			array(
				get => 'start', optional => true, 
				def => 0, type => 'int'
			),
		)
	);

	function index()
	{
		$start = $this->args[start];

		$sentFriendRequests = dbQuery(
			"SELECT * " . 
			"FROM sent_friend_request " . 
			"JOIN identity ON sent_friend_request.identity_id = identity.id " .
			"JOIN relationship ON sent_friend_request.relationship_id = relationship.id " .
			"WHERE sent_friend_request.user_id = %L", 
			$this->USER['USER_ID'] );
		$this->vars['sentFriendRequests'] = $sentFriendRequests;

		# Load the user's friend requests. 
		$friendRequests = dbQuery( 
			"SELECT friend_request.accept_reqid, identity.*, relationship.* " .
			"FROM friend_request " .
			"JOIN identity ON friend_request.identity_id = identity.id " .
			"JOIN relationship ON friend_request.relationship_id = relationship.id " .
			"WHERE friend_request.user_id = %L",
			$this->USER['USER_ID'] );
		$this->vars['friendRequests'] = $friendRequests;

		# Load the friend list.
		$friendClaims = dbQuery(
			"SELECT identity.*, relationship.* " .
			"FROM friend_claim " .
			"JOIN identity ON friend_claim.identity_id = identity.id " .
			"JOIN relationship ON friend_claim.relationship_id = relationship.id " .
			"WHERE friend_claim.user_id = %L",
			$this->USER['USER_ID'] );
		$this->vars['friendClaims'] = $friendClaims;

		# Load the user's images.
		$images = dbQuery( "
			SELECT * FROM image WHERE user_id = %L 
			ORDER BY seq_num DESC LIMIT 30",
			$this->USER['USER_ID'] );
		$this->vars['images'] = $images;

		$activity = dbQuery( "
			SELECT 
				activity.*, 
				activity.publisher_id AS 'publisher.id',
				publisher_fc.iduri AS 'publisher_iduri',
				publisher_fc.name AS 'publisher_name',
				activity.author_id AS 'author.id',
				author_fc.iduri AS 'author_iduri',
				author_fc.name AS 'author_name',
				activity.subject_id AS 'subject.id',
				subject_fc.iduri AS 'subject_iduri',
				subject_fc.name AS 'subject_name'
			FROM activity 
			LEFT OUTER JOIN ( 
					SELECT relationship.id, name, identity.iduri 
					FROM relationship 
					JOIN identity ON relationship.identity_id = identity.id
				) AS publisher_fc ON activity.publisher_id = publisher_fc.id
			LEFT OUTER JOIN ( 
					SELECT relationship.id, name, identity.iduri 
					FROM relationship 
					JOIN identity ON relationship.identity_id = identity.id
				) AS author_fc ON activity.author_id = author_fc.id
			LEFT OUTER JOIN ( 
					SELECT relationship.id, name, identity.iduri
					FROM relationship 
					JOIN identity ON relationship.identity_id = identity.id
				) AS subject_fc ON activity.subject_id = subject_fc.id
			WHERE activity.user_id = %L
			ORDER BY time_published DESC LIMIT %l
			",
			$this->USER['USER_ID'], $start + ACTIVITY_SIZE );
		$this->vars['start'] = $start;
		$this->vars['activity'] = $activity;

#		echo "<pre>";
#		print_r( $activity );
#		echo "</pre>";
#		exit;
	}
}
?>
