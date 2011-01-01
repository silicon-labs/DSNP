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
			"SELECT * FROM sent_friend_request WHERE user_id = %L", 
			$this->USER['USER_ID'] );
		$this->vars['sentFriendRequests'] = $sentFriendRequests;

		# Load the user's friend requests. 
		$friendRequests = dbQuery( 
			"SELECT * " .
			"FROM friend_request "
			"WHERE user_id = %L",
			$this->USER['USER_ID'] );
		$this->vars['friendRequests'] = $friendRequests;

		# Load the friend list.
		$friendClaims = dbQuery(
			"SELECT * FROM friend_claim WHERE user_id = %L",
			$this->USER['USER_ID'],
			REL_TYPE_FRIEND );
		$this->vars['friendClaims'] = $friendClaims;

		# Load the user's images.
		$images = dbQuery( "
			SELECT * FROM image WHERE user_id = %L 
			ORDER BY seq_num DESC LIMIT 30",
			$this->USER['USER_ID'] );
		$this->vars['images'] = $images;

#		$activity = dbQuery( "
#			SELECT 
#				activity.*, 
#				activity.author_id AS 'author.id',
#				author_fc.iduri AS 'author_iduri',
#				author_fc.name AS 'author_name',
#				activity.subject_id AS 'subject.id',
#				subject_fc.iduri AS 'subject_iduri',
#				subject_fc.name AS 'subject_name'
#			FROM activity 
#			LEFT OUTER JOIN friend_claim AS author_fc
#					ON activity.author_id = author_fc.id
#			LEFT OUTER JOIN friend_claim AS subject_fc
#					ON activity.subject_id = subject_fc.id
#			WHERE activity.user_id = %l
#			ORDER BY time_published DESC LIMIT %l
#			",
#			$this->USER['ID'], $start + ACTIVITY_SIZE );
#		$this->vars['start'] = $start;
#		$this->vars['activity'] = $activity;

#		echo "<pre>";
#		print_r( $activity );
#		echo "</pre>";
#		exit;
	}
}
?>
