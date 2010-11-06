<?
class OwnerIndexController extends Controller
{
	var $vars = array();

	var $function = array(
		'index' => array()
	);

	function index()
	{
		if ( isset( $_GET['start'] ) )
			$start = $_GET['start'];
		else
			$start = 0;

		$sentFriendRequests = dbQuery(
			"SELECT * FROM sent_friend_request WHERE from_user = %e", 
			$this->USER[USER] );
		$this->vars['sentFriendRequests'] = $sentFriendRequests;

		# Load the user's friend requests. 
		$friendRequests = dbQuery( 
			"SELECT * FROM friend_request WHERE for_user = %e",
			$this->USER[USER] );
		$this->vars['friendRequests'] = $friendRequests;

		# Load the friend list.
		$friendClaims = dbQuery(
			"SELECT * FROM friend_claim WHERE user_id = %l",
			$this->USER[ID] );
		$this->vars['friendClaims'] = $friendClaims;

		# Load the user's images.
		$images = dbQuery( "
			SELECT * FROM image WHERE user = %e 
			ORDER BY seq_num DESC LIMIT 30",
			$this->USER[NAME] );
		$this->vars['images'] = $images;

		$activity = dbQuery( "
			SELECT 
				activity.*, 
				author_fc.identity AS author_identity,
				author_fc.name AS author_name,
				subject_fc.identity AS subject_identity,
				subject_fc.name AS subject_name
			FROM activity 
			LEFT OUTER JOIN friend_claim AS author_fc
					ON activity.author_id = author_fc.id
			LEFT OUTER JOIN friend_claim AS subject_fc
					ON activity.subject_id = subject_fc.id
			WHERE activity.user_id = %l
			ORDER BY time_published DESC LIMIT %l
			",
			$this->USER[ID], $start + ACTIVITY_SIZE );
		$this->vars['start'] = $start;
		$this->vars['activity'] = $activity;
	}
}
?>
