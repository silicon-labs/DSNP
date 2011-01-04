<?
class FriendIndexController extends Controller
{
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

		# Load the friend list.
		$friendClaims = dbQuery(
			"SELECT identity.*, relationship.* " .
			"FROM friend_claim " .
			"JOIN identity ON friend_claim.identity_id = identity.id " .
			"JOIN relationship ON friend_claim.relationship_id = relationship.id " .
			"WHERE friend_claim.user_id = %L",
			$this->USER['USER_ID'] );
		$this->vars['friendClaims'] = $friendClaims;

#		# Load the user's images.
#		$images = dbQuery( "
#			SELECT * FROM image WHERE user = %e 
#			ORDER BY seq_num DESC LIMIT 30",
#			$this->USER[NAME] );
#		$this->vars['images'] = $images;

		$activity = dbQuery( "
			SELECT 
				activity.*, 
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
				) AS author_fc ON activity.author_id = author_fc.id
			LEFT OUTER JOIN ( 
					SELECT relationship.id, name, identity.iduri
					FROM relationship 
					JOIN identity ON relationship.identity_id = identity.id
				) AS subject_fc ON activity.subject_id = subject_fc.id
			WHERE activity.user_id = %L AND published
			ORDER BY time_published DESC LIMIT %l
			",
			$this->USER['USER_ID'], $start + ACTIVITY_SIZE );

		$this->vars['start'] = $start;
		$this->vars['activity'] = $activity;

		# FIXME: NEED TO DO THIS?
		# $BROWSER = $this->Session->read('BROWSER');
		# $this->set( 'BROWSER', $BROWSER );
	}
}
?>
