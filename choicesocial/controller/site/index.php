<?
class SiteIndexController extends Controller
{
	var $function = array(
		'index' => array(),
	);

	function index()
	{
		# Load the user's sent friend requests
		$users = dbQuery( "SELECT * from user" );
		$this->vars['users'] = $users;
	}
}
?>
