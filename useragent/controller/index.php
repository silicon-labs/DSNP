<?
class IndexController extends Controller
{
	var $vars = array();

	function index()
	{
		# Load the user's sent friend requests
		$users = dbQuery( "SELECT * from user" );
		$this->vars['users'] = $users;
	}
}
?>
