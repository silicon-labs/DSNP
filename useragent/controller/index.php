<?
class Index extends Controller
{
	var $vars = array();

	function cindex()
	{
		# Load the user's sent friend requests
		$users = dbQuery( "SELECT * from user" );
		$this->vars['users'] = $users;
	}
}
?>
