<?
class Index extends Controller
{
	var $vars = array();

	function cindex()
	{
		# Load the user's sent friend requests
		$users = dbQuery( "SELECT * from user" );
		$this->vars['users'] = $users;

#		view( 'index', 'controller' );
#		echo "<pre>";
#		print_r($users);
#		echo "</pre>";
	}
}
?>
