<?
class SiteController extends Controller
{
	function index()
	{
		# Load the user's sent friend requests
		$users = dbQuery( "SELECT * from user" );
		$this->vars['users'] = $users;
	}

	function newuser()
	{
	}

	function snewuser()
	{
		$user = $_POST['user'];
		$pass1 = $_POST['pass1'];
		$pass2 = $_POST['pass2'];

		if ( $pass1 != $pass2 )
			die("password mismatch");

		$connection = new Connection;
		$connection->openLocal();
		$connection->command( "new_user $user $pass1\r\n" );
		$connection->checkResult( "^OK" );

		$identity = $this->CFG[URI] . $user . '/';
		dbQuery( "UPDATE user SET name = %e, identity = %e, " .
			"type = %l WHERE user = %e ",
			$user, $identity, 0, $user );

		# Create the photo directory.
		$photoDirCmd =  "umask 0002; mkdir " . DATA_DIR . "/$user";
		system( $photoDirCmd );

		$this->redirect( $this->CFG[PATH] );
	}
}
?>
