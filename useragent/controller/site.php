<?
class SiteController extends Controller
{
	var $vars = array();

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

		$fp = fsockopen( 'localhost', $this->CFG[PORT] );
		if ( !$fp )
			exit(1);

		$send = 
			"SPP/0.1 " . $this->CFG[URI] . "\r\n" . 
			"comm_key " . $this->CFG[COMM_KEY] . "\r\n" .
			"new_user $user $pass1\r\n";
		fwrite($fp, $send);

		$res = fgets($fp);
		if ( !ereg("^OK", $res) )
			die( "FAILURE *** New user creation failed with: <br> $res" );
   	
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
