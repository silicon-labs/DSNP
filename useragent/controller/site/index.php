<?
class SiteIndexController extends Controller
{
	var $function = array(
		'index' => array(),
		'newuser' => array(),
		'snewuser' => array(
			array( 
				post => 'user', 
				regex => '/^[a-z]+$/',
			),
			array( post => 'pass1', nonEmpty => true ),
			array( post => 'pass2', nonEmpty => true ),
		),
	);

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
		$user = $this->args['user'];
		$pass1 = $this->args['pass1'];
		$pass2 = $this->args['pass2'];

		if ( $pass1 != $pass2 )
			$this->userError( "password mismatch", "" );

		$connection = new Connection;
		$connection->openLocalPriv();
		$connection->newUser( $user, $pass1 );
		if ( !$connection->success ) {
			$this->userError( "FAILURE *** New user creation "
					"failed with: <br> ", "" );
		}

		$identity = $this->CFG[URI] . $user . '/';
		dbQuery( "UPDATE user SET name = %e, identity = %e, " .
			"type = %l WHERE user = %e ",
			$user, $identity, 0, $user );

		# Create the photo directory.
		$photoDirCmd =  "umask 0002; mkdir " . DATA_DIR . "/$user";
		system( $photoDirCmd );

		$this->siteRedirect( "/" );
	}
}
?>
