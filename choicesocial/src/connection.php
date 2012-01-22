<?php

function iduriHash( $iduri )
{
	$iduri = strtolower( $iduri );
	$hash = SHA1( $iduri, true );
	$base64 = base64_encode( $hash );
	$base64 = str_replace( "+", "-", $base64 );
	$base64 = str_replace( "/", "_", $base64 );
	$base64 = str_replace( "=", "", $base64 );
	return $base64;
}

function idurlToIduri( $idurl )
{
	$iduri = preg_replace( '/^https:\/\//', 'dsnp://', $idurl );
	if ( $iduri === $idurl )
		die("failed to convert IDURL $idurl to IDURI\n");
	return $iduri;
}

function iduriToIdurl( $iduri )
{
	$idurl = preg_replace( '/^dsnp:\/\//', 'https://', $iduri );
	if ( $idurl === $iduri )
		die("failed to convert IDURI $iduri to IDURL\n");
	return $idurl;
}

define( 'SOCK_TIMEOUT', 12 );
class Connection
{
	var $fp;
	var $result;

	function openLocal()
	{
		global $CFG;

		$this->fp = fsockopen( 'localhost', $CFG[PORT] );
		if ( ! $this->fp )
			exit(1);
		
		/* --VERSION-- */
		$this->command( "DSNP 0.6 local {$CFG['COMM_KEY']}\r\n" );

		/* Since we supply only one potentential version it suffices to check
		 * for OK. */
		$this->success = ereg(
			"^OK",
			$this->result );
		$this->checkResult();
	}

	function command( $cmd )
	{
		fwrite( $this->fp, $cmd );
		stream_set_timeout( $this->fp, SOCK_TIMEOUT );
		$this->result = fgets( $this->fp );
		$this->info = stream_get_meta_data( $this->fp );
	}

	function checkResult()
	{
		if ( !$this->success ) {
			if ( $this->info['timed_out'] )
			{
				userError( EC_DSNPD_TIMEOUT, array() );
			}
			if ( is_bool( $this->result ) && !$this->result || 
					$this->result == '' )
			{
				userError( EC_DSNPD_NO_RESPONSE, array() );
			}
			else {
				$args = preg_split( '/[ \t\n\r]+/', $this->result );
				array_shift( $args );
				$code = array_shift( $args );
				userError( $code, $args );
			}
		}
	}

	/*
	 * Commands invoked by controllers.
	 */

	function newUser( $user, $pass )
	{
		$this->command( 
			"new_user $user $pass\r\n" );

		$this->success = ereg(
			"^OK",
			$this->result );

		$this->checkResult();
	}

	function relidRequest( $user, $identity )
	{
		$this->command( 
			"relid_request $user $identity\r\n" );

		$this->success = ereg(
			"^OK ([-A-Za-z0-9_]+)",
			$this->result, $this->regs );

		$this->checkResult();
	}

	function relidResponse( $token, $reqid, $identity )
	{
		$this->command( 
			"relid_response $token $reqid $identity\r\n" );

		$this->success = ereg(
			"^OK ([-A-Za-z0-9_]+)", 
			$this->result, $this->regs );

		$this->checkResult();
	}

	function login( $user, $pass, $sessionId )
	{
		$this->command( 
			"login $user $pass $sessionId\r\n" );

		$this->success = ereg(
			"^OK ([-A-Za-z0-9_]+) ([-A-Za-z0-9_]+) ([0-9]+)",
			$this->result, $this->regs );

		$this->checkResult();
	}

	function ftokenRequest( $user, $hash )
	{
		$this->command(
			"ftoken_request $user $hash\r\n" );

		$this->success = ereg(
			"^OK ([^\t\n\r]+) ([-A-Za-z0-9_]+) ([-A-Za-z0-9_]+)", 
			$this->result, $this->regs );

		$this->checkResult();

		$this->iduri = $this->regs[1];
		$this->hash = $this->regs[2];
		$this->reqid = $this->regs[3];
	}

	function ftokenResponse( $token, $hash, $reqid )
	{
		$this->command(
			"ftoken_response $token $hash $reqid\r\n" );

		$this->success = ereg(
			"^OK ([^ \t\r\n]*) ([-A-Za-z0-9_]+)",
			$this->result, $this->regs );

		$this->checkResult();

		$this->iduri = $this->regs[1];
		$this->ftoken = $this->regs[2];
	}

	function submitFtoken( $ftoken, $sessionId )
	{
		$this->command(
			"submit_ftoken $ftoken $sessionId\r\n" );

		$this->success = ereg(
			"^OK ([^ \t\r\n]*) ([-A-Za-z0-9_]+) ([0-9]+)",
			$this->result, $this->regs );

		$this->checkResult();

		$this->iduri = $this->regs[1];
		$this->hash = $this->regs[2];
		$this->lasts = $this->regs[3];
	}

	function frFinal( $user, $reqid, $identity )
	{
		$this->command( 
			"friend_final $user $reqid $identity\r\n" );

		$this->success = ereg(
			"^OK",
			$this->result );

		$this->checkResult();
	}

	function acceptFriend( $token, $reqid )
	{
		$this->command(
			"accept_friend $token $reqid\r\n" );

		$this->success = ereg(
			"^OK", 
			$this->result );

		$this->checkResult();
	}

	function submitBroadcast( $token, $message )
	{
		$len = strlen( $message );

		$cmd = "submit_broadcast $token $len\r\n";
		fwrite( $this->fp, $cmd );
		fwrite( $this->fp, $message, $len );
		fwrite( $this->fp, "\r\n", 2 );
		$this->result = fgets( $this->fp );

		$this->success = ereg(
			"^OK", 
			$this->result );

		$this->checkResult();
	}

	function remoteBroadcastRequest( $floginToken, $message )
	{
		$len = strlen( $message );
		$cmd = 
			"remote_broadcast_request $floginToken $len\r\n";
		fwrite( $this->fp, $cmd );
		fwrite( $this->fp, $message, strlen($message) );
		fwrite( $this->fp, "\r\n", 2 );
		$this->result = fgets( $this->fp );

		$this->success = ereg(
			"^OK ([-A-Za-z0-9_]+)",
			$this->result, $this->regs );

		$this->checkResult();
	}

	function remoteBroadcastResponse( $loginToken, $reqid )
	{
		$this->command(
			"remote_broadcast_response $loginToken $reqid\r\n" );

		$this->success = ereg(
			"^OK ([-A-Za-z0-9_]+)",
			$this->result, $this->regs );

		$this->checkResult();
	}

	function remoteBroadcastFinal( $floginToken, $reqid )
	{
		$this->command(
			"remote_broadcast_final $floginToken $reqid\r\n" );

		$this->success = ereg(
			"^OK", 
			$this->result );

		$this->checkResult();
	}
};
?>
