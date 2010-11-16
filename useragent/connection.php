<?php
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
		
		$send = 
			"SPP/0.1 " . $CFG[URI] . "\r\n" .
			"comm_key " . $CFG[COMM_KEY] . "\r\n";
		fwrite( $this->fp, $send );
	}

	function openLocalPriv()
	{
		global $CFG;
		$this->openLocal();
		$send = "comm_key " . $CFG[COMM_KEY] . "\r\n";
		fwrite( $this->fp, $send );
	}

	function command( $cmd )
	{
		fwrite( $this->fp, $cmd );
		$this->result = fgets( $this->fp );
	}

	function checkResult( $pat )
	{
		if ( !ereg( $pat , $this->result ) ) {
			die( "FAILURE *** New user creation failed with: <br> " .
					$this->result );
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
	}

	function relidRequest( $user, $identity )
	{
		$this->command( 
			"relid_request $user $identity\r\n" );

		$this->success = ereg(
			"^OK ([-A-Za-z0-9_]+)",
			$this->result, $this->regs );
	}

	function relidResponse( $user, $fr_reqid, $identity )
	{
		$this->command( 
			"relid_response $user $fr_reqid $identity\r\n" );

		$this->success = ereg(
			"^OK ([-A-Za-z0-9_]+)", 
			$this->result, $this->regs );
	}

	function login( $user, $pass )
	{
		$this->command( 
			"login $user $pass\r\n" );

		$this->success = ereg(
			"^OK ([-A-Za-z0-9_]+) ([-A-Za-z0-9_]+) ([0-9]+)",
			$this->result, $this->regs );
	}

	function ftokenRequest( $user, $hash )
	{
		$this->command(
			"ftoken_request $user $hash\r\n" );

		$this->success = ereg(
			"^OK ([-A-Za-z0-9_]+) ([^ \t\n\r]+) ([-A-Za-z0-9_]+)", 
			$this->result, $this->regs );
	}

	function ftokenResponse( $user, $hash, $reqid )
	{
		$this->command(
			"ftoken_response $user $hash $reqid\r\n" );

		$this->success = ereg(
			"^OK ([-A-Za-z0-9_]+) ([^ \t\r\n]*)",
			$this->result, $this->regs );
	}

	function submitFtoken( $ftoken )
	{
		$this->command(
			"submit_ftoken $ftoken\r\n" );
	}

	function frFinal( $user, $reqid, $identity )
	{
		$this->command( 
			"friend_final $user $reqid $identity\r\n" );
	}

	function acceptFriend( $user, $reqid )
	{
		$this->command(
			"accept_friend $user $reqid\r\n" );
	}

	function submitBroadcast( $user, $network, $len, $headers, $message )
	{
		$cmd = "submit_broadcast $user $network $len\r\n";
		fwrite( $this->fp, $cmd );
		fwrite( $this->fp, $headers, strlen($headers) );
		fwrite( $this->fp, $message, strlen($message) );
		fwrite( $this->fp, "\r\n", 2 );
		$this->result = fgets( $this->fp );
	}

	function remoteBroadcastRequest( $user, $identity, 
		$hash, $token, $network, $len, $headers, $message )
	{
		$cmd = 
			"remote_broadcast_request $user $identity $hash " . 
			"$token $network $len\r\n";
		fwrite( $this->fp, $cmd );
		fwrite( $this->fp, $headers, strlen($headers) );
		fwrite( $this->fp, $message, strlen($message) );
		fwrite( $this->fp, "\r\n", 2 );
		$this->result = fgets( $this->fp );
	}

	function remoteBroadcastResponse( $user, $reqid )
	{
		$this->command(
			"remote_broadcast_response $user $reqid\r\n" );
	}

	function remoteBroadcastFinal( $user, $reqid )
	{
		$this->command(
			"remote_broadcast_final $user $reqid\r\n" );
	}
};
?>
