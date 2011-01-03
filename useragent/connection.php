<?php

define( 'SOCK_TIMEOUT', 5 );
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
			"DSNP/0.1 " . $CFG['URI'] . "\r\n" .
			"comm_key " . $CFG['COMM_KEY'] . "\r\n";
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

	function relidResponse( $user, $fr_reqid, $identity )
	{
		$this->command( 
			"relid_response $user $fr_reqid $identity\r\n" );

		$this->success = ereg(
			"^OK ([-A-Za-z0-9_]+)", 
			$this->result, $this->regs );

		$this->checkResult();
	}

	function login( $user, $pass )
	{
		$this->command( 
			"login $user $pass\r\n" );

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

	function ftokenResponse( $user, $hash, $reqid )
	{
		$this->command(
			"ftoken_response $user $hash $reqid\r\n" );

		$this->success = ereg(
			"^OK ([^ \t\r\n]*) ([-A-Za-z0-9_]+)",
			$this->result, $this->regs );

		$this->checkResult();

		$this->iduri = $this->regs[1];
		$this->ftoken = $this->regs[2];
	}

	function submitFtoken( $ftoken )
	{
		$this->command(
			"submit_ftoken $ftoken\r\n" );

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

	function acceptFriend( $user, $reqid )
	{
		$this->command(
			"accept_friend $user $reqid\r\n" );

		$this->success = ereg(
			"^OK", 
			$this->result );

		$this->checkResult();
	}

	function submitBroadcast( $user, $message )
	{
		$len = strlen( $message );

		$cmd = "submit_broadcast $user $len\r\n";
		fwrite( $this->fp, $cmd );
		fwrite( $this->fp, $message, $len );
		fwrite( $this->fp, "\r\n", 2 );
		$this->result = fgets( $this->fp );

		$this->success = ereg(
			"^OK", 
			$this->result );

		$this->checkResult();
	}

	function remoteBroadcastRequest( $user, $identity, 
		$hash, $token, $network, $message )
	{
		$len = strlen( $message );
		$cmd = 
			"remote_broadcast_request $user $identity $hash " . 
			"$token $network $len\r\n";
		fwrite( $this->fp, $cmd );
		fwrite( $this->fp, $message, strlen($message) );
		fwrite( $this->fp, "\r\n", 2 );
		$this->result = fgets( $this->fp );

		$this->success = ereg(
			"^OK ([-A-Za-z0-9_]+)",
			$this->result, $this->regs );
	}

	function remoteBroadcastResponse( $user, $reqid )
	{
		$this->command(
			"remote_broadcast_response $user $reqid\r\n" );

		$this->success = ereg(
			"^OK ([-A-Za-z0-9_]+)",
			$this->result, $this->regs );
	}

	function remoteBroadcastFinal( $user, $reqid )
	{
		$this->command(
			"remote_broadcast_final $user $reqid\r\n" );

		$this->success = ereg(
			"^OK", 
			$this->result );
	}
};
?>
