#!/bin/bash
#

BIN=@prefix@/bin/dsnpd
PID_FILE=@PID_DIR@/dsnpd.pid
WHOAMI=/usr/bin/whoami

function dsnpd_start
{
	echo -n starting dsnpd ...

	if test -f $PID_FILE; then
		echo " ERROR: pid file alread present"
		exit 1;
	fi

	$BIN -b

	# Give four seconds to successfully startup. 
	for i in 1 2 3 4; do
		if test -f $PID_FILE; then
			PID=`cat $PID_FILE`
			if ps $PID >/dev/null; then
				echo " done"
				exit 0
			fi
		fi
		echo -n .
		sleep 1;
	done

	echo " ERROR: could not find proces"
	exit 1;
}

function dsnpd_stop
{
	echo -n stopping dsnpd ...

	if ! test -f $PID_FILE; then
		echo " ERROR: no pid file"
		exit 1;
	fi

	PID=`cat $PID_FILE`
	if ! ps $PID > /dev/null; then
		echo " ERROR: pid file exists, but it does not reference an active process"
		exit 1;
	fi

	if ! kill $PID; then
		echo " ERROR: kill $PID failed"
		exit 1;
	fi

	# Give it four seconds to stop.
	for i in 1 2 3 4; do
		if ! test -f $PID_FILE; then
			echo " done"
			exit 0;
		fi
		echo -n .
		sleep 1;
	done

	echo " ERROR: pid file did not disappear"
	exit 1;
}

function dsnpd_restart
{
	echo
}

if test "`$WHOAMI`" != "root"; then
	echo the startup script must be run as root
	exit 1;
fi

case $1 in
	start)    dsnpd_start;;
	stop)     dsnpd_stop;;
	restart)  
		dsnpd_stop
		dsnpd_start
	;;
	*)
		echo "ERROR: invalid command $1"
		exit;
	;;
esac
