#!/bin/bash
#

if test -z "$BASH_VERSION"; then
	echo expecting bash
	exit 1
fi

# Validate the site name.
site_name="$1"
if test -z "$site_name"; then
	echo "usage: $0 site-name"
	exit 1
fi

site_regex='^[a-zA-Z_][a-zA-Z_0-9]*$'

if ! echo "$site_name" | grep -q "$site_regex"; then
	echo "site must match regex '$site_regex'"
	exit 1
fi

function mysql_cmd()
{
	mysql -u root -p"$MYSQL_ROOT_PASS" -B -N "$@"
}

# Get the mysql root password.
cat << EOF
This script will make a number of calls to mysql.
Please enter the password for the root user.
EOF

while true; do
	read -s -p 'mysql root@localhost pass: ' MYSQL_ROOT_PASS; echo;

	# Check the password that was just entered.
	mysql_cmd mysql -e "exit"
	if test $? != 0 ; then
		echo "error: it appears the mysql password you entered was not correct"
		continue
	fi

	echo "mysql root password is good"
	break
done

