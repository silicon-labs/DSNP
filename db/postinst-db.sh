#!/bin/bash
#

runfrom=`dirname $0`
. $runfrom/common.sh

OUTPUT=`mktemp`

# Check for the user.
mysql_cmd mysql -e \
	"SELECT count(user) FROM user WHERE user = '${site_name}_dsnp';" > $OUTPUT

# Create the user if necessary.
if test `cat $OUTPUT` == 0; then
	echo "+ ADDING USER ${site_name}_dsnp"

	cat <<- EOF
	Please choose a password to protect the new database users with. Every site you
	create during this run will have a new user with this password. The user name
	will be derived from the site name.
	EOF

	while true; do
		read -s -p 'password: ' DB_PASS; echo
		read -s -p '   again: ' AGAIN; echo

		if [ -z "$DB_PASS" ]; then
			echo; echo error: password must not be empty; echo 
			continue
		fi

		if [ "$DB_PASS" != "$AGAIN" ]; then
			echo; echo error: passwords do not match; echo
			continue
		fi
		break;
	done

	mysql_cmd mysql -e \
		"CREATE USER '${site_name}_dsnp'@'localhost' IDENTIFIED BY '$DB_PASS';"
fi


# Check for the database.
mysql_cmd mysql -e \
	"SELECT count(db) FROM db WHERE db = '${site_name}_dsnp';" > $OUTPUT

# Create the database if necessary.
if test `cat $OUTPUT` == 0; then
	echo "+ CREATING DATABASE ${site_name}_dsnp"
	mysql_cmd mysql -e \
		"CREATE DATABASE ${site_name}_dsnp;"

	mysql_cmd mysql -e \
		"GRANT ALL ON ${site_name}_dsnp.* TO '${site_name}_dsnp'@'localhost';"
fi

# Check for the init table. If there assume we have run init.sh
if ! mysql_cmd ${site_name}_dsnp -e "show tables;" | grep -q user; then
	# Init the database.
	echo "+ INITIALIAING DATABASE ${site_name}_dsnp"
	mysql_cmd ${site_name}_dsnp < init.sql
fi

rm $OUTPUT

