#!/bin/bash
#

runfrom=`dirname $0`
. $runfrom/common.sh

mysql_cmd mysql << EOF
	DROP DATABASE ${site_name}_dsnp;
	DROP USER '${site_name}_dsnp'@'localhost';
EOF

