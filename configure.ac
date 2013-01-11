dnl 

AC_INIT(dsnp, 0.14)
PUBDATE="May 2012"

AC_PROG_CXX
AC_PROG_CC

dnl Check for definition of MAKE.
AC_PROG_MAKE_SET

dnl Need ragel to build.
dnl FIXME: distribute the ragel-generated code with the tarball.
AC_CHECK_PROG(RAGEL, ragel, ragel)
if test -z "$RAGEL"; then
	AC_ERROR([ragel not found])
fi

AC_CHECK_HEADER([pthread.h], [], AC_ERROR([pthread.h not found]))
AC_CHECK_LIB(pthread, pthread_create, [], AC_ERROR([libpthread not found]))

AM_INIT_AUTOMAKE([foreign])
AC_SUBST(PUBDATE)
AC_CONFIG_HEADER(dsnpd/config.h)

LDFLAGS="${LDFLAGS} -L/usr/lib/mysql"
AC_CHECK_HEADER([mysql/mysql.h], [], AC_ERROR([mysql/mysql.h not found]))
AC_CHECK_LIB(mysqlclient, mysql_init, [], AC_ERROR([libmysqlclient not found]))

AC_CHECK_HEADER([openssl/ssl.h], [], AC_ERROR([openssl/ssl.h not found]))
AC_CHECK_LIB(ssl, SSL_new, [], AC_ERROR([libssl not found]))

AC_ARG_WITH(dsnpd-user, 
	[  --with-dsnpd-user=who   user the dsnpd should run as (default is dsnpd)], 
	[DSNPD_USER="$withval"], [DSNPD_USER="dsnpd"] )
AC_ARG_WITH(dsnpk-user, 
	[  --with-dsnpk-user=who   user the dsnp key agent should run as (default is dsnpk)],
	[DSNPK_USER="$withval"], [DSNPK_USER="dsnpk"] )
AC_ARG_WITH(notif-user,   
	[  --with-notif-user=who   user the notification callback should run as (default is www-data)], 
	[NOTIF_USER="$withval"], [NOTIF_USER="www-data"] )

AC_SUBST(NOTIF_USER)
AC_SUBST(DSNPD_USER)
AC_SUBST(DSNPK_USER)

AC_ARG_ENABLE(debug,
	[  --enable-debug       Enable debug statements],
	[ENABLE_DEBUG=1],
	[ENABLE_DEBUG=0])

AC_SUBST(ENABLE_DEBUG)

AC_ARG_WITH(pid-dir,
	[  --with-pid-dir=dir   directory to put the pid file],
	[PID_DIR="$withval"],
	[PID_DIR=${localstatedir}/run])
AC_SUBST(PID_DIR)

CA_CERT_FILE=""
AC_ARG_WITH(ca-cert-file,
	[  --with-ca-cert-file=file   location of the certificate authority cert list],
	[WITH_CA_CERT_FILE="$withval"],
	[AC_CHECK_FILE(/etc/ssl/certs/ca-certificates.crt,
		[WITH_CA_CERT_FILE=/etc/ssl/certs/ca-certificates.crt], [])
	])

if test -n "$WITH_CA_CERT_FILE"; then
	if test \! -f "$WITH_CA_CERT_FILE"; then
		AC_ERROR([$WITH_CA_CERT_FILE does not exist])
	fi

	CA_CERT_FILE="$WITH_CA_CERT_FILE";
else
	AC_ERROR([could not guess default for --with-ca-cert-file, please specify it])
fi
AC_SUBST(CA_CERT_FILE)


dnl write output files
AC_OUTPUT([
	Makefile
	dsnpd/Makefile
	doc/Makefile
])
