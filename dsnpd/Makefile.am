
bin_PROGRAMS = dsnpd

dsnpd_SOURCES = \
	main.cc parser.cc string.cc rcfile.cc encrypt.cc \
	log.cc db.cc tls.cc base64.cc test.cc broadcast.cc queue.cc \
	friendreq.cc prefriend.cc message.cc network.cc notification.cc user.cc \
	login.cc flogin.cc identity.cc connect.cc keys.cc conversion.cc server.cc \
	packet.cc umessage.cc listenfork.cc keyagent.cc barrier.cc command.cc \
	buffer.h config.h dlist.h dsnp.h encrypt.h error.h keyagent.h lstring.h \
	packet.h parser.h recipients.h schema.h

BUILT_SOURCES = \
	parser.cc \
	packet.cc \
	umessage.cc \
	packet.cc \
	parser.cc \
	rcfile.cc \
	base64.cc \
	umessage.cc \
	command.cc \
	schema.h

dsnpd_CXXFLAGS = \
	-DPREFIX='"@prefix@"' \
	-DSYSCONFDIR='"@prefix@/etc"' \
	-DLOGDIR='"@prefix@/var/log/dsnpd"' \
	-DDSNPD_USER='"@DSNPD_USER@"' \
	-DDSNPK_USER='"@DSNPK_USER@"' \
	-DNOTIF_USER='"@NOTIF_USER@"' \
	-DCA_CERT_FILE='"@CA_CERT_FILE@"' \
	-DPID_DIR='"@PID_DIR@"' \
	-DENABLE_DEBUG=@ENABLE_DEBUG@


# No automatic dependency computation for Ragel includes.
parser.cc: common.rl
packet.cc: common.rl
umessage.cc: common.rl

packet.cc: packet.rl
	ragel -G2 -o $@ $<

parser.cc: parser.rl
	ragel -G2 -o $@ $<

rcfile.cc: rcfile.rl
	ragel -G2 -o $@ $<

base64.cc: base64.rl
	ragel -G2 -o $@ $<

umessage.cc: umessage.rl
	ragel -G2 -o $@ $<

command.cc: command.rl
	ragel -G2 -o $@ $<

schema.h: Makefile ../db/dsnpd.ver
	echo "#ifndef _SCHEMA_VERSION_H" > $@
	echo "#define _SCHEMA_VERSION_H" >> $@
	echo "#define SCHEMA_VERSION `cat ../db/dsnpd.ver`" >> $@
	echo "#endif" >> $@

