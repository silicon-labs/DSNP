#!/bin/bash
#

find . \
	-name .svn -prune -or \
	-path ./tmp -prune -or \
	\( -type f -not -name debug.log -not -name error.log -print \)
