#!/bin/bash
#

d="$1"
[ -z "$d" ] && d=.

find "$d" \
	-name db -prune -or \
	-name .svn -prune -or \
	-path ./tmp -prune -or \
	\( -type f -not -name debug.log -not -name error.log -print \)
