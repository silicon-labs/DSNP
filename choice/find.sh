#!/bin/bash
#

d="$1"
[ -z "$d" ] && d=.

find "$d" -name .svn -prune -or \( -type f -print \)
