#!/bin/sh

cd "$(dirname "$0")" || exit 1

CC=${CC:=cc}
CCOPT="-Wall -W -O2"

$CC gentables.c -o gentables $CCOPT
./gentables > tables.c
./gentables h > tables.h
echo Tables generated
