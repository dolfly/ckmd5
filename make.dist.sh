#!/bin/sh

mkdir $1
cp ChangeLog.txt LICENSE Makefile.in PLANS README *.c *.h configure configure.test.c md5.copyright $1/
cp -r test $1/
