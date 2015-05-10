#!/bin/bash

tmp_lock()
{
	fname=$(mktemp --tmpdir=.)
	err=1
	while [ $err -ne 0 ]; do
		ln $fname gai.conf.tmp
		err=$?
		[ $err -eq 0 ] && break
		sleep 0.01
	done
	rm $fname
	return
}

flag=0

case $1 in
  "add") flag=1 
	echo "add $2 $3 $4"
	tmp_lock
	echo "$2 $3 $4" | cat /etc/gai.conf - >> gai.conf.tmp
	mv gai.conf.tmp /etc/gai.conf
	chmod ugo+r /etc/gai.conf
	;;
  "del") flag=1
	echo "delete $2 $3 $4"
	tmp_lock
	grep -v "$2 $3 $4" /etc/gai.conf | cat > gai.conf.tmp
	mv gai.conf.tmp /etc/gai.conf
	chmod ugo+r /etc/gai.conf
	;;
esac

if [ $flag -eq 0 ]
  then echo "Wrong parameter!"
       echo "usage: add|del precedence|label PREFIX VALUE"
fi
