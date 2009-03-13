#!/bin/bash
while [[ 1 ]] ; do 
real=`nslookup arma.keygen.com.ru 2>/dev/null | tail -2|grep Address|cut -d' ' -f3`
apparent=`nslookup ns1.static.void.ee 2>/dev/null | tail -2|grep Address|cut -d' ' -f3`

if [[ X$real != X && X$apparent != X ]] ; then
echo in check yy ${real} 
echo xx ${apparent} xx
	if [[ $real != $apparent ]] ; then
		date
		echo "real ${real}"
		echo "apparent ${apparent}"
		echo ". restarting"
		./start.sh stop
		./start.sh start
	fi
fi
sleep 60
done;