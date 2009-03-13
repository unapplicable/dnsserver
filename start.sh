#!/bin/bash
GETIPURL="http://zone.ee/shellcode/gethost.php"
BINARY=g:/dev/dnsserver/Release/dnsserver.exe
DIR=g:\\dev\\dnsserver
cd $DIR

function config() {
	my=0
	name[$my]=my
	zone[$my]=my.zone
	ip[$my]=192.168.2.11
	port[$my]=53

	xtee=1
	name[$xtee]=xtee
	zone[$xtee]=xtee.zone
	ip[$xtee]=10.222.1.2
	port[$xtee]=53

	dtv=2
	name[$dtv]=dtv
	zone[$dtv]=dtv.zone
	ip[$dtv]=10.0.16.7
	port[$dtv]=53
}

function getIp() {
	PUBLICIP=`wget -O - ${GETIPURL}`
}

function subst() {
	zone=$1
	zonefile=$zone
	grep -c PUBLICIP $zone
	omg=$?
	[ $omg != 0 ] && return 
	zonefile=${zone}.effective
	sed -e "s/PUBLICIP/$PUBLICIP/g" $zone > $zone.effective
}

function start() {
	conf=$1
	echo -n "starting ${name[$conf]} .."
	subst ${zone[$conf]}
	cmd="${BINARY} ${ip[$conf]} ${port[$conf]} ${zonefile}"
	echo 	cmd /c "g: && cd $DIR && start $cmd" 
	cmd /c "g: && cd $DIR && start $cmd" &
	echo started
	return 0
}

function stop() {
	conf=$1
	echo -n "stopping ${name[$conf]} .. "
	pid=`handle ${zone[$conf]}|grep pid|cut -d' ' -f8`

	if [ x${pid} == x ] ; then
		echo instance not found
		return 1
	fi

	echo -n "pid ${pid} "
	pskill ${pid} >/dev/null 2>&1
	if [ $? != 0 ] ; then
		echo failed to kill
		return 1
	fi

	echo stopped
	return 0
}

function restart() {
	stop $1
	start $1
}

config
getIp
echo "PUBLICIP is $PUBLICIP"

$1 $2