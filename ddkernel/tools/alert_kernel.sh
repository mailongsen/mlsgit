#!/bin/bash

### BEGIN INIT INFO
# Provides:          rt_monit
# Required-Start: 
# Required-Stop: 
# Default-Start:
# Default-Stop: 
# Short-Description:
# Description:     
#                 
### END INIT INFO

# PATH should only include /usr/* if it runs after the mountnfs.sh script
RAW_FILE="/tmp/raw_file"
PROC_FILE="/proc/dd_domain_files"
DIFF_FILE="/tmp/diff_file"
CMP_FILE="/tmp/cmp_file"
res=`grep zone /var/lib/named/etc/smbind/TIET/smbind-TIET-slave.conf |awk -F'"' '{print $2}'|sort >$RAW_FILE`


for line in `cat $RAW_FILE`
do
	value="A_$line"
	echo $value > $PROC_FILE
done


while true
do
{
	echo " into loop monitoring ..."
	res=`mv  $RAW_FILE  $CMP_FILE`

	
	res=`grep zone /var/lib/named/etc/smbind/TIET/smbind-TIET-slave.conf |awk -F'"' '{print $2}' |sort >$RAW_FILE`

	diff $CMP_FILE $RAW_FILE > $DIFF_FILE

	cat $DIFF_FILE | while read line
	do
			key=`echo $line | awk -F" " '{print $1}'`
			value=`echo $line | awk -F" " '{print $2}'`

			if [ $key == ">" ];then
				vl="A_$value"
				echo $vl >$PROC_FILE

			fi

			if [  $key == "<"  ];then
				vl="D_$value"
				echo $vl  >$PROC_FILE
			fi
	done
	echo "end loop..."
	sleep 1m
}
done
