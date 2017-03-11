#!/bin/bash
Subject="dns flood alert: $1"
To="op@unlun.com"
From="monitorusr@anquanbao.com.cn"
SMTP="58.215.176.222"
PASSWD="123.com"
TMP_MAIL="/tmp/atten_mail.txt"

ip=`ifconfig |grep "inet addr" |awk -F':' '{print $2}'|awk '{print $1}'|xargs`

function mailtext() 
{ 
	echo -n > ${TMP_MAIL} 
	echo "Subject: ${Subject}" >> ${TMP_MAIL} 
	echo "To: ${To}" >> ${TMP_MAIL} 
	echo "From: ${From}" >> ${TMP_MAIL} 
	echo "" >> ${TMP_MAIL} 
	echo " by server ip: ${ip}" >> ${TMP_MAIL}
	echo "" >> ${TMP_MAIL}
}

mailtext
echo "sendmail -f ${From} -bs ${SMTP} -au${From} -ap${PASSWD} < ${TMP_MAIL}"
/usr/local/bin/sendmail -f ${From} -S${SMTP} -au${From} -ap${PASSWD} < ${TMP_MAIL}

