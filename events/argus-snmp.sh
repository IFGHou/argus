#!/bin/sh
#
#  Argus Software
#  Copyright (c) 2006-2012 QoSient, LLC
#  All rights reserved.
#
#  argus-snmp - collect snmp stats and report them as XML oriented argus events.
#               This program requires a lot of site specific customization, and
#               so, be sure and change the community string for snmp agent access
#               and pick the interfaces of interest.
#
# Carter Bullard
# QoSient, LLC
#
#  $Id: //depot/argus/argus/events/argus-snmp.sh#3 $
#  $DateTime: 2012/01/03 19:15:19 $
#  $Change: 2274 $
# 

prog="/usr/bin/snmpwalk -Os -c qosient -v 2c 192.168.0.1" 
stats="/usr/bin/snmpget -Os -c qosient -v 2c 192.168.0.1" 
interfaces="2 3 9"

echo "<ArgusEvent>"

echo "   <ArgusEventData Type = \"Program: $prog\" >"
retn=`$prog ipNetToMediaPhysAddress | awk 'BEGIN{FS="="}{print "      < Label = \""$1"\" Value = \""$2"\" />"}'`;
echo "$retn"
echo "   </ArgusEventData>"

echo "   <ArgusEventData Type = \"Program: $stats\" >"
for i in $interfaces; do
   echo "      "`$stats ifInUcastPkts.$i | awk 'BEGIN{FS="="}{print "< Label = \""$1"\" Value = \""$2"\" />"}'`;
   echo "      "`$stats ifOutUcastPkts.$i | awk 'BEGIN{FS="="}{print "< Label = \""$1"\" Value = \""$2"\" />"}'`;
   echo "      "`$stats ifInOctets.$i | awk 'BEGIN{FS="="}{print "< Label = \""$1"\" Value = \""$2"\" />"}'`;
   echo "      "`$stats ifOutOctets.$i | awk 'BEGIN{FS="="}{print "< Label = \""$1"\" Value = \""$2"\" />"}'`;
   echo "      "`$stats ifOutDiscards.$i | awk 'BEGIN{FS="="}{print "< Label = \""$1"\" Value = \""$2"\" />"}'`;
done
echo "   </ArgusEventData>"

echo "</ArgusEvent>"
