#!/bin/bash
#
#  Argus Software
#  Copyright (c) 2006-2012 QoSient, LLC
#  All rights reserved.
#
#  vmstat - report vmstat output as XML oriented argus event.
#           This example is provided to show how you can format most programs
#           to get to the XML oriented output used by the argus events system.
#
# Carter Bullard
# QoSient, LLC
#
# 
#  $Id: //depot/argus/argus/events/argus-vmstat.sh#3 $
#  $DateTime: 2012/01/03 19:15:19 $
#  $Change: 2274 $
#

output=`vm_stat | sed -e 's/"//g' -e 's/\.//' -e 's/: */:/' | \
        awk 'BEGIN {FS = ":"}{ if ($1=="Mach Virtual Memory Statistics") \
        print "   <ArgusEventData Type = \""$1"\" Comment = \""$2"\" >" ; \
        else print "      < Label = \""$1"\" Value = \""$2"\" />"}'`
#
# 
echo "<ArgusEvent>"
echo "$output"
echo "   </ArgusEventData>"
echo "</ArgusEvent>"
