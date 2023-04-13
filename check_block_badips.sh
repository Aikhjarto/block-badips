#!/bin/bash
# Nagios plugin to check number of blocked entries.

# NAGIOS' wanted return values
NAG_OK=0
NAG_WARN=1
NAG_CRIT=2
NAG_UNKNOWN=3

# abosulte path to binary files
IPTABLES_BIN=/usr/sbin/iptables
IPSET_BIN=/usr/sbin/ipset

if [ -x $IPSET_BIN ]; then
	NUM_ENTRIES=$(${IPSET_BIN} list BADIP -o save | grep add | wc -l);
	if [ $? -ne 0 ]; then
		echo "UNKNOWN - Get number of blocked IPs via ipset failed"
		exit $NAG_UNKNOWN
	fi
else
        # use iptables if ipset is not available
	NUM_ENTRIES=$(${IPTABLES_BIN} -L INPUT | grep "/\* BADIP \*/" | grep DROP | wc -l)
        if [ $? -ne 0 ]; then
                echo "UNKNOWN - Get number of blocked IPs via iptables failed"
                exit $NAG_UNKNOWN
        fi
fi

if [ ${NUM_ENTRIES} -lt 1 ]; then
	echo "CRITICAL - BADIP list contains no entries."
	exit $NAG_CRIT
else
	echo "OK - BADIP list contains ${NUM_ENTRIES} entries|num_entries=${NUM_ENTRIES}"
	exit $NAG_OK
fi

