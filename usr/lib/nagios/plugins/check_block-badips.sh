#!/bin/bash
# Nagios plugin to check number of blocked entries.

# NAGIOS' wanted return values
NAG_OK=0
NAG_WARN=1
NAG_CRIT=2
NAG_UNKNOWN=3

# abosulte path to binary files
IP4TABLES_SAVE_BIN=/usr/sbin/iptables-save
IP6TABLES_SAVE_BIN=/usr/sbin/ip6tables-save
IPSET_BIN=/usr/sbin/ipset

# get list of IPs blocked via ipset
if [ -x $IPSET_BIN ]; then
        NUM_IPSET4=$(${IPSET_BIN} list BADIP4 -o save | grep add | wc -l);
        if [ $? -ne 0 ]; then
                echo "UNKNOWN - Get number of blocked IPv4 adresses via ipset failed"
                exit $NAG_UNKNOWN
        fi

        NUM_IPSET6=$(${IPSET_BIN} list BADIP6 -o save | grep add | wc -l);
        if [ $? -ne 0 ]; then
                echo "UNKNOWN - Get number of blocked IPv6 addresses via ipset failed"
                exit $NAG_UNKNOWN
        fi
fi

# get single IPs blocked via iptables
NUM_IP4=$((${NUM_IPSET4:-0} + $(${IP4TABLES_SAVE_BIN} | grep "BADIP4" | grep -v -e '--match-set' | grep "/32" | wc -l)))
NUM_IP6=$((${NUM_IPSET6:-0} + $(${IP6TABLES_SAVE_BIN} | grep "BADIP6" | grep -v -e '--match-set' | grep "/128" | wc -l)))

# get ranges blocked via iptables
NUM_RANGES4=$(${IP4TABLES_SAVE_BIN} | grep "BADIP4" | grep -v -e '--match-set' | grep -v "/32" | wc -l)
if [ $? -ne 0 ]; then
        echo "UNKNOWN - Get number of blocked IPv4 ranges via iptables failed"
        exit $NAG_UNKNOWN
fi
NUM_RANGES6=$(${IP6TABLES_SAVE_BIN} | grep "BADIP6" | grep -v -e '--match-set' | grep -v "/128" | wc -l)
if [ $? -ne 0 ]; then
        echo "UNKNOWN - Get number of blocked IPs via iptables failed"
        exit $NAG_UNKNOWN
fi

NUM_ENTRIES=$(($NUM_IP4 + $NUM_IP6 + $NUM_RANGES4 + $NUM_RANGES6))

if [ ${NUM_ENTRIES} -lt 1 ]; then
        echo "CRITICAL - BADIP list contains no entries."
        exit $NAG_CRIT
else
        echo "OK - BADIP list contains ${NUM_ENTRIES} entries|num_entris=${NUM_ENTRIES}, num_ip4=${NUM_IP4}, num_ip6=${NUM_IP6}, num_ranges4=${NUM_RANGES4}, num_ranges6=${NUM_RANGES6}"
        exit $NAG_OK
fi

