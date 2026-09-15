#!/bin/bash
# Nagios plugin to check number of blocked entries.

set -o nounset

# NAGIOS' wanted return values
NAG_OK=0
NAG_WARN=1
NAG_CRIT=2
NAG_UNKNOWN=3

# absolute path to binary files
IP4TABLES_SAVE_BIN=/usr/sbin/iptables-save
IP6TABLES_SAVE_BIN=/usr/sbin/ip6tables-save
IPSET_BIN=/usr/sbin/ipset

# iptables-save/ip6tables-save are required; without them we cannot count
# anything meaningful, so report UNKNOWN rather than silently counting 0.
for BIN in "$IP4TABLES_SAVE_BIN" "$IP6TABLES_SAVE_BIN"; do
	if [ ! -x "$BIN" ]; then
		echo "UNKNOWN - required binary $BIN not found or not executable"
		exit $NAG_UNKNOWN
	fi
done

# Count entries currently blocked via ipset for the given set name. A
# missing ipset binary or a not-yet-created set (e.g. block-badips.sh never
# ran yet) is a legitimate "0 entries" case, not an error.
ipset_count () {
	local name="$1"
	if [ -x "$IPSET_BIN" ] && "$IPSET_BIN" list "$name" >/dev/null 2>&1; then
		"$IPSET_BIN" list "$name" -o save 2>/dev/null | grep -c '^add '
	else
		echo 0
	fi
}

NUM_IPSET4=$(ipset_count BADIP4)
NUM_IPSET6=$(ipset_count BADIP6)

# get single IPs blocked via iptables
NUM_IP4=$((NUM_IPSET4 + $("$IP4TABLES_SAVE_BIN" | grep "BADIP4" | grep -v -e '--match-set' | grep -c "/32")))
NUM_IP6=$((NUM_IPSET6 + $("$IP6TABLES_SAVE_BIN" | grep "BADIP6" | grep -v -e '--match-set' | grep -c "/128")))

# get ranges blocked via iptables
NUM_RANGES4=$("$IP4TABLES_SAVE_BIN" | grep "BADIP4" | grep -v -e '--match-set' | grep -vc "/32")
NUM_RANGES6=$("$IP6TABLES_SAVE_BIN" | grep "BADIP6" | grep -v -e '--match-set' | grep -vc "/128")

NUM_ENTRIES=$((NUM_IP4 + NUM_IP6 + NUM_RANGES4 + NUM_RANGES6))

if [ "${NUM_ENTRIES}" -lt 1 ]; then
	echo "CRITICAL - BADIP list contains no entries."
	exit $NAG_CRIT
else
	echo "OK - BADIP list contains ${NUM_ENTRIES} entries|num_entris=${NUM_ENTRIES}, num_ip4=${NUM_IP4}, num_ip6=${NUM_IP6}, num_ranges4=${NUM_RANGES4}, num_ranges6=${NUM_RANGES6}"
	exit $NAG_OK
fi
