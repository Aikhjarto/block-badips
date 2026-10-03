#!/bin/bash
# Nagios plugin to check number of blocked entries.
# Run with -h for a description of the options.

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

# defaults; the update timer pauses for several hours at night, hence the generous age thresholds
WARN_ENTRIES=1
CRIT_ENTRIES=1
WARN_AGE_S=21600
CRIT_AGE_S=43200
WARN_FILL_PERCENT=90
STATUS_FILE=/var/lib/block-badips/status

USAGE="$(basename "$0") [-h] [-w entries] [-c entries] [-W seconds] [-C seconds] [-f percent] [-s status_file]"

usage () {
	echo "UNKNOWN - usage: ${USAGE}"
	exit $NAG_UNKNOWN
}

# Like the monitoring-plugins, exit with UNKNOWN after printing the help.
help () {
	cat <<-EOF
		Nagios/Icinga plugin checking the IPs and ranges blocked by block-badips.sh.

		Usage: ${USAGE}

		Options:
		  -h          show this help text and exit
		  -w entries  WARNING if fewer entries are blocked (default: ${WARN_ENTRIES})
		  -c entries  CRITICAL if fewer entries are blocked (default: ${CRIT_ENTRIES})
		  -W seconds  WARNING if the last successful update is older (default: ${WARN_AGE_S})
		  -C seconds  CRITICAL if the last successful update is older (default: ${CRIT_AGE_S})
		  -f percent  WARNING if an ipset is filled to more than this percentage
		              of its maxelem (default: ${WARN_FILL_PERCENT})
		  -s file     status file written by block-badips.sh
		              (default: ${STATUS_FILE})

		Additionally CRITICAL is reported if an ipset contains entries but no
		iptables rule uses it, or if no successful update is found in the status file.
	EOF
	exit $NAG_UNKNOWN
}

while getopts ":hw:c:W:C:f:s:" OPT; do
	case "$OPT" in
		w) WARN_ENTRIES=$OPTARG ;;
		c) CRIT_ENTRIES=$OPTARG ;;
		W) WARN_AGE_S=$OPTARG ;;
		C) CRIT_AGE_S=$OPTARG ;;
		f) WARN_FILL_PERCENT=$OPTARG ;;
		s) STATUS_FILE=$OPTARG ;;
		h) help ;;
		*) usage ;;
	esac
done

for NUM in "$WARN_ENTRIES" "$CRIT_ENTRIES" "$WARN_AGE_S" "$CRIT_AGE_S" "$WARN_FILL_PERCENT"; do
	[[ "$NUM" =~ ^[0-9]+$ ]] || usage
done

# ipset and iptables-save/ip6tables-save are required; without them we cannot
# count anything meaningful, so report UNKNOWN rather than silently counting 0.
for BIN in "$IPSET_BIN" "$IP4TABLES_SAVE_BIN" "$IP6TABLES_SAVE_BIN"; do
	if [ ! -x "$BIN" ]; then
		echo "UNKNOWN - required binary $BIN not found or not executable"
		exit $NAG_UNKNOWN
	fi
done

CRIT_MSGS=()
WARN_MSGS=()

# Print "<hosts> <ranges> <maxelem>" of the given ipset. A not-yet-created set
# (e.g. block-badips.sh never ran yet) is a legitimate "0 entries" case, not an
# error.
ipset_count () {
	local name="$1"
	"$IPSET_BIN" list "$name" -o save 2>/dev/null | awk '
		/^create / { for (i = 1; i < NF; i++) if ($i == "maxelem") m = $(i + 1) }
		/^add / { if (index($3, "/")) r++; else h++ }
		END { print h + 0, r + 0, m + 0 }'
}

# Print 1 if an iptables rule matching the given ipset exists, 0 otherwise.
set_rule_present () {
	local save_bin="$1" name="$2"
	"$save_bin" | awk -v set="--match-set ${name} src" 'index($0, set) { s = 1 } END { print s + 0 }'
}

# check one address family; sets NUM_IP<family> and NUM_RANGES<family>
check_family () {
	local family="$1" save_bin="$2"
	local name="BADIP${family}"
	local hosts ranges set_max set_entries set_rule

	read -r hosts ranges set_max < <(ipset_count "$name")
	set_rule=$(set_rule_present "$save_bin" "$name")
	set_entries=$((hosts + ranges))

	printf -v "NUM_IP${family}" '%d' "$hosts"
	printf -v "NUM_RANGES${family}" '%d' "$ranges"

	# a filled ipset blocks nothing if the iptables rule referencing it is missing
	if [ "$set_entries" -gt 0 ] && [ "$set_rule" -eq 0 ]; then
		CRIT_MSGS+=("ipset ${name} has ${set_entries} entries but no iptables rule uses it")
	fi

	# once an ipset is full, block-badips.sh fails to add further entries
	if [ "$set_max" -gt 0 ] && [ $((set_entries * 100)) -ge $((set_max * WARN_FILL_PERCENT)) ]; then
		WARN_MSGS+=("ipset ${name} is $((set_entries * 100 / set_max))% full (${set_entries}/${set_max})")
	fi
}

check_family 4 "$IP4TABLES_SAVE_BIN"
check_family 6 "$IP6TABLES_SAVE_BIN"

NUM_ENTRIES=$((NUM_IP4 + NUM_IP6 + NUM_RANGES4 + NUM_RANGES6))

if [ "$NUM_ENTRIES" -lt "$CRIT_ENTRIES" ]; then
	CRIT_MSGS+=("BADIP list contains only ${NUM_ENTRIES} entries")
elif [ "$NUM_ENTRIES" -lt "$WARN_ENTRIES" ]; then
	WARN_MSGS+=("BADIP list contains only ${NUM_ENTRIES} entries")
fi

# age of the last successful update, as logged by block-badips.sh
AGE_S=""
LAST_UPDATE=""
if [ -r "$STATUS_FILE" ]; then
	LAST_UPDATE=$(grep ' - updated$' "$STATUS_FILE" | tail -n 1 | cut -d ' ' -f 1)
fi
if [ -n "$LAST_UPDATE" ] && LAST_UPDATE_S=$(date -d "$LAST_UPDATE" +%s 2>/dev/null); then
	AGE_S=$(( $(date +%s) - LAST_UPDATE_S ))
	if [ "$AGE_S" -ge "$CRIT_AGE_S" ]; then
		CRIT_MSGS+=("last update ${LAST_UPDATE} is $((AGE_S / 3600))h old")
	elif [ "$AGE_S" -ge "$WARN_AGE_S" ]; then
		WARN_MSGS+=("last update ${LAST_UPDATE} is $((AGE_S / 3600))h old")
	fi
else
	CRIT_MSGS+=("no successful update found in ${STATUS_FILE}")
fi

PERFDATA="num_entries=${NUM_ENTRIES};${WARN_ENTRIES}:;${CRIT_ENTRIES}:;0; num_ip4=${NUM_IP4} num_ip6=${NUM_IP6} num_ranges4=${NUM_RANGES4} num_ranges6=${NUM_RANGES6}"
if [ -n "$AGE_S" ]; then
	PERFDATA+=" last_update_age=${AGE_S}s;${WARN_AGE_S};${CRIT_AGE_S};0;"
fi

join_msgs () {
	local IFS=";"
	echo "$*" | sed 's/;/; /g'
}

if [ ${#CRIT_MSGS[@]} -gt 0 ]; then
	echo "CRITICAL - $(join_msgs "${CRIT_MSGS[@]}" "${WARN_MSGS[@]}")|${PERFDATA}"
	exit $NAG_CRIT
elif [ ${#WARN_MSGS[@]} -gt 0 ]; then
	echo "WARNING - $(join_msgs "${WARN_MSGS[@]}")|${PERFDATA}"
	exit $NAG_WARN
else
	echo "OK - BADIP list contains ${NUM_ENTRIES} entries|${PERFDATA}"
	exit $NAG_OK
fi
