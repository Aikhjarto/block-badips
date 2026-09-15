#!/bin/bash
# This script downloads a list of IPs known for brute force attacking within the last two weeks.
# The fetched IPs get blocked with iptables with the special comment "BADIP". This script only
# modifies iptables rules with that comment. This measure makes it well compatible with other firewall
# scripts like the SUSEFirewall.
# The iptables rules are updated every time this script is executed. Additionally this script is
# quiet on stdout, which makes it well suited for being executed as a cronjob.
# This script uses ipset when available.
# If /etc/block-badips.whitelist exists, IP adresses, standing in lines containing nothing else
# than a single IPv4 address, are never blocked.
# If /etc/block-badips.blacklist exists, IP adresses, standing in lines containing nothing else
# than a single IPv4 address, are always blocked.
# HTTP 504 and HTTP 502 errors are ignored up to MAX_N_ERROR times.
#
# Please also use fail2ban with the badips modification and help to maintain the list of attackers.
# See also: fail2ban and http:///www.badips.com
#
# Requirements
#	* iptables
#	* ipset or iptables-save
#	* curl or wget
#	* logger
#	* mktemp, wc, sed, grep, sort, comm, flock
#

set -o nounset
set -o errexit

# debug
#set -x

IP4TABLES_BIN=/usr/sbin/iptables
IP4TABLES_SAVE_BIN=/usr/sbin/iptables-save
IP6TABLES_BIN=/usr/sbin/ip6tables
IP6TABLES_SAVE_BIN=/usr/sbin/ip6tables-save
LOGGER_BIN=/usr/bin/logger
IPSET_BIN=/usr/sbin/ipset
WHITELIST_FILE=/etc/block-badips.whitelist
BLACKLIST_FILE=/etc/block-badips.blacklist
# STATE_DIRECTORY/RUNTIME_DIRECTORY are set by systemd (StateDirectory=/RuntimeDirectory=
# in the .service files); fall back to sensible defaults when run outside of systemd.
STATE_DIRECTORY=${STATE_DIRECTORY:-/var/lib/block-badips}
STATUS_FILE="${STATE_DIRECTORY}/status"
LOCK_FILE="${RUNTIME_DIRECTORY:-/run}/block-badips.lock"
BADIPS_NO_STDERR=${BADIPS_NO_STDERR:-""}
N_DOWNLOAD_RETRY=5
DOWNLOAD_RETRY_WAIT_S=30

type "$LOGGER_BIN"  >/dev/null 2>&1 || { echo >&2 "$LOGGER_BIN not found.  Aborting."; exit 1; }

LOGGER_OPTS="-t block_badips"

if [ -n "$BADIPS_NO_STDERR" ]; then
	LOGGER_OPTS_ERROR="$LOGGER_OPTS -p err"
	LOGGER_OPTS_WARN="$LOGGER_OPTS -p warn"
else
	LOGGER_OPTS_ERROR="$LOGGER_OPTS -p err -s"
	LOGGER_OPTS_WARN="$LOGGER_OPTS -p warn -s"
fi

# Fail fast with a clear log message instead of running into an obscure
# error (or, with `set -o nounset`, an unbound-variable crash) deep inside
# the script once a required binary turns out to be missing.
for BIN in "$IP4TABLES_BIN" "$IP4TABLES_SAVE_BIN" "$IP6TABLES_BIN" "$IP6TABLES_SAVE_BIN"; do
	type "$BIN" >/dev/null 2>&1 || { "$LOGGER_BIN" $LOGGER_OPTS_ERROR "$BIN not found. Aborting."; exit 1; }
done

if type curl >/dev/null 2>&1; then
	DOWNLOAD_PROGRAM="curl"
elif type wget >/dev/null 2>&1; then
	DOWNLOAD_PROGRAM="wget"
else
	"$LOGGER_BIN" $LOGGER_OPTS_ERROR "Neither curl nor wget found. Aborting."
	exit 1
fi

# Make sure only one instance is modifying iptables/ipset at a time; a second,
# concurrently started instance (e.g. onboot service racing the timer) would
# otherwise be able to corrupt the rule set.
mkdir -p "$(dirname "$LOCK_FILE")"
exec 200>"$LOCK_FILE"
if ! flock -n 200; then
	"$LOGGER_BIN" $LOGGER_OPTS_WARN "Another instance of $(basename "$0") is already running. Exiting."
	exit 0
fi

mkdir -p "$STATE_DIRECTORY"

# Collect every temporary file created below so a single trap can remove all
# of them on exit, regardless of where the script stops.
TMP_FILES=()
cleanup () {
	rm -f "${TMP_FILES[@]}"
}
trap cleanup INT TERM EXIT

# set a default URL where to fetch IP list
URL=${URL:-"https://www.badips.com/get/list/ssh/2?age=2w"}
BADIPS_USER=${BADIPS_USER:-""}
BADIPS_PASSWORD=${BADIPS_PASSWORD:-""}

if [[ -r "${URL}" ]]; then
	"$LOGGER_BIN" $LOGGER_OPTS "Fetching list of bad IPs from file ${URL}"
	FILE=$(mktemp -t block_badips.new.XXXXXX)
	TMP_FILES+=("$FILE")
	cat "${URL}" > "${FILE}"

	if grep -v -q -oE '^(([0-9]{1,3}[\.]){3}[0-9]{1,3})|(([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4})(/[1-9][0-9]?)?$' "${FILE}"; then
		# something else than an IP or range is found
		"$LOGGER_BIN" $LOGGER_OPTS_WARN "${URL} contained something else than a list of IP addresses and ranges"
		# uncomment mail for debugging, productive script shouldn't depend on mail
		# mail -s "badip erronous file" root < "${FILE}"
		date -Is >> "${STATUS_FILE}"
		cat "${FILE}" >> "${STATUS_FILE}"
		exit 1
	fi
else
	# check format of user supplied data to avoid parameter injection to curl/wget
	regex='^(https?|ftp|file)://[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]'
	if [[ ! ${URL} =~ $regex ]]; then
		"$LOGGER_BIN" $LOGGER_OPTS_ERROR "Supplied URL \"${URL}\" is malformatted."
		exit 1
	fi
	regex=" |'"$'|\t'
	if [[ "${BADIPS_USER}" =~ $regex ]]; then
		"$LOGGER_BIN" $LOGGER_OPTS_ERROR "Username BADIPS_USER is \"${BADIPS_USER}\" and contains a whitespace, which is not supported."
		exit 1
	fi
	if [[ "${BADIPS_PASSWORD}" =~ $regex ]]; then
		"$LOGGER_BIN" $LOGGER_OPTS_ERROR "Username BADIPS_PASSWORD is \"${BADIPS_PASSWORD}\" and contains a whitespace, which is not supported."
		exit 1
	fi

	# Pass credentials via a netrc file instead of on the command line, where
	# they would be readable by any local user through /proc/<pid>/cmdline or
	# `ps`.
	NETRC_FILE=""
	if [ -n "${BADIPS_USER}" ] || [ -n "${BADIPS_PASSWORD}" ]; then
		NETRC_FILE=$(mktemp -t block_badips.netrc.XXXXXX)
		TMP_FILES+=("$NETRC_FILE")
		chmod 600 "${NETRC_FILE}"
		URL_HOST=${URL#*://}
		URL_HOST=${URL_HOST%%/*}
		URL_HOST=${URL_HOST%%:*}
		printf 'machine %s\nlogin %s\npassword %s\n' "${URL_HOST}" "${BADIPS_USER}" "${BADIPS_PASSWORD}" > "${NETRC_FILE}"
	fi

	# download IP list
	while [ ${N_DOWNLOAD_RETRY} -gt 0 ]; do
		### download
		"$LOGGER_BIN" $LOGGER_OPTS "Fetching list of bad IPs from ${URL} using username \"${BADIPS_USER}\""
		FILE=$(mktemp -t block_badips.new.XXXXXX)
		TMP_FILES+=("$FILE")
		# Try curl or wget to download.
		set +e
		if [ "${DOWNLOAD_PROGRAM}" = "curl" ]; then
			if [ -n "${NETRC_FILE}" ]; then
				r=$(curl -s --netrc-file "${NETRC_FILE}" "${URL}" -o "${FILE}" 2>&1)
			else
				r=$(curl -s "${URL}" -o "${FILE}" 2>&1)
			fi
		else
			if [ -n "${NETRC_FILE}" ]; then
				r=$(wget -q --netrc-file="${NETRC_FILE}" -O "${FILE}" "${URL}" 2>&1)
			else
				r=$(wget -q -O "${FILE}" "${URL}" 2>&1)
			fi
		fi
		ret=$?
		set -e
		if [ ${ret} -ne 0 ]; then
			"$LOGGER_BIN" $LOGGER_OPTS_WARN "Download of ${URL} using ${DOWNLOAD_PROGRAM} and username \"${BADIPS_USER}\" failed with exit code ${ret} and message \"${r}\""
			N_DOWNLOAD_RETRY=$((N_DOWNLOAD_RETRY-1))
			sleep ${DOWNLOAD_RETRY_WAIT_S}
			continue
		else
			"$LOGGER_BIN" $LOGGER_OPTS "Got "$(wc -l < "$FILE" ) " lines"
		fi

		### input check
		# Check downloaded file (should contain a single IP adresses in each line).
		# In the case of an error, $FILE is either empty or an HTML page
		# Hint: grep returns 1 or true if there is no match in the file
		if [ ! -s "${FILE}" ]; then
			# file does not exist or is empty
			"$LOGGER_BIN" $LOGGER_OPTS_WARN "${URL} sent empty or no file"
			N_DOWNLOAD_RETRY=$((N_DOWNLOAD_RETRY-1))
			sleep ${DOWNLOAD_RETRY_WAIT_S}
			continue
		elif grep -q -i HTML "${FILE}"; then
			# file contains HTML code
			if grep -q "<head><title>504 Gateway Time-out</title></head>" "${FILE}"; then
				"$LOGGER_BIN" $LOGGER_OPTS_WARN "${URL} cannot be fetched because of 504 Gateway Time-out"
				echo "$(date -Is) - ERROR 504" >> "${STATUS_FILE}"
			elif grep -q "<head><title>502 Bad Gateway</title></head>" "${FILE}"; then
				"$LOGGER_BIN" $LOGGER_OPTS_WARN "${URL} cannot be fetched because of 502 Bad Gateway"
				echo "$(date -Is) - ERROR 502" >> "${STATUS_FILE}"
			else
				# if there was a problem, sometimes a HTML file containing an error message is sent
				"$LOGGER_BIN" $LOGGER_OPTS_WARN "${URL} got HTML file instead of text file, see ${STATUS_FILE} for details."
				# uncomment mail for debugging, productive script shouldn't depend on mail
				#mail -s "add badips error" root < "${FILE}"
				date -Is >> "${STATUS_FILE}"
				cat "${FILE}" >> "${STATUS_FILE}"
			fi
			N_DOWNLOAD_RETRY=$((N_DOWNLOAD_RETRY-1))
			sleep ${DOWNLOAD_RETRY_WAIT_S}
			continue
		elif grep -v -q -oE '^((([0-9]{1,3}[\.]){3}[0-9]{1,3})|(([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}))(/[1-9][0-9]?)?$' "$FILE"; then
			# something else than an IP or range is found
			"$LOGGER_BIN" $LOGGER_OPTS_WARN "${URL} contained something else than a list of IP addresses and ranges"
			# uncomment mail for debugging, productive script shouldn't depend on mail
			# mail -s "badip erronous file" root < "${FILE}"
			date -Is >> "${STATUS_FILE}"
			cat "${FILE}" >> "${STATUS_FILE}"
			N_DOWNLOAD_RETRY=$((N_DOWNLOAD_RETRY-1))
			sleep ${DOWNLOAD_RETRY_WAIT_S}
			continue
		else
			# everything fine, continue outside loop
			break
		fi
	done

	# quit if no valid file could be retrieved
	if [ ${N_DOWNLOAD_RETRY} -le 0 ]; then
		"$LOGGER_BIN" $LOGGER_OPTS_ERROR "ERROR: ${URL} does not provide list of IPs after several tries. Giving up now. Systemlog should have more information, e.g. journalctl SYSLOG_IDENTIFIER=block_badips or grep block_badips /var/log/messages"
		exit 1
	fi
fi

# assert: $FILE contains a single IPv4 or IPv6 adresses or range in each line

# remove /32 and /128 prefix for IPv4 Hosts (will bog split in ranges and hosts later)
sed -i -E -e 's/^(([0-9]{1,3}[\.]){3}[0-9]{1,3})\/32$/\1/' "${FILE}"
sed -i -E -e 's/\/128//' "${FILE}"

# remove the NULL IP since ipset will trigger errexit if 0.0.0.0 appears
sed -i -e '/0.0.0.0/d' "${FILE}"

# remove IPs from whitelist file
if [ -s "${WHITELIST_FILE}" ]; then
	FILE_TMP=$(mktemp -t block_badips.prefilter.XXXXXX)
	TMP_FILES+=("$FILE_TMP")
	mv "${FILE}" "${FILE_TMP}"
	comm -23 <(sort "${FILE_TMP}") <(grep -oE '^(([0-9]{1,3}[\.]){3}[0-9]{1,3})|(([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4})$' "${WHITELIST_FILE}" | sort) > "${FILE}"
fi

# add IPs from blacklist file
if [ -s "${BLACKLIST_FILE}" ]; then
	FILE_TMP=$(mktemp -t block_badips.prefilter.XXXXXX)
	TMP_FILES+=("$FILE_TMP")
	mv "${FILE}" "${FILE_TMP}"
	# Hint: grep will exit with error if no IP was in BLACKLIST_FILE. Thus disable 'errexit' briefley
	set +e
	grep -oE '^(([0-9]{1,3}[\.]){3}[0-9]{1,3})|(([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4})$' "${BLACKLIST_FILE}" >> "${FILE_TMP}"
	set -e
	# Remove duplicates (same IP could have been in downloaded file and local blacklist file) to avoid warnings
	# from ipset.
	sort --unique "${FILE_TMP}" > "${FILE}"
fi

# whitelist unroutable (local) addresses
sed -i -E -e '/^(192\.168|10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|169\.254|127\.)/d' "${FILE}"
sed -i -E -e '/^((fe80)|(fec0)|(f[cd][0-9a-f]{2})):.*$/d' "${FILE}"


update () {

	if [ "$IPTABLES_BIN" = "$IP4TABLES_BIN" ]; then
		IPSET_NAME=BADIP4
		IPSET_FAMILY=inet
		IPTABLES_SAVE_BIN=$IP4TABLES_SAVE_BIN
	else
		IPSET_NAME=BADIP6
		IPSET_FAMILY=inet6
		IPTABLES_SAVE_BIN=$IP6TABLES_SAVE_BIN
	fi

	### main part
	if [ -x "$IPSET_BIN" ] && [ -z "${FORCE_IPTABLES}" ] ; then
		# use ipset if available since it's faster than plain iptables
		# http://daemonkeeper.net/781/mass-blocking-ip-addresses-with-ipset/

		# create new ipset if not already there
		if ! "$IPSET_BIN" list "${IPSET_NAME}" >/dev/null 2>&1; then
			"$IPSET_BIN" create "${IPSET_NAME}" hash:ip hashsize 4096 family "${IPSET_FAMILY}"
		fi

		# iptables should be added only once. So check if it already there.
		if ! "$IPTABLES_BIN" -w -C INPUT  -m set --match-set "${IPSET_NAME}" src -m comment --comment "${IPSET_NAME}" -j REJECT > /dev/null 2>&1; then
			"$IPTABLES_BIN" -w -I INPUT  -m set --match-set "${IPSET_NAME}"  src -m comment --comment "${IPSET_NAME}" -j REJECT
		fi

		### get currently blocked entries
		CURRENT_ENTRIES=$("$IPSET_BIN" list "${IPSET_NAME}" -o save | grep add | awk '{ print $3 }' | sort)
		"$LOGGER_BIN" $LOGGER_OPTS "Found "$(echo "$CURRENT_ENTRIES" | wc -l)" entries in ipset ${IPSET_NAME}"

		### list of ips that are not considered bad any more
		OUTDATED_ENTRIES=$(comm -13 <(echo "$FETCHED_ENTRIES") <(echo "$CURRENT_ENTRIES"))

		### list of ips that are new and should be blocked
		NEW_ENTRIES=$(comm -23 <(echo "$FETCHED_ENTRIES") <(echo "$CURRENT_ENTRIES"))

		### delete old rules, that are not needed any more
		if [ -n "$OUTDATED_ENTRIES" ]; then
			"$LOGGER_BIN" $LOGGER_OPTS "Removing "$(echo "$OUTDATED_ENTRIES" | wc -l )" outdated entries from ipset ${IPSET_NAME}"
			while read -r IP; do
				#$IPSET_BIN del BADIP $IP || echo "Warning when deleting $IP"
				"$IPSET_BIN" del "${IPSET_NAME}" "$IP"
			done <<< "$OUTDATED_ENTRIES"
		fi

		### add new IPs that should be blocked
		if [ -n "$NEW_ENTRIES" ]; then
			"$LOGGER_BIN" $LOGGER_OPTS "Adding "$(echo "$NEW_ENTRIES" | wc -l)" new entries to ipset ${IPSET_NAME}"
			while read -r IP; do
				#$IPSET_BIN add BADIP $IP || echo "Warning when adding $IP"
				"$IPSET_BIN" add "${IPSET_NAME}" "$IP"
			done <<< "$NEW_ENTRIES"
		fi

	else
		# use iptables for ranges and if ipset is not available

		### get old blocked entries
		# export all rules with comment "BADIP" and replace -A (add) with -D (delete)
		CURRENT_RULES=$("$IPTABLES_SAVE_BIN"  | { grep -e "--comment ${IPSET_NAME}" || true ; } |  grep -v -e '--match-set' || true )
		if [ -n "$CURRENT_RULES" ]; then
			"$LOGGER_BIN" $LOGGER_OPTS "Found "$(echo "$CURRENT_RULES" | wc -l )" entries in iptables for ${IPSET_FAMILY}"

			# get format of old rule (exact rule must be given to iptables as argument)
			FMT=$(echo "$CURRENT_RULES" | tail -n 1 | sed 's/-A /-D /')
			# Hint: don't pipe to 'head' but use 'tail' to avoid 'echo' being closed when something is still to write resulting in broken pipes

			# get currently blocked IPs/ranges
			CURRENT_ENTRIES=$(echo "$CURRENT_RULES" | grep -oE '((([0-9]{1,3}[\.]){3}[0-9]{1,3})|(([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}))(/[1-9][0-9]?)?' | sort)

			### list of ips that are not considered bad any more
			OUTDATED_ENTRIES=$(comm -13 <(echo "$FETCHED_ENTRIES") <(echo "$CURRENT_ENTRIES"))

			### list of ips that are new and should be blocked
			NEW_ENTRIES=$(comm -23 <(echo "$FETCHED_ENTRIES") <(echo "$CURRENT_ENTRIES"))

			### delete old rules, that are not needed any more
			if [ -n "$OUTDATED_ENTRIES" ]; then
				"$LOGGER_BIN" $LOGGER_OPTS "Removing "$(echo "$OUTDATED_ENTRIES" | wc -l)" outdated entries from iptables for ${IPSET_FAMILY}"
				while read -r IP; do
					# $FMT is a full iptables rule spec (e.g. "-D INPUT -s <ip> -j DROP ...")
					# and must be word-split into its individual arguments here.
					"$IPTABLES_BIN" -w $(echo "$FMT" | sed -r "s!((([0-9]{1,3}[\.]){3}[0-9]{1,3})|(([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}))(/[1-9][0-9]?)?!$IP!")
				done <<< "$OUTDATED_ENTRIES"
			fi
		else
			NEW_ENTRIES="$FETCHED_ENTRIES"
		fi

		### add new IPs that should be blocked
		if [ -n "$NEW_ENTRIES" ]; then
			"$LOGGER_BIN" $LOGGER_OPTS "Adding "$(echo "$NEW_ENTRIES" | wc -l)" new entries from iptables for ${IPSET_FAMILY}"
			while read -r IP; do
				"$IPTABLES_BIN" -w -I INPUT -s "$IP" -j DROP -m comment --comment "${IPSET_NAME}"
			done <<< "$NEW_ENTRIES"
		fi
	fi
}


# split into IPv4 and IPv6 addresses and ranges (IPs are faster with ipset and ranges are easier to handle with iptables)
# Hint 1: || true is necessary for grep  to not trigger errexit when grep operates on empty data
# Hint 2: Curly brackets are required since | binds tighter than ||

# add IPv4 addresses
FETCHED_ENTRIES=$({ grep -v ":" "${FILE}" || true ; } | grep -v "/" || true)
IPTABLES_BIN=$IP4TABLES_BIN
FORCE_IPTABLES=""
update

# add IPv4 ranges
FETCHED_ENTRIES=$({ grep -v ":" "${FILE}" || true ; } | grep "/" || true)
# add IPv4 ranges
IPTABLES_BIN=$IP4TABLES_BIN
FORCE_IPTABLES="y"
update

# add IPv6 addresses
FETCHED_ENTRIES=$({ grep ":" "${FILE}" || true ; } | grep -v "/" || true)
IPTABLES_BIN=$IP6TABLES_BIN
FORCE_IPTABLES=""
update

# add IPv6 ranges
FETCHED_ENTRIES=$({ grep ":" "${FILE}" || true ; } | grep "/" || true)
IPTABLES_BIN=$IP6TABLES_BIN
FORCE_IPTABLES="y"
update

### end of script
"$LOGGER_BIN" $LOGGER_OPTS "Finished applying block rules"

echo "$(date -Is) - updated" >> "${STATUS_FILE}"

# keep just the last lines in STATUS_FILE
echo "$(tail -1000 "${STATUS_FILE}")" > "${STATUS_FILE}"
