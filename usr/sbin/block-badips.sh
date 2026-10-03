#!/bin/bash
# This script downloads a list of IPs known for recent attacks, by default the list of blocklist.de.
# The fetched IPs get blocked with iptables with the special comment "BADIP". This script only
# modifies iptables rules with that comment. This measure makes it well compatible with other firewall
# scripts like the SUSEFirewall.
# The iptables rules are updated every time this script is executed. Additionally this script is
# quiet on stdout, which makes it well suited for being executed as a cronjob.
# This script uses ipset when available.
# If /etc/block-badips.whitelist exists, IP adresses, standing in lines containing nothing else
# than a single IPv4 or IPv6 address, are never blocked, even if they are on the blacklist.
# If /etc/block-badips.blacklist exists, IP adresses, standing in lines containing nothing else
# than a single IPv4 or IPv6 address, are always blocked unless they are on the whitelist.
# HTTP 504 and HTTP 502 errors are ignored up to MAX_N_ERROR times.
#
# Please also use fail2ban with its blocklist_de action and help to maintain the list of attackers.
# See also: fail2ban and https://www.blocklist.de
#
# Requirements
#	* iptables
#	* ipset or iptables-save
#	* iptables-restore, ip6tables-restore
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
IP4TABLES_RESTORE_BIN=/usr/sbin/iptables-restore
IP6TABLES_RESTORE_BIN=/usr/sbin/ip6tables-restore
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
# maximum duration of a single download attempt
DOWNLOAD_TIMEOUT_S=60
IPTABLES_RESTORE_CHUNK=250
# hash:net holds single addresses as well as ranges
IPSET_TYPE=hash:net

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
for BIN in "$IPSET_BIN" "$IP4TABLES_BIN" "$IP4TABLES_SAVE_BIN" "$IP4TABLES_RESTORE_BIN" "$IP6TABLES_BIN" "$IP6TABLES_SAVE_BIN" "$IP6TABLES_RESTORE_BIN"; do
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
URL=${URL:-"https://lists.blocklist.de/lists/all.txt"}
BADIPS_USER=${BADIPS_USER:-""}
BADIPS_PASSWORD=${BADIPS_PASSWORD:-""}

# regular expressions for IP addresses and ranges, defined once to keep all checks consistent
IPV4_REGEX='([0-9]{1,3}\.){3}[0-9]{1,3}'
IPV6_REGEX='([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}'
IP_REGEX="((${IPV4_REGEX})|(${IPV6_REGEX}))"
PREFIX_REGEX='(/[1-9][0-9]?)?'
# a line of the downloaded list: a single address or range
LIST_ENTRY_REGEX="^${IP_REGEX}${PREFIX_REGEX}\$"

if [[ -r "${URL}" ]]; then
	"$LOGGER_BIN" $LOGGER_OPTS "Fetching list of bad IPs from file ${URL}"
	FILE=$(mktemp -t block_badips.new.XXXXXX)
	TMP_FILES+=("$FILE")
	cat "${URL}" > "${FILE}"

	if grep -v -q -E "${LIST_ENTRY_REGEX}" "${FILE}"; then
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

	# count a failed download attempt and wait before the next one, if any
	retry_later () {
		N_DOWNLOAD_RETRY=$((N_DOWNLOAD_RETRY-1))
		if [ ${N_DOWNLOAD_RETRY} -gt 0 ]; then
			sleep ${DOWNLOAD_RETRY_WAIT_S}
		fi
	}

	# download IP list
	while [ ${N_DOWNLOAD_RETRY} -gt 0 ]; do
		### download
		"$LOGGER_BIN" $LOGGER_OPTS "Fetching list of bad IPs from ${URL} using username \"${BADIPS_USER}\""
		FILE=$(mktemp -t block_badips.new.XXXXXX)
		TMP_FILES+=("$FILE")
		# Try curl or wget to download.
		set +e
		if [ "${DOWNLOAD_PROGRAM}" = "curl" ]; then
			# --fail turns HTTP errors into a non-zero exit code instead of saving the error page
			if [ -n "${NETRC_FILE}" ]; then
				r=$(curl -s -S --fail --max-time "${DOWNLOAD_TIMEOUT_S}" --netrc-file "${NETRC_FILE}" "${URL}" -o "${FILE}" 2>&1)
			else
				r=$(curl -s -S --fail --max-time "${DOWNLOAD_TIMEOUT_S}" "${URL}" -o "${FILE}" 2>&1)
			fi
		else
			if [ -n "${NETRC_FILE}" ]; then
				r=$(wget -q --timeout="${DOWNLOAD_TIMEOUT_S}" --tries=1 --netrc-file="${NETRC_FILE}" -O "${FILE}" "${URL}" 2>&1)
			else
				r=$(wget -q --timeout="${DOWNLOAD_TIMEOUT_S}" --tries=1 -O "${FILE}" "${URL}" 2>&1)
			fi
		fi
		ret=$?
		set -e
		if [ ${ret} -ne 0 ]; then
			"$LOGGER_BIN" $LOGGER_OPTS_WARN "Download of ${URL} using ${DOWNLOAD_PROGRAM} and username \"${BADIPS_USER}\" failed with exit code ${ret} and message \"${r}\""
			retry_later
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
			retry_later
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
			retry_later
			continue
		elif grep -v -q -E "${LIST_ENTRY_REGEX}" "$FILE"; then
			# something else than an IP or range is found
			"$LOGGER_BIN" $LOGGER_OPTS_WARN "${URL} contained something else than a list of IP addresses and ranges"
			# uncomment mail for debugging, productive script shouldn't depend on mail
			# mail -s "badip erronous file" root < "${FILE}"
			date -Is >> "${STATUS_FILE}"
			cat "${FILE}" >> "${STATUS_FILE}"
			retry_later
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

# remove the NULL IP
sed -i -E -e '/^0\.0\.0\.0(\/[0-9]{1,2})?$/d' "${FILE}"

# add IPs and ranges from blacklist file
if [ -s "${BLACKLIST_FILE}" ]; then
	# Hint: grep exits with 1 if there is no IP in BLACKLIST_FILE, hence || true
	grep -E "${LIST_ENTRY_REGEX}" "${BLACKLIST_FILE}" >> "${FILE}" || true
fi

# Addresses and ranges that are never blocked go into an allow set, which the
# blocking rule excludes. In contrast to removing entries from the list, this
# also exempts them if they are part of a larger blocked range.
ALLOW_FILE=$(mktemp -t block_badips.allow.XXXXXX)
TMP_FILES+=("$ALLOW_FILE")
# unroutable (local) addresses
printf '%s\n' 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 127.0.0.0/8 \
	fe80::/10 fec0::/10 fc00::/7 > "${ALLOW_FILE}"
if [ -s "${WHITELIST_FILE}" ]; then
	grep -E "${LIST_ENTRY_REGEX}" "${WHITELIST_FILE}" >> "${ALLOW_FILE}" || true
fi

# print the lines of stdin that belong to the given address family (4 or 6)
# Hint: || true is necessary for grep to not trigger errexit when there is no match
filter_family () {
	if [ "$1" = 4 ]; then
		grep -v ":" || true
	else
		grep ":" || true
	fi
}

# Remove rules created by older versions of this script: one iptables rule per
# range and a rule matching the set without excluding the allow set. Rules are
# identified by their comment, all other rules are left alone.
remove_legacy_rules () {
	local name="$1" save_bin="$2" restore_bin="$3"
	local rules
	rules=$("$save_bin" | awk -v name="$name" -v keep="! --match-set ${name}_ALLOW src" -v n="${IPTABLES_RESTORE_CHUNK}" '
		/^\*/ { table = $0; next }
		/^-A / && $0 ~ ("--comment \"?" name "\"?( |$)") && !(table == "*filter" && index($0, keep)) {
			if (open && (cur != table || c >= n)) { print "COMMIT"; open = 0 }
			if (!open) { print table; open = 1; cur = table; c = 0 }
			sub(/^-A /, "-D "); print; c++
		}
		END { if (open) print "COMMIT" }')
	if [ -n "$rules" ]; then
		"$LOGGER_BIN" $LOGGER_OPTS "Removing $(grep -c '^-D ' <<< "$rules") rules of older versions for ${name}"
		"$restore_bin" -w --noflush <<< "$rules"
	fi
}

# Replace the content of an ipset with the entries of a file. The entries are
# loaded into a new set, which is then swapped with the old one, so the update
# is atomic and the set is never partially filled.
load_set () {
	local name="$1" family="$2" file="$3"
	local new="${name}_NEW" old_count=0

	if "$IPSET_BIN" list -t "$name" >/dev/null 2>&1; then
		if "$IPSET_BIN" list -t "$name" | grep -q "^Type: ${IPSET_TYPE}\$"; then
			old_count=$("$IPSET_BIN" list -t "$name" | awk '/^Number of entries:/ { print $4 }')
		else
			# sets of another type, e.g. hash:ip of older versions, cannot be swapped
			"$IPSET_BIN" destroy "$name"
		fi
	fi

	# a leftover from an aborted run
	"$IPSET_BIN" destroy "$new" >/dev/null 2>&1 || true

	{
		echo "create ${new} ${IPSET_TYPE} family ${family}"
		sed "s|^|add ${new} |" "$file"
	} | "$IPSET_BIN" restore -exist

	if "$IPSET_BIN" list -t "$name" >/dev/null 2>&1; then
		"$IPSET_BIN" swap "$new" "$name"
		"$IPSET_BIN" destroy "$new"
	else
		"$IPSET_BIN" rename "$new" "$name"
	fi
	"$LOGGER_BIN" $LOGGER_OPTS "Loaded $(wc -l < "$file") entries into ipset ${name} (previously ${old_count})"
}

# update the sets and the iptables rule of one address family (4 or 6)
apply_family () {
	local v="$1"
	local name="BADIP${v}" family iptables_bin save_bin restore_bin block_file allow_file

	if [ "$v" = 4 ]; then
		family=inet
		iptables_bin=$IP4TABLES_BIN
		save_bin=$IP4TABLES_SAVE_BIN
		restore_bin=$IP4TABLES_RESTORE_BIN
	else
		family=inet6
		iptables_bin=$IP6TABLES_BIN
		save_bin=$IP6TABLES_SAVE_BIN
		restore_bin=$IP6TABLES_RESTORE_BIN
	fi

	block_file=$(mktemp -t block_badips.block.XXXXXX)
	allow_file=$(mktemp -t block_badips.allow.XXXXXX)
	TMP_FILES+=("$block_file" "$allow_file")
	filter_family "$v" < "${FILE}" > "$block_file"
	filter_family "$v" < "${ALLOW_FILE}" > "$allow_file"

	# must come first, since rules of older versions may reference a set of the old type
	remove_legacy_rules "$name" "$save_bin" "$restore_bin"

	load_set "$name" "$family" "$block_file"
	load_set "${name}_ALLOW" "$family" "$allow_file"

	# block everything in the set except for the allowed addresses; the rule is added only once
	local rule=(INPUT -m set --match-set "$name" src -m set ! --match-set "${name}_ALLOW" src -m comment --comment "$name" -j REJECT)
	if ! "$iptables_bin" -w -C "${rule[@]}" >/dev/null 2>&1; then
		"$iptables_bin" -w -I "${rule[@]}"
	fi
}

apply_family 4
apply_family 6

### end of script
"$LOGGER_BIN" $LOGGER_OPTS "Finished applying block rules"

echo "$(date -Is) - updated" >> "${STATUS_FILE}"

# keep just the last lines in STATUS_FILE
echo "$(tail -1000 "${STATUS_FILE}")" > "${STATUS_FILE}"
