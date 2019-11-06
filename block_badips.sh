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
#	* mktemp, wc, sed, grep, sort, comm
#

set -o nounset
set -o errexit

trap 

IPTABLES_BIN=/usr/sbin/iptables
IPTABLES_SAVE_BIN=/usr/sbin/iptables-save
LOGGER_BIN=/usr/bin/logger
IPSET_BIN=/usr/sbin/ipset
WHITELIST_FILE=/etc/block-badips.whitelist
BLACKLIST_FILE=/etc/block-badips.blacklist
STATUS_FILE=/tmp/block-badips.status
BADIPS_NO_STDERR=${BADIPS_NO_STDERR:-""}
N_DOWNLOAD_RETRY=5
DOWNLOAD_RETRY_WAIT_S=30

if ( [ ! -x $IPSET_BIN ] ) && ( [ ! -x $IPTABLES_BIN ] || [ ! -x $IPTABLES_SAVE_BIN ] ); then
	echo >&2 "Either ipset or iptables and iptables-save must be available"
fi

type "$LOGGER_BIN"  >/dev/null 2>&1 || { echo >&2 "$LOGGER_BIN not found.  Aborting."; exit 1; }

LOGGER_OPTS="-t block_badips"

if [ -n "$BADIPS_NO_STDERR" ]; then
	LOGGER_OPTS_ERROR="$LOGGER_OPTS -p err"
	LOGGER_OPTS_WARN="$LOGGER_OPTS -p warn"
else
	LOGGER_OPTS_ERROR="$LOGGER_OPTS -p err -s"
	LOGGER_OPTS_WARN="$LOGGER_OPTS -p warn -s"
fi

# URL where to fetch IP list from badips.com
URL="https://www.badips.com/get/list/ssh/2?age=2w"

while [ ${N_DOWNLOAD_RETRY} -gt 0 ]; do
	### download
	$LOGGER_BIN $LOGGER_OPTS "Fetching list of bad IPs from $URL"
	FILE=$(mktemp -t block_badips.new.XXXXXX)
	# set trap to remove temp file if download failes
	trap "rm -f $FILE" INT TERM EXIT
	# Try curl or wget to download.
	if type curl >/dev/null; then
		r=$(curl -s $URL > "$FILE")
	elif type wget >/dev/null; then 
		r=$(wget -q -O "$FILE" "$URL")
	fi
	if [ $? -ne 0 ]; then
		$LOGGER_BIN $LOGGER_OPTS_WARN "Download of $URL failed with exit code $? and message ${r}"
		N_DOWNLOAD_RETRY=$((N_DOWNLOAD_RETRY-1))
		sleep ${DOWNLOAD_RETRY_WAIT_S}
		continue
	else
		$LOGGER_BIN $LOGGER_OPTS "Got "$(wc -l < "$FILE" ) " lines"
	fi

	### input check
	# Check downloaded file (should contain a single IP adresses in each line).
	# In the case of an error, $FILE is either empty or an HTML page
	# Hint: grep returns 1 or true if there is no match in the file
	if [ ! -s ${FILE} ]; then
		# file does not exist or is empty
		$LOGGER_BIN $LOGGER_OPTS_WARN "${URL} sent empty or no file"
		N_DOWNLOAD_RETRY=$((N_DOWNLOAD_RETRY-1))
		sleep ${DOWNLOAD_RETRY_WAIT_S}
		continue
	elif grep -q -i HTML ${FILE}; then
		# file contains HTML code
		if grep -q "<head><title>504 Gateway Time-out</title></head>" ${FILE}; then
			$LOGGER_BIN $LOGGER_OPTS_WARN "${URL} cannot be fetched because of 504 Gateway Time-out"
			echo $(date -Is) - ERROR 504 >> ${STATUS_FILE}
		elif grep -q "<head><title>502 Bad Gateway</title></head>" ${FILE}; then
			$LOGGER_BIN $LOGGER_OPTS_WARN "${URL} cannot be fetched because of 502 Bad Gateway"
			echo $(date -Is) - ERROR 502 >> ${STATUS_FILE}
		else
			# if there was a problem, sometimes a HTML file containing an error message is sent
			$LOGGER_BIN $LOGGER_OPTS_WARN "${URL} got HTML file instead of text file, see ${STATUS_FILE} for details."
			# uncomment mail for debugging, productive script shouldn't depend on mail
			#mail -s "add badips error" root < "${FILE}"
			date -Is >> ${STATUS_FILE}
			cat ${FILE} >> ${STATUS_FILE}
		fi
		N_DOWNLOAD_RETRY=$((N_DOWNLOAD_RETRY-1))
		sleep ${DOWNLOAD_RETRY_WAIT_S}
		continue
	elif grep -v -q -oE '^(([0-9]{1,3}[\.]){3}[0-9]{1,3})|(([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4})$' $FILE; then
		# something else than an IP is found
		$LOGGER_BIN $LOGGER_OPTS_WARN "${URL} contained something else than a list of IPv4 addresses"
		# uncomment mail for debugging, productive script shouldn't depend on mail
		# mail -s "badip erronous file" rooti < "${FILE}"
		date -Is >> ${STATUS_FILE}
		cat ${FILE} >> ${STATUS_FILE}
		N_DOWNLOAD_RETRY=$((N_DOWNLOAD_RETRY-1))
		sleep ${DOWNLOAD_RETRY_WAIT_S}
		continue
	else
		# everything fine, continue outside loop
		break
	fi
done

# quit if no valid file could be retrieved
if [ ${N_DOWNLOAD_RETRY} -lt 0 ]; then
	$LOGGER_BIN $LOGGER_OPTS_ERROR "ERROR: ${URL} does not provide list of IPs after several tries. Giving up now. "
	exit 1
fi

# assert: $FILE contains a single IPv4 od IPv6 adresses in each line

# leave just IPv4 addresses in ${FILE} 
sed -i -E '/^([0-9]{1,3}[\.]){3}[0-9]{1,3}$/!d' ${FILE}

# assert: $FILE contains a single ipv4 adresses in each line

# remove the NULL IP since ipset will trigger errexit if 0.0.0.0 appears
sed -i ${FILE} -e '/0.0.0.0/d'

# whitelist unroutable (local) IPv4 addresses
sed -i -E '/^(192\.168|10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|169\.254|127\.)/d' ${FILE}

# remove IPs from whitelist file
if [ -s "${WHITELIST_FILE}" ]; then
	FILE_TMP=$(mktemp -t block_badips.prefilter.XXXXXX)
	mv ${FILE} ${FILE_TMP}
	comm -23 <(sort ${FILE_TMP}) <(grep -oE '^(([0-9]{1,3}[\.]){3}[0-9]{1,3})|(([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4})$' ${WHITELIST_FILE} | sort) > ${FILE}
	rm ${FILE_TMP}
fi

# add IPs from blacklist file
if [ -s "${BLACKLIST_FILE}" ]; then
	FILE_TMP=$(mktemp -t block_badips.prefilter.XXXXXX)
	mv ${FILE} ${FILE_TMP}
	# Hint: grep will exit with error if no IP was in BLACKLIST_FILE. Thus disable 'errexit' briefley
	set +e
	grep -oE '^(([0-9]{1,3}[\.]){3}[0-9]{1,3})|(([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4})$' ${BLACKLIST_FILE} >> ${FILE_TMP}
	set -e
	# Remove duplicates (same IP could have been in downloaded file and local blacklist file) to avoid warnings
	# from ipset.
	sort --unique ${FILE_TMP} > ${FILE}
	rm ${FILE_TMP}
fi

### main part
if [ -x $IPSET_BIN ]; then
	# use ipset if available since it's faster than plain iptables
	# http://daemonkeeper.net/781/mass-blocking-ip-addresses-with-ipset/
	
	# create new ipset if not already there
	if ! $IPSET_BIN list BADIP >/dev/null 2>&1; then
		$IPSET_BIN create BADIP hash:ip hashsize 4096
	fi

	# iptables should be added only once. So check if it already there.
	if ! $IPTABLES_BIN -w -C INPUT  -m set --match-set BADIP src -m comment --comment "BADIP" -j REJECT > /dev/null 2>&1; then
		$IPTABLES_BIN -w -I INPUT  -m set --match-set BADIP src -m comment --comment "BADIP" -j REJECT
	fi
	
	### get old blocked entries
	FILE2=$(mktemp -t block_badips.old.XXXXXX)
	trap "rm -f $FILE $FILE2" INT TERM EXIT
        #       $IPSET_BIN list BADIP -o plain | tail -n +8 > "$FILE2"
        # at first run, grep returns 1 since list is empty
        # use tail instead is also no good since number of header lines depend on ipset version
        # use computationally more demanding grep and awk
        $IPSET_BIN list BADIP -o save | grep add | awk '{ print $3 }' > "$FILE2"
                                        
	### list of ips that are not considered bad any more
	OLD_IPS=$(mktemp -t block_badips.old.XXXXXX)
	trap "rm -f $FILE $FILE2 $OLD_IPS" INT TERM EXIT
	comm -13 <(sort $FILE) <(sort $FILE2) >> $OLD_IPS

	### list of ips that are new and should be blocked
	NEW_IPS=$(mktemp -t block_badips.newips.XXXXXX)
	trap "rm -rf $FILE $FILE2 $OLD_IPS $NEW_IPS" INT TERM EXIT
	comm -23 <(sort $FILE) <(sort $FILE2) >> $NEW_IPS

	# remove long lists (not needed any more)
	rm $FILE $FILE2	
	trap "rm -rf $OLD_IPS $NEW_IPS" INT TERM EXIT

	### delete old rules, that are not needed any more
	$LOGGER_BIN $LOGGER_OPTS "Removing "$(wc -l < $OLD_IPS )" old entries"
	while read IP; do
		#$IPSET_BIN del BADIP $IP || echo "Warning when deleting $IP"
		$IPSET_BIN del BADIP $IP
	done < "$OLD_IPS"
	rm "$OLD_IPS"
	trap "rm -f $NEW_IPS" INT TERM EXIT
	
	### add new IPs that should be blocked
	$LOGGER_BIN $LOGGER_OPTS "Adding "$(wc -l < $NEW_IPS)" new entries"
	while read IP; do
		#$IPSET_BIN add BADIP $IP || echo "Warning when adding $IP"
		$IPSET_BIN add BADIP $IP 
	done < "$NEW_IPS"
	rm "$NEW_IPS"
	
else
	# use iptables if ipset is not available
		
	### get old blocked entries
	FILE2=$(mktemp -t block_badips.old.XXXXXX)
	trap "rm -f $FILE $FILE2" INT TERM EXIT
	# export all rules with comment "BADIP" and replace -A (add) with -D (delete)
	$IPTABLES_SAVE_BIN  | grep -e "--comment BADIP" | sed 's/-A/-D/' > "$FILE2"
	$LOGGER_BIN $LOGGER_OPTS "Found "$(wc -l < $FILE2)" old entries"
	
	### list of ips that are not considered bad any more
	OLD_IPS=$(mktemp -t block_badips.old.XXXXXX)
	trap "rm -f $FILE $FILE2 $OLD_IPS" INT TERM EXIT
	comm -13 <(sort $FILE) <(grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' $FILE2 | sort) >> $OLD_IPS

	### list of ips that are new and should be blocked
	NEW_IPS=$(mktemp -t block_badips.newips.XXXXXX)
	trap "rm -rf $FILE $FILE2 $OLD_IPS $NEW_IPS" INT TERM EXIT
	comm -23 <(sort $FILE) <(grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' $FILE2 | sort) >> $NEW_IPS
	
	# get format of old rule (exact rule must be given to iptables as argument)
	FMT=$(head -n 1 $FILE2)
	
	# remove long lists (not needed any more)
	rm $FILE $FILE2	
	trap "rm -rf $OLD_IPS $NEW_IPS" INT TERM EXIT
	
	### delete old rules, that are not needed any more
	$LOGGER_BIN $LOGGER_OPTS "Removing "$(wc -l < $OLD_IPS )" old entries"
	while read IP; do
		$IPTABLES_BIN -w $(echo $FMT | sed -r "s/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/$IP/")
	done < "$OLD_IPS"
	rm "$OLD_IPS"
	trap "rm -f $NEW_IPS" INT TERM EXIT
	
	### add new IPs that should be blocked
	$LOGGER_BIN $LOGGER_OPTS "Adding "$(wc -l < $NEW_IPS)" new entries"
	while read IP; do
		$IPTABLES_BIN -w -I INPUT -s $IP -j DROP -m comment --comment "BADIP"
	done < "$NEW_IPS"
	rm "$NEW_IPS"
	
fi

### end of script
$LOGGER_BIN $LOGGER_OPTS "Finished applying iptables rules"

echo $(date -Is) - updated >> ${STATUS_FILE}

# keep just the last lines in STATUS_FILE
echo "$(tail -1000 ${STATUS_FILE})" > ${STATUS_FILE}

