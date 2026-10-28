#!/bin/bash
# Tests for block-badips.sh and check_block-badips.sh.
#
# The tests run in a new network namespace, so they don't touch the firewall of
# the host. As non-root user, a user namespace is created as well, which
# requires unprivileged user namespaces to be enabled.
#
# Requirements: iptables, ipset, python3, unshare

set -o nounset

REPO_DIR=$(cd "$(dirname "$0")/.." && pwd)
SCRIPT="${REPO_DIR}/usr/sbin/block-badips.sh"
PLUGIN="${REPO_DIR}/usr/lib/nagios/plugins/check_block-badips.sh"

# re-execute in a new network namespace
if [ -z "${BADIPS_TEST_NETNS:-}" ]; then
	export BADIPS_TEST_NETNS=1
	if [ "$(id -u)" -eq 0 ]; then
		exec unshare --net "$0" "$@"
	else
		exec unshare --map-root-user --net "$0" "$@"
	fi
fi

PATH=/usr/sbin:/sbin:$PATH
export LC_ALL=C

TEST_DIR=$(mktemp -d -t block_badips_test.XXXXXX)
trap 'rm -rf "${TEST_DIR}"' EXIT

export STATE_DIRECTORY="${TEST_DIR}/state"
export RUNTIME_DIRECTORY="${TEST_DIR}/run"
export BADIPS_WHITELIST_FILE="${TEST_DIR}/whitelist"
export BADIPS_BLACKLIST_FILE="${TEST_DIR}/blacklist"
export BADIPS_STATUS_FILE="${STATE_DIRECTORY}/status"
export BADIPS_NO_STDERR=1
export TMPDIR="${TEST_DIR}"

N_FAILED=0

check () {
	local description="$1" expected="$2" actual="$3"
	if [ "$expected" = "$actual" ]; then
		echo "ok - ${description}"
	else
		echo "FAILED - ${description}: expected \"${expected}\", got \"${actual}\""
		N_FAILED=$((N_FAILED + 1))
	fi
}

# run block-badips.sh with the given list, print its exit code
run () {
	URL="$1" bash "${SCRIPT}" >/dev/null 2>&1
	echo $?
}

# print the sorted entries of an ipset on a single line
set_entries () {
	ipset list "$1" -o save 2>/dev/null | awk '/^add / { print $3 }' | sort | tr '\n' ' ' | sed 's/ $//'
}

set_count () {
	ipset list -t "$1" 2>/dev/null | awk '/^Number of entries:/ { print $4 }'
}

# send a UDP packet from the given source address to the local address 192.0.2.1
send_packet () {
	python3 -c "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('$1', 0)); s.sendto(b'x', ('192.0.2.1', 9))"
}

# packets dropped by the BADIP4 rule
dropped_packets () {
	iptables -w -t raw -L PREROUTING -v -x -n | awk '/BADIP4/ { print $1 }'
}

printf '%s\n' 198.51.100.1 198.51.100.2 203.0.113.0/24 2001:db8::1 2001:db8:1::/48 > "${TEST_DIR}/list"
printf '%s\n' '# blacklist' 192.0.2.99 2001:db8::99 > "${BADIPS_BLACKLIST_FILE}"
printf '%s\n' '# whitelist' 203.0.113.7 198.51.100.2 > "${BADIPS_WHITELIST_FILE}"

### basic run
check "initial run succeeds" 0 "$(run "${TEST_DIR}/list")"
check "IPv4 set contains list and blacklist" "192.0.2.99 198.51.100.1 198.51.100.2 203.0.113.0/24" "$(set_entries BADIP4)"
check "IPv6 set contains list and blacklist" "2001:db8:1::/48 2001:db8::1 2001:db8::99" "$(set_entries BADIP6)"
check "whitelist is in allow set" 1 "$(set_entries BADIP4_ALLOW | grep -c '203.0.113.7')"
check "one IPv4 rule" 1 "$(iptables-save | grep -c 'comment BADIP4')"
check "one IPv6 rule" 1 "$(ip6tables-save | grep -c 'comment BADIP6')"
check "second run succeeds" 0 "$(run "${TEST_DIR}/list")"
check "rule is not duplicated" 1 "$(iptables-save | grep -c 'comment BADIP4')"

### packets
ip link set lo up
for IP in 192.0.2.1 203.0.113.7 203.0.113.8; do
	ip addr add "${IP}/32" dev lo
done
send_packet 203.0.113.7
check "whitelisted address within blocked range passes" 0 "$(dropped_packets)"
send_packet 203.0.113.8
check "address within blocked range is dropped" 1 "$(dropped_packets)"

### invalid and too broad entries
printf '%s\n' 198.51.100.1 '198.51.100.3 garbage' > "${TEST_DIR}/invalid"
check "invalid list is ignored while the last valid list is active" 0 "$(run "${TEST_DIR}/invalid")"
check "sets are unchanged after invalid list" 4 "$(set_count BADIP4)"
: > "${TEST_DIR}/empty"
check "empty list is ignored while the last valid list is active" 0 "$(run "${TEST_DIR}/empty")"
check "sets are unchanged after empty list" 4 "$(set_count BADIP4)"
check "rule is kept after empty list" 1 "$(iptables-save | grep -c 'comment BADIP4')"
check "keeping the last valid list is logged" 1 "$(grep -c ' - kept last valid list$' "${BADIPS_STATUS_FILE}" | awk '{ print ($1 >= 1) }')"

printf '%s\n' 198.51.100.1 198.51.100.2 203.0.113.0/24 0.0.0.0/1 2001:db8::1 2001:db8:1::/48 ::/1 > "${TEST_DIR}/broad"
check "list with too broad ranges is accepted" 0 "$(run "${TEST_DIR}/broad")"
check "too broad IPv4 range is ignored" 0 "$(set_entries BADIP4 | grep -c '0.0.0.0/1')"
check "too broad IPv6 range is ignored" 0 "$(set_entries BADIP6 | grep -c '::/1')"

### shrinking list
seq 1 100 | awk '{ print "198.18.0." $1 }' > "${TEST_DIR}/long"
head -n 40 "${TEST_DIR}/long" > "${TEST_DIR}/short"
check "long list is accepted" 0 "$(run "${TEST_DIR}/long")"
check "list shrinking by 60 % is refused" 1 "$(run "${TEST_DIR}/short")"
check "sets are unchanged after refused list" 101 "$(set_count BADIP4)"
check "shrinking list is accepted if allowed" 0 "$(BADIPS_MAX_SHRINK_PERCENT=100 run "${TEST_DIR}/short")"
check "sets contain shrunk list" 41 "$(set_count BADIP4)"

### last valid list
iptables -w -t raw -F PREROUTING
check "failing fetch succeeds with the last valid list" 0 "$(run "${TEST_DIR}/empty")"
check "last valid list is applied if rule is missing" 1 "$(iptables-save | grep -c 'comment BADIP4')"
check "set contains last valid list" 41 "$(set_count BADIP4)"
check "malformed URL is an error despite the last valid list" 1 "$(run "${TEST_DIR}/does-not-exist")"
check "rule is kept after malformed URL" 1 "$(iptables-save | grep -c 'comment BADIP4')"
mv "${STATE_DIRECTORY}/list" "${TEST_DIR}/saved-list"
check "failing fetch without last valid list returns error" 1 "$(run "${TEST_DIR}/empty")"
mv "${TEST_DIR}/saved-list" "${STATE_DIRECTORY}/list"

### migration from older versions, which had no cache
rm "${STATE_DIRECTORY}/list"
for TABLE in raw filter; do
	iptables -w -t "$TABLE" -F
done
for SET in BADIP4 BADIP4_ALLOW BADIP6 BADIP6_ALLOW; do
	ipset destroy "$SET" 2>/dev/null
done
ipset create BADIP4 hash:ip family inet
ipset add BADIP4 198.51.100.1
iptables -w -I INPUT -m set --match-set BADIP4 src -m comment --comment BADIP4 -j REJECT
iptables -w -I INPUT -s 203.0.113.0/24 -m comment --comment BADIP4 -j DROP
iptables -w -I INPUT -s 192.0.2.50 -m comment --comment other -j ACCEPT
check "run after older version succeeds" 0 "$(run "${TEST_DIR}/list")"
check "set of older version is replaced" "hash:net" "$(ipset list -t BADIP4 | awk '/^Type:/ { print $2 }')"
check "rules of older version are removed" 0 "$(iptables-save -t filter | grep -c 'comment BADIP4')"
check "other rules are kept" 1 "$(iptables-save | grep -c 'comment other')"

### check plugin
check "plugin reports OK" 0 "$(bash "${PLUGIN}" >/dev/null; echo $?)"
iptables -w -t raw -F PREROUTING
check "plugin reports missing rule as CRITICAL" 2 "$(bash "${PLUGIN}" >/dev/null; echo $?)"
check "plugin rejects -s" 3 "$(bash "${PLUGIN}" -s /etc/shadow >/dev/null; echo $?)"

if [ "${N_FAILED}" -gt 0 ]; then
	echo "${N_FAILED} tests failed"
	exit 1
fi
echo "all tests passed"
