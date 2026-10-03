# block-badips

This project provides a bash script to download a list of IPs to block and updates iptable rules accordingly.
Additionally, systemd service file for periodic updates and a Nagios/Icinga plugin to check the iptable rules is provided.

## How it works

`block-badips.sh` downloads a list of IPv4/IPv6 addresses and ranges, by default the list of all attackers reported to
[blocklist.de](https://www.blocklist.de). It then

1. checks the list and ignores ranges that are too broad,
2. adds the entries of the local blacklist,
3. loads all addresses and ranges into the ipsets `BADIP4` and `BADIP6`, and
4. loads the local whitelist and private and other special-purpose addresses into the ipsets `BADIP4_ALLOW` and
   `BADIP6_ALLOW`.

One iptables rule per address family in the `PREROUTING` chain of the `raw` table drops all traffic from addresses in
`BADIP4`/`BADIP6` that are not in `BADIP4_ALLOW`/`BADIP6_ALLOW`. Since the `raw` table is processed before connection
tracking and routing, blocking is cheap and also covers traffic forwarded to VMs or containers.

On each run, the sets are filled completely and swapped in atomically, so the firewall never holds a partially loaded
list. The rules carry the comment `BADIP4` or `BADIP6`, and the script never touches any other rule. This makes it work
alongside other firewall tools such as firewalld, SuSEfirewall2 or fail2ban.

The script logs to syslog only (identifier `block_badips`), so it is quiet when run from cron or a systemd timer.

### Safety checks

- **Invalid lists:** if the list contains anything else than one address or range per line, e.g. an HTML error page, it
  is rejected and the firewall is left unchanged.
- **Too broad ranges:** ranges of the downloaded list with a prefix shorter than `/8` (IPv4) or `/32` (IPv6) are
  ignored and logged, since an entry like `0.0.0.0/1` would block half of the internet.
- **Shrinking lists:** a list that is more than 50 % shorter than the last valid one is refused, since it is more
  likely broken than a sign that the attacks stopped.
- **Last valid list:** each valid list is stored in `/var/lib/block-badips/list`. If the blocking rules are missing,
  e.g. after a reboot or a firewall restart, this list is applied right away, before the download, which may take a
  while or fail.
- **Downloads** are retried 5 times with 30 seconds between the tries. Each try is limited to 60 seconds.

## Requirements

- bash
- iptables, ip6tables, iptables-save, ip6tables-save, iptables-restore and ip6tables-restore; both the legacy and the
  nf_tables backend work
- ipset
- curl or wget
- logger, flock, mktemp, sed, grep, awk, head, tail, tr, wc

## Installation

The repository mirrors the target file system layout, so copy the files to the same paths on the target host:

```sh
install -m 755 usr/sbin/block-badips.sh /usr/sbin/
install -m 644 usr/lib/systemd/system/block-badips-* /usr/lib/systemd/system/
install -m 600 etc/block-badips.conf /etc/
install -m 644 etc/block-badips.whitelist etc/block-badips.blacklist /etc/
```

`/etc/block-badips.conf` may contain credentials, hence it should be readable by root only.

Then edit the configuration (see below) and enable the services:

```sh
systemctl daemon-reload
systemctl enable --now block-badips-onboot.service block-badips-update.timer
```

### Upgrading from older versions

Older versions blocked single addresses via `hash:ip` ipsets and ranges via one iptables rule each in the `INPUT`
chain. These sets and rules are replaced automatically on the first run of the new version.

## Configuration

### /etc/block-badips.conf

The systemd services read their settings from `/etc/block-badips.conf`. When running the script manually, the same
variables can be set in the environment. All variables are optional.

| Variable                    | Description                                                                                                       | Default                                    |
|-----------------------------|-------------------------------------------------------------------------------------------------------------------|--------------------------------------------|
| `URL`                       | Where to fetch the list from: an `http(s)://`, `ftp://` or `file://` URL, or the path of a local file.            | `https://lists.blocklist.de/lists/all.txt` |
| `BADIPS_USER`               | User name for the download. Must not contain whitespace.                                                          |                                            |
| `BADIPS_PASSWORD`           | Password for the download. Must not contain whitespace.                                                           |                                            |
| `BADIPS_NO_STDERR`          | If not empty, errors and warnings go to syslog only and are not printed to stderr as well.                        |                                            |
| `BADIPS_MIN_PREFIX4`        | Ranges of the downloaded list with a shorter IPv4 prefix are ignored.                                             | `8`                                        |
| `BADIPS_MIN_PREFIX6`        | Ranges of the downloaded list with a shorter IPv6 prefix are ignored.                                             | `32`                                       |
| `BADIPS_MAX_SHRINK_PERCENT` | A list that is shorter than the last valid one by more than this percentage is refused. `100` disables the check. | `50`                                       |
| `BADIPS_IPSET_MAXELEM`      | Maximum number of entries of each ipset.                                                                          | twice the list's entries, at least 65536   |
| `BADIPS_WHITELIST_FILE`     | Path of the whitelist.                                                                                            | `/etc/block-badips.whitelist`              |
| `BADIPS_BLACKLIST_FILE`     | Path of the blacklist.                                                                                            | `/etc/block-badips.blacklist`              |

Credentials are passed to curl/wget via a temporary netrc file, so they do not show up in the process list.

Example for a list that requires authentication:

```sh
BADIPS_NO_STDERR=1
BADIPS_USER="username"
BADIPS_PASSWORD="password"
URL="https://myurl.invalid/blocklist"
```

### Format of the list

The list must contain one IPv4 or IPv6 address or range per line and nothing else. Empty lines and comments are not
allowed.

```
192.0.2.17
198.51.100.0/24
2001:db8::1
2001:db8:1234::/48
```

### Whitelist and blacklist

- `/etc/block-badips.blacklist`: addresses and ranges listed here are always blocked, even if they are not on the
  downloaded list.
- `/etc/block-badips.whitelist`: addresses and ranges listed here are never blocked, even if they are on the
  downloaded list, on the blacklist, or part of a blocked range.

Only lines that contain nothing but a single IPv4 or IPv6 address or range are used; all other lines are ignored, so
comments are possible. Changes take effect on the next run.

Additionally, the following addresses are never blocked:

- IPv4: `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`,
  `192.168.0.0/16`, `224.0.0.0/4` and `240.0.0.0/4`
- IPv6: `::`, `::1`, `::ffff:0:0/96`, `fc00::/7`, `fec0::/10`, `fe80::/10` and `ff00::/8`

## systemd units

- `block-badips-onboot.service` applies the rules at boot, after the network is online and before fail2ban and libvirtd
  start. It is `PartOf` firewalld and SuSEfirewall2, so it runs again when the firewall is restarted and may have
  flushed the rules.
- `block-badips-update.timer` runs `block-badips-update.service` every hour, except from 2 am to 5 am, with a random
  delay of up to 10 minutes.

Both services retry on failure and are hardened: they run with only the capabilities iptables and ipset need and a
read-only file system except for `/run` and `/var/lib/block-badips`. A lock file ensures that only one instance modifies
the firewall at a time.

## Monitoring

`check_block-badips.sh` is a Nagios/Icinga plugin that reports the number of blocked addresses and ranges. It returns
CRITICAL or WARNING if

- fewer entries than the given thresholds are blocked,
- the last successful update is older than the given thresholds,
- an ipset contains entries but no iptables rule uses it, e.g. after the firewall was reloaded,
- an ipset is nearly full.

```
Usage: check_block-badips.sh [-h] [-w entries] [-c entries] [-W seconds] [-C seconds] [-f percent]

  -h          show this help text and exit
  -w entries  WARNING if fewer entries are blocked (default: 1)
  -c entries  CRITICAL if fewer entries are blocked (default: 1)
  -W seconds  WARNING if the last successful update is older (default: 21600)
  -C seconds  CRITICAL if the last successful update is older (default: 43200)
  -f percent  WARNING if an ipset is filled to more than this percentage
              of its maxelem (default: 90)
```

The default age thresholds take into account that the timer pauses at night. The plugin reports the performance data
`num_entries`, `num_ip4`, `num_ip6`, `num_ranges4`, `num_ranges6` and `last_update_age`.

The plugin needs root privileges to read the firewall rules. Install it together with the sudoers snippet, which lets
the user `nagios` run it via sudo without a password:

```sh
install -m 755 usr/lib/nagios/plugins/check_block-badips.sh /usr/lib/nagios/plugins/
install -m 440 etc/sudoers.d/check_block-badips /etc/sudoers.d/
```

Then call it as `sudo /usr/lib/nagios/plugins/check_block-badips.sh` in the command definition.

The plugin reads the status file `/var/lib/block-badips/status`. For testing, another file can be set via the
environment variable `BADIPS_STATUS_FILE`; there is deliberately no option for it, so the `nagios` user cannot make the
plugin read other files as root.

## Troubleshooting

- Log messages: `journalctl SYSLOG_IDENTIFIER=block_badips` or `grep block_badips /var/log/messages`
- Status file: `/var/lib/block-badips/status` records each successful update as well as rejected downloads, including
  the content that was received. Only the last 1000 lines are kept.
- Last valid list: `/var/lib/block-badips/list`
- Currently blocked entries: `ipset list BADIP4` and `ipset list BADIP6`
- Never blocked entries: `ipset list BADIP4_ALLOW` and `ipset list BADIP6_ALLOW`
- Blocking rules and their packet counters: `iptables -t raw -L PREROUTING -v` and `ip6tables -t raw -L PREROUTING -v`
- If a valid list is refused because it shrank a lot, raise `BADIPS_MAX_SHRINK_PERCENT` or delete
  `/var/lib/block-badips/list`.

## Uninstallation

Disable the units, then remove the rules and ipsets:

```sh
systemctl disable --now block-badips-update.timer block-badips-onboot.service
for v in 4 6; do
	[ $v = 4 ] && ipt=iptables || ipt=ip6tables
	$ipt -t raw -D PREROUTING -m set --match-set BADIP$v src -m set ! --match-set BADIP${v}_ALLOW src \
		-m comment --comment BADIP$v -j DROP
	ipset destroy BADIP$v
	ipset destroy BADIP${v}_ALLOW
done
```

Finally, delete the installed files and `/var/lib/block-badips`.

## Development

`tests/run-tests.sh` tests the script and the check plugin in a new network namespace, so it doesn't touch the firewall
of the host. It needs iptables, ipset and python3, and runs as root or, if unprivileged user namespaces are enabled, as
a normal user. The GitHub workflow runs these tests and shellcheck on each push.

## License

GNU General Public License v3.0, see [LICENSE](LICENSE).
