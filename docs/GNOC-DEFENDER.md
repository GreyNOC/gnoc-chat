# gnoc defender: defending a machine and its network

`/mode defender` turns gnoc chat into a blue team for machines you own or administer: the computer
it runs on, a Linux box it can reach over SSH, and the LAN/WLAN and gateways around them. This is
the full guide; the README has the short version.

Code: `scripts/gnoc_defender.py` (sweep, profile, baselines, plan/apply/undo, watcher),
`scripts/gnoc_defend.py` (the read-only checks), `scripts/gnoc_alerts.py` (alert queue),
`scripts/gnoc_triage.py` (incidents), `scripts/gnoc_enforce.py` (gateway/endpoint enforcement),
`scripts/gnoc-defender-helper` (the root helper). Tests: `scripts/test_gnoc_defender.py` (the
private workspace only; not shipped).

## 1. Quick start

```text
gnoc chat
/mode defender              # or /mode defender auto, or just describe the problem
/defender sweep
/defender admin 192.168.1.0/24
/defender watch on 60       # alert only; /defender auto on 60 to defend automatically
```

## 2. What a sweep looks at

| Area | Checks |
|---|---|
| Ports | every socket reachable from the network, the process behind it, known risky services (databases, API-gateway and container admin APIs, remote desktop) |
| Firewall | ufw / nftables / iptables state; "no active firewall" is high |
| SSH | password login, root login, authorized keys and weak key types |
| Processes | reverse-shell and miner signatures, binaries in `/tmp` `/dev/shm` `/var/tmp`, deleted executables |
| Connections | outbound connections to suspicious ports (IRC, Tor, mining pools, common RAT ports) |
| Logins | failed SSH logins per source, and an ACCEPTED login from a source that was failing |
| Persistence | `/etc/systemd/system`, user units, cron (`/etc/crontab`, `/etc/cron.*`), shell start-up files, `/etc/profile.d`, XDG autostart, `rc.local`, `/etc/init.d`, `/etc/ld.so.preload` |
| Settings | allowlisted kernel sysctls, uid-0 accounts, root-equivalent groups, world-writable `/etc` files, odd setuid binaries, crontab lines |
| Packets | a few seconds of capture (tshark, or `sudo -n tcpdump`): port scans, SYN floods; kernel counters otherwise |
| LAN | neighbour table: MAC changes (ARP spoof), one MAC claiming several IPv4 addresses, new devices |
| Gateways | MAC pinning and change, reachability, optional admin-port audit (`/defender allow scan`) |
| DHCP | a short listen for OFFER/ACK from anything but the known gateway (rogue DHCP) |
| Wi-Fi | SSID/BSSID change, security downgrade, open twins of your network |
| DNS | resolver changes since the baseline |

The light pass the watcher runs every interval covers ports, processes, connections, recent
logins, persistence, host drift and the network state. A full sweep adds settings, the firewall,
packets, the Wi-Fi neighbourhood and DHCP.

What it cannot see without help: the system journal (join `systemd-journal`), packets (join
`wireshark`, or allow passwordless `sudo tcpdump`), root-only files. Each sweep says what it
skipped and why.

## 3. Baselines and drift

The first sweep on a host records:

- a **network baseline** (gateway MACs, neighbour MACs, Wi-Fi association, DNS, DHCP servers);
- a **host baseline** (a hash of every persistence file, the fingerprint of every authorized SSH
  key, and every port reachable from the network).

Later sweeps report drift instead of re-learning it. A new SSH key is **high**. A changed
`/etc/ld.so.preload` is **critical** and counts as an intrusion signal. A new or edited
unit/cron/start-up file and a new listening port are **warnings**. Drift is never folded into the
baseline on its own, so an implant cannot become "normal" by surviving a watcher pass. After you
check a change and it was yours:

```text
/defender baseline accept           # both
/defender baseline accept host      # persistence, keys, ports
/defender baseline accept network   # gateway/device MACs, Wi-Fi, DNS
```

A pass that cannot read the files (SSH down, a timeout) never records or replaces a baseline.

## 4. The profile: answers that change verdicts

Each host has a profile under the workspace (`.claude/state/defender/`, owner-only). The defender
asks for what a scan cannot know and stores the answers:

- `admin_sources`: who must never be locked out (`/defender admin <ip/cidr>`);
- `role`: workstation, server, router...;
- `exposed.<port>`: whether an open port is meant to be (`lan`, `all`, `vpn`, `no`);
- gateways, subnets and the expected Wi-Fi SSID;
- `allow_net_scan`: whether it may probe the gateway's admin ports and discover hosts on the subnet;
- `notify`: desktop notifications from the watcher.

A model cannot grant itself permissions: an `allow_*` answer counts only when you typed it in reply
to that exact question, or set it with `/defender allow|deny ...`.

## 5. Acting: auto-defense, proposals, enforcement

**Auto-defense (on by default, local, reversible, journalled):**

| Kind | Permission | Effect | Undo |
|---|---|---|---|
| `block_ip` | `allow_block_ips` | drop one PUBLIC address in an nft set with a 1 h timeout | expires, or `/defender undo` |
| `pause_pid` | `allow_contain` | SIGSTOP one process (a crit signature, or a high finding talking to the internet) | SIGCONT via undo |
| `sysctl` | `allow_sysctl` | set one allowlisted kernel setting at runtime | the previous value via undo |
| `quarantine_lan` | `allow_quarantine` | drop one LAN address on THIS host for 30 min (ARP spoof, rogue DHCP) | expires, or undo |

Turn any of them off with `/defender deny block|contain|sysctl|quarantine`, all of them with
`/defender auto off`. `/defender journal` lists every action; `/defender undo [last|all|d3]`
reverts. A failed undo stays in the list to retry.

**Proposals:** closing a port, editing `sshd_config`, the firewall policy, disabling a unit or cron
entry, removing a key. The finding carries the exact command; you run it.

**Enforcement beyond this machine** (`/defender setup` guides it):

| Where | Actions | Backend |
|---|---|---|
| Gateway / router | block an IP, deny a MAC | nft sets with timeouts (OpenWrt, any Linux), a pf table (pfSense/OPNsense), a controller API |
| Access point | deny a MAC, deauthenticate a client | hostapd_cli, UniFi controller API |
| Linux endpoints | isolate (keeps the admin, gateway and DNS paths), pause/kill a pid, block an IP | the helper over SSH |

Every gateway and endpoint action is an **ASK**, even with auto-defense on: gnoc proposes it with
the exact target and waits for your yes. Blocks on pf, hostapd and controller APIs have no expiry
on those platforms and stay until `/defender undo`; the proposal says so.

## 6. Anti-lockout

Enforced twice, in the chat and in the root helper:

- never blocked or quarantined: your `admin_sources`, every live SSH / remote-desktop peer, logged-in
  remote users, the default gateways (IPv4 and IPv6), the machine's own addresses and its DNS
  resolvers (including systemd-resolved's upstreams);
- never paused or killed: sshd, the remote-desktop and VPN daemons, init and core system processes,
  and the chat's own process tree;
- the helper also refuses every address listed in the root-owned `/etc/gnoc-defender/protect` (one
  IP or CIDR per line), whether or not a session from it is live;
- isolating an endpoint keeps loopback, the admin peers, the gateway, DNS, DHCP, NTP and IPv6
  neighbour discovery, and refuses to run with no admin path at all;
- the address of a failed login is taken from what sshd appends last, so a username crafted to look
  like an IP cannot get that IP blocked.

## 7. The root helper

`/defender install` checks the target first and prints five numbered steps. Each step has its command
on its own line and what you should see afterwards, and is marked `[done]`, `[todo]` or `[wait]` (waiting
on an earlier step) from the machine's real state:

1. the helper is root-owned, not group/world-writable, and byte-identical to this gnoc's copy (an
   older copy counts as not done);
2. and 3. `sudo -n` accepts the rule (the rule file itself is root-only, so this is how it is checked);
4. `/etc/gnoc-defender/protect` exists and covers every admin source in the profile;
5. `sudo -n gnoc-defender-helper status` answers.

While anything is left, it re-checks every few seconds. It announces each step as it completes
and then says **ROOT HELPER READY**, stopping after 15 minutes otherwise. It never calls `sudo` until the
helper exists, so a half-done install does not fill the auth log. The commands, in outline:

```bash
sudo install -o root -g root -m 0755 <gnoc>/scripts/gnoc-defender-helper /usr/local/sbin/gnoc-defender-helper
echo "$USER ALL=(root) NOPASSWD: /usr/local/sbin/gnoc-defender-helper" | sudo tee /etc/sudoers.d/gnoc-defender
sudo chmod 0440 /etc/sudoers.d/gnoc-defender && sudo visudo -cf /etc/sudoers.d/gnoc-defender
sudo install -d -m 0755 /etc/gnoc-defender && echo '192.168.1.0/24' | sudo tee /etc/gnoc-defender/protect
```

It accepts only: block/unblock a public IP with a timeout, quarantine/release a LAN IP with a
timeout, pause/resume/kill a pid, isolate/unisolate this endpoint, set an allowlisted sysctl, show
status, and flush its own tables. Everything it does is logged. Without it the defender still
sweeps, alerts and triages; it just cannot act.

## 8. Hourly vulnerability watch (`scripts/gnoc_vulnwatch.py`)

`/defender vulnwatch on` installs a systemd user timer (`gnoc-vulnwatch.timer`: hourly, 5 min after
boot, catches up after sleep) that runs `gnoc_vulnwatch.py run --quiet`. Also: `run`, `status`,
`report`, `off`, `npm add|rm <dir>`, `pip add|rm <python>`; the model reads it with
`defend(action=vulnwatch)`.

| Step | Source | Sends |
|---|---|---|
| Actively exploited | CISA KEV, every entry, every pass (ETag-cached) | nothing |
| Newly announced | NVD CVEs published since the last pass, CVSS >= 7.0 (the first pass looks back 24 h) | nothing |
| Installed | dpkg binaries + source packages, running kernel, ollama/node/chrome/code (podman's docker shim is not Docker), network-facing services | nothing |
| Already patched? | Debian's record for the CVE (OSV `DEBIAN-<CVE>`): fixed version vs the installed source version | the CVE id |
| No Debian record | NVD's CPE version ranges for that CVE (cached a week, at most 10 lookups per pass, 6.5 s apart) | the CVE id |
| Dependencies | OSV batch for npm lockfiles and pip environments you name | package names + versions |
| Keeping up | `apt list --upgradable` (security origin or `+debNNuN`), the age of the package lists, unattended-upgrades | nothing |

Rules that keep it quiet and right:

- A name match is never a finding by itself. It needs Debian saying "not fixed in your version" or an
  NVD range that contains your version. Without either, it is deferred and checked again next hour.
- Debian rating a CVE "unimportant" clears it for a dpkg package. For a non-dpkg program that Debian
  tracks under another package (Chrome under chromium, node under nodejs, the kernel under linux), only
  the fixed version is used.
- Each matched NVD CVE is tracked until the installed version is out of range or patched. Only then does
  it drop off.
- Findings are grouped per installed package and version: `vuln:<kind>:<name>:<version>`. A new CVE
  against the same version counts as new and notifies again. Updating the package gives a new id, and the
  old one stops repeating.
- Severity: critical for actively exploited and unpatched (or outdated) or network-facing; high for KEV,
  CVSS >= 9 or network-facing; warning otherwise. Pending security updates are high.

State: `vulnwatch.json` (cursor, caches, tracked CVEs), `vulnwatch-config.json`, `vulnwatch-kev.json`,
and the last report in `vulnwatch-latest.txt`, all in the defender's state folder.

## 9. Alerts and triage

Alerts are a persistent queue deduplicated by finding: open → ack → resolved, or suppressed for a
while. A repeat raises the count and the severity, and reopens an acknowledged alert only when the
repeat is worse than what was acknowledged. Old resolved alerts are compacted away.

Triage scores every sweep. An incident (`IR-...`) opens only when there is an active signal: malware
execution with C2, gateway impersonation, an ARP spoof, rogue DHCP, an evil twin, a login after
brute force, or an installed reverse shell or rootkit hook. Priority runs P1–P4 with an SLA clock.
Escalation restarts the clock at the new priority. Phases move forward only (triage → contained
→ eradicated → recovered); `close` and `false_positive` end a case from any phase.

```text
/defender triage                       # the queue
/defender triage IR-20261118-0001      # one case: evidence, assets, playbook
/defender triage IR-20261118-0001 contain
/defender triage note IR-20261118-0001 isolated the laptop at 14:02
```

## 10. Command reference

`/defender` alone prints the status and this list.

| Command | Does |
|---|---|
| `sweep`, `respond`, `status` | full sweep; plan/apply responses; current state |
| `target local\|<user@host>` | which machine the checks run on |
| `admin <ip/cidr>` | never lock these out |
| `gateway [add\|rm <ip>]`, `subnet [add\|rm <cidr>]`, `network`, `wlan` | scope and the network view |
| `baseline accept [network\|host]` | accept reviewed drift |
| `watch on\|off [secs]`, `auto on\|off [secs]` | the watcher, alert-only or defending |
| `allow\|deny block\|contain\|sysctl\|quarantine\|scan\|auto` | permissions |
| `alerts [ack\|resolve\|suppress <id>]`, `triage [...]` | the queues |
| `undo [last\|all\|d3]`, `journal` | revert and review actions |
| `setup`, `gateway ssh\|platform\|iface\|api\|test`, `endpoint [list\|add\|rm\|test\|sweep]` | enforcement setup |
| `enforce block-ip\|block-mac\|deauth <ip\|mac> [ttl]`, `enforce isolate\|unisolate <dst>`, `enforce pause\|kill <dst> <pid>` | gateway/endpoint actions (always asked) |
| `install` | the helper install, checked step by step |
| `vulnwatch [run\|status\|report\|on\|off\|npm\|pip ...]` | the hourly vulnerability watch |

The model uses the same machinery through the `defend` tool (`action=sweep`, `persistence`,
`processes`, `connections`, `packets`, `settings`, `firewall`, `logins`, `services`, `onion`,
`network`, `gateway`, `wlan`, `alerts`, `triage`, ...).
