# The firewall, and who may reach which page

*Settings → This server → Firewall and access* (isemon 1.10.222) looks after
two things, both put in place by root on this machine and neither touched
until somebody saves something there:

1. **Who may reach which page.** The dashboard, the published ban list
   (`/banfeed.php`) and the health check (`/healthz.php`) all answer on port
   443, so a firewall cannot tell them apart. nginx can: each has a list of
   its own in `/etc/nginx/conf.d/isemon.conf`.
2. **The machine's firewall** - iptables and ip6tables (the
   `iptables-services` package on AlmaLinux / RHEL). Off by default.

## How it is put in place

The daemon runs as `isemon` and may not change nginx or the firewall. What is
saved on the page is kept in the database; the daemon then writes
`/var/lib/isemon/web/request.json`, systemd (`isemon-web.path`) starts
`isemon-web.service`, and that runs `/usr/local/lib/isemon/isemon_web.py` as
root. The helper:

- checks every value again, against the one shape it may have (addresses
  and networks, ports, protocols, notes stripped to plain letters);
- writes the files, asks `nginx -t` before reloading nginx and
  `iptables-restore --test` before replacing `/etc/sysconfig/iptables`;
- **puts every file back as it was** when either says no;
- writes what it did into `/var/lib/isemon/web/status.json` - shown on the
  page and by `isemon --web-status`.

Every minute the daemon compares what is kept with what root last put in
and asks again when they differ (after a copy of the database was put back,
say). A request that failed is not asked again by itself for the same thing:
only once something changes, or *Try again* is pressed.

`install.sh` (1.10.222 and later) installs the helper and the units, on a
fresh install and on an upgrade. **An upgrade changes nothing of nginx or the
firewall by itself**: the units only act on a request.

## Who may reach which page

| Page | Where | Choices |
|---|---|---|
| The dashboard | the HTTPS server's own `allow` lines | everybody, or only from a list |
| The published ban list | `location = /banfeed.php` | as the dashboard, everybody, or only from a list |
| The health check | `location = /healthz.php` | as the dashboard, everybody, or only from a list |

This machine itself (`127.0.0.1`, `::1`) is always let in. The first save
replaces the `allow` lines `install.sh` wrote (or the site's own) with a
list between `# DASHBOARD-ALLOW-BEGIN` and `# DASHBOARD-ALLOW-END`; a list of
the ban feed or the health check is a location of its own between
`# isemon-banfeed-begin/end` and `# isemon-health-begin/end`, handed to PHP
the way the vhost's own `location ~ \.php$` does it. "As the dashboard" takes
that location out again. Until the first save the page shows the list as
nginx has it, marked *as install.sh wrote it*.

## The machine's firewall

Only a chain of isemon's own, `ISEMON-IN`, jumped to first from `INPUT`:

```
INPUT ─► ISEMON-IN: your rules (in their order) ─► what isemon needs ─► the rest of INPUT
```

It starts with two fixed rules - loopback, and the answers to connections
this machine opened itself (`conntrack ESTABLISHED,RELATED`: the routers,
the directory, DNS, the public lists) - and on IPv6 neighbour discovery.
Anything it does not let in goes back to INPUT and on to the rules that were
there before (your SSH, Zabbix, the final REJECT…). isemon never changes
those. It is put in at once (`iptables-restore --noflush`) and written into
`/etc/sysconfig/iptables` and `ip6tables` between lines that start
`# isemon:`, so it is there after a reboot. Turned off, the jump and the chain
are taken away - live and in the files - and nothing else: the file is the
one there was, to the byte.

### What isemon lets in by itself

| Rule | Let in | Can be turned off |
|---|---|---|
| SSH | tcp on the port(s) sshd listens on (its own file says), from anywhere | yes - keep a rule of your own if you do |
| ICMP / ICMPv6 | ping; IPv6 needs ICMPv6 | yes |
| DHCPv6 client | udp 546 from fe80::/10 | yes |
| The dashboard | tcp 80,443 - from everybody when a page is for everybody, else from the networks the lists name | yes |
| The logs arriving | every port rsyslog listens on (read off `/etc/rsyslog.conf` and `/etc/rsyslog.d/*.conf` by root: `imudp`, `imtcp`, `imptcp`, `imrelp`, and the old `$UDPServerRun` lines) - from anywhere, or only from the senders named | yes |
| Automatic certificates (HTTP-01) | tcp 80 from anywhere, while *Settings → Automatic certificates* checks the name by HTTP-01: the CA asks from wherever it is ([automatic-certificates.md](automatic-certificates.md), 1.10.251) | yes |

They follow what is set up: change a list, or tell rsyslog to listen on
another port, and the rules change within a minute.

### Rules of your own

Accept, drop or reject; TCP, UDP, ICMP or any protocol; a port, a range
(`6514-6515`) or several (`80,443`); from an address or a network; IPv4,
IPv6 or both. They come first in `ISEMON-IN`, in the order shown, so a DROP
of yours wins over what isemon lets in. Each carries its note as an iptables
comment (`isemon: Zabbix agent`). A rule can be kept without being in force.

## Before turning it on

```
dnf install iptables-services
systemctl disable --now firewalld        # if it is running
systemctl enable --now iptables ip6tables
```

If firewalld is running, isemon leaves the firewall to it and says so on the
page; the lists of who may reach which page work either way.

## On trial (1.10.228)

A save here is put in on trial: unless somebody presses *Keep it* (the banner
on every page, or `isemon --change-keep fw`) within `fw_confirm_min` minutes
(5), what was set before the first change of the trial comes back by itself
and root puts it in again - a rule that shuts SSH or the dashboard out does
not stay. Further saves within the trial move its deadline on.
`isemon --change-back fw` puts the old back at once; `fw_confirm_min` 0 keeps
every change at once. See [network-and-power.md](network-and-power.md).

## Checking

The page shows both at the bottom of the firewall card (*The firewall on this
machine as it is now*): INPUT with the jump to ISEMON-IN, and ISEMON-IN as the
kernel holds it.


```
isemon --web-status                     # what root did last
iptables -S ISEMON-IN; ip6tables -S ISEMON-IN
grep -n isemon /etc/sysconfig/iptables
grep -n 'ALLOW\|isemon-.*-begin' /etc/nginx/conf.d/isemon.conf
```

## Undoing it by hand

- The firewall: turn it off on the page, or
  `iptables -D INPUT -j ISEMON-IN; iptables -F ISEMON-IN; iptables -X ISEMON-IN`
  (the same with `ip6tables`) and remove the `# isemon:` lines from the two
  files.
- nginx: the lists are ordinary `allow` lines between marks; edit them, or
  put back the vhost `install.sh` wrote (`/usr/local/lib/isemon/nginx-isemon.conf`
  is the one this version ships, for comparing).
