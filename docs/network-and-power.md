# The network of this server, restarting it and switching it off

*Settings → Network* and *Settings → Restart and power off* (isemon 1.10.228,
after otp 1.0.119). Both are done by the server itself: the daemon runs as
`isemon` and may not change the network, so it asks root the same way as for
the firewall and TLS - it lays `/var/lib/isemon/web/net.ask` down,
`isemon-web.path` starts `isemon-web.service`, and
`/usr/local/lib/isemon/isemon_web.py` checks every value again as root and
answers in `net.json`.

## Settings → Network

- **As it is now** - the host name, the NetworkManager connection and its
  device, the IPv4 address with its prefix (and whether it was set by hand or
  by DHCP), the gateway, the DNS servers, the search domains, IPv6 and its
  addresses. *Read it again* asks root at once. Once somebody has looked at
  it, it is read again by itself every five minutes.
- **New settings** - the host name (FQDN), IPv4 (address/prefix, gateway,
  DNS, search domains) and IPv6. *Check it* lists what will happen. *Change it
  and restart* does it.

It needs NetworkManager (`nmcli`), as AlmaLinux and Rocky 9 have. Without it
the page says so and the network is set by hand. install.sh does not install
NetworkManager.

Anybody signed in may look; only a full administrator may change it.

### What a change does, in order

1. **What the server has now is kept** in the job, to go back to (see *On
   trial* below).
2. **This server's own settings** that named the old address or host name
   change with it: `db_host` when it is this server's old address (the
   database reached at its own address), and the name of the installation
   (`site_name`) when it is the old host name or its first part. Settings
   that name other machines - the directory, the firewalls, the log senders,
   the whitelist - are never touched.
3. **Its own certificate** (Certificates and TLS), where isemon keeps it and
   it signs itself, is made again with the new address and name in it, and
   root puts it in. A certificate from an authority, or the one install.sh
   made (whose key only nginx has), is not changed: the job says what it
   names, and you get a new one.
4. **NetworkManager** (`nmcli connection modify`), the host name
   (`hostnamectl`) and this machine's lines in `/etc/hosts` (the old file is
   kept as `/etc/hosts.isemon-before`) - then a **reboot** 8 seconds later.
5. **Back up**, the server checks that it has the new address - and waits to
   be kept.

The job is kept in the database, so it survives the reboot. The page shows
each step with a progress bar. While the server restarts it counts the time;
if the page was opened at the server's old address or name, it goes to the
new one once the server has had time to come back. You sign in there again:
a sign-in belongs to the address the page was opened at.

When it is over, the steps stay on the page until *Hide this* is pressed, or
for 6 hours (a day when the change failed). Everything is in Events.

If the server comes up without the new address and the change cannot go back
by itself, the job says so. The network is then put right at the console
(`nmtui`, or `nmcli connection modify …`). What it had before is kept in the
job and in `/etc/hosts.isemon-before`.

### IPv6 (dual stack)

Switched on, by hand (address/prefix, gateway, DNS) or automatically
(SLAAC/DHCPv6), the server takes IPv6 beside IPv4. When IPv6 was switched off
in the kernel, `/etc/sysctl.d/90-isemon-ipv6.conf` switches it on again.
*Firewall and access* already covers IPv4 and IPv6 alike.

## On trial

A new network is put in on trial: unless somebody presses *Keep it* within
`net_confirm_min` minutes (10) of the server coming back up, the server goes
back to its old network by itself - and at once when it comes up without its
new address at all. Going back is the same job the other way round: the old
settings are put in as an ordinary change (its own settings and its
certificate swap back too), and the server restarts. It is not put on trial
again.

**Only a network set by hand (`ipv4.method manual`) can be put back by
itself.** One from DHCP is said so in the plan and in the job, and the new one
is kept at once.

A change of the firewall or of who may reach which page (*Firewall and
access*) is put on trial the same way, for `fw_confirm_min` minutes (5): what
was set before the first change of a trial - the chain on or off, the rules
of your own, what isemon lets in by itself, the senders of the logs, and the
lists of who may reach which page - is kept. Further changes within the
trial move its deadline on. Not kept in time, all of it comes back and root
puts it in within seconds.

| Setting | Default | |
|---|---|---|
| `net_confirm_min` | 10 | a new network goes back unless kept within these minutes; 0: kept at once |
| `fw_confirm_min` | 5 | a change of the firewall or of who may reach which page goes back unless kept within these minutes; 0: kept at once |

Both are under *Settings → Accounts*, *Changes taken back unless kept*.

While a change waits, **every page shows a banner** with the time left,
*Keep it* and *Put the old back now*; `isemon --status` says so too.

```bash
isemon --change-keep net     # keep the new network
isemon --change-back net     # go back to the old one now (a restart)
isemon --change-keep fw      # keep the firewall change
isemon --change-back fw
```

Keep a change only once you have checked that what it could have cut off
still answers: the server at its new address; SSH and the dashboard after a
firewall change.

## Settings → Restart and power off

A card for this server - its address, how long it has run, how long isemon
has run, its version - with **Restart** and **Power off**. Each asks first.
Root does it 5 seconds later (`systemd-run … systemctl reboot|poweroff`), so
the page has its answer first.

The page follows the server: *going down*, *restarting*, then *up again*,
with a countdown while it does not answer; it reloads when the server is
back. A restart that has not come back in 15 minutes is marked as failed.
What is over has *Hide this* too, and goes by itself half an hour after it
began. Neither is possible while the network is being changed.

From the command line:

```bash
isemon --net               # the network as it is, and a change under way
isemon --reboot            # asks first; --yes does not
isemon --poweroff --yes
```

Everything is in Events: who asked, and what the server did.

## For testing

`isemon_web.py` takes the programs it calls from the environment, so a test
can stand in for them: `ISEMON_NMCLI`, `ISEMON_HOSTNAMECTL`, `ISEMON_IP`,
`ISEMON_HOSTS_FILE`, `ISEMON_RESOLV`, `ISEMON_SYSCTL_IPV6` and
`ISEMON_POWER_CMD` (a file the reboot or power-off is written to instead).
The daemon reads the boot time from `ISEMON_BTIME_FILE` when it is set. See
`test/fixes228_net.py`.
