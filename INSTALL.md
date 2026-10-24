# isemon — installing it

A banning daemon for Cisco ISE. It reads what the two ISE nodes write over
syslog, decides who is trying to break into the VPN, and carries that to a
Mikrotik as an address list.

One Python file and one PHP page. The Python standard library and nothing
else: there is no `pip install` anywhere in this.

---

## The short version

```bash
tar xzf isemon-1.9.4.tar.gz
cd isemon-1.9.4
sudo ./install.sh
```

It asks a handful of questions, installs everything, makes the first account
and prints its password. Then open `https://<the hostname you gave>/`.

To see what it would do without doing it:

```bash
sudo ./install.sh --dry-run
```

---

## What it installs, and where

| What | Where |
|---|---|
| the daemon | `/usr/local/lib/isemon/isemon.py`, linked as `/usr/local/bin/isemon` |
| its settings | `/var/lib/isemon/isemon.db` — saved settings live in the database |
| what it is set up with | `/etc/isemon/config.json` — read, and written only for the database settings (`db_*`); what is saved wins over it |
| everything it records | `/var/lib/isemon/isemon.db` |
| copies of that | `/var/lib/isemon/backups/` — portable, go into any engine |
| the nightly dump | `/var/lib/isemon/dumps/` — the engine's own, goes back into that engine |
| its own log | `/var/log/isemon/isemon.log` |
| the dashboard | `/var/www/isemon/` |
| what PHP will accept there | `/var/www/isemon/.user.ini` — the size of a database put back |
| the service | `/etc/systemd/system/isemon.service` |
| nginx | `/etc/nginx/conf.d/isemon.conf` |
| rotation | `/etc/logrotate.d/isemon` |
| receiving the logs | `/etc/rsyslog.d/00-isemon-permissions.conf`, `/etc/rsyslog.d/10-ise.conf` |
| rsyslog's umask, where it hid the logs | `/etc/systemd/system/rsyslog.service.d/isemon-umask.conf` |
| rotating what arrives | `/etc/logrotate.d/remote-logs`, `/etc/cron.daily/isemon-logs-tidy` |
| where the logs land | `/var/log/remote/` — `root:isemon`, 0750, an ACL for `isemon` on what is in it |
| tuning PostgreSQL here | `/etc/polkit-1/rules.d/49-isemon-database.rules`, and rights given inside PostgreSQL |

It runs as its own user, `isemon`, which can read the ISE logs and write
nothing but its own directory.

---

## Before you start

**One thing matters more than the rest: put your own networks on the
whitelist before the daemon has read anything.** An address on the whitelist
is never banned by anything — not the counting, not a public list, not
somebody pressing *Ban*. Your own offices, your own VPN concentrators and
your monitoring belong there.

```bash
sudo isemon --allow 192.168.0.0/16 --why "the office"
sudo isemon --allow 10.0.0.0/8     --why "everything internal"
```

The installer asks for this too.

**And check the machine's own time zone.** ISE writes the offset that was in
force on every record — `2026-09-25 10:21:25.123 +02:00` — so the ISE logs
are read correctly whatever this machine is set to. The token log and the
eduroam log write `Sep 25 10:21:25` and no zone at all, and a line like that
can only be read in the zone of the machine reading it. A machine left on the
zone its image was built with reads every one of those records hours from
where it belongs, and **nothing looks wrong**: the rows arrive, the counts
count, the page draws, and only the clock on the screen disagrees with the
clock in the log.

```bash
timedatectl                              # what this machine thinks it is
sudo timedatectl set-timezone Europe/Prague
systemctl show isemon -p Environment     # nothing here should set TZ
sudo systemctl restart rsyslog isemon
```

Where the logs genuinely come from a machine in another zone, say so instead
of moving this one: `isemon --set log_zone=Europe/Prague`, or Settings → The
ISE logs. Either way `isemon --check` says whether any log is dated after the
moment it was read, which is the one thing that cannot happen and is how this
is noticed at all.

**And decide how those logs get rotated before they are big.** The daemon does
not run as root, so the one thing that has to be right is the group on the
file logrotate creates after a rotation — get it wrong and the logs go on
arriving, the page goes on drawing yesterday, and nothing says so until
somebody reads `isemon --status`. The whole of it, with the two things
logrotate must not be pointed at, is in
[docs/log-rotation-and-permissions.md](docs/log-rotation-and-permissions.md);
`./install.sh --with-syslog` puts the files in place for you.

---

## Getting the ISE logs onto this machine

isemon does not receive syslog itself. rsyslog is already on the machine,
already runs as root, already handles rotation and restarts, and is better at
all of it. isemon reads the files rsyslog writes.

### On the ISE side

**Administration → System → Logging → Remote Logging Targets → Add**

| | |
|---|---|
| Target Type | UDP Syslog (or TCP) |
| Host / IP | this machine |
| Port | 514 |
| Facility Code | whatever you use |
| Maximum Length | 8192 |

Then **Logging Categories**, and point these two at that target:

* **Failed Attempts** — what the banning is made of
* **Passed Authentications** — so a burst of refusals can be read against
  whether anybody was actually getting in

Do this on **both** nodes of the pair. Which of them is authenticating changes
without warning, and isemon reads both all the time for exactly that reason.

### On this machine

A fresh install does this by itself (since 1.10.201; before, only with
`--with-syslog`). A plain `--upgrade` never touches it, so a machine where
receiving already works stays exactly as it is; on an installed machine that
should have it, run `sudo ./install.sh --upgrade --with-syslog`:

* installs `rsyslog`, `rsyslog-relp` and `rsyslog-openssl` where they are
  missing (the last two are what a receiver over RELP and TLS needs, see
  [docs/freeradius-rsyslog-forwarding.md](docs/freeradius-rsyslog-forwarding.md));
* puts `/etc/rsyslog.d/00-isemon-permissions.conf` in place, so every file
  rsyslog makes is `0640` and every folder `0750`, both in the `isemon` group;
* where rsyslog's own unit has a umask that takes the group's read away
  (`UMask=0066` on the RHEL family turns `0640` into `0600`), loosens it to
  `0027` in `/etc/systemd/system/rsyslog.service.d/isemon-umask.conf`;
* makes `/var/log/remote` `root:isemon 0750` (an existing one gets the group
  only where it was `root`'s) and puts an ACL for `isemon` on everything
  already in it - nothing loses a right it had;
* adds the ISE receiver, `/etc/rsyslog.d/10-ise.conf` (UDP and TCP 514);
* rotates what arrives: `/etc/logrotate.d/remote-logs` (daily, thirty kept,
  `create 0640 root isemon`) and, with it, `/etc/cron.daily/isemon-logs-tidy`
  (which deletes what is older than thirty days, so it is never added beside
  a rotation of the machine's own).

Nothing of the machine's own is replaced. A file already there is left alone;
no receiver is added where rsyslog already listens (in any file) or something
else holds port 514; no rotation is added where another logrotate file already
names `/var/log/remote`, because logrotate then refuses both. rsyslog is
checked with `rsyslogd -N1` before it is restarted, and what was added is taken
out again if it would not start. Where syslog-ng receives the logs, rsyslog is
left alone and the installer prints what to write in syslog-ng instead.

Port 514 is opened in firewalld to the senders given with `--log-from
ISE1,ISE2`; a fresh install without it opens it to anybody (and says so), an
upgrade never does. `--no-syslog` leaves all of this out of a fresh install.

By hand, copy `deploy/rsyslog-ise.conf` to `/etc/rsyslog.d/10-ise.conf` and
restart rsyslog. Either way the files end up as:

```
/var/log/remote/ise1/CISE_Failed_Attempts.log
/var/log/remote/ise1/CISE_Passed_Authentications.log
/var/log/remote/ise2/CISE_Failed_Attempts.log
/var/log/remote/ise2/CISE_Passed_Authentications.log
```

which is what `ise_paths` in the settings points at.

If the folders were already there before isemon was installed, the installer
puts an ACL on them so the daemon may read them without owning them:

```bash
setfacl -R -m  u:isemon:rX /var/log/remote
setfacl -R -d -m u:isemon:r /var/log/remote
```

A folder that does not exist yet is not a problem: the daemon waits for it and
starts reading the moment it appears.

### The one-time password logs

Optional, and off unless you switch it on: *Settings → The OTP logs*. On a
site that asks for a token as well as a password, the token server's log is
the other half of a VPN sign-in and it is in no ISE log anywhere.

The folders it reads are the two in the setting — `/var/log/remote/otp` and
`/var/log/remote/otpsec` by default, one per token server. If the servers
send their logs here over syslog, `deploy/rsyslog-otp.conf` is the matching
rule; copy it to `/etc/rsyslog.d/11-otp.conf` and restart rsyslog.

**isemon does not run as root**, so those files have to be readable by the
`isemon` user, exactly as the ISE ones are. A folder made before any of this
existed is usually `0700 root:root`, and the daemon then says so against that
file on the front page and in `isemon --status`:

```
/var/log/remote/otp/totp.cgi.log   this daemon runs as isemon and may not read that file
```

which is one command per folder:

```bash
sudo chgrp -R isemon /var/log/remote/otp /var/log/remote/otpsec
sudo chmod 750       /var/log/remote/otp /var/log/remote/otpsec
sudo chmod 640       /var/log/remote/otp/*.log /var/log/remote/otpsec/*.log
```

Then make whatever writes them create them that way from now on — the
rsyslog rule above does, and for logrotate it is `create 0640 root isemon`.
An ACL does the same without changing who owns anything:

```bash
sudo setfacl -R -m  u:isemon:rX /var/log/remote/otp
sudo setfacl -R -d -m u:isemon:r /var/log/remote/otp
```

Nothing in these logs is ever judged: the address in such a record is the
machine that asked the token server, which is the token server itself.

### The eduroam logs

Optional as well, and off unless you switch it on: *Settings → The eduroam
logs*. The visitors' network is not ISE at all — it is a FreeRADIUS of the
site's own — and none of what it does appears in any ISE log.

One folder per eduroam server, `/var/log/remote/edurad1` by default, and
**two files are read out of each**:

```
/var/log/remote/edurad1/radius.log         who got in and who did not
/var/log/remote/edurad1/detail-20260924    what each session turned out to be
```

The first is where the rows come from. The second is the accounting, and it
is where the access point, the network, the VLAN, the address the machine was
given and the name the machine calls itself actually are; the two are joined
by the machine's MAC. FreeRADIUS starts a new accounting file every day and
names it for the day, so what the setting holds is the beginning of the name —
`detail-` — and the newest one is followed. Leave that setting empty to read
no accounting at all; the rows then say who signed in without saying where
from.

Both files are usually `0600 root:root` in a folder that is `0710 root:root`,
which is stricter than the ISE and token folders and means **isemon cannot
read either of them** until you say so:

```bash
sudo chgrp -R isemon /var/log/remote/edurad1
sudo chmod 750       /var/log/remote/edurad1
sudo find /var/log/remote/edurad1 -type f -exec chmod 640 {} +
```

`chmod 640 *.log` is not enough here: the accounting file is not called
`.log`. Then make whatever writes them create them that way from now on — for
FreeRADIUS's own detail writer that is `permissions = 0640` and
`group = isemon` in the `detail` module, and for logrotate
`create 0640 root isemon`.

Last, **the account the controller tests with**. Every wireless controller
signs in as somebody who does not exist every few seconds to see whether its
RADIUS server is alive, for ever; on the log this was written against that was
two thirds of every line. Put that account's name in *Accounts to leave out
altogether* and nothing it does is written down anywhere.

Nothing in these logs is ever judged either: the only address on one of these
lines is the wireless controller the request came through.

**Getting them here in the first place** — shipping a FreeRADIUS server's logs
to this machine over syslog, with RELP and TLS, without touching the RADIUS
configuration — is written up in
[docs/freeradius-rsyslog-forwarding.md](docs/freeradius-rsyslog-forwarding.md),
including the file permissions on the receiving end.

### The Windows domain controllers' Security logs

Optional, and off unless you switch it on: *Settings → The domain
controllers*. This is what the domain itself saw, and it is half of what a VPN
refusal means — whether the account was locked, which machine the bad password
came from, which program had the old one saved. None of it is in any ISE log.

One folder per controller, the way rsyslog files them, and one file in each:

```
/var/log/remote/dc01/WinSecurity.log
/var/log/remote/dc02/WinSecurity.log
/var/log/remote/dc03/WinSecurity.log
```

**All of them are read**, into one timeline, for the reason both ISE nodes
are: any controller may answer any request and which one did is not something
anybody can predict. The file name comes from the syslog tag NXLog was given —
`WinSecurity` becomes `WinSecurity.log`.

**Getting them here in the first place** is
[docs/windows-security-log.md](docs/windows-security-log.md), with the working
NXLog configuration beside it in `docs/nxlog.conf`.

Two settings are worth a moment. **The zone**: a Windows event carries no zone
of its own once syslog has been through it, so it is read in this machine's
zone unless you say otherwise. **Accounts to leave out**: a domain controller
talks to every machine in the domain all day. Machine accounts — the ones
ending in `$` — are counted apart rather than hidden, and there is a tick box
on the page for them; this setting is for the service accounts that never stop.

The events are kept for **30 days** by default rather than for the year the
sign-ins are, because there are thousands of them an hour and most are one
machine renewing a ticket. Set it to **0** to keep them all and delete
nothing, for a site that wants a year of the domain in here to answer "when
did this start"; the database then grows for as long as the logs keep
arriving, and *Settings → The database* says how big it has got.

**The controllers themselves** is worth filling in, or worth leaving empty on
purpose. The three rights behind "an account asked to replicate the directory"
are how every password in a domain is read at once: an alarm from a member
server, and simply what two controllers do all day. So a replication by one of
the controllers — or by whatever a site has told this is meant to read the
directory whole, which is Entra Connect's `MSOL_` account out of the box —
is marked as expected and is not counted as an incident. Nothing is hidden by
it: the events are read, kept and searchable exactly as before.

**A domain that rebuilds its desktops every day** — Horizon instant clones
and their like — has a switch of its own, *This domain runs non-persistent
desktops*. Off by default. On, the shape of a desktop being rebuilt (a
MACHINE account acting on a COMPUTER account or on a machine's own connection
point) stops filling the cards. A person doing any of it, a machine account
writing a user or a group, and the audit log being cleared are drawn exactly
as before, and every event is read, kept and searchable either way.

Left empty, the list is worked out rather than asked for: the controllers
these logs come from, the directory servers this signs in against, and the
machines the domain itself says are its controllers, which each connected
directory is asked once a day. Read only, like everything else here. Fill it
in to say so exactly — `DC01`, `DC01$` and `dc01.example.com` are all one
machine. Change it later and the events already stored are read again by the
new answer rather than keeping the old one.

**Nothing read here is ever judged and nothing here can earn anybody a ban.**
A VPN sign-in checked against Active Directory is one attempt; the ISE record
and the domain's own event are two views of it. They live in a table of their
own, are never a row in the refusals or the sign-ins, and the chart on the
front page does not know they exist. What they get is a **Domain** page of
their own, which appears when the setting is on and is not drawn at all when
it is off.

### A second directory

*Settings → A second directory*, and off unless you switch it on. It is for
the site whose administrators sign in against one domain while the people in
its ISE logs live in another: when a name is not in the first directory, this
one is asked.

It is **only ever asked who somebody is**. Nobody signs in against it, no role
comes from its groups, no account is made from it, and — like the first — it
is only ever read. The reading account it uses needs nothing beyond the right
to read.

*Check it…* reaches it, signs in as that account and reads its base, and says
which step failed if one does. *Look a name up…* asks both directories about
one name, in order, and shows which of them answered.

---

## The firewall

isemon touches **one address list** on the Mikrotik, and only the entries it
put there itself — every one of them carries a comment beginning `isemon:`.
Anything you add to the same list by hand has no such comment and is never
moved. No other address list is ever named in any command it sends, and it
never writes a firewall rule: what the list is *for* is a decision that
belongs on the router, in front of somebody who can see the rest of it.

### An account for it

On the router:

```
/user group add name=isemon-group policy=ssh,read,write,test
/user add name=isemon group=isemon-group password=<something long>
```

`write` is needed for the address list; `read` and `ssh` to get in and look.
Nothing else.

### A key instead of a password

Better: the key never leaves this machine and the router holds only its public
half.

**Settings → Reaching the router → Make a key**, then copy the public half it
shows and, on the router:

```
/user ssh-keys import public-key-file=isemon.pub user=isemon
```

Then press **Try reaching it**. It signs in, asks the router its name, and
changes nothing.

### The rule that actually stops anybody

isemon fills the list. Dropping what is on it is one line, and it is yours to
write:

```
/ip firewall filter add chain=input  src-address-list=isemon action=drop \
    comment="isemon: refused VPN brute force"
/ipv6 firewall filter add chain=input src-address-list=isemon action=drop \
    comment="isemon: refused VPN brute force"
```

Put it above whatever accepts the VPN. If the VPN is terminated behind this
router rather than on it, use `chain=forward` instead.

---

### A pair, for high availability

Two Mikrotiks carrying the same lists, so that whichever of them has the
traffic at any moment is already dropping everything the other is. Switch the
second one on under **Settings → Reaching the firewall**, give it its own
address, account and port, and make it a key of its own.

They share the list names and every banning rule — it is one blacklist kept on
two machines, not two blacklists. What they do not share is how they are
reached, because the two halves of a pair are usually on different management
addresses and often have different credentials.

Everything written to the first is written to the second in the same pass. One
of them refusing does not stop the other: the one that answered is written,
the one that did not is reported against itself, and the next pass catches it
up. The **Firewall** page has a line per machine — what each is carrying, how
far behind it is, when it was last written to — and says whether the two agree.
An address counts as banned on the dashboard only when *both* are carrying it,
because one of them holding it and the other not is one of them letting the
traffic through.

```bash
isemon --mikrotik          # what each of them is carrying, and whether they agree
```

### A firewall that fetches the list itself (Cisco FTD, FortiGate)

A firewall this machine does not log in to can fetch the list of banned
addresses from `https://<this server>/banfeed.php` by itself: a Cisco FTD
through its FMC's Security Intelligence, or a FortiGate as an external threat
feed. Switch it on under **Settings → Banning → Publish the ban list for
other firewalls**. That card shows the URL (a click copies it) and who has
been fetching it, and has a step-by-step guide for each kind of firewall.

The firewall fetches over HTTPS, so its address, not a person's, has to be on
the web server's allow list, the `allow` lines in `/etc/nginx/conf.d/isemon.conf`
(or `--allow` to the installer). The FMC is the machine that fetches, not the
FTD. By default the URL asks for nothing else. A key in the URL, or a user name
and a password by HTTP basic authentication, can be asked for under the same
card.

```bash
curl -fsS 'https://isemon.example/banfeed.php?f=ftd'          # what the firewall is given
curl -fsS 'https://isemon.example/banfeed.php?f=ftd&md5=1'    # ...and its MD5, which the FMC asks first
```

---

## The country list (GeoIP)

A **second** address list on the same router, holding whole countries rather
than individual offenders. Nothing of the banning touches it and it touches
nothing of the banning.

1. **Settings → GeoIP → Fetch it now** — about four hundred thousand ranges,
   a minute or two.
2. Switch on `geolist`, give the list a name (not the same as the ban list),
   and tick the countries.
3. **Fill it now.** It shows a progress bar and says what it is doing on the
   router as it goes.

With `geolist_auto` on it is filled again by itself whenever the country
database is refreshed, which is the one moment it is certainly out of date.

What the list is used for is again a rule you write:

```
# only let these countries near the VPN
/ip firewall filter add chain=input dst-port=443 protocol=tcp \
    src-address-list=!isemon-geo action=drop comment="isemon: not from here"
```

A country is never judged by isemon itself. A scanner in Rotterdam looks
exactly like an employee in Rotterdam, so acting on one is a decision, made
once, deliberately, on the router.

---

## Keeping the lists current

Both the public blocklists and the country database are fetched again by
themselves. **Settings → Automatic updates** is where that lives: a switch for
each, how often, and what time of day to do it — the country database is about
a hundred megabytes, and doing that in the middle of the working day over
somebody's line is a choice worth being able to make differently. The default
is 03:30.

The same page lists everything that is fetched with when it was last fetched,
when it is next due, and whether the last attempt failed. A machine that was
switched off through the chosen hour does not wait another whole day: once
something is a day past due it is fetched whatever the clock says.

A list that is switched off is neither fetched nor asked, and the ranges it
left behind are dropped — a switched-off list that still answers "yes, I know
that address" is the kind of thing nobody ever works out.

---

## Accounts

Two roles and no more.

* **fulladmin** — may change anything: ban, unban, settings, the router,
  accounts.
* **readonly** — may look at every page and change nothing. No ban, no
  setting, not even a fetch.

From the server, which is how to get back in when nobody can:

```bash
isemon --users                                  # who there is
isemon --add-user petr --role fulladmin         # make one (asks for the password)
isemon --passwd petr                            # set or reset one
isemon --set-role petr --role readonly          # change what they may do
isemon --del-user petr                          # remove one
```

The last full administrator cannot be demoted or removed; make another one
first. Changing somebody's password ends every sign-in of that account at
once.

If there is no account at all, the daemon makes one called `admin` on its
first run and writes the password into `/var/lib/isemon/first-login.txt`,
readable by root and by the daemon's own account (0600, `isemon`). Delete that
file once you have changed the password.

---

## Upgrading

```bash
tar xzf isemon-1.9.4.tar.gz
cd isemon-1.9.4
sudo ./install.sh --upgrade
```

It replaces the daemon, the dashboard, the unit and the rotation, and restarts.
Nothing else on the machine is changed: how the logs are received and what
PostgreSQL lets this program do stay as they are. To have those set up on an
installed machine as a fresh install does (see *Getting the ISE logs onto this
machine* and *What it needs*), adding only what is missing, ask by name:

```bash
sudo ./install.sh --upgrade --with-syslog --db-rights
```
The database, the settings, the accounts and who is banned are untouched. Any
column a newer version needs is added to the database in place, so there is no
migration step.

From 1.10.222 an upgrade also installs what the pages may ask of root - two
helpers (`isemon_web.py`, `isemon_upgrade.py`), the release key and four
systemd units (`isemon-web.path`/`.service`, `isemon-upgrade.path`/`.service`).
They change nothing by themselves: nginx and the firewall are touched only
when somebody saves something under *Settings → This server*. And from
1.10.222 on a new version can be put in from the page as well - see
[docs/upgrades.md](docs/upgrades.md).

The one exception is the nginx vhost, which is otherwise the site's own: since
1.10.218 an upgrade puts one rule into it - refusing multipart bodies, against
php2shell (CVE-2026-109618, CVE-2026-109619) - keeping the file it changed
beside it as `isemon.conf.before-php2shell`, and putting it back if nginx will
not read it with the rule (then it says what to add by hand).

### PHP itself: php2shell

The dashboard runs on PHP, and PHP before 8.2.35, 8.3.36, 8.4.27 and 8.5.12
(21 October 2026) can be made to run code by anybody who can reach the web
server. Update it and restart php-fpm:

```bash
sudo dnf update 'php*' && sudo systemctl restart php-fpm      # AlmaLinux/Rocky/RHEL
sudo apt update && sudo apt upgrade && sudo systemctl restart 'php*-fpm'   # Debian/Ubuntu
dnf updateinfo list --cve CVE-2026-109618                     # whether a fix is there
```

A distribution that backported the fix keeps its old version number, so the
dashboard's warning in the header (shown to an administrator while the
version is below those) can stay after a backported update; the installer
and the warning both say the version they see. Until PHP is updated the
dashboard keeps out of the way: nginx refuses multipart bodies, and
`web/.user.ini` switches body parsing and upload progress off in its
directory. A `.user.ini` is applied late in a request, though, so also switch
upload progress off for the whole of PHP:

```bash
printf 'session.upload_progress.enabled = 0\nsession.use_strict_mode = 1\n' \
    | sudo tee /etc/php.d/99-php2shell.ini && sudo systemctl restart php-fpm
```

The whole procedure - checking what is installed, the guards, moving to
another PHP stream, verifying the fixed package and that php-fpm runs it,
and what to look for afterwards - is in [docs/php2shell.md](docs/php2shell.md).

## Moving to another machine, and rebuilding one

Two tools, for two different jobs. Getting them the wrong way round is the
mistake that costs a morning.

**Rebuilding this machine** — the disk died, the server was reinstalled, you
want it back exactly as it was. Use **a copy of the database**. It is one
file and it holds everything: the settings, the accounts, the never-banned
list, who is banned, every record ever read, the whole ban history, the
public lists and the country ranges. Nothing has to be typed in afterwards.

```bash
# on the old machine, or from its backups folder
sudo isemon --backup
# on the new one, after ./install.sh, with the daemon stopped
sudo systemctl stop isemon
sudo isemon --restore /path/to/isemon-20260924-010334.db
sudo systemctl start isemon
```

The dashboard does the same thing without stopping anything: **Settings → the
database**, where every copy has a **Restore** beside it and a file from
elsewhere can be dropped in.

**Moving to another machine**, or keeping a readable record of how this one is
set up — use the **configuration export**, which is JSON a person can read.

```bash
sudo isemon --export /path/to/isemon-config.json            # the plain one
sudo isemon --export /path/to/isemon-config.json --secrets  # the complete one
sudo isemon --import /path/to/isemon-config.json
```

| | plain | complete |
|---|---|---|
| settings | yes | yes |
| accounts, and what they may do | yes | yes |
| their passwords | **no** | yes |
| never banned | yes | yes |
| who is banned now | yes | yes |
| router password, ssh key | **no** | yes |
| directory password, certificate | **no** | yes |
| records, ban history, country ranges | no | no |

The plain one is safe to mail, commit or paste into a ticket. A machine built
from it is correct in every way except that it cannot reach the router or ask
the domain anything until those are set, and nobody can sign in until somebody
sets a password — **the import says exactly which of those are missing**, so
it is not something to be discovered later.

The complete one needs nothing typed in at all. It also holds the private half
of the ssh key that reaches your firewall, so it is written readable only by
its owner and belongs where passwords belong.

Neither carries the records or the country ranges: those are read from the ISE
logs and fetched from the internet, and a new machine gets them by itself.

---

## Copies, and putting one back

A copy of the database is one file, and it holds everything: the records read,
who is banned, the story of every ban, the settings and the accounts. One is
made every night; **Settings → The database** makes one now, and also
downloads one to the machine you are sitting at — which is the one that
matters, because a copy that lives only on the machine it is a copy of is not
a copy.

Putting one back is on the same page, or from the shell:

```bash
sudo isemon --backup                      # a portable copy, into /var/lib/isemon/backups
sudo isemon --dump                        # the engine's own dump, into /var/lib/isemon/dumps
sudo isemon --restore /path/to/file       # put either one back; it reads which it is
sudo systemctl restart isemon
```

Either way the file is read and checked before anything is replaced — it has
to be a database this application wrote, and it has to have an administrator
account in it — and a copy of what is being replaced is made first and kept
with the others. Afterwards the daemon carries on from wherever that copy says
it had read each ISE log to, and writes the router again.

Uploading a copy through the dashboard goes through nginx and PHP, and both
have their own idea of how big a request may be. The install sets them:
`client_max_body_size` in `/etc/nginx/conf.d/isemon.conf`, and
`upload_max_filesize` and `post_max_size` in `/var/www/isemon/.user.ini`. If a
restore is refused for being too big, those are the two places to look; the
page says which one stopped it.

### A full backup, with its keys

The copy above carries everything but the three files kept beside the
database on purpose - `settings.key`, which opens every password and private
key in it, `banfeed.key` and the routers' `known_hosts`. A **full backup**
(1.10.222) carries those too:

```bash
sudo isemon --backup --full          # or Settings -> The database -> Download a full backup
```

Put back on a freshly installed machine (the ordinary restore), that machine
is this one again, certificate and firewall included. It is as secret as the
key itself. See [docs/the-database.md](docs/the-database.md), section 5.2.

## The server: firewall, certificate, upgrades (1.10.222)

Under *Settings → This server*, put in by root through `isemon-web.path` and
`isemon-upgrade.path` - nothing is changed until it is saved there:

- **Firewall and access**: who may reach the dashboard, the published ban list
  and the health check (nginx), and a chain of isemon's own, `ISEMON-IN`, in
  iptables and ip6tables - [docs/firewall-and-access.md](docs/firewall-and-access.md).
- **Certificates and TLS**: upload (PEM, PFX), a request for your CA, or
  self-signed; TLS presets, DH, HSTS - [docs/certificates-and-tls.md](docs/certificates-and-tls.md).
- **Upgrades**: a signed package sent from the page, with a progress bar -
  [docs/upgrades.md](docs/upgrades.md).
- **The health check** for monitoring: `https://<dashboard>/healthz.php` -
  `200 ok`, or `503` and why (`?json=1` for JSON). Who may ask it is set on
  *Firewall and access*.

```bash
isemon --web-status        # what root has in place, and the last upgrade
```

## Removing it

```bash
sudo ./install.sh --uninstall
```

The service, the dashboard and the nginx file go. `/var/lib/isemon` and
`/etc/isemon` are kept, so you can put it back exactly as it was. To remove
those too:

```bash
sudo rm -rf /var/lib/isemon /etc/isemon
sudo userdel isemon
```

---

## When something is wrong

```bash
isemon --check                   # a health check: the daemon, the logs, the database, the accounts
isemon --status                  # everything it is doing, in one screen
journalctl -u isemon -n 50       # why it will not start
tail -f /var/log/isemon/isemon.log
```

**The dashboard says the API token is unreadable.**
The account php-fpm runs as is not in the `isemon-web` group, or SELinux is in
the way. php-fpm is the one that reads it, and on AlmaLinux/Rocky/RHEL it runs
as `apache`, not as `nginx`:

```bash
grep '^user' /etc/php-fpm.d/www.conf              # which account that is
usermod -a -G isemon-web apache && systemctl restart isemon php-fpm
setsebool -P httpd_can_network_connect 1
```

Since 1.10.98 the web server's accounts are in `isemon-web`, a group for the
token alone, and no longer in `isemon`, which is also the group of the
database, its copies and the configuration with the database password in it.
`install.sh --upgrade` moves them across and checks the page can still read
the token before it takes anything away.

**It reads no records at all.**
`isemon --status` lists every file it is watching and says whether it is
there. If a file exists and shows nothing, the daemon cannot read it:

```bash
sudo -u isemon head -1 /var/log/remote/ise1/CISE_Failed_Attempts.log
```

**A file says "this daemon runs as isemon and may not read that file".**
It is not running as root and the folder is `0700 root:root` — usually one
made by hand, or by an older syslog rule. `isemon --status` prints the
command for each folder it cannot read; it is:

```bash
sudo chgrp -R isemon /var/log/remote/otp
sudo chmod 750       /var/log/remote/otp
sudo chmod 640       /var/log/remote/otp/*.log
```

and then whatever writes those files should create them that way from now on:
`fileCreateMode="0640" fileGroup="isemon"` in the rsyslog action, `create 0640
root isemon` in logrotate.

**The times on the page do not match the times in the log.**
Almost always the machine's own zone. ISE records carry their own offset and
cannot be wrong this way; the token log and the eduroam log carry no zone at
all, so they are read in this machine's. `isemon --check` says so outright —
*totp.cgi.log is dated 5 h 59 min ahead of this machine's clock* — and names
the offset those lines look like they are really written at.

```bash
timedatectl                                  # is this machine where it thinks it is?
sudo timedatectl set-timezone Europe/Prague
sudo systemctl restart isemon
# or, where the logs really do come from elsewhere:
isemon --set log_zone=Europe/Prague
```

The records already written keep the times they were written with. To put
those right as well, erase that log's records — which also forgets where the
file was read up to, so what is still in it is read again with the clock as
it now is:

```bash
isemon --erase otp        # or: isemon --erase eduroam
```

Nothing in either of those logs is ever judged, so nothing there can let
anybody in or keep anybody out.

**It reads records but bans nobody.**
Check `watch_devices` against what the logs actually say. Every failed attempt
on the *Failed attempts* page shows its device; the setting must name one of
them, or nothing can ever earn a ban.

```bash
isemon --failed --limit 5
```

Also check `judge_max_age_h`: a first run reading months of backlog only
judges what is recent, on purpose.

**The router will not take the list.**
Settings → Reaching the router → **Try reaching it** says what ssh said,
whole. Usually: the public half of the key is not on the router yet, or the
account has no `ssh` policy.

**Everything is banned, including us.**

```bash
isemon --unban all
isemon --allow 192.168.0.0/16 --why "the office"
```

and then look at `watch_devices` and `block_tries`.

---

## What it needs

* AlmaLinux 9, RHEL 9, Rocky 9 or anything close. Debian and Ubuntu work.
* Python 3.8 or newer — the standard library, nothing else.
* `openssh-clients`, for the router.
* `acl`, for reading the ISE logs without owning them.
* nginx and php-fpm, for the dashboard. `--no-web` leaves them out and the
  command line does everything.
* **No database server.** Everything is kept in one file on this machine,
  and that file is part of Python. It can be kept in MariaDB or PostgreSQL
  instead - `--with-db mariadb`, `--with-db postgres` or `--with-db both`
  puts the driver in place, and Settings -> The database does the rest,
  including making the database and the account on the server. The file is
  the faster of the two; a server is for when the data has to live with
  everything else rather than on this machine. See
  [docs/the-database.md](docs/the-database.md), and
  [docs/mariadb-on-almalinux9.md](docs/mariadb-on-almalinux9.md) or
  [docs/postgresql-on-almalinux9.md](docs/postgresql-on-almalinux9.md) for
  standing one up on AlmaLinux 9 from nothing and moving into it.
  Where PostgreSQL runs on this same machine, the installer lets the
  `isemon` account restart it - restart it and nothing else, through a
  polkit rule - so that the dashboard can finish tuning it for the machine
  (`shared_buffers` takes effect only at a start). `--no-db-restart` leaves
  that out; the dashboard then shows the command instead. polkit is
  installed for it where it is missing (a fresh install, or `--db-rights`).

  Changing the settings needed an administrator of PostgreSQL typed into the
  popup every time. Since 1.10.201 a fresh install (or `--db-rights`), as
  root, signs in as
  `postgres` over the server's own socket - no password asked, kept or
  written anywhere - and gives the account in `/etc/isemon/config.json` the
  right to change the settings the popup tunes and no others (`GRANT ALTER
  SYSTEM ON PARAMETER ...`, PostgreSQL 15 and newer), to reload the server,
  and to read the settings (`pg_read_all_settings`). Making the database from
  Settings -> The database does the same. A server moved to after the install:

  ```bash
  sudo ./install.sh --db-rights      # from the unpacked folder; only this
  ```

  On PostgreSQL 14 and older, or a server on another machine, the popup asks
  for an administrator as before. MariaDB has no right as narrow as this, so
  it asks too.

About 60 MB of memory, and a few percent of one core on a VPN taking a
thousand failed logins an hour.

### Turning addresses back into names

Switched on under *Settings -> Names of addresses*, this asks a name server
of your own for the name behind each address it sees - `nb-novak.example.loc`
beside `10.20.30.40`, and machines findable in the box at the top by the
name people call them. It needs:

* **UDP and TCP 53 out to the servers you name**, and nothing else. It never
  uses this machine's own resolver: a site keeps more than one reverse zone
  and they are not all on the same server, so the servers are named on that
  page and asked in the order written.
* nothing on the servers themselves. It asks, and only asks.

Off unless somebody switches it on, and off not one packet is sent. On, no
page and no log read ever waits for it: the asking happens on threads of its
own and a name server that has gone away leaves a name blank.

### Saying who made the machine behind a MAC

On by default, and worth nothing until it has been fetched. It needs
**outbound HTTPS to `standards-oui.ieee.org`**, where the IEEE publish the
three registers of MAC assignments; they are fetched on the same schedule as
the country database, under *Settings -> Automatic updates*, and answered
out of a table here afterwards. A machine with no way out simply has no
makers to show, and nothing else behaves differently.
