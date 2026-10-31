# isemon

A banning daemon for Cisco ISE.

Two ISE nodes in an HA pair write their logs to a server over syslog. isemon
reads both — always both, because which of them is doing the authenticating
changes without warning — works out who is trying to get into the VPN and
cannot, and carries that to a Mikrotik as an address list.

The same nodes usually answer for a good deal more than the VPN: 802.1X on
the LAN and on the wireless, MAB, and TACACS+ on the switches. All of it is
read and shown, each behind its own tab, and none of it is ever judged.
Banning is for the VPN alone. A token server, where a site has one, is read
the same way and shown beside them, and so is the RADIUS server behind a
site's eduroam, which is not ISE at all.

One Python file, one PHP page, the standard library and nothing else.

```
    isemon --status              what it is doing, in one screen
    isemon --failed              the failed attempts, newest first
    isemon --blocked             who is banned, and until when
    isemon --ban 45.9.148.9      ban one by hand
    isemon --allow 10.0.0.0/8    ...and one that may never be banned
    isemon --mikrotik            what the router is actually carrying
    isemon --ios-acl             the permanent bans as a Cisco IOS access list
```

Installing it: see [INSTALL.md](INSTALL.md). Rotating the logs that arrive
here, and keeping them readable by a daemon that is not root: see
[docs/log-rotation-and-permissions.md](docs/log-rotation-and-permissions.md).
Getting a FreeRADIUS server's logs here over syslog in the first place: see
[docs/freeradius-rsyslog-forwarding.md](docs/freeradius-rsyslog-forwarding.md).
Getting the RADIUS detail log from a token server here, so that a token
attempt says whose address it really was rather than the token server's own:
see [docs/otp-radius-detail.md](docs/otp-radius-detail.md), with the files to
do it with in `docs/otp-radius-detail/`.
Getting a Windows domain controller's Security log here as well, so that a
VPN refusal can be read beside what the domain saw: see
[docs/windows-security-log.md](docs/windows-security-log.md), with the NXLog
configuration itself in `docs/nxlog.conf`.
Reading a TACACS+ daemon of your own beside ISE's — who signed in to which
switch, from where, and every command they ran: the procedure step by step in
[docs/tacplus-setup.md](docs/tacplus-setup.md), with the rsyslog files for
both machines in `deploy/tacplus/`, and why it works the way it does in
[docs/tacplus-logs.md](docs/tacplus-logs.md).
Reading a Windows NPS server — RADIUS that is not ISE — beside ISE: what to
log on the NPS server, how to get the files here and what appears once they
are read: see [docs/nps-logs.md](docs/nps-logs.md) - and for eduroam answered by NPS
rather than FreeRADIUS, [docs/eduroam-nps.md](docs/eduroam-nps.md) - with the NXLog
configuration for the NPS servers in `docs/nxlog-nps.conf` and the rsyslog
rule for this side in `deploy/nps/`.
Keeping everything in MariaDB or PostgreSQL rather than in the file on this
machine: see [docs/the-database.md](docs/the-database.md), and, for standing
one of those up on AlmaLinux 9 from nothing and moving into it,
[docs/mariadb-on-almalinux9.md](docs/mariadb-on-almalinux9.md) or
[docs/postgresql-on-almalinux9.md](docs/postgresql-on-almalinux9.md).
Making a PostgreSQL quick enough for a domain writing millions of events a
day — what to measure, what to set, and what the daemon already does about it
itself: see [docs/postgresql-tuning.md](docs/postgresql-tuning.md).
When `isemon --status` says *NOT keeping up* on a busy firewall: is it a
backlog or a limit, and what to change on the database to write faster — see
[docs/postgresql-write-speed.md](docs/postgresql-write-speed.md).
Running out of disk on a VMware machine: growing the root filesystem after
the disk was enlarged (AlmaLinux 9, ext4 without LVM, swap moved out of the
way) is [docs/growing-the-root-disk-almalinux9.md](docs/growing-the-root-disk-almalinux9.md).
A Cisco FTD or ASA on the Traffic tab, a failover pair as one firewall and
read beside ISE: [docs/ftd-logs.md](docs/ftd-logs.md). A MikroTik's own log
(RouterOS) on the Traffic tab: [docs/mikrotik-logs.md](docs/mikrotik-logs.md).
A FreeRADIUS server of your own - MAB, 802.1X on the LAN and on Wi-Fi, the VPN,
and bans from its VPN refusals: [docs/freeradius-logs.md](docs/freeradius-logs.md).
Rotating a domain controller's log apart from everything else, at a couple of
gigabytes a day: the two logrotate files to do it with are in
`deploy/logrotate-split-dc/`.

---

## What it does

### It reads both nodes as one timeline

ISE writes each record over syslog as several lines, cut wherever the length
limit falls — often through the middle of a field. isemon gathers the lines
back into records by their sequence number, and orders what comes out by the
record's own timestamp rather than by when it arrived.

That last part is the whole reason both paths are read. A pair that changes
over halfway through an attack puts two attempts on one node and three on the
other; counted per node that is two and three and earns nothing, and counted
as one timeline it is five and earns a ban. The same record read twice — both
paths holding it, a file replayed, a restart re-reading the tail — lands on
the same row, because ISE's own `AcsSessionID` is what identifies it.

### It decides who may not come back

Two ways in.

An address a **public blocklist** already names is banned the first time it
fails a login here at all. It is on somebody else's list of known-bad **and**
it has now knocked on this door, which is two things rather than one. Nothing
is banned for being on a list alone.

Everything else is **counted**: so many failed logins inside so many minutes.
The first time earns ten minutes, then an hour, then a day, then for good —
the ladder, and it is written out in the settings as `10, 60, 1440, forever`
so it can be read. An address that behaves for a month starts at the bottom
again, because counting for ever is how somebody who was a nuisance in March
ends up banned in September for nothing.

Only failures from the devices named in `watch_devices` can earn a ban. That
setting is what keeps a mistyped switch password from banning an
administrator's desk. Everything is recorded whatever device it came from;
the setting is only about banning.

### Nothing overrules the whitelist

An address or a range on the whitelist is never banned. Not by the counting,
not by a public list, not by somebody pressing *Ban*, and nothing of it is
ever sent to the router. Adding one lets go of anything already banned inside
it at the same moment: a list that says "never" beside a rule on the router
that says otherwise is a pair nobody can read.

### It folds a street into one line

Attacks arrive from whole streets — this VPN saw thirty-two tries each from a
dozen addresses in one /24. Folding turns those into one subnet: one line on
the page and one rule on the router instead of a dozen. A subnet is only made
where two or more banned addresses fall inside it, and never where it would
swallow something on the whitelist. Everything kept about each address stays
under its own name, and any folding can be undone on its own afterwards.

### It carries it to the router, carefully

Only **one** address list is ever touched, and only the entries carrying this
daemon's own comment. An address somebody added to the same list by hand has
no such comment and stays. Every other address list on the router is never
named in any command it sends. It never writes, changes or removes a firewall
rule: what the list is *for* is one line you write on the router yourself.

There is a button that takes everything of ours back off the router, and it
is as careful as the sync: ours goes, nothing else moves, and one sync
afterwards puts it all back.

### It knows where everybody is, and judges nobody for it

A free monthly country database gives every address on every page its flag.
isemon never decides anything from it: a scanner in Rotterdam looks exactly
like an employee in Rotterdam.

What it will do is keep a **second** address list on the router holding whole
countries, refilled by itself whenever the database is refreshed. Tens of
thousands of prefixes, sent in batches rather than one ssh call each, with a
progress bar that says what it is doing on the router as it goes. What that
list is used for is, again, a rule you write.

### It says who made the machine behind a MAC

The IEEE publish which company every MAC assignment belongs to. With them
fetched — on the same schedule as the country database — pointing at any MAC
on any page says <b>Apple</b>, <b>VMware</b>, <b>Zebra</b>: a page of MAB
refusals becomes a page of printers, phones and laptops. All three registers
are read, so a maker given a 28- or 36-bit slice of somebody else's block is
named as the maker rather than as whoever administers the block.

### It turns the addresses back into machines

Switched on, every address on these pages carries the name its reverse zone
gives it - `nb-novak.example.loc` over `10.20.30.40` - and a machine can be
found in the box at the top by the name people call it rather than by an
address nobody remembers. The name servers to ask are yours, listed in the
order to ask them, because a site keeps its offices in one set of servers
and its DMZ in another; the first one that hands over a name is the answer.

Nothing waits for any of it, an answer is kept with the time it was given -
a DHCP lease moves, so a record from March is shown the name its address had
in March - and off, not one packet is sent.

---

## The dashboard

Nobody sees anything without signing in. Three roles: **fulladmin** may change
anything; **banadmin** may look at every page, ban an address, let one back in
and put the lists on the firewall, and nothing else; **readonly** may look at
every page and change nothing — no ban, no setting, not even a fetch. The role
is read from the account on every request, so moving somebody to readonly
takes effect at once rather than when they next sign in.

* **Overview** — the shape of the day: what is failing, who is trying
  hardest, which names they are trying, where they are coming from.
* **Banned** — who may not reach the VPN, why, for how long, and whether the
  router is carrying it. Each address carries its marks: 🤖 the counting
  decided, ✋ somebody did, 📕 a public list already knew it, 🧩 it is a
  folded subnet, 🛡️ the router has it, ⚠️ the router does not.
* **Failed attempts** — every refusal, with the reason ISE gave. Click a row
  for the whole record: every field, exactly as ISE wrote it, with the ten
  that usually matter pulled out on top.
* **Logins** — everybody who did get in, in two lists. **AnyConnect logins**
  are the VPN, with the authorisation profile, the directory groups and the
  firewall each session was handed; **TACACS logins** are the switches and
  routers, saying for each row whether somebody signed in or was allowed to
  run something. ISE writes the downloadable ACL as a record of its own,
  whose user is called `#ACSACL#-IP-AnyConnect_OLYMPUS-6913329c`. It is not a
  login and it is not listed as one: it is tied to the login it was handed
  down for, by the session both of them carry, and shown inside that login's
  record as what it is — permits and denies in order, the remarks as headings
  over the rules they were written for, each address and port in its own
  column, rather than the one long line the log writes it on.
* **Router** — what the Mikrotik is actually carrying, beside what is known
  here, and what each half has that the other does not.
* **Settings** — the ISE logs, banning, the whitelist, the public lists,
  automatic updates, folding, the router, GeoIP, accounts and the database,
  one at a time down a rail at the left edge. The rail is a column of icons
  that slides open when you point at it and shuts again, or stays open when
  you press the pin — and nothing inside it moves as it opens, so the icon
  under the pointer is still the one that gets clicked.

Every setting is named in words, with its long explanation, the name it has on
the command line and which of the three layers its value is standing on —
saved here, from `config.json`, or the built-in default — behind the small
**i** beside it. Saved settings go into the database, so they are carried by
every backup and survive a reinstall; `config.json` is still read and still
means what it says, and anything saved wins over it. Put a setting back to
exactly what the file says and it stops being saved at all.

Every table can be laid out by whoever is looking. Press your name at the top
right and switch on *Edit the columns*; then drag the edge of a column's
heading to size it and the heading itself to move the column. The layout is
kept with that person's account and comes back wherever they sign in; the
same popup puts it back as it comes, and a full admin can do the same for
anybody under *Settings → Accounts*. The switch lasts for one sign-in.

The ladder is built rather than typed: a ready-made one for the usual four
shapes, or a step at a time, each length picked from a list, with "for good"
ending it.

Anything on any page that
carries more than a label's worth of meaning says so in the same panel when
the pointer rests on it — what a mark on a banned address means, what a
button is about to do to the router, why a list says it has never been
fetched.

Everything the page needs comes from the daemon, including the list of
settings: a setting added to the daemon appears on the page by itself. The
page loads nothing from anywhere — no CDN, no font, no analytics — so it works
on a machine with no way out to the internet.

---

## Everything from the command line

The dashboard is a convenience. The moment it is most needed is the moment
nobody can sign in, so the accounts and the passwords are handled by talking
to the database directly and never through the API:

```
isemon --status              what it is doing
isemon --failed --limit 50   the failed attempts
isemon --passed              the successful logins
isemon --blocked             who is banned
isemon --address 45.9.148.9  everything known about one address
isemon --ban ADDR --forever  ban one by hand
isemon --unban ADDR          let one back in ("all" for everybody)
isemon --whitelist           what may never be banned
isemon --allow ADDR          add one to that list
isemon --unallow ADDR        take one off it
isemon --mikrotik            what the router is carrying
isemon --mikrotik --sync     write the list to it now
isemon --mikrotik --purge    take ours off it, and nothing else
isemon --geo-sync            fill the country list on the router
isemon --fw-test [1|2]       reach a firewall (Mikrotik, OPNsense, pfSense) and say what it answered
isemon --fw-key [show|generate|forget] [--fw 2] [--fw-kind KIND]
                             a firewall's ssh key, of the kind in use or of another
isemon --banfeed             the published ban list: its URLs and who fetched it
isemon --banfeed opnsense    what that kind of firewall is given (any format)
isemon --banfeed newkey      a new key in the URL
isemon --fetch feeds|geo     fetch the public lists, or the country database
isemon --settings            every setting, as it stands
isemon --set block_tries=8   change one
isemon --users               who may open the dashboard
isemon --add-user NAME --role fulladmin
isemon --passwd NAME         set or reset a password
isemon --backup              a copy of the database, now
isemon --dump                a dump of it in the engine's own format, now
isemon --rescan              go back over every log and apply what it earns
isemon --rescan --days 7     ...only as far back as a week
isemon --erase               what collected data can be erased
isemon --erase geo --yes     ...erase one of them
isemon --disable-user NAME   stop an account signing in, keeping everything
isemon --enable-user NAME    let it sign in again
isemon --events              what it has been doing
isemon --rollup              what is counted / worked out ahead: the Domain page
                             and the Traffic overview, how old and how long
isemon --rollup-build        count it all again now (or just `domain` / `traffic`)
isemon --check               a health check
isemon --web-status          what root has in place: nginx, TLS, the firewall, upgrades
isemon --backup --full       a full backup: the copy with its keys in it
isemon --php-notice hide     hide the dashboard's PHP version notice until the
                             daemon starts again (`show` brings it back)
isemon --help                all of it
```

Every one of these writes in colour on a terminal and in plain text anywhere
else, so `isemon --blocked | grep` and `isemon --check > report.txt` give you
what you expect. Colour is off when the output is not a terminal, when
`--no-color` is given, and when `NO_COLOR` is set in the environment;
`FORCE_COLOR=1` turns it on for something that is not a terminal but
understands the codes anyway. With no colour, the lines that were green or red
carry `[ ok ]` and `[fail]` instead, so a captured run still says which was
which.

[colorama](https://pypi.org/project/colorama/) is used when it is installed —
the installer offers it — and nothing needs it: without it isemon writes the
same escape sequences itself, which is all colorama does on a Linux terminal.
What it adds is a Windows console that understands them and a terminal that is
reset whatever way the program ends.

`--json` is never coloured, on any terminal, because the answer is for
something that is not a person.

---

## How it is put together

```
isemon.py            the daemon: reading, deciding, the router, the API, the command line
web/index.php        the dashboard — markup, style and script in one file
web/isemon-api.php   the page's side of the daemon API
deploy/              systemd, nginx, logrotate, rsyslog, an example config
test/                what to run before believing any of it
install.sh           all of the above, put in the right places
```

The daemon holds everything in one database - a SQLite file on this machine
unless somebody moves it into MariaDB or PostgreSQL - and answers a JSON API on
localhost. The page has no database, no shell and no router credentials: it
asks the daemon, and the daemon decides whether whoever is signed in may have
it. The browser never holds the API token — it is in a cookie the page cannot
read, and the token itself never leaves the server.

## Running the tests

```
./test/checks.py      the engine: parsing, the ladder, folding, accounts, settings
./test/endpoints.py   the API: every endpoint, as an admin and as a readonly account
./test/router.py      the whole router half, against a Mikrotik that is not there
./test/rotation.py    every way logrotate moves an ISE log, and nothing lost or doubled
./test/directory.py   signing in against Active Directory, against one that is not there
./test/ranges.py      is this address on one of the lists, asked the fast way and the slow one
./test/carry.py       export here, import onto a machine that has never been run
./test/doors.py       one ISE, several doors, and only one of them ever judged
./test/engines.py     the file, MariaDB and PostgreSQL: the same installation in each
./test/names.py       turning an address back into the machine it is, against a mock DNS
./test/domain.py      the Windows domain controllers' Security logs, as they really arrive
./test/tacplus.py     a tac_plus of the site's own: sittings, commands and refusals
./test/nps.py         a Windows NPS server's log: requests joined to answers, doors, probes
./test/columns.py     tables laid out by hand: kept per account, capped, put back
./test/windows.py     a time window by its dates: the first record, from and to, until now
./test/replay.py DIR  real ISE logs through the real reader, and what it made of them
```

`test/mockdns.py` answers the way a name server does, including the ways that
are not answers: quiet, refused, "no such name", and a reply cut short.

`test/mockrouter.py` stands in for ssh and answers the way RouterOS does. It
exists because a Mikrotik is the one part of this that cannot be stood up in a
test, and it is also the part where a mistake is a firewall that stops
working.

---

## Version

1.10.252

- **isemon on the newest Python there is**: an upgrade (from the pages too)
  and a fresh install put in the newest Python the distribution offers beside
  its own - python3.14, 3.13, 3.12 or 3.11 on AlmaLinux / RHEL 9 (AppStream)
  - and run isemon on it, when it imports what isemon needs (ssl, sqlite3, and
  the database's driver: python3.X-PyMySQL or -psycopg2 put in for it) and
  `isemon.py --version` runs on it; else the next older, else the one it ran
  on. **The system's python3 (3.9, dnf's own) is never changed.** What is
  chosen is `/usr/local/lib/isemon/python`, a link the three units
  (isemon, isemon-web, isemon-upgrade) and the `isemon` command
  (`/usr/local/bin/isemon`, now a small script) run through; when isemon does
  not start on the new one, the link goes back to the one before and isemon
  is started again. `--no-python-update` keeps the Python it runs on; Debian
  and Ubuntu run on their own python3.

1.10.251

- **Settings - Automatic certificates** (ACME, off until switched on, for a
  full administrator): the dashboard's certificate ordered from Let's Encrypt,
  its staging or a CA of your own (step-ca, an internal ACME CA) and renewed
  by itself when fewer than 30 days are left - a short-lived certificate at a
  third of its life. It goes into Certificates and TLS exactly as an uploaded
  one does; its TLS settings stay as they are. See
  `docs/automatic-certificates.md`.
- The CA checks the name by **HTTP-01** - root's helper puts
  `/.well-known/acme-challenge/` into nginx's port-80 server for everybody
  (whoever else the pages are for), handed to the new `acme.php`, and
  isemon's own firewall lets tcp 80 in by itself (its own card, *Automatic
  certificates (HTTP-01)*) - or by **DNS-01**: RFC 2136 (nsupdate, the TSIG
  key in a 0600 file for the moment it runs, never on its command line),
  Cloudflare, acme-dns, deSEC (its own name servers asked until both have the
  record, then a minute more) or by hand (the record shown, the order waiting
  up to an hour for *It is in DNS*). *DNS servers for ACME*; the card *In your
  DNS* with *Check DNS*; *Try port 80*.
- Who renews it: switching ACME on takes over a dashboard with no certificate
  of isemon's or a self-signed one; one uploaded or answered to a request is
  kept until *Look after it* or *Order it now*. Putting one in by hand on
  Certificates and TLS takes it out of ACME's care (asked first). The one ACME
  replaced is kept: *Back to the one before…*.
- An account the CA no longer knows is made anew by itself and the request
  asked again; what is being waited for is said as it goes; each order's
  steps are kept on the card; every order is an event. The account key, the
  TSIG secret and the tokens are kept sealed.
- `isemon --acme`, `isemon --acme-order this` (followed); the console:
  *Network, time and power → Automatic certificates (ACME)*.

1.10.250

- **PHP to the release with the php2shell fix, by the installer**: an upgrade
  (from the pages too) and a fresh install with the pages move a PHP below
  8.3.36 (8.4.27 / 8.5.12 on those) to PHP 8.3 from the Remi repository -
  EPEL and Remi added, the stream php:remi-8.3, what Remi offers checked to be
  8.3.36 or later before a package is changed, `dnf distro-sync 'php*'` with
  the configuration kept, php-fpm restarted and asked its version. Anything
  that does not work puts the stream and the PHP it was on back, and is said.
  `--no-php-update` leaves PHP as it is; Debian and Ubuntu are told, not
  changed. See [docs/php2shell.md](docs/php2shell.md).

1.10.249

- **Settings - Certificates and TLS - Download** opens a popup of the formats:
  PEM (the certificate and its chain), DER (.cer), PKCS#7 (.p7b), **PFX /
  PKCS#12** (AES-256, SHA-256) and a PFX for older systems (3DES, SHA-1 - what
  Windows Server 2016 and Java 8 open), PEM with the private key, and the key
  alone - with or without the chain. The private key goes out to a full
  administrator only, under a password typed twice (8 characters at least; a
  PFX always has one, a PEM key may be left unencrypted); the password goes
  to openssl by the environment, never on its command line, and is kept
  nowhere, and every export with the key is written to Events with who made
  it. A certificate isemon does not hold the key of (nginx's own, never
  uploaded or made here) is exported without it. Offered for that one too
  now, not only for a certificate isemon looks after.

1.10.248

- *Encrypted receiving (TLS)*: the dot beside the machine's name is green when
  the input is on, rsyslog listens and nothing has gone wrong with TLS since
  rsyslog was started last; yellow only when it does not listen or something
  did go wrong - a node refused, an authority not known, a certificate
  expired. It was yellow for every line rsyslog had written about TLS in the
  last half hour: its own words when it starts, a set-up refused before, a node
  hanging up after otp's *Try it*. Those lines are no longer counted, and the
  ones that are show under *what went wrong with TLS since rsyslog started*
  (`isemon --otp-tls` the same).

1.10.247

- *Encrypted receiving (TLS)* on The OTP logs: **Switch off…** and **Remove…**
  are always on the card - greyed, and saying why, when there is nothing for
  them to do (they were left out then, and looked missing). Remove… is there
  too for whatever a set-up refused half way left in `/etc/pki/rsyslog/otp/`.

1.10.246

- **The otp logs over TLS: rsyslog took no input** where imtcp is loaded by a
  file read after `10-otp-tls.conf` (a `10-remote-logs.conf`, say): rsyslog
  reads its folder in order, and an input of a module not loaded yet is refused
  - "input module name 'imtcp' is unknown" and every TLS parameter "not
  known". The file is `/etc/rsyslog.d/99-otp-tls.conf` now, read after every
  file that loads imtcp; a `10-otp-tls.conf` there before (1.10.245's, or one
  by hand from otp's README - that one kept beside as `.isemon-before`) is
  taken away when it is written. Checked against the real rsyslogd in the
  tests where there is one. Nothing was changed by the refusal: rsyslog was
  asked first and said no.
- **isemon's firewall: The otp logs over TLS**, a card of its own under *What
  isemon lets in by itself*, there once the encrypted input is switched on -
  and the port let in at once, not at the next look (up to ten minutes): from
  anywhere, or only from otp's nodes once their addresses are named on it; it
  can be turned off like the others. Its port is no longer counted among the
  plain logs' ports. The card on The OTP logs says what isemon's firewall does
  with it.
- **Remove…** on *Encrypted receiving (TLS)* (and `isemon --otp-tls-remove`, in
  the console too): the encrypted receiving taken away whole - the input,
  isemon's certificate and key, otp's authority and the one made here, the
  folder `/etc/pki/rsyslog/otp/` with them. *Switch off…* goes on keeping the
  certificate to switch it on again. Either way the plain input on 514 stays.

1.10.245

- **The otp logs over TLS** - *Settings → The OTP logs → Encrypted receiving
  (TLS)*, the isemon side of otp 1.0.172's *Settings → isemon → Encrypted
  sending*. *Set up…* takes isemon's certificate from **the file otp made**
  (`isemon-tls.zip`, every entry AES-256: opened here, in memory - no 7z, no
  copy left; its key goes to root once and is kept only where rsyslog reads
  it), **made here** by an authority of this machine's own (shown to paste into
  otp as *isemon has one from its own CA*; made again, otp trusts it as it is),
  or **pasted** (your own CA or a public one); then the port (6514), mutual TLS
  and the nodes (by name, or any node with a certificate of otp's authority).
  Root's helper writes `/etc/pki/rsyslog/otp/` and its own
  rsyslog file (otp's is read for the port, the mode and the
  nodes, never put in as it is): the TLS files per input, imtcp loaded once,
  the gtls driver (ossl where that is the one there; rsyslog-gnutls installed
  when neither is), `rsyslogd -N1` before the restart and a listening port
  after it - every file put back when either says no. firewalld lets the port
  in; isemon's own firewall lets it in from the log senders by itself. The card
  says whether rsyslog listens, the certificate's names and end, and rsyslog's
  own words about TLS; *Change nodes…*, *Switch off…* (the certificate stays).
  **The plain input on 514 is never touched**: nodes not switched over go on
  sending there, and what arrives either way is filed into the same files.
  `isemon --otp-tls`, `--otp-tls-import`, `--otp-tls-make`, `--otp-tls-set`,
  `--otp-tls-off`, and in `isemon --console`. install.sh adds rsyslog-gnutls
  where rsyslog is and it is not. See
  [docs/otp-logs-over-tls.md](docs/otp-logs-over-tls.md).

1.10.244

- The test of the page's status question follows the page (15 seconds until
  the first answer, then a minute), and the test of `--os-update` waits for
  the look for updates the daemon begins after an update before it asks for
  the next one. Nothing else changed.

1.10.243

- **After an upgrade from the pages, *Load it again* loads a page that draws.**
  It loaded the page in the seconds after the new version had started; the
  page's first question waited on a daemon still starting, and nothing was
  drawn until F5. The button now waits until the new version answers (its
  version, then its status - two minutes at most), and a page whose first
  question has not been answered asks again after 15 seconds, not a minute.

1.10.242

- **System updates and SSH keys of root on the command line and in the
  console**, as on the pages and with the same refusals:
  `isemon --os-updates` (what waits, `--json`), `--os-updates-check` (look
  now, followed), `--os-update [--reboot-after ask|auto]` (asks first unless
  `--yes`, then followed with a bar and what the package manager says;
  Ctrl+C stops the following, not the update), `--os-update-stop` (one
  waiting to begin); `isemon --root-keys` (`--json`), `--root-key-add
  LINE|FILE` (a public line, a .pub, or a private key of which only the public
  half goes in - its passphrase from `--passphrase-file`,
  `ISEMON_KEY_PASSPHRASE` or asked), `--root-key-drop FINGERPRINT` (asks
  first; the last key only with `--last` and asked twice), `--root-key-make
  ed25519|rsa4096 [--out FILE]` (the private half once: into a new 0600 file,
  or printed). In `isemon --console`: Network, time and power - 6 System
  updates, 7 SSH keys of root.

1.10.241

- **Popups close only when they are closed.** A click beside a popup closes
  nothing any more - only its own buttons, its cross and Escape do.
- **A popup opened from a popup comes back to it.** The one underneath is
  kept whole - what was typed, searched, filtered, paged and scrolled - and
  closing the one on top brings it back exactly as it was left, as many deep
  as they go (*Kept out now* → an address → whatever is opened from that, and
  back). A popup whose answer arrives is drawn in its own place; a button that
  is done with its popup and opens another (*Put it back* → the progress)
  hands its place over; going to another tab closes them all.

1.10.240

- **SSH keys of root: the server's card wide enough.** Its file,
  `/root/.ssh/authorized_keys`, is on one line; the pane's own styles are in the
  page's stylesheet, no longer inside the part of the pane that is drawn again.

1.10.239

- **Settings - System updates**, as otp has it: what dnf (or apt) has waiting
  on this server - how many, how many of them security, the packages, and
  whether the update will need a restart (kernel, glibc, systemd,
  linux-firmware...) or one is needed already - and *Update it now*, with a bar
  and what the package manager says as it goes (hidden, shown, or the window
  cleared for good). A restart it needs is offered at the end, or made by
  itself, as chosen. Refused while an upgrade of isemon, a restart, a power-off
  or a change of the network is going on; it can be stopped until it begins.
  The update runs as a unit of its own, outside root's helper, under its own
  lock. See [docs/system-updates.md](docs/system-updates.md).
- **Settings - SSH keys of root**, as otp has it: the keys that may sign in to
  this server as root (`/root/.ssh/authorized_keys`) - *A key for root* makes
  one (Ed25519, or RSA 4096) whose private half is shown once and kept nowhere;
  *Add a key* takes a public line or .pub file, or a private key of which only
  the public half is used; each key exported as a .pub file, or taken away
  (the last one only when said again). RSA under 3072 bits, DSA and lines with
  options before the key are refused. Written by root as 0600 in a 0700
  folder, never through a link; what sshd makes of root is shown beside it.
  See [docs/ssh-keys-of-root.md](docs/ssh-keys-of-root.md).

1.10.238

- **Settings - Time:** a time server's name with a line end hidden in it (it
  passed both checks and put a line of its own into chrony.conf, which stops
  chronyd) is refused; chrony.conf is checked by chronyd before it is put in,
  and put back as it was when chronyd will not start with it; while isemon
  does not set the time servers the file is never rewritten (a missing final
  newline, a blank line at the end and Save on the page rewrote it and
  restarted chronyd); a file whose end mark is missing is refused instead of
  everything after the beginning mark being taken away; `Server` and `POOL`
  are commented out like `server` and `pool`; a chrony.conf with Latin-2
  letters is read; a time zone that cannot be set is said and the time
  servers are set all the same; "Step it now" or Save asked while the clock
  was being read are no longer lost; the machine's own time zone for *Its
  time*; chronyc asked without reverse DNS. An upgrade starts chronyd only
  where it is enabled (or was installed just now), never one an admin
  switched off; ntpsec, ptp4l and phc2sys count as keeping the time.
- **Firewall and access:** the trial running out, *Keep it* and a save are
  under one lock - Keep pressed in that moment answered "kept" of rules put
  back, and a save could lose its trial; who may reach which page is never
  changed on trial where nginx's lists could not be put back exactly (they
  were left open to everybody); an `allow` of nginx's that is no address no
  longer stops the page; the requests to root (which carry the pages' key)
  are the isemon account's alone (0600); a request root never finished is
  not waited on for ever; folders put in place of the asking files are moved
  aside; a chain declared after INPUT's first rule no longer has rules
  written twice.
- **Backups of the configuration:** put back on another machine, its own
  settings.key stays - what the backup's key sealed is opened with it and
  sealed again with this machine's, so every password still opens after a
  restart; a configuration this machine refuses changes nothing; *How to put
  it back* is the guide of the kind made now; full backups and backups of the
  configuration are kept each on their own (the configuration's, every day,
  took away every full one); what could not be brought back is said on the
  page too.
- **Backups:** a backup is not made while one is put back, nor the other way
  round; a second restore asked meanwhile is refused, not joined to the first;
  a saved password is never handed to another server typed over a destination;
  SCP's folder holds nothing a shell reads as more; IPv6 servers work for SCP,
  SFTP and SMB; going back looks through 40 versions at the address, not 10.
- A request refused (401/403) while its body was still on the way reads it
  first: the sender sees the refusal, not a reset connection.

1.10.237

- **chronyd installed but not running is started.** The version before put chrony in
  where it was missing, but its package marks chronyd enabled without starting
  it, and the installer then left it so - Settings - Time said `chronyc
  tracking: 506 Cannot talk to daemon`. The installer now starts chronyd
  whenever it is not running (unless something else keeps the time); the page
  says *chronyd is not running*, and its button *Start chronyd* starts it and
  sets the clock.

1.10.236

- **The installer puts in what is missing, on every upgrade too.** `install.sh`
  and `install.sh --upgrade` (also an upgrade from the pages) install whatever
  isemon uses and the machine lacks: the ssh client, `acl`, `openssl`,
  `smbclient`, `chrony`, python3-colorama, nginx and PHP where the pages are,
  and the driver and dump program of the database engine config.json names.
  Only ever adds - nothing installed is changed, upgraded or taken away; a
  package that cannot be had is said and the rest goes on (ten minutes at
  most). chronyd is started when it is not running, unless something else
  keeps the time.

1.10.235

- **Backups: everything, or the configuration only.** *What is backed up*
  (`rbackup_what`, Settings - Backups): *Everything, the logs too* (as it comes,
  and as until now) or *The configuration only, without the logs* - no copy of
  the database, so it is small however big the logs are: every setting with
  its passwords, the accounts, the whitelist and the bans, the keys, the pages'
  certificate and firewall, the destinations of the backups. Its name ends in
  `-config`, and the page marks it. Put back - on the page, from a destination,
  or `isemon --restore-bundle` - it is imported into the database there is:
  every log record stays. See [docs/remote-backups.md](docs/remote-backups.md).
- **Upgrades: a card *This server* at the top** - the machine, the version it
  runs, since when, and whether it is running, being upgraded or restarting.

1.10.234

- **A new network on trial goes back exactly as it was.** Going back puts every
  NetworkManager setting the change touched back as it was (all addresses,
  search domains, `ignore-auto-dns`, the IPv6 method), also with the
  connection down and with an old host name of one word; isemon's IPv6 sysctl
  file goes away again when IPv6 goes back off. While a change waits to be
  kept, no other change of the network and no restart is taken; *Keep it*
  pressed as the time runs out is never told "kept" for a network that goes
  back; a server that never restarted after a change on trial gets its old
  settings back. `/etc/hosts`: only this machine's names are taken out of its
  lines (other names and other machines' lines stay), and
  `/etc/hosts.isemon-before` is written once. A time zone never begins with
  `-`; chrony.conf lines with tabs are read.
- **Going back to an older version, twice, never gets below the floor.** Root
  keeps the highest floor it has seen (`/usr/local/lib/isemon/downgrade-floor`);
  the page offers only what root takes. The console's login script is taken
  away only once the older version's `install.sh` went through.
- **Upgrades online:** every redirect must be https (not only the last one);
  four-part versions (`isemon-1.10.233.1.tar.gz`) are found; a listing's size
  that is not a number no longer stops `--upgrade-check`; a whole answer has a
  deadline; `--upgrade-follow` says when root never took the upgrade up. A
  damaged package is refused with what is wrong, not a traceback, and an nginx
  that took a change but did not reload is said.
- **The console reads its log safely as root:** a link is not followed, a FIFO
  does not hold the login up, lines are cut at 64 kB, and no escape sequence
  from a file (or from a log far away) reaches root's terminal.
- **Remote backups:** retention takes away only backups this installation sent
  itself - never another machine's with a name that looks the same, never the
  one just sent; a file missing from the server's list after it was sent is a
  failure; a damaged or cut-short backup is said (`--restore-bundle` no longer
  ends in a traceback); a key's passphrase and a password both work; a wrong
  password on the page keeps the file sent for another try; a backup's work
  folder (a whole database, unlocked) left by a stopped service is taken away
  after a day; a scheduled backup that met a job of the page runs the next
  minute instead of being skipped; `--passphrase-file` with Windows line ends.
  About: systemd's and MariaDB's versions read right.
- **The console at login waits for Save** (Settings - About): the switch is a
  change like any other, put in by *Save the changes*.

1.10.233

- **Going back to an older version is off until it is switched on.** *Offer
  going back to an older version* (`downgrade_offered`, Settings - Upgrades,
  off as it comes): off, the card *Going back to an older version* is not
  shown, and going back is refused on the page, by `isemon --downgrade` and in
  the console alike, saying where it is switched on. Switched on and saved,
  the card is there at once.
- **What changed, for every older version.** *What changed* beside each one on
  the card shows its entry out of this version's own README (which keeps every
  version's - nothing is fetched); `isemon --downgrade-check --changes` prints
  them, and the console offers it before it goes back.

1.10.232

- **Going back to an older version, as far back as is safe - the database
  left exactly as it is.** *Settings - Upgrades - Going back to an older
  version*, `isemon --downgrade-check`, `isemon --downgrade VERSION` and the
  console's *Upgrades - Go back to an older version*: a version published at
  `upgrade_url`, only as far back as can still run on the database as it is.
  Nothing is copied or put back, however big the database. How far is
  `DOWNGRADE_FLOOR` (1.10.226 - the database has had exactly the same shape
  since), written into the database (it only ever rises) and checked again by
  root from its own copy of the program; refused while anything is half done
  (an upgrade, a change waiting to be kept, a restart, a backup or another long
  job). Every older version at the address is said safe or not, and why. The
  version is typed before it goes. See [docs/upgrades.md](docs/upgrades.md).

1.10.231

- **Upgrades - From the web: which version, when there are several.** With
  more than one version newer than this one at `upgrade_url`, a list above
  the buttons picks which is put in - the newest unless another is chosen -
  and *Upgrade to X now* and *Only fetch it* go by it. With only one there is
  no list and the page is as it was. The command line already had it
  (`isemon --upgrade-online 1.10.230`), and the console too.

1.10.230

- **Settings - About: the console when root signs in, switched on the page.**
  The same choice as `isemon --console-at-login on|off` - the console opening
  by itself when root signs in at the server's screen or over SSH - with a
  switch under *The console*. /etc is not the isemon account's to write, so
  root's own helper (isemon_web.py) writes /etc/isemon-console-login, as a
  plain file put in place, never through a link. Anybody signed in sees it; a
  full administrator switches it; Events says who. The page says when the
  login script itself is not installed yet.

1.10.229

- **Settings - About says what this server runs on**, as otp's does: isemon,
  Python and where it is, psycopg2 (with its libpq), PyMySQL, colorama,
  Python's OpenSSL and SQLite, the database server as it names itself,
  pg_dump and mariadb-dump, nginx, php-fpm and the command line's PHP, the
  system and its kernel, systemd, the system's OpenSSL, rsyslog, chrony,
  NetworkManager, iptables, firewalld, OpenSSH and smbclient - only what is
  there. Under it the page's own PHP as php-fpm runs it (the version, how,
  OPcache, the web server) and every extension it has loaded. Asked of the
  machine at most once an hour.

1.10.228

What otp - the token server of the same author - learned about running a
server, brought over: its network, its clock, restarting it, backups to
another machine, upgrades from the web and a console, each with the same
pages and the same words as otp has them. A plain upgrade switches none of it
on and changes nothing on the machine.

- **Settings, the menu on the left, in groups that say what is in them**:
  Logs read, Banning, The firewall, Access (Accounts, Active Directory,
  Certificates and TLS, Firewall and access), Server (Network, Time, Restart
  and power off), Data (The database, Backups, Export and import), Monitoring
  and updates (Upgrades, About).
- **Settings - Network** ([docs/network-and-power.md](docs/network-and-power.md)):
  this server's address with its prefix, gateway, DNS servers, search
  domains, host name and IPv6 as NetworkManager has them, and new ones. *Check
  it* says what will happen; *Change it and restart* is done by the server
  itself, step by step on the page: the settings that named the old address or
  name (the database's address when it was this server's own), a certificate
  made here made again with the new name and address, NetworkManager, the
  host name, /etc/hosts (the old one kept as /etc/hosts.isemon-before), and a
  restart. A page opened at the old address goes to the new one.
- **On trial, and back by itself unless kept**: a new network
  (`net_confirm_min`, 10 min) and a change of the firewall or of who may reach
  which page (`fw_confirm_min`, 5 min). A banner on every page counts the time
  down with *Keep it* and *Put the old back now*; `isemon --change-keep
  net|fw`, `--change-back`, the console and `isemon --status` too. Not kept -
  or come up without its new address - the server goes back to its old network
  (a restart) and the firewall and the lists to what they were.
- **Settings - Restart and power off**: this server restarted or switched off,
  the page following it down and back up; `isemon --reboot`, `--poweroff`.
- **Settings - Time** ([docs/time.md](docs/time.md)): the clock as chrony sees
  it - how far off, synchronised, the source, stratum, frequency, root delay
  and dispersion, leap, the zone - every source with its state and reach, and
  *Step it now*. When isemon is to set them (off unless switched on): the time
  servers and pools with iburst, prefer and NTS, makestep, minsources, the
  networks served the time (opened in isemon's firewall by itself) and the
  time zone, written into /etc/chrony.conf between marks and taken out again
  as they were. A clock not synchronised, or more than a second off, is a
  problem in the header and in `isemon --status`; `isemon --time`,
  `--time-step`. install.sh installs chrony only on a fresh install.
- **Settings - SSH keys of root** ([docs/ssh-keys-of-root.md](docs/ssh-keys-of-root.md)):
  the keys in /root/.ssh/authorized_keys with what sshd makes of root; a key
  made here (Ed25519 or RSA 4096) whose private half is shown once and kept
  nowhere, a key of one's own added (its public line, .pub file or private
  key - only the public half used), each exported as a .pub file or taken
  away (the last one only when said again). Written by root's helper, 0600 in
  a 0700 folder, never through a link; every change in Events.
- **Settings - The OTP logs - Encrypted receiving (TLS)**
  ([docs/otp-logs-over-tls.md](docs/otp-logs-over-tls.md)): the isemon side of
  otp's *Encrypted sending* (otp 1.0.172) - rsyslog's TLS input on 6514/tcp put
  in by root, with the certificate from the file otp makes (isemon-tls.zip,
  AES-256, opened here), one made by an authority of this machine's own, or one
  pasted; mutual TLS with otp's nodes by name or by otp's authority alone. The
  plain input on 514 is never touched. `isemon --otp-tls`, `--otp-tls-import`,
  `--otp-tls-make`, `--otp-tls-set`, `--otp-tls-off`.
- **Settings - Backups** ([docs/remote-backups.md](docs/remote-backups.md)):
  a backup of everything - the full backup, the database with its keys -
  packed, locked with the backups' password (`openssl enc -aes-256-cbc -pbkdf2
  -iter 600000 -md sha256`, opened by isemon or by openssl alone) and sent to
  other machines: a folder, FTP, FTPS (an authority of your own, a pinned
  certificate, a client certificate), SFTP and SCP (a key made here, the
  server's host key trusted once), SMB (SMB3 encryption) - up to twenty, on a
  schedule (daily or weekly) or now, the newest N kept at each and none older
  than so many days. Without a password nothing is sent. Each backup carries
  its own RESTORE.md; one is put back from a destination's list, from a file
  sent on the page or with `isemon --restore-bundle FILE` on a machine
  installed from nothing - a copy of the database as it is is made first.
  `isemon --rbackup-status`, `--rbackup-now`. No destination and the schedule
  off until somebody sets them up.
- **Upgrades - From the web** ([docs/upgrades.md](docs/upgrades.md)):
  `upgrade_url` (https://github.com/falco81/ISEMon/tree/main/release - a
  GitHub folder, a page or listing linking to packages, or one package) is
  looked at once a day (`upgrade_check`) and on *Look now*; a newer one is
  offered - *Upgrade to X now*, or *Only fetch it* - fetched over HTTPS and
  checked by root exactly as a package sent by hand. Nothing is put in by
  itself. `isemon --upgrade-check`, `--upgrade-online [VERSION] [--yes]`,
  `--upgrade-follow`, `--upgrade-status`.
- **`isemon --console`** ([docs/console.md](docs/console.md)): the whole of
  isemon by its menus, on the server's screen or over SSH - a bar at the top
  with what matters, menus by the arrows, windows with fields instead of
  prompts, Yes/No before anything that cannot be undone, lists to scroll and
  find in, the live log and the journal with what is typed as a grep. Every
  action is the `isemon ...` command its window shows. `isemon
  --console-at-login on|off|status` opens it when root signs in (never for a
  command over SSH, scp or a script); a fresh install switches it on, an
  upgrade leaves it off until switched on. `--set KEY=@env` takes a secret
  from the environment rather than the command line.

1.10.227

A search for faults, and what it found.

- **otp's packets read twice are written once.** A request and its reply put
  together across a second (1.10.226) were written again as a second row
  when the same lines came in again - a file read from its start, a shipper
  sending twice: the request nobody answered, or the answer to nobody, and a
  refusal before any code written twice, once with nobody's name on it. The
  shipper's own id of each line is now looked for in the row it was put into.
- **An id is somebody's own packet.** A token line whose packet had not been
  shipped yet was given the nearest packet carrying the same id - the
  client's address and port, which the next person through the same head end
  uses too - on another node and of another person, and the opened record
  said it was certain. The packet now has to be on the same machine and of
  the same person, as the match by name always required.
- **A code typed is not "a code by SMS was sent and never typed".** Where the
  question's request was never put together with it, it has no name on it,
  and the code typed into the second window was looked for under that empty
  name and not found. It is looked for by otp's `State` instead.
- **Upgrades from the page.** An upgrade whose helper was killed (systemd's
  25 minutes, a restart under it) left its request behind, and every
  upgrade after it said *an upgrade is running already*, for good; a request
  no longer counts once it and root's last word on it are half an hour old,
  which is when the page calls it stuck. The 20-minute deadline on
  install.sh stopped only bash and went on waiting for what bash had started
  (a dnf, a sleep); it now stops all of it. A package of a few megabytes
  whose headers say gigabytes is refused at the first header, not after root
  has unpacked it.
- **Certificates and TLS.** Choosing only another DH group wrote the new
  parameters and never reloaded nginx, which went on with the old ones; it
  is reloaded now, and a refusal puts the old parameters back too. A
  firewall that cannot be kept here (firewalld, or no iptables) is refused
  before nginx is touched, not after the new certificate is already in force
  under a status that said *failed*.
- **The ban list.** A key, user name or password that is not UTF-8 (a
  FortiGate sending its password in Latin-1, or junk in the address) was a
  500 that never reached the daemon to be counted; it is refused like any
  other wrong one.
- **php2shell notice.** Upload progress is read as PHP as a whole has it:
  `.user.ini` is applied after the body is read, so the notice said
  *guarded* on a PHP that was not, and pointed at `.user.ini` as the fix. It
  points at `/etc/php.d/99-php2shell.ini` as well now
  ([docs/php2shell.md](docs/php2shell.md)).
- FTD message 722033 was named *AnyConnect DTLS established*; it is the first
  connection of a session.
- `tools/release.py` refuses a linked folder, which it used to sign and every
  machine then refused.
- The tests no longer depend on the day or the zone they are run in: ISE's
  offset was written as `+02:00` whatever the season, Prague and New York
  were taken to be six hours apart in the week they are five, one test of
  1.10.226 passed only on the afternoon of 24 October, and two read
  Prague's lines in the machine's own zone.

1.10.226

- **otp - the token server that replaced totpcgi, with codes by SMS and by
  mail - is read as fully as totpcgi ever was, and totpcgi exactly as
  before.** Every sentence otp 1.0.92 writes on its token line has words of
  its own on the page, in Czech as well: a code by SMS or by mail that was
  right, rate limit, lockout, a token switched off, never confirmed or whose
  key cannot be opened, the four sentences written while a new token is
  confirmed. See [docs/otp-server.md](docs/otp-server.md).
- **How the code came.** A code typed into the VPN's second window is joined,
  through the RADIUS `State`, to the question otp asked: the row is marked
  *by SMS*, *by mail* or *from the app*, and the opened record says where the
  code went (the masked number or address otp wrote). It works across the
  two nodes of a cluster.
- **Not every code is a sign-in.** A code typed on otp's enrolment page
  (`mode=PROVISION`), confirmed by an administrator or a test (`-DRY`) is
  marked so, beside the words.
- **What otp refuses without a word, and the code nobody typed.** otp sends
  no reason with a refusal unless asked to, and refuses a wrong directory
  password or an account outside the realm's groups before any code is
  checked - so there was no token line and nothing on the page. Those are
  now *refused before a code was looked at*. A code sent by SMS or mail that
  never came back into the second window is, fifteen minutes on, *a code by
  SMS was sent and never typed* - the SMS that did not arrive.
- **A request and its reply a second apart are one row again.** otp writes
  the reply with the moment it went out, often the next second; isemon kept
  the two as two rows and joined a token line to whichever was nearer. Now
  they are one row when up to 15 s apart from the same server and port, and
  a one-time repair puts the rows already written together. FreeRADIUS,
  which writes both with one second, is not affected.
- Three of totpcgi's own refusals (*that token had been used already*, *this
  account has nothing enrolled here*, *a one-off recovery code was used*)
  were shown in English on the Czech page. They are translated now.
- Settings → Automatic updates: on the night summer time ends, *next* said
  02:30 for a fetch set for 03:30 (a day worked out as 86,400 seconds, when
  that day has 25 hours). It is worked out as a date now.

1.10.225

- **A copy of the database no longer puts the machine into swap.** Off
  PostgreSQL a copy is written table by table and its indexes are built at
  the end - and each index was sorted in memory (`temp_store=MEMORY`, a fixed
  256 MB cache). Over twenty-three million firewall lines that is more than
  a gigabyte per index, on a machine of 3.6 GB whose service may use half of
  it (`MemoryMax=50%`): the daemon went into swap, the copy stood for half an
  hour on one index, and reading the logs coming in stood with it ("the whole
  program stood still for 5.5 s"). Now an index sort spills to a file in the
  folder the copy is written to (it has the room for the copy anyway), and
  the cache - which is also how much a sort holds before it spills - is a
  twenty-fourth of what the service may really use, the machine's memory or
  its cgroup limit, whichever is smaller: between 16 and 256 MB, 77 MB on
  that machine. A copy off the file engine is unchanged (SQLite's own online
  backup, which never builds an index).
- **...and it says which index it is building.** The bar used to stand at
  "building its indexes: 27% - 22 of 82" for as long as an index took. Now
  it says `building its indexes - fw_src_ts on fw_events, 23,437,003 row(s)`,
  and the log has a line for every index that took ten seconds or more, with
  how long.
- **Settings → Upgrades: the bar no longer freezes when you look at another
  tab.** While the window was in the background the next ask was dropped
  rather than put off, so one look elsewhere while root was at *checking it
  answers* left the bar at 95 % until F5. Now it keeps asking, and asks at
  once when the window is looked at again. (The last step, `isemon --check`,
  can itself take a minute or two on a big PostgreSQL database.)

1.10.224

- **Settings → Firewall and access: "What root did last" is gone from the
  machine's firewall card**, as it went from the certificate card in
  1.10.223. The card keeps its state line (in place · when); if root could
  not put something in, what it said is still shown, with *Try again*. The
  full account of the last run is still there for whoever wants it:
  `isemon --web-status`.

1.10.223

- **Settings → Firewall and access: the firewall as it is now shows
  isemon's own chain too.** Under *The firewall on this machine as it is now
  (read only)*, in one window: INPUT as iptables-save shows it - now with
  the jump to `ISEMON-IN` where it stands - and right below it `ISEMON-IN`
  itself, as the kernel holds it (`iptables -S ISEMON-IN`), for IPv4 and
  IPv6. isemon's own lines are in blue, the site's own as they are: what is
  really in force, not what is saved on the page. Before, the chain was left
  out of that view altogether. (The jump line needs root's helper of this
  version: `./install.sh --upgrade`, or the upgrade from the page.)
- **Settings → Certificates and TLS**: the card no longer folds out *What
  root did last* - only whether the certificate is in place, and what root
  said when it was not.

1.10.222

What otp does for its own server, now in isemon too - with the same pages.
Everything new is under **Settings → This server**, a full administrator's,
and put in place by root: the daemon runs as `isemon` and may not write a
byte of /etc, so it lays a request down in `/var/lib/isemon/web/` or
`/var/lib/isemon/upgrade/` and a systemd path unit runs a helper of root's
(`isemon_web.py`, `isemon_upgrade.py`), which checks every value again, asks
nginx (`nginx -t`) and iptables (`iptables-restore --test`) before anything
goes live, and puts every file back as it was when either says no. **Nothing
of nginx or the firewall changes until somebody saves something there**; an
upgrade only installs the helpers and the units.

- **Firewall and access** ([docs/firewall-and-access.md](docs/firewall-and-access.md)):
  - who may reach the dashboard, the published ban list and the health
    check - each everybody or only from a list (IPv4 and IPv6), the ban
    list and the health check also "as the dashboard"; this machine itself
    always;
  - the machine's firewall, off by default: a chain of isemon's own,
    `ISEMON-IN`, first in INPUT for IPv4 and IPv6, kept over a reboot in
    `/etc/sysconfig/iptables` and `ip6tables`; the rules already there are
    never touched, and turned off the files are as they were to the byte;
  - what isemon lets in by itself, worked out from what is set up: SSH (on
    the port sshd says), ICMP, DHCPv6, the dashboard (from the networks its
    lists name), and the logs arriving - on every port rsyslog listens on,
    read off its own files, from anywhere or only from the senders named.
    Each can be turned off;
  - rules of your own - accept, drop, reject; a port, a range, several; from
    a network; kept without being in force - looked at first, in order;
  - the rest of the firewall shown, read only; firewalld is left alone, and
    said so.
  Its changes wait for the save bar, as every setting does.
- **Certificates and TLS** ([docs/certificates-and-tls.md](docs/certificates-and-tls.md)):
  upload PEM (any order, sorted by themselves), a .pfx with its password or
  a DER .cer; a request (CSR) made here, its key waiting sealed for the
  certificate the CA sends back; a self-signed one; Standard, Mozilla
  intermediate, Mozilla modern or a cipher list of your own; DH parameters
  (RFC 7919, or made here with a bar); HSTS. The key is kept sealed in the
  database. `--check` says the days left, and fails once it has run out.
- **Upgrades from the page, with a progress bar** ([docs/upgrades.md](docs/upgrades.md)):
  send `isemon-X.Y.Z.tar.gz`, press *Upgrade*; root accepts only a package
  signed by a release key in `/usr/local/lib/isemon/release-keys/` (Ed25519
  over a MANIFEST of every file's SHA-256), with nothing in it that was not
  signed, no link and nothing older, and runs its own `install.sh --upgrade
  --yes`. The bar shows the step install.sh is at, how long it has taken,
  and that isemon is restarting; then the page offers to load itself again.
  `install.sh --upgrade` on the command line works as before, and is the way
  in for the first version with this and for a package signed by a new key.
  `tools/release.py` signs a release.
- **A full backup** ([docs/the-database.md](docs/the-database.md), 5.2):
  *Download a full backup* on The database, or `isemon --backup --full` -
  the copy with `settings.key`, `banfeed.key` and `known_hosts` in it, and
  config.json to read. Put back on a new machine, that machine is this one
  again, certificate and firewall and the routers' passwords included. The
  keys there before are kept beside the new ones; the keys never stay in the
  live database, so ordinary copies afterwards carry none of them.
- **The health check**: `healthz.php` - `200 ok`, or `503` and why, for
  monitoring or a balancer; it says nothing else, not even the version.
- `isemon --web-status`: what root has in place, and the last upgrade.

1.10.221

- **Security: nobody from Active Directory signs in without a group.**
  Somebody from the directory gets in only when a group named for a role
  matches one they are in (directly, or nested when that is on).
  - With **no group named for any role**, nobody from the directory gets in.
    Before, everybody the directory knew got in, read only - every person
    and every service account in the domain, with the right password.
  - A role whose group is left empty is given to nobody (as before).
  - Whoever is signed in from the directory when the last group is emptied
    is signed out at once on the save; and a daemon that starts with no
    group named - an upgrade from 1.10.220 or older - signs them out within
    a minute. The local accounts (`admin`) are not touched and still get in.
  - The refusal is the same words on the sign-in page as for somebody in
    none of the groups; the events say that no group is named for any role,
    and the directory's check under *Settings → Active Directory* now marks
    that as a failed step rather than a way of working.
  - **On an upgrade:** if the three group settings are empty and people
    sign in from the directory, name the group(s) first -
    `isemon --directory-groups`, then
    `isemon --set directory_readonly_group="CN=...,OU=...,DC=..."` - or they
    will be refused.
  - The help beside the admin and ban-admin group said several groups are
    separated by commas; they are separated by semicolons, which is how
    they have always been read.

1.10.220

- **`isemon --php-notice hide`** puts away the dashboard's notice that the
  PHP running the page may have php2shell - for example on a distribution
  whose backported fix kept the old version number, which the notice cannot
  tell from an unfixed one. Nothing is saved: the daemon holds it in memory,
  so the next start of the daemon (`systemctl restart isemon`, a reboot, an
  upgrade) shows the notice again while PHP's version is still below the
  fixed ones. `isemon --php-notice show` brings it back at once, and
  `isemon --php-notice` alone says which it is. Open pages follow within a
  few seconds, with the status; hiding and showing are written in the
  events. Only an administrator may do either (`/api/php-notice`).

1.10.219

- **`docs/php2shell.md`**: the whole php2shell procedure in one place, in
  English - what the two flaws are, what isemon does against them, guarding
  PHP as a whole in `/etc/php.d/99-php2shell.ini`, checking that nginx
  refuses multipart bodies, moving AlmaLinux 9 to another PHP stream,
  installing the fixed package and verifying it by the CVE (a backport keeps
  the old version number) and that php-fpm runs the new build, and signs of
  an attack before the guard. Linked from INSTALL.md.
- Corrected: `web/.user.ini` alone is not enough to switch upload progress
  off - PHP applies it too late in the request (AlmaLinux). INSTALL.md and
  the installer now say to set it in `/etc/php.d` as well.

1.10.218

- **php2shell (CVE-2026-109618, CVE-2026-109619, 21 October 2026).** Two
  remote code executions in how PHP takes a request's body apart - a
  multipart one and its upload progress - before a line of any page has run,
  for anybody who can reach the web server. Updating PHP is the fix (8.2.35,
  8.3.36, 8.4.27, 8.5.12 or later, or a distribution's fixed package, then
  `systemctl restart php-fpm`). Until it is updated, the dashboard keeps out
  of the way of it:
  - nothing on the page needs PHP to take a body apart any more: everything
    it sends is JSON, and a database put back (*Settings → The database*)
    is now sent as the file itself rather than as a multipart form, read
    from `php://input` and written down as it arrives - never whole in
    memory, as before;
  - `web/.user.ini` (the page's directory only) switches PHP's own reading
    of bodies off (`enable_post_data_reading = Off`), and upload progress
    (`session.upload_progress.enabled = 0`, `session.use_strict_mode = 1`);
  - the nginx vhost refuses every multipart body with 403. A vhost of the
    site's own is otherwise never touched by the installer; this one rule is
    put into it on an upgrade - the file kept beside it as
    `isemon.conf.before-php2shell`, nginx asked whether it still reads, and
    put back as it was if not;
  - the installer says whether the PHP it finds has the fix, and an
    administrator is told in the dashboard's header while the PHP running
    the page may not have it - and whether the page's own guard is in force.
  The ban feed (`banfeed.php`) is in the same directory and guarded the
  same way.

1.10.217

A look over the whole of it for faults and for waiting.

- **The MikroTik reader.** Over ssh, a router that did not know a field
  asked for left the reader waiting on itself for good - asked again
  without it, it now answers. Over ssh the connection table has two minutes
  to be printed (a command has 45 s), and a try from the page no longer
  than it waits. A round that could not read IPv6's connection table no
  longer wrote every IPv6 connection as ended (and counted it twice when it
  really ended). The router's clock is read: the times it writes - when a
  VPN it dials came up - are in its own zone, and were read as this
  machine's. Its API is read through a buffer (a word's length and the word
  were each a read of the socket), its interfaces looked up once a round,
  an interface gone a day forgotten, a session stopped from the page shut
  rather than closed under a read, and what the page is given copied before
  the reader adds to it (a growing table raised "changed size").
- **The NAT page** is kept and worked out behind the page like any search,
  not read back line by line at every five-second poll; a search reads a
  line apart only when it asks something of what is inside it, and only
  lines that hold one of those fields; `area:` uses its index.
- **Suggestions** for a field that is not counted are read once and picked
  out of as somebody types - not the newest three thousand lines read apart
  again at each key.
- **Kept answers.** Whoever worked out a slow answer and stopped at their
  own limit: one waiter takes it over, the others are told it is still
  being answered, rather than all of them running it at once. A list nobody
  has kept yet is worked out once for everybody asking it at the same
  moment. The firewalls' marks in the header no longer fill the cache until
  the expensive answers are pushed out of it; the names of addresses are
  counted once a minute, not at every opening of Settings; the overview
  does not wait for the VPN to be put together after a start.
- **The Router page** is narrowed a quarter of a second after the last key
  (it was drawn whole, and its day of an interface asked for again, at every
  key), asks the router at most every quarter of a minute, draws no answer
  that came after a later question, and opened straight from a link shows
  the routers once they are known.
- **Its settings.** A row made a MikroTik shows its API at once (and one no
  longer one stops showing it); a row named after it was drawn keeps its
  certificate, key and authority under the name it has when the button is
  pressed; *Try reaching it* is there as soon as an address is typed; over
  ssh an emptied port is 22; a password's dots - here and in every kept
  password in Settings - are chosen whole when the box is pressed, so what
  is typed replaces them.

1.10.216

- **The service of a line with no ports.** An ICMP, ICMPv6, GRE, ESP, AH,
  OSPF, VRRP, IGMP or PIM line - of any firewall - had an empty Service:
  the service was only ever a TCP or UDP port. It is now its protocol, and
  an ICMP message by its type (`icmp/echo-request`,
  `icmpv6/neighbor-solicitation`, `gre`, `esp`, `proto/115` for one with no
  name), given to every line before it is written - so the busiest services
  count them and `service:icmp*` finds them - and a MikroTik's line says its
  ICMP message (`proto ICMP (type 8, code 0)`). Lines written before say
  their protocol on the page. A firewall's own word for it (FortiGate's
  `PING`) is kept.

1.10.215

- **One kind of password box for a password that is kept.** A MikroTik's
  API password (*Settings → The firewall log*) was an empty box saying
  "set — leave empty to keep it"; it is now the box every other kept
  password in Settings has (the database's, the router's, the directory's):
  its dots and its last two letters, left as it is to keep it, typed over to
  replace it. The dots are never saved, nor tried on the router, as a
  password. The boxes for a password typed once - signing in, a new
  password, a database administrator - stay hidden as they were.

1.10.214

- **A MikroTik read through its API or over ssh tells the whole Traffic tab
  more.** Only for a router read that way; every other firewall, and a
  MikroTik read from its log alone, is as it was.
  - Its sessions are told what the router knows: the interfaces each came
    in and went out by (its own networks and its routes, the longest prefix
    first - a dst-nat by its server inside), the name its DNS answered for
    where it went (the *host*, from `/ip/dns/cache`), the MAC its ARP table
    has and the machine's name its DHCP leases give (`srcmac`, `srcname`,
    `dstmac`, `dstname`), and the person on its VPN whose address it was.
    So the busiest interfaces, names and people on the overview, the bytes
    on *Carried* and every search find them.
  - Its VPN on *Connected now*: each PPP person (OpenVPN, PPTP, L2TP, SSTP,
    PPPoE) with what they carried, out of the interface RouterOS makes for
    them; each WireGuard peer heard from in the last three minutes that
    comes in, as a person; and every VPN the router dials out on - OpenVPN,
    PPTP, L2TP, SSTP, PPPoE clients and WireGuard peers it goes to - as a
    tunnel, with where to, since when and its bytes.
  - The *Router* page: who is busiest now (by source, by where it went, by
    service, as rates between the last two looks - a row opens its
    sessions), each interface over the day (five minutes a bar, kept since
    the reading began), and every VPN it dials out on, down ones too.
  - The overview: *Through it now*, what goes through its way out to the
    internet (the interface of its default route) this minute.

1.10.213

- **MikroTik API: "TLS without a certificate" works with a router that has
  one.** It offered only the anonymous suites, which RouterOS's api-ssl
  speaks only when it has no certificate assigned: with one (as most have),
  the handshake failed. Both are offered now - it is still encrypted and
  still does not check which router it is; *TLS, its certificate pinned* is
  the way that does.
- **MikroTik API: TLS with a certificate an authority signed.** A fourth way,
  *TLS, its certificate checked by an authority*: the router's api-ssl
  certificate is checked as a browser checks a site - signed by an authority
  this machine trusts (Let's Encrypt and the like) or by one of yours (*Use
  my own authority*, its certificate pasted as PEM; *Forget it* goes back to
  the trusted ones), and for the router's name: *The name on its
  certificate* when it is reached by its address. Signed in with the
  account's name and password, as the other API ways. *Check its
  certificate* switches the checking off for a router of yours - still
  encrypted, any certificate taken, and said so beside the switch.
- **Over ssh, "Sign in with: password" is saved.** It was drawn and not
  saved, so a router read over ssh always tried a key.

1.10.212

- **MikroTik API: TLS with a router whose api-ssl speaks only the older
  suites.** RouterOS's api-ssl over TLS 1.2 often offers only AES-CBC with
  SHA-1, which Python leaves out by default: the router logged `ssl: no
  common ciphers` and the settings said `SSLV3_ALERT_HANDSHAKE_FAILURE`. With
  the certificate pinned those suites are offered too, after the strong ones
  (the router still takes GCM where it has it); the certificate is checked by
  its fingerprint as before. A handshake that still fails says to check that
  api-ssl's certificate has its private key on the router (flag K).

1.10.211

- **MikroTik: read through its API as well, read-only.** Under a MikroTik's
  row in *Settings → The firewall log* a switch, *Read more of it through
  its API*, and once it is on how to reach the router: its address, TLS
  with its certificate pinned / TLS without a certificate / the plain API,
  the port, an account that may only read, its password (kept sealed, never
  shown back) and how often - drawn the way *Reaching the firewall* draws
  the banning's router, all of it inside the section with the switch: its
  fields, the lines of how it is, *How to set it up on the router…* (the
  read-only group, the account, api-ssl), and the panel the ssh key has.
  *Make a certificate* makes the router a key and a certificate for api-ssl
  and pins it, kept here like the ssh key; *Use my own* pins one you have;
  *Download it* gives both as `isemon-api.pem` (written into Events);
  *Forget it*; *Try reaching it* signs in and says which RouterOS it is, how
  many connections it tracks and whether the account could change anything.
  One session per router, kept open; only ever prints (anything else is refused
  before it is sent); a few cheap questions a minute, the fields asked for
  named. What it reads:
  - the connection tracking table: each connection that ended becomes a
    session with its bytes and packets each way, how long it was seen and
    its address translation - so the Traffic tab finally counts how much
    went where for a MikroTik (`via:api`), and the NAT page has its
    translated connections;
  - who is on its VPN, its IPsec peers and its tunnels' interfaces: *Connected
    now* shows that router as its API says it is now;
  - how the router is (CPU, memory, uptime, version) every five minutes;
  - its DHCP leases, for the FreeRADIUS sign-ins beside them;
  - its interfaces with what they carry now, its addresses, routes, ARP
    table, neighbours, WireGuard peers, the counters of every firewall rule
    and its sensors - IPv4 and IPv6 alike: IPv6's connection table, its
    neighbours, DHCPv6 bindings and IPv6 firewall rules too - on a new
    *Router* page of the Traffic tab, there only while a router is read this
    way.
  Or over ssh instead of the API (*How it is reached → Over ssh*), signed in
  with a key made here - the banning's key panel: *Make a key*, *Use my
  own*, *Download it*, *Forget it*, the public half to copy - or a password;
  the panel offers the certificate or the key by the way chosen.
  A table of more than 150,000 connections is skipped for that round, and
  any other table of more than 3,000 entries is counted and not read.
  Nothing else changes: switched off - as every row is until somebody
  switches it on - nothing is opened. See docs/mikrotik-logs.md.

1.10.210

- **The NAT page for a FortiGate and an FTD too.** Their translations are
  written in their sessions rather than as lines of their own, so the NAT
  page now also lists every FortiGate and FTD session that was translated,
  said the same way as a MikroTik's: the kind (src-nat, dst-nat, both),
  what the source was made (`195.189.0.3:63693`), where the destination was
  sent (`→ 192.168.43.17:443`, the server inside) and the address it was
  asked at (`← 46.227.172.22:443`). FortiOS writes the asked-at address as
  the destination and the server inside as `tranip`; FTD the other way
  round (the real server, the mapped address in brackets) - both are said
  the same. The button counts every translation, the quick searches *src-nat*
  and *dst-nat* find every firewall's, and the column *Translated* on the
  Sessions page shows them too. The sessions stay on the Sessions page as
  they were. As the page is read line by line out of the sessions, a busy
  firewall's rare dst-nat may be said as "at least" - a shorter window finds
  them all. A MikroTik alone is read as before.
- Searching `area:` together with a field read out of the lines (`area:session
  transip:*`) found nothing: the rows read back did not carry their page.

1.10.209

- **Names of addresses where they were missing.** The translated addresses
  on the NAT page (*Translated to*: the server inside a dst-nat, what a
  masquerade's source was made) and in the popup were written as text with
  a port and an arrow in it, so nothing asked what they are called; they
  are drawn as addresses now and get their name above them like the source
  and destination beside them. Every IPv6 address with a port on the Traffic
  tab was the same - written `[2001:db8::1]` with its brackets, it was never
  an address to the page - and is given its name now too.
- **Asked as they arrive.** The name kept for an address is the one it had
  at that moment, but only where a record came from was asked about as the
  records arrived. The site's own machines are now too: on a firewall line
  the private address it went to and the server inside a dst-nat, and on a
  sign-in the address the machine was given (802.1X, MAB, the VPN; ISE, NPS
  and FreeRADIUS). The internet's addresses a firewall talks to are still
  left for the page to ask about, as there are too many. *Fill in the names*
  goes over the machines' addresses as well.

1.10.208

- **MikroTik: a dst-nat says where it went.** A NAT rule logs a
  connection's first packet before it is translated, so a dst-nat line
  said only the published address (`195.189.0.26:443`) and *Translated to*
  stayed empty. It now shows the server inside (`→ 192.168.43.17:443`),
  taken from the filter's own lines about the same connection - the same
  client and port within the next two minutes - and so, exactly, does a
  masquerade's source (until now the address that way out usually has,
  marked ≈). This works for lines already in the database too, on the NAT
  page and in the popup; while the log is read, the reader also remembers
  each published address and port and writes the server inside on the line
  (marked ≈). Search it with `natto:192.168.43.17*`.

1.10.207

- **Review of MikroTik, NAT, DHCP and FreeRADIUS, searching them included.**
  - *Traffic search:* a MAC typed on its own (`AA:BB:CC:DD:EE:01`,
    `aa-bb-…`, `aabb.ccdd.eeff`) was read as the field `aa` and found
    nothing - it is now looked for as a word and in the line's MAC fields,
    however it is written, and so is an IPv6 address starting with letters
    (`fe80::1`). `connectionstate:snat` finds `established,snat` (one of the
    states), quoted with commas all of them. `user:*` - the quick search
    *names a person* - was every line, because `*` matched an empty column
    too; `field:*` is now a line that has one, here and on the sign-in lists
    (`country:*`, `vlan:*`, `mac:*`).
  - *What the box offers:* the values and the field names come from the
    lines of the page it is on (the DHCP page offered no MAC, the
    administrators no script), the NAT and DHCP pages offer their own
    fields first, and a kind of line is no longer offered on a page that
    never holds it. *Changes* on the administrators' page includes
    MikroTik's.
  - *Cards:* a NAT rule's line is counted on the NAT page and in the hours
    only - it was also counted under the sessions' rules, ports and
    addresses, and the card's row then opened a list that does not hold it.
    A RouterOS event is counted by what kind it is (*DHCP lease given out*,
    *signed in*, *configuration changed*…) instead of by its whole message,
    which made a new row of every count for every lease.
  - *MikroTik lines:* a change logged with the step RouterOS 7 numbers
    (`…admin@10.0.0.2/action:42`) lost who made it and from where; it says
    both now. A mangle line (prerouting, postrouting) with no verdict in its
    prefix is only said. The choice *a line whose log prefix names no
    verdict* is said in words.
  - *The popup:* its labels and title were in English on a Czech page;
    they are translated, what the firewall wrote is shown as written (a rule
    called `drop` is not translated), a MikroTik line shows no policy number,
    bytes or duration it never wrote, the translation (NAT) and a DHCP lease
    are each a part of it, and the NAT and DHCP lists say which firewall
    wrote a line where there are several.
  - *Sign-in lists:* a MAC typed with colons finds a FreeRADIUS row that
    keeps it with dashes.
  - *FreeRADIUS:* going back over the logs kept leaving it out ("its zone
    was changed") once a second folder's accounting or summer time moved the
    clock offset it had learned; the key is the settings alone, and one
    written by 1.10.204-206 still reads as the same zone. A server on this
    machine's own clock is read in its zone, which knows summer time, rather
    than at a fixed offset. A machine put on its door after the accounting
    has its switch, network and port in that door's drop-downs, and a VPN
    refusal behind FreeRADIUS is described as the VPN's.
  - *Going back over the logs:* a firewall whose sessions let through are
    not kept is listed but cannot be ticked (it would be counted twice);
    ticked, it made the daemon refuse a pass that named only some logs.

1.10.206

- **MikroTik: the firewall log shown whole.** A line whose rule's prefix
  names no verdict - no prefix, `LOG-FORWARD`, `OVPN -`, i.e. a rule that
  only logs or lets through with `log=yes` - was shown as *said*, so the
  Traffic tab said nothing was let through. It is now **let through** (an
  `invalid` packet only said), and a packet that such a rule and a logging
  `DROP` rule both wrote in the same second is counted once, as the
  refusal. A new setting, *MikroTik: a line whose log prefix names no
  verdict*, puts it back to *info* for a router that refuses without
  logging behind a rule that only logs. A packet of the answer is shown the
  way its session was opened (client first, the service it asked for, not
  `tcp/54997`), the address translation is read in all three shapes RouterOS
  writes (the one in the sample logs, `NAT a->(b->c)`, was not read at all),
  the whole connection state is kept (`established,snat`), a protocol
  written straight after the state is read, and the router's own fields
  are named in the details. A prefix named after the rule's action, as the
  router now logs them (`accept`, `drop`, `v6-accept`, `nat-masquerade`...),
  is read for what it is: a NAT rule's line and one whose action goes on to
  the next rule (`add-src-to-address-list`) are only said. A change a script
  made says who ran it and which script (it said nobody). Lines already read keep what they were read
  as: erase the firewall's lines and go back over its log to see them anew.
- **MikroTik: NAT and DHCP each a page of the Traffic tab.** The NAT
  rules' own lines are no longer among the sessions: the *NAT* page shows
  the connection, the kind of translation (masquerade, src-nat, dst-nat,
  not translated) and the address and port it was made (from the router's
  other lines for that way out, marked ≈, where the NAT rule logged the
  packet before translating it). The DHCP leases have a *DHCP* page: when,
  given out or given back, the address, the MAC, the machine's name and the
  server. Each page shows only where there are lines of it. A session
  through a translation stays under Sessions, says what its source was made
  and the address its destination was asked at (`natsrc`, `natdst`, also a
  column *Translated*), and a packet coming back through a translation is
  turned round whatever its ports (NTP's 123->123, an answer to port 63603).
  FortiGate and FTD lines stay on the pages they were.
- The Traffic chart's legend and tooltip said *said* and the line under it
  *1 day(s) for what was let through* in English on a Czech page; each is
  now a string of its own.

1.10.205

- **Public lists: a switch waits for Save the changes.** Each list saved
  itself the moment its switch was flipped, so flipping several quickly was
  several saves racing one another, the card drawn again between them, and
  errors. Now they behave as every other setting: flip what you want, the
  bar at the bottom counts the change, *Save the changes* saves them all at
  once and *Put them back* throws them away. A list flipped and not saved
  is shown in blue, and stays flipped when another page is looked at and
  back.

1.10.204

- **Going back over the logs reads every log that is switched on** - ISE,
  the token server, eduroam, tac_plus, NPS, the domain controllers, the
  firewall, FreeRADIUS, and whatever kind is added later, because it reads
  what the daemon follows rather than a list of its own - with every rotated
  copy and every day still in each folder (eduroam's accounting files of
  every day too). Until now only ISE's were read unless others were named on
  the command line. Settings → Go back over the logs lists them, each
  ticked, to leave one out. A log without a zone of its own whose zone was
  changed since its records were read is left out, saying so - read again it
  would file every line twice - until its records are erased, which reads it
  again in the new zone; the zone each was read in is written down for that.
  The firewall is left out where what it let through is not kept (it would
  be counted twice), as it always was when named.
- **...and weighs the sources counted on their own over the same span**:
  logins at the firewall, to network devices, to the domain and the VPN
  through FreeRADIUS, where they are on or watched. Their pass of their own
  looks at the last hour, so what they wrote before was never weighed; now
  an address that went over the bar inside the window at any time in the
  span is banned by the same ladder, once, "found going back over the logs".
- **FreeRADIUS: as much as its logs say.** The sign-ins in radius.log now
  carry what the accounting said of each machine - its door (802.1X or MAB,
  on Wi-Fi or the LAN), the network, the access point, the address it was
  given, the box that asked, the VLAN - and, on the VPN, the address inside.
  It is learned as the files are read, so the first sign-in of a session no
  longer comes out as *FreeRADIUS other*; one that still does is put on its
  door, with its network and address, once the accounting says. Yesterday's
  accounting file is read as well as today's. Where a MikroTik's DHCP is
  read too, a machine has the name it gave and the address it got.
- **The zone of the FreeRADIUS server's clock** is worked out from its own
  accounting (each record says the same moment as its clock showed it and
  as a number), or set as *The zone its times are written in*. A server
  writing in another zone was hours out, and its sign-ins never met their
  accounting. Rows already read in the wrong zone keep their time: erase
  the FreeRADIUS records (Settings → The database) and they are read again.
- RADIUS clients named AP, AP-something or wlc… are radios and sw… switches
  unless set otherwise.

1.10.203

- **MikroTik RouterOS** is a kind of firewall *Settings → The firewall log*
  reads, beside FortiGate and Cisco FTD/ASA. Its lines become the Traffic tab:
  every packet a rule logged (the chain, both ends with their ports, IPv4 and
  IPv6, the interfaces, the source MAC, protocol and flags, NAT, the
  connection state and marks), with its verdict read off the rule's log
  prefix - DROP, REJECT, DENY, BLOCK a refusal, ACCEPT, ALLOW, PERMIT a pass,
  anything else *logged*; sign-ins to the router (winbox, ssh, web, API) and
  refused ones, which count towards a ban under *Logins at the firewall
  itself*; every change to its configuration, by whom and from where; the
  VPN of people (OpenVPN, L2TP, SSTP, PPTP) and the tunnels to other sites;
  DHCP. Filed a topic to a file or all in one, every file of the folder is
  followed. See docs/mikrotik-logs.md and deploy/mikrotik/.
- **A FreeRADIUS server of your own**, a new pane: *Settings → The
  FreeRADIUS logs*. Not eduroam: the doors ISE and NPS answer - MAB and
  802.1X on the LAN and on Wi-Fi, and the VPN - as buttons of their own on
  Logins and Failed attempts (FreeRADIUS VPN, 802.1X LAN, 802.1X Wi-Fi, MAB
  LAN, MAB Wi-Fi, other), cards on the Overview, bands and a legend in the
  chart, the search box, the filters and the database page. radius.log is
  read as a syslog server writes it or as FreeRADIUS writes its own file; the
  door is worked out from the calling station (an address is the VPN), the
  name (the machine's MAC is MAB) and the RADIUS clients named as the VPN,
  radios or switches - or what the accounting detail files said of that
  machine, which also give each one its address, access point and network.
  A password FreeRADIUS writes into its log is never kept.
- **Banning from it**: *The VPN through a FreeRADIUS of your own* under
  Banning → Where the bans come from, off until switched on (off, watch,
  on). VPN refusals from an address on the internet are counted every minute,
  as the firewall's are, and banned by the same bar, window and ladder.
- Nothing changes until one of them is switched on.

1.10.202

- **A plain `--upgrade` changes nothing of a machine that works.** 1.10.201
  set up receiving the logs and the tuning rights of PostgreSQL on every
  upgrade; now only a fresh install does, and an installed machine only when
  asked by name: `--upgrade --with-syslog` for receiving the logs,
  `--upgrade --db-rights` (or `--db-rights` alone) for PostgreSQL. polkit is
  no longer installed by a plain upgrade either. Everything else of 1.10.201
  is as it was.

1.10.201

- **The installer receives the logs by itself** on a fresh install (it used
  to need `--with-syslog`; see 1.10.202 for the upgrade): `rsyslog`, `rsyslog-relp` and `rsyslog-openssl` where missing;
  the permissions of what rsyslog makes (`0640`/`0750`, the `isemon` group);
  rsyslog's own `UMask=0066` loosened to `0027` where it hid the logs from
  the group; `/var/log/remote` as `root:isemon 0750` with an ACL for the
  daemon on what is already there; the ISE receiver; the rotation of what
  arrives (`/etc/logrotate.d/remote-logs`) and the daily tidy. Nothing of
  the machine's own is replaced: no receiver where rsyslog already listens
  or 514 is taken, no rotation where something already rotates
  `/var/log/remote`, rsyslog checked before it is restarted and what was
  added taken out again if it would not start, syslog-ng left alone with
  what to write in it printed. An upgrade never opens 514 to anybody;
  `--log-from` names the senders. `--no-syslog` leaves all of it out.
- **Tuning a PostgreSQL on this machine needs no administrator any more.**
  The installer (and `sudo ./install.sh --db-rights` on its own, for a
  server moved to later) signs in as `postgres` over the server's socket -
  no password asked or kept - and gives the program's account the right to
  change the settings the popup tunes and no others, to reload the server
  and to read its settings (PostgreSQL 15 and newer). Making the database
  from the dashboard does the same. polkit, which lets the account restart
  PostgreSQL, is installed where it is missing. The popup says the command.
- **Who may open this**: the buttons and the role picker of a row in one
  line, the same height; *last signed in* written as *made* is.

1.10.200

A further review round. What was found and put right:

- **The domain.** Accounts are compared by their whole names (`svc.adsync`
  is no longer `svc`, so a setting naming one service account no longer
  excuses every `svc.` account); the marks are redone once. A spray chained
  to the same server written as `dc04` or `dc04.corp.int` is one chain.
  Where the marking had got to is saved only after its batch is written.
  `winsec_ignore` matches a name however it is written (svc@REALM,
  DOMAIN\svc). `winsec_zone` refuses `local`.
- **The records.** On SQLite, upper and lower case are compared for every
  letter, not only A-Z. A prompt at a switch over RADIUS (Service-Type NAS
  Prompt or Administrative) is no longer counted as a VPN refusal.
  `country:` in the find box takes the two letters; `country:China` is
  refused rather than read as CH.
- **The firewall.** A pair passed in the other direction keeps its
  countries the right way round. A FortiGate tunnel given to somebody else
  ends the session that had it. A rescan skips what is older than it keeps.
- **The lists and the feeds.** A byte-order mark no longer costs a list its
  first entry; a download cut short or a gzip that never ends is an error,
  not a shorter list. A list switched off is not used by the banning. The
  Cisco IOS access list starts by removing the list of before, so pasting
  it twice no longer leaves the old entries. Several firewalls fetching the
  ban feed at once build it once. Reverse lookups give up after a hundred
  failures in a row; names with non-ASCII letters are read and asked.
- **Bans.** Erasing the bans writes a "let back in" for every address that
  was out, so the next pass does not ban them all again from the attempts
  still in the window. A cache is never treated as fresh after the clock was
  put back. An address that is not in a folded range never writes onto it.
- **Backups.** A backup or dump made by root is given to the folder's owner,
  so the daemon can read it back; temporary folders older than six hours
  are cleared. Emptying a table that is being read waits three seconds at
  most and says so.
- **Accounts.** `--add-user --must-change` is kept; a user that must change
  the password can also sign out instead, and the page reloads after the
  change. A command-line sign-in ends when the command does.
- **The page.** The domain bar of the chart is clipped to the chart (this
  replaces the change of 1.10.198). The find box asks before letting a range
  in, and names it. The sort keys of the authentication tabs match their
  columns. The events list can show the bans only watched and the
  whitelist.
- **Tests.** The test run of 1.10.197-1.10.199 hid a few failures (a check
  read "996 ok, 4 failed" as passing); they are fixed and the run is checked
  by every line now.

1.10.199

- *Who is signed in* (Settings → Accounts) has a **Disconnect** button on
  every row: it ends that one sign-in - whoever uses it is asked to sign in
  again - and leaves the account and its other sign-ins as they are. The
  sign-in you are using is marked *this one*; its button signs you out,
  after asking. *End them all* is still there. Full administrators only,
  and every sign-in ended this way is written in the events.

1.10.198

A second review of the whole program, the page and the installer. What was
found and put right:

- **Accounts and the directory.**
  - A domain person switched off here is recognised by every name the
    directory gives them - the short name and the name@domain - wherever
    they are moved in the directory, and a DN given again to somebody new
    is not that person. Names with Czech letters in their DN were missed.
  - One person under two names is one full administrator: switching off
    your own other name, or the last administrator under it, is refused.
  - An account named name@domain can be switched off and on.
  - The right password of a switched-off domain account no longer counts
    towards locking the address out.
- **Logs.**
  - A user name typed at an ASA/FTD WebVPN or ssh prompt can no longer
    choose which address is counted and banned.
  - A Windows logon whose name holds the words Windows writes after its
    fields keeps its address, and a name holding "Result Code: 0x0" no
    longer turns a refusal into a success.
  - ASA 113012 is a sign-in that worked, not a refusal.
  - Time stamps with more than six digits of a second are read.
- **Banning.**
  - Refusals at a door switched off - or only watched, for a ban that is
    carried - no longer lengthen a ban or make it for good.
  - Two parts of the program banning one address at the same moment never
    shorten what the other made, and are one step on the ladder.
  - A fold no longer races a ban let go or a subnet unfolded at the same
    moment.
  - A ban nobody carried, carried by a source counted apart, lasts what the
    ladder says - not the minute it had left; one made by hand and carried
    through a public list keeps who made it.
  - A wrong password from a private address never bans through a public
    list (FireHOL level 1 names 10/8 and 192.168/16).
  - fold_widest of 25-27 folds no wider than asked (/28).
- **Speed and memory.** Asking whether a ban is carried no longer scans
  every ban on each refusal (half a second after every change on a big
  list) or keeps megabytes per change; the Banned page's answer is kept once,
  not once per change; switching a source on looks up the watched bans in
  one statement; a full disk or a database that may only be read keeps the
  records for later instead of dropping them; the firewall is looked at by
  one reader at a time.
- **Settings, restore and import.**
  - Two saves at the same moment no longer lose one; a restore or a page
    save that names the ISE logs no longer reads files again.
  - A restored database runs on its own settings and its own ladder.
  - An import without the passwords leaves the passwords here as they are;
    directory accounts named name@domain are carried; a file with a broken
    part is refused before anything is written; an end that is not a moment
    (inf, nan) is left out.
  - An erase of the bans takes the folded members and source marks with it;
    a second job of the same kind with other arguments is refused instead of
    joining the first.
  - winsec_zone is checked as log_zone is.
- **Command line.** `--minutes 0` is refused, not a ban for good; a file
  that cannot be written is said, not a traceback; `--set` with the database
  away says what was not saved and exits 1; nothing is written into the
  stand-in for a database that will not open; a first administrator that
  must change its password no longer locks the command line out; an option
  on its own at its default no longer starts a daemon.
- **The page.** Bans nobody carries are never called "kept out" (the
  Overview, the find box, a record's popup); an address kept out by a range
  offers to let the range in; Enter in the find box acts on what was typed;
  two public lists switched quickly are both kept; the chart counts the
  domain's refusals in its scale; IPv6 addresses sort by their value; the
  Events pager knows when it is capped; a group named by its name is found
  in the directory list; the sources table scrolls on a phone; the ban cells
  of old tables are let go; a refused restore says why.

1.10.197

A review of the whole program and the page. What was found and put right:

- **Sources only watched or off.**
  - A ban that keeps nobody out - only watched, or its every source off - is
    no closed door: an address under one that fails at a door that bans is
    counted as if it had no ban, and is banned for real only at the bar.
    One refusal there used to carry the ban at once - and a whole folded
    subnet, for one neighbour's typo.
    Its own ban carried that way stays as it was made - for good stays for
    good, one by hand keeps who made it - and is only ever lengthened.
  - A ban that is carried is earned by the doors that ban alone: two
    refusals at one that is on and one at one only watched are two, not
    three. Short of the bar, the lot makes a ban only watched.
  - Refusals at a door switched off lengthen no ban; at a door only watched,
    no ban that is carried.
  - A ban only watched that becomes carried - its source switched on, or a
    source that bans earning it too - is written down as carried from then:
    the ladder counts it, and its end is the floor of the counting. How a ban
    ends in its history follows how it was made, not today's setting.
  - A watched ban that ran out is not made again from the same attempts.
  - Letting a source's bans go wrote "let back in" twice for every address.
  - The header's "for good" is counted out of what is carried (it could go
    below nought), and every place on the page that marks an address as
    banned says "only watched" or "not carried" for a ban nobody carries,
    without the red bar; the history no longer says such an address cannot
    reach the VPN.
  - Firewall, domain and device failures written as `::ffff:a.b.c.d` or in
    capitals were counted and never banned; "start counting again" now holds
    for those sources too; their charge marks are tidied away.
  - A backup restored from before there were sources is written down by
    source at once, as a start does.
- **Firewalls.**
  - pfSense (REST API): an apply that failed - a filter reload past the
    timeout - is applied at the next sync; it never was, and the running
    table stayed as it was while the page said the bans were carried.
  - OPNsense/pfSense with the sync off: bans that ended leave the table with
    the blacklist switched off as well.
  - The Cisco access list is written under the name saved (dots were
    dropped, so `EDGE.IN-v4` became a second list applied to nothing).
  - A bracketed IPv6 address reaches ssh without its brackets.
  - The country list's trouble on one of two firewalls is no longer wiped
    by the other's success.
- **Accounts.** A domain account switched off here is off under both names
  the directory knows it by (`jnovak` and `jnovak@corp.example`); it could
  sign in under the other one. Letting every ban of a source go is a full
  administrator's, as "let them all back in" is.
- **Settings and logs.**
  - A setting taken out of the database by another writer falls back to the
    file at once, not at the next restart.
  - A config.json that does not read is never written over (it lost the
    database's address and password).
  - A HUP or a setting saved from outside leaves the files being read where
    they are; going back to the last saved positions counted some firewall
    sessions twice.
  - An option given without its command (`isemon --sync`) says so instead of
    starting a second daemon.
  - A FortiGate line with a value cut short is read at once (it took
    seconds, the reader waiting).
  - MariaDB upgraded from before 1.10.185 builds its device indexes.
- **The page.** The firewall-log list no longer stays "changed" after an
  edit taken back, and one edited while saving is not lost; bans by hand
  never show off when the daemon reads them as on; the sources are asked
  again on the Banned page once a minute.
- **Installing.** Debian/Ubuntu: rsyslog is told to reopen its files after
  rotation (it has no reload there), php-fpm is restarted under its own
  name and the vhost points at its socket, the ssh client and the MariaDB
  driver are asked for by their names there; a too short `--admin-password`
  is said at once.

1.10.196

- A source of bans has three states under *Where the bans come from*, set
  with a three-way switch - grey off, amber watching, green on:
  - **off** - nothing is counted, as before;
  - **watching** - counted and its bans made, shown and said as what they
    would be, and carried nowhere: no firewall, no published list, no
    access list. They are no step on the ladder and move no floor under
    the counting, so watching changes nothing about what is banned;
  - **on** - as before. Switching from watching to on carries every ban it
    made that is still running at once, and the page asks first, with how
    many.
- The Banned page has a group of its own, *Only watched*; the history, the
  counting and each ban mark a watched source. The count in the header is
  of what is carried.
- The settings take 0/1 as before (`--set ban_from_win=on | watch | off`);
  the old ones stay on, the new ones off. Bans made by hand are on or off.

1.10.195

- The Banned page says where each ban came from everywhere: *Kept out
  right now* as before, *Counting up to a ban* - which source each address
  is counting for, the VPN through ISE or through NPS, and the sources
  counted by a pass of their own while they are on; one whose source is
  off is said to earn nothing - and *Ban history*, in a column of its own
  that can be sorted (bans from before 1.10.193 are the counting's or by
  hand, as they were).
- The sources card adds up: an address banned by two sources - the VPN
  and by hand - is a ban of each and counted under each, which is why the
  column came to one more than the bans there were; it now says how many
  are, and a column *Only this one* gives the bans a source alone stands
  behind - what letting its bans go lets back in. With banning itself
  switched off, nothing is said to be carried. The groups on the Banned
  page are something else - how a ban was made - and the card says so.
- *Let them all back in* asks first which sources: a switch for each that
  has bans, all of them on. With every one on it is everybody, as it
  always was; otherwise every ban of the sources chosen is let go, an
  address another source banned as well staying for that one - after a
  confirmation.

1.10.194

- One switch for the VPN through NPS: *Judge the VPN through NPS as well*
  and the source *The VPN through a Windows NPS* were two switches for one
  thing, either off stopping it. The source is the switch now, and the old
  one is no longer shown. An installation that had the old one off has the
  source off instead, once, at the first start; `isemon --set
  judge_nps_vpn=…` and a configuration exported before set the source.
- The bans from before there were sources were read as the VPN through
  ISE's wherever no refusal of the address was left to read, and a folded
  subnet as ISE's whatever its addresses were: on a site that reads only
  NPS, the card said "the VPN through ISE". Read again once: by the
  address's own refusals, and with none left, by the VPN the installation
  reads - NPS where the ISE logs are switched off. A folded subnet is what
  its addresses were, each written down in it.
- The numbers on the sources card under their headings, and its buttons
  said whole: *Let every ban of this source go*.
- The words beside the NPS, tac_plus, firewall-log and domain-controller
  settings no longer say that nothing there can earn a ban: each says which
  source under Banning makes it.

1.10.193

Where the bans come from - a switch a source, under Settings → Banning:

- **The VPN through ISE** and **the VPN through a Windows NPS** - the two
  that always banned, on as before.
- **Logins to network devices** (TACACS+ through ISE, a tac_plus server),
  **logins at the firewall itself** (its VPN portal and administration, as
  its log writes them) and **domain logons from outside** (a wrong
  password, Kerberos or NTLM refusing one) - new, off until switched on.
  Each is counted from the records already read, as the VPN is: so many
  failures in the window, from the end of the last ban, the same ladder.
  Only addresses on the internet: the bans go to a firewall in front of the
  network, and an address inside it is never banned by them.
- **Bans made by hand** - the Banned page, `isemon --ban`, an import.

Every ban says what made it, one source or several (banned by the VPN and
by hand, it is both). One list is carried - to the firewalls, into the
published list, into the access list - made of the bans of every source
switched on. A source switched off makes no new bans, and the ones it made
are kept and run out as they would but are carried nowhere; switched on
again, the ones still running are carried again. An address banned by two
sources is carried while either is on. *Let its bans go…* beside each
source lets every ban of it go; an address another source banned as well
stays, for that one.

Folding follows the sources: a folded subnet is from all the addresses
folded into it; with a source switched off it is carried whole while
enough of its addresses (`fold_least`) have a source on, and otherwise as
those addresses alone; an address whose source is off is never folded.

The bans from before there were sources are written down once by what they
were: the VPN through NPS where every judged refusal of the address was
there, the VPN through ISE otherwise, and by hand where nobody's counting
made them.

The Banned page shows where each ban came from, a source switched off
struck through, and a group of its own for the bans no source switched on
stands behind; `source:` searches by it. The command line: `isemon
--ban-sources`, `isemon --unban-source SOURCE`, and `isemon --set
ban_from_win=1` and the like. An export carries each ban's sources.

Nothing changes until a source is switched: the two VPN sources and the
bans by hand are on, as everything always was.

1.10.192

Another pass for faults, the command line brought up to the firewall cards
and the published list, and quicker paths:

- An OPNsense or a pfSense with *Keep the firewall in sync by itself* off:
  a ban that ended is taken out of its alias every minute anyway (a pf
  table has no timeouts, so a ban of ten minutes stayed until somebody
  pressed Sync). Nothing is added by it.
- An OPNsense's or a pfSense's API answering with a redirect is refused:
  urllib carried the API key along to wherever it pointed, plain HTTP
  included, and a POST turned into a GET read as done.
- A firewall whose kind or list was changed in the settings while a sync
  was reading it is not written to with the new settings on the strength
  of the old answer; the next sync does it.
- A pfSense through the REST API is sent one change and one filter reload
  a sync, not two of each.
- Remove our address lists for the banned list and then for the country
  list are two jobs; the second was joined to the first and never done. A
  second rename of a list while the first was being cleared, likewise. An
  alias renamed while no firewall is of that kind starts nothing.
- Changing the address of an OPNsense or a pfSense is said in the events,
  as a Mikrotik's always was.
- The published ban list asks where a fetch comes from before anything
  else: an address that may not fetch it could tell from the answer
  whether the password it tried was right. Two firewalls fetching two
  shapes at once could make one of them answered with an error.
- ssh with a password could read a command that failed as one that
  worked.
- The status, the header and the firewall card show the ssh key of the
  kind the first firewall is.
- The page: *Try reaching it* is not offered for a kind chosen and not
  saved yet (it tried the one saved); buttons pressed before the settings
  are in no longer throw; a password box left untouched no longer keeps
  "1 change not saved" after a save; the pair's line is drawn again when a
  kind is chosen; the guide of a kind opens again when chosen again; the
  published list's guide gives the URL with the family chosen and the
  alias under the name the settings use.
- How to set each kind of firewall up, and each shape of the published
  list, is behind its own button - *How to set it up on the firewall…* on
  each firewall's card and on the published list's - and no longer opens by
  itself when a kind or a shape is chosen.
- The command line: `--fw-test [1|2]`, `--fw-key [show|generate|forget]`
  with `--fw 2` and `--fw-kind`, and `--banfeed` (its state and URLs, what
  each kind of firewall is given, `newkey`, `forget`); `--mikrotik` says
  which kind each firewall is.
- Quicker: the Traffic overview unchanged since the last refresh is not
  sent and drawn again every five seconds; three lists that never show a
  count no longer wait for one; the lines without a page are looked for
  within the window, not in every day's part; a TLS context per request
  to a firewall's API is made once; the names of addresses are written
  without waiting for the disk; the header's firewall marks are kept five
  seconds.

1.10.191

- The published ban list for an OPNsense: a recent OPNsense signs in when
  it fetches a URL alias (its Basic authentication, with a user name and a
  password), as a FortiGate does, and the guide now says how. A pfSense
  cannot, and is given the key in the URL or the addresses allowed to
  fetch, as before.

1.10.190

An OPNsense or a pfSense as either firewall, beside the Mikrotik:

- Each of the two firewalls is one of five kinds (Settings → Firewall,
  *What kind of firewall*): a Mikrotik over ssh, as always; an OPNsense
  through its API (an alias of the type External (advanced), filled with
  `alias_util`) or over ssh (`pfctl`); a pfSense through the REST API
  package from pfrest.org (an alias of the type Network, sent whole and
  applied) or over ssh (`pfctl`, with sudo if the account is not root).
  The two of a pair may be of different kinds.
- The banned list, the country list, the sync, *Remove our address
  lists*, the clearing when the blacklist is switched off and *Try reaching
  it* work for every kind. A pf table carries no comments, so every entry
  in the alias is this machine's: anything else in it is taken off at the
  next sync. Nor does it carry timeouts: a ban that runs out is taken off
  by the sync, and an alias emptied by a restart (or, on a pfSense over
  ssh, by a filter reload) is filled again by it. A country list is read,
  compared and only the difference sent.
- Every kind keeps settings of its own - address, port, account, API key,
  ssh key - and only those of the kind chosen are shown. Switched to
  another kind and back, a firewall finds everything as it was; a
  Mikrotik's settings keep the names they always had. The aliases' names
  (`pf_list`, `pf_geolist`) are settings of their own as well, held to
  what a pf table takes.
- The kinds that sign in over ssh have a key each, made, uploaded,
  downloaded and forgotten on the card as the Mikrotik's always was.
- *How to set it up…* on each firewall's card, and when a kind is chosen:
  the alias, the rule, the account and its key or API key, step by step.
- The published ban list comes in two more shapes, for an OPNsense (an
  alias of the type URL Table (IPs)) and for a pfSense (a URL Table alias,
  or pfBlockerNG); choosing one shows how to set it up.
- Nothing changes for a Mikrotik.

1.10.189

From a second site's start-up log and profile:

- Index builds behind the daemon could deadlock each other at a start.
  Waiting for the lock index work is done under was one statement that
  waited - a transaction with a snapshot, for as long as it waited - while
  `CREATE INDEX CONCURRENTLY` in the session holding the lock waits for
  every older transaction to end. The server ended one of them as a
  deadlock and that build was thrown away (`fw_kept_verdict_ts`, retried
  ten minutes later). The lock is now asked for again once a second
  instead, so nothing waits inside a statement.
- The Domain page's list of several kinds at once (the sign-ins, the
  refusals) newest first: each kind's newest rows are read down its own
  index and the few put together, instead of every row of the window read
  and sorted to show a hundred - three to nine seconds on a busy domain.
  The same rows, in the same order.
- No `SyntaxWarning` at start on Python 3.12.

1.10.188

Another pass for faults - in the banning, in the reading of the logs and in
the database's upkeep:

- A ban that had run out but had not been swept yet was charged again with
  the attempts that earned it, a rung higher, off the back of one new
  attempt - on a restart, every ban that ran out while the daemon was
  stopped. And a ban swept late is now written as ending when it ran out,
  not when it was noticed: what was read for the hours in between is
  counted from then, and the history shows the real moment.
- A folded subnet let go as it was typed (`2001:DB8::/48`, `192.0.2.7/24`)
  is taken apart into its members instead of letting all of them out.
  "Let everybody in" takes a subnet's list of members with it, so undoing
  the folding afterwards brings nobody back; nor does an undo bring back an
  address whitelisted since.
- A ban that has run out is no longer put back on the router for a minute;
  a RouterOS time with milliseconds (`4m59s990ms`) is five minutes, not
  seventeen hours.
- On PostgreSQL every folding reported itself as number 0 (the driver's
  `lastrowid` is not the row's id there).
- Domain: the accounts named as expected to replicate the directory are
  compared whole - `svc.adsync` no longer excuses `svc.helpdesk`, and
  `*.sync` no longer excuses everybody. Controllers are matched as before.
  An address a client smuggled into its workstation name is not taken for
  the address the logon came from.
- The night the clocks go back, each log file keeps its own idea of which
  hour it is in: a firewall's log and a domain controller's no longer move
  each other's lines by an hour.
- With copytruncate and delaycompress, the copy that holds the unread lines
  is read, not yesterday's compressed file.
- ISE: a half-record from long ago is never joined to a new one that
  reuses its number; the same line arriving twice is still one record.
- tac_plus `stop` records are filed when the session ended; FTD's own
  stamp beats a relay's ISO one; RFC 5424 lines are from their host rather
  than from `-` (new lines only - older ones stay under `-`); FortiGate
  pairs written before `date=` are read (`devname` among them).
- PostgreSQL upkeep:
  - a split stopped part way no longer leaves a promise on the table that
    refuses every new line after the next midnight, and the rows it set
    aside are put back rather than dropped;
  - days missed while the daemon was stopped are made (today and the days
    ahead first), instead of their lines piling into the default part;
  - an index over a split table left part-built at a restart is finished
    from where it stopped, not dropped with every day's finished index;
    a day made meanwhile is not given a second copy of it; the narrow
    index it replaces stays until it is really there;
  - a day that could not be frozen is tried again in an hour;
  - a stride of the tidying that cannot be found is tried again later
    rather than turned into one enormous delete.
- The copy made before a restore or an erase is the engine's own dump on a
  big server (the portable copy was hours with a snapshot held open). Room
  is made for the nightly dump before it is made, so one full disk no
  longer stops the backups for good.

1.10.187

Another pass for faults, and for anything the pages or the reading of the
logs waited on that they need not have:

- Signing out with no session (a cookie already gone, or nobody signed in
  at all) signed EVERYBODY out: an empty token fell through to "end every
  sign-in". It ends nothing now; "end every sign-in" on the Sessions page
  has to say so in so many words.
- Settings read again (a HUP from logrotate, config.json edited, a setting
  saved from the command line) are replaced in one go. For as long as the
  database took to answer, every other thread used to run on the file and
  the built-in values - the nightly tidying included, with the default
  retention.
- Answers worked out again behind the pages are capped at 24 at once; past
  that the page is handed the last answer and the new one is asked for at
  the next poll. With the database slow they piled up until the machine
  would start no more threads - and the next one the log reader needed
  ended the daemon. A thread that cannot be started is now said, not
  fatal.
- Replacing the country list (three quarters of a million ranges) no longer
  holds the write lock every log waits for: on a database server it is a
  transaction of its own. The firewalls' fetches of the ban list no longer
  wait for that lock either.
- A purge of the router's lists, and the clearing owed to a router that was
  away, take the same one-writer-at-a-time lock as every sync. Two Banned
  pages at once start one count, not two; a ban remembered for the ladder
  can no longer be lost to the tidying running beside it.
- Directory lookups no longer take one of the four turns every page's
  answers share, nor hold a turn among the page's questions while the
  directory answers. A person's card is kept per realm and name (`corp-eu`
  + `jan` and `corp` + `eu-jan` were one card).
- The find box: an address typed in capitals (`FE80`) is found; a short
  prefix that would count most of every sign-in there has ever been gives
  way after three seconds to the addresses in order; names are counted in
  one statement a table instead of two per name.
- Popups: a domain event is looked for on its own day; an account's story
  reads the columns it shows rather than every packed record; a lockout's
  machines, an address's story and a VPN session are kept a few seconds;
  the remaining "is this the VPN" lookups seek the index instead of going
  through a function of the column.
- The router view pages the bans that have not reached it and looks up the
  history of the first sixty only - after the router's list was emptied it
  was a search per ban, thousands of them, before the page drew.
- The Domain page asks again five seconds after the answer arrives, never
  while one is still out, and its list of events waits for its search
  instead of starting it again every five seconds. The front page and the
  Traffic overview stop the question asked before when somebody chooses
  another window. The router read is numbered so an older answer cannot
  overwrite a newer one. Names for more than 400 addresses on a page are
  asked in the next round instead of never. A day's bar on Traffic is
  named after the UTC day it counts.
- `secrets=0` on the export is no longer read as yes; the firewall-field
  suggestions are kept per window.

1.10.186

Another pass over everything - faults first, then what a very large
database waits for:

- A host setting (router, second router, database server) is checked in a
  moment however it is typed. The pattern it was held to could be made to
  go back and forth for minutes by a long enough name, holding the page's
  thread the whole time.
- "Empty the other database" knows the database in use however its server
  is spelled: `127.1`, `127.0.0.2`, `[::1]`, `::ffff:127.0.0.1`,
  `localhost.localdomain`, the machine's own name or any address of its
  own are all the server right here. Before, any of those slipped past the
  check meant to stop the live database being emptied.
- The name of the address list (and of the country list) is refused when
  the router would be given a different one: "isemon bans" quietly managed
  a list called `isemonbans`. A name already in use is left alone.
- "What the routers hold" on the Banned page works when only the second
  router is in use.
- Two administrators changing accounts at the same moment can no longer
  together leave no full administrator: switching off, changing a role and
  removing an account are checked and written one at a time.
- The refusals that count towards a ban (the VPN, and the VPN through
  NPS) are found as two plain comparisons rather than through a function
  of the column, so PostgreSQL and MariaDB read them from the index over
  (kind, time) instead of every refusal in the window - the counting on
  the Banned page, the names being tried and the weighing every few
  seconds.
- The domain's counted answers are summed over three days once a day and
  over the last six hours on the other hours, instead of three days every
  hour.
- On PostgreSQL, yesterday's day of each split table is frozen and counted
  once, the day after, behind the daemon and never waiting for a lock - so
  the server's own emergency pass over every old day never has to come,
  and the planner knows yesterday's numbers the morning it is first asked.
- The firewall gauges on the Traffic overview read each line from its own
  day rather than from every day there is.

1.10.185

Searching, on a site whose firewall writes sixteen million sessions a day:

- A search of the firewall's lines narrowed by anything at all - a
  verdict, an address, a policy, a field in the box - now goes an hour at
  a time and stops when its time is up with what it found and how far back
  it looked, as a search by words already did. `verdict:block` over a day
  of sixteen million sessions ran out of time and showed nothing.
- A verdict no session let through can have (`block`, `fail`) is looked
  for only in the parts of each day that can hold it, with an index of
  its own over those parts (`fw_kept_verdict_ts`).
- The Sessions, Web and Threats pages no longer ask for lines "without a
  page" (written before 1.10.126) once there are none left: the question
  kept PostgreSQL off the index over the page and the time.
- A word typed into the Failed attempts and Logins boxes is an index
  lookup on PostgreSQL (`pg_trgm`, as the Domain page's already is): it was
  a walk of every refusal or sign-in in the window, five to ten patterns
  on each. Built behind the daemon once; where `pg_trgm` cannot be had,
  the boxes work as before.

1.10.184

Another pass over everything, for a site where nothing may wait for what it
does not need to. On the same two-processor test machine, 5,000 lines a
second and four people using the page, from the same empty database: 3,880
-> 4,350 lines a second taken, the slowest answer to the page 14 s -> 9 s,
nine answers in ten within 0.20 s (0.24 s).

- **Pages no longer reload every five seconds because the firewall wrote.**
  The firewall's lines move a serial of their own; only the Traffic page
  follows it (and the front page at most every half minute). The bans, the
  refusals, the events and the Domain page were fetched again on every tick
  of a busy site, by every person who had one open.
- **The counts and filter lists of the refusals and sign-ins are no longer
  thrown away for the firewall's and the domain's writes**, which made every
  one of them "out of date" every second; an empty answer was then refused,
  counted again, and the page waited for it.
- **Waiting for an answer somebody else is working out no longer holds one
  of the page's turns**, and a question that failed is said to everybody
  waiting on it rather than asked again by all of them at once. Three
  quarters of the processors answer the page at once, at least two (half,
  at least one, before).
- **The first status after a start does not wait for the dear counts** -
  today's numbers, the totals, the busiest addresses, the nodes: worked out
  behind it, drawn a moment later.
- **The front page's questions carry the asker's time limit**, and the page
  does not ask again while one is still out.
- **The country database is held in memory** (IPv4 as four bytes a range):
  every address a firewall line named that had not been seen before was a
  statement on the reader, hundreds a second when a scan reached new ones.
- **Where the files were read up to is not saved past lines the database
  refused** and that were handed back to be tried again: a lot written after
  a refused one saved positions past it, and a stop then lost those lines.
  While a backlog is read, the positions are saved at most once a second
  rather than with every lot.
- The catalogue of values is written behind the loop, and never from inside
  a lot's own write (where a lot refused afterwards undid all of it).
- The domain's controllers are asked behind the reader, not on it.
- A rotated file's lines already read are kept when the new file cannot be
  opened yet.
- A search asked again behind the page keeps its own words.
- Indexes: a device picked in the Failed attempts and Logins filters, and
  the ban history in the order it is shown.

1.10.183

- **The VPN of a week is the newest lines again, read newest first a page
  at a time.** 1.10.182 read every line of the week forwards - on a head
  end writing a million VPN lines a day, seven million, minutes of it -
  and the 1.10.181 way of finding where the newest two hundred thousand
  began was one statement counting back over all of them. Now each page of
  five thousand starts where the last one ended, newest first, goes to a
  file of its own, and the pages are then handed to the folding oldest
  first: the same lines as before 1.10.181, a page of them in memory.
- **The Traffic page no longer waits for it.** While the VPN is first being
  put together after a start, the page is told so at once and asks again
  in a few seconds; every request used to wait a minute for the same
  answer, until the page said the daemon was not answering.
- The ids kept to tell a line read twice are let go of now and then rather
  than after every page.

1.10.182

- **The VPN of a week no longer starts by counting back two hundred thousand
  lines.** 1.10.181 found where the newest of them began with one statement
  that did exactly that, and on a busy head end it ran past its two minutes,
  was stopped, and the Traffic page had no VPN at all. The week is now read
  forwards from its start a page at a time, each page beginning where the
  last one ended on the time index - every line of the week, however many,
  with only a page held at once.

1.10.181

What the watch added in 1.10.180 found on a busy site: every time the whole
program stood still, the Traffic page's VPN was reading its week.

- **The VPN of a week is read a page at a time** (5,000 lines), the two
  kinds merged as they come and fed to the folding as they arrive. It was
  read whole - two hundred thousand lines of each kind, each a row and then
  a dictionary with its fields unpacked, all held at once and sorted: well
  over a gigabyte on a busy head end. The same lines, the same answer.
- **The daemon may use half of the machine** (`MemoryMax=50%` in
  `isemon.service`) rather than 768 MB. A unit at its cap is not killed at
  once: every thread of it waits while the kernel finds memory - the page
  cache of the logs it reads is charged to it too - which was the program
  standing still for half a minute at a time and the dashboard saying the
  daemon was not answering. `install.sh --upgrade` puts the new unit in
  place; a drop-in of your own under `isemon.service.d` still wins.

1.10.180

For a site where everything is slow and the database server is not: its
connections from this program were seen "idle in transaction" for eight,
fourteen and thirty-eight seconds, two at the same moment, holding rows
everything else then waited for.

- **The moments the whole program stands still are found and written
  down.** A watch outside the interpreter (Python's `faulthandler`) writes
  what every thread was doing into `isemon-stalls.log` beside the log when
  nothing could run for 5 seconds, and the log says it happened.
- **A transaction held open with nothing asked of it for 5 seconds** is
  said in the log with the thread holding it, its last question, what
  every thread is doing and what the database server says each connection
  is waiting for. At most once a minute each.
- A slow statement's line in the log no longer asks the database whether a
  counting is running elsewhere - from inside the statement's own
  transaction, or on a second connection while the first held its locks.
  The watchdog asks every few seconds instead.

1.10.179

- **Who did it, in the log and among the events.** Every ban, every ban
  made longer or for good, every letting back in, every fold, unfold and
  undoing of one says either "automatically" - with why: the counting, the
  ladder, a public list, a ban that ran out, the fold every N hours - or
  "by <name>". A ban that ran out left no line in the log at all before;
  a fold left none either, and now names the subnets it made.

1.10.178

Nothing slow on the loop that reads the logs, and fewer reads of the same
rows:

- **The Banned page with thousands of bans.** Its answer was two megabytes
  and was worked out and sent again with nearly every poll: the stamp that
  says "nothing has changed" moved every time any banned address was
  turned away again. It no longer moves for that (the counts are brought up
  to date once a minute), each ban carries its first six names rather than
  twenty-five (the popup has them all), and the names and counts that have
  gone out of date are handed out as they were and asked again behind the
  page - every ban's names ran out together every ten minutes, and the page
  that asked then waited for a count over every attempt those addresses
  ever made. 2.2 MB -> about 1 MB for 1,900 bans.

- **The housekeeping, the folding, the public lists and the directory run
  behind the loop**, each one at a time, instead of on it. On a big
  database the housekeeping was tens of seconds a pass, a list download
  minutes and a slow domain controller as long as it took to answer - and
  no log was read meanwhile.
- **A list is downloaded to its end before the database is written.** The
  country database and the public lists were read from the network inside
  the write, so every other writer, the logs' included, waited for the
  download.
- **A failed nightly copy is not started again every five minutes**: an
  hour later, then two, four, six. On PostgreSQL or MariaDB above 8 GB no
  row-by-row copy is made in its place, nor instead of a dump where the
  dump client is missing - hours of reading, on the disk the dump has
  probably just filled. Said once a day.
- **The ban history (`block_events`) is let go of** after as many days as
  the log is kept and the ladder counts (never, where the ladder never
  forgets). The history of bans has an index on when each ban ended, which
  is what it is tidied by.
- One clean-up at a time: the pass, the daily one and the button no longer
  run the same deletes side by side.
- The tables held to a cap are counted before the write is taken, and only
  one over its cap takes it.
- The check for anything over the bar asks about the devices only when
  something is over it, and finds the bans among those by their key rather
  than by reading the whole list every five seconds.
- People waiting on the same slow answer are told it is busy rather than
  all asking it again at once when the first has not finished in a minute.
- Folding finds each address's subnet by its own supernets, asks what each
  ban was for in one statement, and an automatic fold plans once.
- The catalogue of values is written a thousand at a time, each its own
  write. The rollup check is one walk of the window rather than seven.
- A whole day let go of on PostgreSQL waits under a second for its turn, a
  few times over, rather than five seconds with the table locked behind it.
- **Domain page.**
  - The filters beside the event list are counted over the dates picked
    (they were counted over every event ever kept when dates were picked)
    and kept under them; the popups do not ask for them at all.
  - The page is drawn again by itself when something moves, at most every
    half minute.
  - The lockout popup asks for the refusals around it, not the newest forty
    of anything.
  - The overall answer is kept under the machine-accounts setting.
  - A machine has an index over its name in any case; an IPv4 address is
    asked of its index.
  - Identical events split across two reads are counted per controller.
  - An event counted twice when the live reader and a pass back read the
    same lines: what is already there is asked inside the write.
- An address typed in capitals, the IPv6 way or as /32 is the same address
  in its popup and in the search box; its ban history is its own, by key.
- An emptied search box no longer shows the answer to the words before.
- A switched-off full administrator can be made something else or removed.

1.10.177

What a very busy site showed, two thousand bans and a VPN head end of two
hundred thousand lines a week:

- **The VPN as it stands is put together from what arrived since the last
  look**, added to what was made of the lines before. It read the whole
  week again every few minutes - two hundred thousand lines from all over
  the disk, two minutes each time, with every other question of the
  database waiting behind it - and the Traffic overview with it. Each look
  reads from shortly before the newest line it has of each firewall, so a
  firewall whose lines come late is not passed by; the whole week is read
  again every three hours and after anything is erased, and a read that
  fails is not kept as the VPN for those hours.
- **The public lists are held in memory** (up to two million ranges), so
  "which lists name this address" is a look in memory rather than a
  statement for each list. The Banned page and every sync of the router
  asked it for every ban: two thousand bans and ten lists were twenty
  thousand statements.
- **The sync of the router asks only what it needs** of each ban, not the
  whole Banned page with its names, counts and lists.
- **The names tried from each banned address, and its day's count, are kept
  a while for each address** and counted only for the ones not kept: they
  were counted for every ban each time one more was made.
- Pages of the VPN for one firewall no longer wait for another's.
- The check of the whole database at start, and the indexes built behind
  the daemon, are slow on purpose and say so themselves: no longer a
  warning for every statement. A search stopped by the page is not one
  either.

1.10.176

On the same two-processor test machine as 1.10.175, 5,000 lines a second
and four people searching, from the same empty database: 1,700 -> 2,170
lines a second taken, the longest answer to the page 20 s -> 9 s, and a
search for a word in the Traffic list answered in 1.2 s rather than 4.8 s
nine times in ten.

- **PostgreSQL.**
  - The split tables let go of a whole day at a time by default (rows are
    kept up to a day past their setting), where every aged row was deleted
    on its own - the deleting, its log and its vacuum all day long.
  - The counted buckets' days are made with room in each page, so an
    addition rewrites its row in place; the catalogue of values and the
    domain's counts get the same once.
  - The refusals and sign-ins are vacuumed and analysed after every 2% more
    rows rather than 20%. Two indexes on the refusals that are the first
    columns of two others are taken away (PostgreSQL only).
  - The writes of what was read from the logs do not wait for the disk at
    their commit; where the files had got to is saved after them, so a crash
    of the server can only mean lines read again.
  - Connections are named in `pg_stat_activity`, and a transaction left idle
    is let go after half an hour.
  - Settings -> The database -> Tune also sets a checkpoint every quarter of
    an hour and caps each vacuum's memory.
  - The word index of the domain's events on a split table is built a day at
    a time, without holding the writes up.
  - Splitting a table waits for its turn a few seconds at most rather than
    holding every reader and writer behind it.
- **Searching.** A search for words in the Traffic list reads an hour at a
  time, each statement stopped by the server when the page's few seconds
  are up; the page says how far back it looked. A statement stopped at its
  limit keeps its connection. The status counts the bans rather than reading
  them all; the global search asks the bans of the database; the rescan
  popup's total is kept a minute; the tabs of a list count the window the
  list shows, end as well as start; a short list of events is its own
  count.
- **Reading the logs.**
  - A line a parser cannot take costs that line, where it cost the whole
    window read (up to 8 MB).
  - A rotated file already compressed is read to its end over several
    passes, where it stopped after 64 windows; one rotated again while it
    was still being followed is found again and read to its end.
  - A file emptied in place no longer reads last week's rotated copy as
    "recovered".
  - What was read of rotated copies counts against the firewall's budget.
  - A tac_plus `start_time` from no real moment is not believed: it stopped
    that file from being read at all, even after a restart.
  - An FTD line without a time stamp keeps its id when read again.
  - ISE's time stamps are read once a second (29 -> 2 us a record).
- **Banning and the router.**
  - Each command sent to the router in a batch has an `on-error` of its own:
    one the router refused took the rest of its batch with it, the same
    addresses every sync.
  - A ban longer than RouterOS keeps a timeout (35 weeks) is written without
    one and taken off when it ends.
  - A ban whose time has run out keeps nobody out before the sweep comes.
  - Bans and the whitelist written another way than the one compared by (an
    IPv4 address written the IPv6 way, upper-case IPv6) are written again,
    once - they could not be taken off from the page.
  - An address range in an ISE record is not taken as the address that
    tried.
  - A ban by hand is from one minute to a year, or for good.
  - "Never kept out" refuses `0.0.0.0/0`; an imported configuration's bans
    and whitelist are checked as the page's are, and never cut short a
    longer ban.
  - Switching the blacklist off waits for a sync already going.
- **API.** Pruning the authentications lets go of what was kept about them;
  a list worked out while data was erased is not kept; two presses of a job
  start it once; a name asked of the directory is cut once, before both the
  key and the asking.
- **The page.**
  - Closing a job's popup no longer stops what comes after the job (the
    country list after the ban list, the page drawn again after an erase).
  - A database is restored only with a header of the page's own.
  - The ban list draws only the newest answer; only the ban cells that
    changed are drawn again.
  - A page past the end of a list goes to the last one; sizes sort in 1024s;
    suggestions do not reopen after the box was left; Escape in the country
    picker does not close the popup; a setting changed while others were
    being saved is kept; "yesterday" and "this week" start at midnight
    across a change of the clocks.
  - The Domain page and the Traffic overview do not ask while hidden.

1.10.175

- **Five thousand lines a second while the page is searched.** The
  readers are cheaper: a FortiGate line is taken apart by one expression
  (74 -> 53 us), an FTD head is read once per second it was written in,
  the packed detail starts from a ready compressor, and a line with
  nothing to clean is not copied to be cleaned. Each firewall file gets
  its share of a pass, so one big FortiGate file is no longer held back by
  many small ones. On a two-processor test machine taking 5,000 lines a
  second with four people searching, from the same empty database: 1,060
  -> 1,920 lines a second taken, and nine in ten of the page's answers in
  0.4 s rather than 4.2 s.
- **ISE's refusals a third cheaper** (2.5 -> 1.6 ms each on the test
  machine). A lot of records asks once for the bans, the earlier bans let
  go and the marks of every address in it, where it was a statement for
  every refusal; the hits of an address still trying while banned are
  added up and written once a lot; and a lot is taken without a savepoint
  a record - one record refused undoes the lot and it is taken again with
  them, as before. The same bans, to the record.
- **A search cannot hold the writing up.** Every question from the page
  is stopped by the server after 25 seconds (the page says so, and what to
  narrow); what is worked out behind the page - kept lists, counts, the
  drop-downs - takes a turn, as many at once as half the processors, and is
  stopped after two minutes. Counts on a table split by day are made a day
  at a time with a budget of time; a word searched for stops reading back a
  second and a half after the page is full; an address range of /8 or
  narrower is said to the database exactly instead of read back; the
  Failed list no longer reads the packed detail it does not show. Lists
  asked again within a minute are answered from what was kept, and counts
  are worked out again at most every fifteen seconds while records arrive.
- **The database away is not records lost.** A database restarted or out
  of reach: what it did not take is held (up to 200,000) and given to it
  again, and where the files had got to is not saved until it has; a
  question that only reads is asked again once on a fresh connection; the
  firewall is read no further while its writer is refusing (for ten
  minutes at most: a disk that stays full is not waited out with every
  file standing still). Windows events are tried again five times, or for
  half an hour while it is away. Stopping with records not taken does not
  save where the files had got to.
- **Bugs.**
  - An FTD head with the relay's stamp and the firewall's was remembered by
    the relay's: every line in that second got the first one's time.
  - The management centre's end of a session (430003) beside the
    firewall's (302014) counted its bytes twice; the second copy of a
    command (111008) was dropped instead of kept as a line.
  - The lines FTD pairs up are remembered from one read to the next, so a
    pair split across two reads is still one.
  - A log rotated between being looked at and being opened was read from
    the old offset.
  - Renaming the router's list or the country list leaves no entries of
    ours behind under the old name; changing the router's address is said
    in the log.
  - A ban of a range shows a button to let the range in; the router's user
    is written into the page as text; the status tick drops an answer that
    came after a newer one.
  - A connection could be kept from going back to the pool after a
    drop-down was refreshed; a country typed with `_` or `%` matched more
    than it said.

1.10.174

- **Tuning the database server: a popup wide enough for its table.** Each
  setting's name, what it is now, what it is worked out to be and when it
  takes effect stay on one line - "8.0 GB" broken in two was not a number
  anybody could read; only the why wraps. The facts above it are as wide as
  what they say, and the server's version is said without the package it
  came in.

1.10.173

- **Settings -> The database -> Tune it for this machine.** A database
  server is installed with settings for a small machine: PostgreSQL keeps
  128 MB of the database in memory, MariaDB likewise, on a VM of 32 GB. The
  button reads what the machine the server runs on has - its memory (a
  container's limit counts), its processors, whether its disk is an SSD -
  works the settings out for it and shows them beside what is there now,
  each with why. Nothing changes until somebody presses *Put it in*.
  - **Read from the machine.** A server on this machine is read from this
    machine's own files - and "on this machine" is checked, not assumed from
    127.0.0.1: PostgreSQL's postmaster has to be a process here, MariaDB has
    to say this machine's name, or it is a tunnel or a container and counts
    as elsewhere. A MemoryMax on the server's own service counts. A server
    elsewhere is read as PostgreSQL's administrator (`pg_read_file` of
    /proc), or typed in. In a virtual machine, where every disk says it
    spins, thirty small writes are timed instead, less the time a question
    takes to go there and back: about a millisecond is an SSD. Every value
    can be put right in the popup and the plan worked out again - memory
    only downwards on a machine that was read, and numbers that were only
    typed are put in once somebody ticks that they are that server's.
  - **PostgreSQL**: the arithmetic of docs/postgresql-tuning.md -
    shared_buffers a quarter of the memory, effective_cache_size three
    quarters, work_mem small enough for the connections allowed,
    maintenance_work_mem, the parallel workers for the processors, WAL sized
    for the free disk, random_page_cost and effective_io_concurrency for the
    disk, autovacuum, jit off. Put in with ALTER SYSTEM and a reload;
    shared_buffers waits for a restart. A larger shared_buffers is asked for
    only as far as the memory free right now allows - a server that asks for
    more than there is at its start does not start.
  - **MariaDB**: the buffer pool (half the memory), the redo log, the I/O
    capacity and flushing for the disk, the I/O threads, the temporary
    tables. Put in with SET GLOBAL, at once; what the server takes only at a
    start - a buffer pool past the `innodb_buffer_pool_size_max` a newer 10.11
    was started with, which it otherwise cuts down with a warning - comes in
    the file to keep it all: `/etc/my.cnf.d/zz-isemon-tuning.cnf`, named to
    be read last.
  - **Who may.** This program's own account where it has the right;
    otherwise an administrator, typed into the popup, used for that one
    request and stored nowhere - not in config.json, not in the database,
    not in the log. Only settings worked out by the daemon are put in, never
    values sent by the page.
  - A setting somebody set higher than the plan, within what is safe, is
    left alone. `max_connections` is never touched.
  - **Restart.** Where PostgreSQL is on this machine, install.sh lets the
    `isemon` account restart it - restart, and nothing else (a polkit rule,
    deploy/49-isemon-database.rules; `--no-db-restart` leaves it out) - and
    the page offers to. The service restarted is the one whose main process
    is the postmaster this program talks to, never Debian's
    postgresql.service that restarts every cluster. Not when it may not come
    back: a shared_buffers larger than the memory free now, or huge_pages on.
    The daemon waits for the server it started (not the one still shutting
    down), within what the web server waits, and carries on; if it does not
    come back, the page says which line to take out of which file.
    Otherwise the page shows the command.
  - **Put back as it was** goes back to what was there before the first
    press, on the server it was put in on: what was in postgresql.auto.conf
    goes back there, what was not is reset. A setting somebody has changed
    since is left as it is, and said so.
  - The card says what was put in, when and by whom, what still waits for a
    restart, and - on MariaDB - when a restart has since undone it.
  - The note about a cache too small for the database offers the button.

1.10.172

- **Four thousand events a second.** Measured on a two-processor test
  machine, with PostgreSQL on the same two processors and logs read as fast
  as they could be: the firewall's lines and ISE's records together at
  3,500-5,500 a second against a database of 40 million rows, where the same
  test gave 2,400-3,000 before. With PostgreSQL on processors of its own and
  its cache set for the machine (below), there is room to spare.
  - **The firewall's lines are written behind the reader**, by a thread of
    their own, while the reader reads and parses the next pass. The reader
    makes each lot ready (FTD's lines paired, each line once, the rows and
    their packed details made); the writer only writes. One lot at a time,
    in the order they were read, at most two waiting. Where the files had
    been read up to is saved once that lot is written, never before - the
    order the reader has always kept. A pass back over the files, the
    checks and a stop wait for the writer first.
  - Lots waiting are written as one, and a transaction adds up twenty
    thousand lines' counted buckets instead of five: the buckets were more
    of the database's work than the lines.
  - On PostgreSQL and MariaDB, writing the firewall's lines no longer waits
    for the sign-ins being written, nor they for it: each is a transaction
    of its own on tables the other does not touch.
  - While it is behind, the reader comes straight back for more instead of
    resting a fifth of a second between passes - it spent two thirds of its
    time asleep while it fell behind.
  - Each thread is let in within a millisecond, rather than five, after it
    has waited for the database or packed a record: the reader and the
    writer were waiting on each other instead of working side by side.
  - ISE's records: the savepoint each is undone to is let go of and the
    next one made in one round trip on PostgreSQL, rather than two.
- **Settings -> The database** says when the database server's own cache is
  left as installed (PostgreSQL's 128 MB) and the database has outgrown it:
  its indexes are then read off the disk for every line written, and that,
  not this program, is what limits how many events a second it takes. With
  how much memory the machine has and where the numbers for it are
  (docs/postgresql-tuning.md: on 32 GB, `shared_buffers` 8 GB).

1.10.171

- **The page no longer holds up the reading of the logs.** Measured at a
  thousand events a second on a machine with two processors, with six people
  asking the page everything at once: the reading fell to nothing for
  minutes and was hundreds of megabytes behind. Now it keeps reading at
  85-100 % of its pace and catches up as it goes.
  - **The VPN as it stands** (the Traffic tab's VPN page, its count on every
    page of the tab, the person page) was put together by walking every
    open session for every line of the week - 25 s of the daemon's one
    interpreter on a busy head end, every 20 s. The sessions are now looked
    up by person and by address: the same answer, field for field, in under
    2 s, and kept a minute.
  - **The page's questions of the records take turns**: at most half the
    processors' worth at once, the rest waiting (up to 20 s, then "busy, try
    again"). Whether the daemon is there, its status, signing in, Stop, the
    bans themselves and the ban feed the routers fetch never wait.
    `/api/status` says how many are waiting (`api_gate`).
- **An address banned and still trying** cost 80 ms of the reader for every
  try - whether any of them offered a name that was never an account was
  answered by reading all its tries since the ban (38,000 in an hour from
  one address). An index answers it in 0.2 ms (built behind the daemon after
  the upgrade; not on MariaDB). The reading went from a few hundred records
  a second to 2,000-3,700 while catching up.
- The subnets on the ban list are no longer read again for every refusal
  while an attack lengthens single bans several times a second.
- **The Traffic list ordered by Bytes** ordered every session of the window
  to show a hundred: 14 s over a week. It now starts from the sessions that
  carried a megabyte or more (an index of under 1 % of them): 0.05 s, the
  same page. Not on MariaDB.

1.10.170

- **Nothing the database does at night holds up the reading any more.**
  - The nightly dump is made on a thread of its own. On a 90 GB PostgreSQL
    database it took seven minutes, during which no log was read at all -
    the watchdog said the loop had not come round, and the morning's lines
    piled up behind it.
  - The firewall's old lines and counts are let go of behind the loop too:
    seconds every pass on a big database, and once a day...
  - ...a minute walking the part of the table from before it was split by
    day, to find nothing. That part only ever gets smaller; it is now walked
    again only when something has gone into it (a line read late), or once
    a week.
  - Whether a walk of old rows got all the way is each thread's own answer,
    so the daily clean-up and the firewall's cannot read each other's.
- **The page could not read the API token for up to a minute after every
  log rotation.** `systemctl reload` sets the service's run folder back to
  the service's own group; the daemon now gives the token back to the web
  group as it takes the reload, instead of at the next check a minute later
  (which said "the page could not have reached this daemon" every night).
- A rotated file read to its end - nothing lost - is said as information
  rather than as a warning, with its folder, so two firewalls' files of the
  same name are told apart.
- **Settings -> The database, with PostgreSQL or MariaDB on this machine:**
  the page said "the database itself is on isemon@127.0.0.1" as if it were
  elsewhere, and left out how long the disk will last. It now finds where
  the server keeps its files (asked of the server, or its usual folder) and
  says whether that is the same disk as the copies - then it counts the days
  left - or a disk of its own, which is then measured and counted on its
  own. These sentences are translated now as well.

1.10.169

- **The Traffic cards put first what they are about.** On a card ranked by
  the refused (Refused, from; Refused, at which port; Countries knocking)
  the bar of each row begins with the refused, and its numbers and the
  words under the pointer begin with them too; on the drops the dropped,
  on the downloadable ACLs the refused, on the intrusions, malware and
  Security Intelligence the blocked, on the failing tunnels and the names
  that do not resolve the failures. Each card keeps one order on all its
  rows, so the colours line up; the cards about everything (Who talks the
  most, Services...) keep the usual one, let through first.

1.10.168

- **Large data and many events a second: the pages ask for less and the
  answers are quicker.** Measured with 1,000-3,000 events a second coming
  in (firewall, ISE refused and passed) on PostgreSQL; the reading keeps up.
  - The Banned page asks every few seconds only whether anything changed,
    and gets the bans without the evidence behind each (it is fetched when
    a ban is opened); the history is fetched on its own. The ones about to
    be banned are sent up to 1,000 at a time.
  - Whether an address is banned is looked up by the address first, and the
    banned ranges are kept for a few seconds instead of read for every line.
  - New indexes (built in the background after an upgrade) for the Traffic
    tops, the bans' expiry and the destination port.
  - The Traffic tops are picked by PostgreSQL itself rather than all groups
    read out; the ISE names beside the addresses are read in batches.
  - Counting the rows of a slow word search stops after a few seconds and
    says "more than"; the pager then offers Next instead of a last page.
  - The VPN page is sent a page at a time (200 clients or tunnels) and
    searched on the server - it was several megabytes and froze the browser.
  - The Traffic sub-pages refresh only their counts; the status poll leaves
    out the log list except on the Overview and Logs tabs; the suggestions
    under the Traffic search are kept for half a minute.
- **The page:**
  - A refresh no longer throws away what is being typed or selected - it
    waits (at most half a minute) and runs afterwards; nothing is fetched
    while the browser tab is hidden. The first load fetched the status twice.
  - "Everything about" closed the window it had just opened.
  - Ctrl+K: Escape and Tab stay in the box, and the focus goes back where it
    was.
  - Placeholders and hints of the boxes are translated; numbers in Czech have
    spaces between thousands and a decimal comma, and sort and search as
    shown.
  - The time left of a ban counted from the wrong clock.
  - A hidden Traffic page opened from a link (#traffic/vpn) is shown.
  - The clock warning for a firewall with its own time zone points at that
    firewall's zone, not ISE's.
  - Translations and repeated sentences tidied ("stále platí", "bude
    zablokována").

1.10.167

- **OTP: `from:` (and the machine, the VPN group, the box that asked) finds
  only the attempts that column shows it beside.** Where the token server
  passes on the head end's address as the id of every packet, 1.10.166
  matched by that id alone and a search for one person's address listed
  everybody who signed in near the same time. The search now gives each
  attempt its packet exactly as the page does, and keeps those whose packet
  matches.
- **Values typed as a column shows them were not put back on a page in
  English** - only once a language was chosen - so `how:"the token was
  right"` found nothing. They are now in every language.
- **tac_plus:** `service:` is the column headed Service.
- **The Traffic page:** `service:` finds the application shown under the
  service as well; `policy:` takes the policy's name shown under its
  number, and `local-in`.
- The fields offered match the headings of the optional columns too
  (Groups, Failure code), and the OTP cards' Where from and Token server;
  NPS's refusals offer Server rather than Node.
- Checked in a browser, every field of every card: the sign-ins and the
  refusals on every door, the domain, the events, the ban history and every
  page of the Traffic tab - a value read out of a column, searched for,
  every row found showing it and none of the rows turned round showing it.

1.10.166

- **Every search box offers the columns of the card it is on, and each
  field finds what its column shows.**
  - The sign-ins and the refusals: each door offers its own columns, by
    their headings and in their order - on eduroam `name`, `institution`,
    `endpoint`, `address`, `ap`, `network`, `vlan`, `controller`, `server`;
    on 802.1X `endpoint`, `address`, `switch`, `port`, `profile`, `vlan`... A
    letter typed offers the rest of what the rows hold as well.
  - eduroam: Address, Access point, Network and VLAN come from the
    accounting kept beside the sign-ins, and are searched there - `ip:10.88.*`
    found nothing, because it searched the controller's address in the record.
    A plain word finds them too.
  - 802.1X and MAB: `address:` (and `ip:`) is the machine's address in the
    Address column, not the network device's. Behind NPS, where the address
    and the VLAN come from the controller's accounting, they are searched
    there as well.
  - A VLAN is found as it is shown - `vlan:607`, `vlan:"VLAN 607"` or by its
    name - however the record wrote it (`607|LAN_Odbor`, `|LAN_Odbor`, or a
    name this site pairs with that number).
  - The VPN: `firewall:AnyConnect_X` is the short name the Firewall column
    shows. NPS's VPN: `policy:` is the column headed Policy.
  - TACACS+: `command:conf*` finds the sittings those commands were run in.
  - OTP: `from:`, `machine:`, `vpngroup:` and `asker:` are out of the RADIUS
    packet beside each attempt, as the columns are; `how:` and `account:`
    are the two columns of the sign-ins. `country:` there says it cannot be
    searched (the country is worked out from the address) rather than
    finding nothing.
  - A word on its own, a second word, a word in brackets or after NOT: all
    looked for in the same columns as the first one.
  - `door:vpn` finds the sign-ins with no door written on them, as the
    doors count them.
- **Values typed as the column shows them**, in either language: "the token
  was right", "signed in", "let through", a country's two letters on the
  Traffic page, `#6` for a policy, "the counting" for who banned it. Values
  offered show those words beside what is kept.
- **The domain:** `from:` is the machine, or the address where there is
  none; `through:lsass.exe` the program by its name; `why:` what the domain
  said or what was changed.
- **The Banned list:** `member:` finds a subnet by an address folded into it
  (it found nothing); `hits:>10` and `name:` are new.
- **The Traffic page:** the box offers the page's own columns first; `cat:`,
  `data:>1M`, `lasted:>1h` and `source:` are the headings' names.
  - **A row of an overview card** - Refused, from; Who talks the most;
    the countries - opens on every line rather than on Sessions. The cards
    count every line the firewall wrote (a failed VPN sign-in, what it
    said about itself), and an address refused only at the VPN's door was
    "Nothing matches" on the Sessions page. Cards that keep to the
    sessions still open there. The same for the firewall chips in an
    address's popup.
- Nothing is written anywhere new and nothing about the database changes;
  going back to 1.10.165 is the old searching.

1.10.165

- **A third role: ban admin** (`banadmin`). It sees every page as read only
  does, and may also:
  - ban an address, for a while or for good, from anywhere a Ban button is
    (the Banned page, an address's popup, a record, the box at the top);
  - let an address back in, which also takes a folded subnet apart;
  - put the lists on the firewall ("Put the lists on it", including the
    country list where it is set up).
- **What a ban admin may not do**, and the daemon refuses even when asked
  directly:
  - let everybody back in at once;
  - start the counting again or erase the history;
  - fold into subnets;
  - take ours off the firewall, or touch its keys;
  - change any setting, the whitelist, or the accounts.
- **Local accounts:**
  - `isemon --add-user NAME --role banadmin`.
  - On *Settings → Accounts*, each account's role is now picked from all
    three rather than swapped between two.
- **Directory accounts:**
  - A new setting under *Active Directory*: *The group that may ban and let
    back in* (`directory_banadmin_group`). The group list there offers it
    beside Full admin and Read only.
  - Full admin wins over ban admin, and ban admin over read only.
  - With no group of any role filled in, everybody the directory knows reads,
    as before. (Changed in 1.10.221: with none filled in, nobody from the
    directory gets in.)
  - With only some filled in, somebody in none of them gets in nowhere.
  - The check of the directory looks for the new group as well.
- **Going back to 1.10.164:** an account left as `banadmin` still signs in,
  and may only look, as read only does.

1.10.164

- **The bars on the Traffic overview's cards now show every colour that
  the numbers beside them are written in.**
  - A row reading "130 let through · 498,831 refused · 41,298 said" was
    drawn as one red bar. Two things caused it:
    - A piece was its own width against the longest row, with a floor so
      small that a hundred beside half a million was a two-pixel sliver,
      rounded away at the end of the bar.
    - The floors added up past the end of the bar and pushed the last
      colour out.
  - Now the bar is as long as the row's total against the fullest row.
    Its colours share that length by their counts, and each is at least a
    few pixels wide.
  - The "refused" cards also draw everything the row holds, the same
    numbers that are written beside them. They are still ordered by how
    much was refused.
- **The hour-by-hour chart** draws every colour an hour has at least two
  pixels tall. A dozen let through beside a hundred thousand refused was a
  tenth of a pixel, so the hour looked as if nothing had been let through.

1.10.163

- **Every search box understands fields**, as the Traffic page's always
  has, and offers them as you type.
  - Covered: Failed attempts, Logins, Domain, Events and the ban history,
    every list in a popup, every list on a card, and the groups of bans.
  - Click into a box and it lists the fields that list has, each with what
    it is and an example. Type `field:` and it offers the values the field
    holds, most common first. ↑ ↓ choose, Tab or Enter takes one, Esc
    closes.
  - What you can type:
    - `user:novak`
    - `user:novak,mkral` (any of them)
    - `-user:admin` or `user!=admin` (not)
    - `reason:*password*` or `reason~password` (has it inside)
    - `ip:10.1.0.0/16`, `ip:10.0.0.0/12` or `ip:10.1.*`
    - `mac:98fc.84e0.29d6`, written any way
    - `event:4625,4740-4771`
    - `hits>10`
    - brackets with `OR`, and words beside the fields.
  - A box with no field in it searches exactly as before. A MAC, an IPv6
    address or a time typed on its own is still a word.
  - Something the daemon cannot read, a range too wide for instance, is
    said under the box rather than answered with an empty list.
  - On the lists the daemon searches, the fields are read by the daemon and
    become part of the database query, with the same window and door as the
    list.
    - The values offered come from the catalogue of values where it keeps
      that column, and otherwise from the newest 20,000 rows of the window.
      Either way asking is cheap on any size of table.
  - On lists already in the page, a field is a column of the table by its
    heading (`why:`, `country:`, `how-it-ended:`), and `field:word` finds
    the rows whose column has the word.

1.10.162

- **The VPN as it stands** (Traffic → VPN, and the count on the Traffic
  overview) is worked out from far fewer lines.
  - It used to read a week of every remote-access line with all its fields,
    up to 200,000 of them: on a firewall facing the internet that took over
    a minute, and while it ran the whole application answered slowly.
  - Refused sign-ins are no longer read for it. They were read, unpacked and
    then skipped.
  - A FortiGate's statistics older than 30 hours are no longer read for it.
    A FortiGate writes them every few minutes for every tunnel, and only the
    newest says anything new.
  - The answer is the same: the same people, the same start, the same
    counters, the same tunnels. `test/fixes162.py` compares it with every
    line read.
- **The size of a table on PostgreSQL** (the database page, "what can be
  erased") is read from the catalogue without locking anything. It could
  wait half a minute behind other work on a busy server.

1.10.161

- **A firewall filed a file per kind of message** (rsyslog's usual way with an
  FTD or an ASA) is now one row per folder in `isemon --status` and on the
  Logs page.
  - It used to be a row for every file, and that is a file for every kind of
    message the firewall has ever written: logrotate makes each one again,
    empty, every night.
  - The folder's row adds up what its files hold. It also says how many are
    *quiet*: nothing new for as long as the firewall's lines are kept.
  - A file with something wrong with it (not there, may not be read, dated
    ahead) keeps a row of its own, so trouble is never folded away.
  - `isemon --status --files` lists every file. On the Logs page, pressing
    the folder's row shows or hides them.
  - Nothing about the reading changed: every file is still followed, its
    rotated copies too, and `isemon --rescan` reads them exactly as before.
    Files on disk are only ever read; deleting them stays with logrotate.
- **`isemon --status`, "who has been busy"** no longer lists a firewall's
  folders as machines that wrote no authentications. The Logs page already
  left them out.

1.10.160

Mostly speed on PostgreSQL with a lot of data and a lot of events a second,
plus a round of making the pages behave the same way everywhere.
`test/fixes160.py` checks each faster answer against the slower one it
replaced, on the same rows.

- **Taking in records**
  - **Records are written several hundred to a transaction.** It was one
    transaction per record.
    - A lot holds up to 500 records or half a second.
    - Each record has its own savepoint. One that fails is undone alone and
      then taken on its own, exactly as before, so a bad record loses
      nothing else.
    - On a mixed real log on PostgreSQL this went from about 1,100 to about
      2,500 records a second. A steady 2,000 a second is kept up with, and
      bursts of 5,000 and 10,000 are caught up.
  - **A file that still has more waiting is read again at once**, rather
    than on the next tick.
  - **Firewall lines are read faster.** The fields are split in one pass
    and the counted hours are added up by the hour first. The sums are
    exactly the same.
  - **Whether an address is already banned** is asked once for the whole
    list when many addresses cross the line together, instead of once
    each.
  - **The time a session was last used** is written at most every 30
    seconds, not on every request.
- **Big tables on PostgreSQL**
  - **The Traffic list in time order** is read a day at a time from the
    end it starts at, so only the days it needs are looked at.
    - The overview over dates went from 3.75 s to 0.48 s.
    - The firewall's own events went from 0.95 s to 0.04 s.
  - **Opening one firewall line** looks only in that line's day.
  - **The newest line** (asked every few seconds while a page is open)
    looks at the last two days first.
  - **"What can be erased"** uses the database's own estimate for a huge
    table instead of counting it. It went from 4.6 s to 0.03 s.
  - **Going back over every domain event** went from hours to minutes.
  - **A day of a split table that has aged out** is detached and dropped,
    rather than emptied where it is.
  - **New setting: *Let the split tables go a whole day at a time*.**
    - It is off by default, so nothing changes until somebody turns it on.
    - On, rows are kept until the end of the day they age out in, and that
      day goes in one step. That is much less writing on a big database.
    - The cost is that each kind of row can be kept up to a day longer
      than its setting says. That is why it is a choice and not the
      default.
- **The pages**
  - **Every paged list has the same four buttons**: First, Back, On, Last.
    Some lists said "newer" and "older", which was only true while they
    were ordered by time.
  - **Pressing a heading for the first time** puts numbers, sizes and times
    biggest and newest first. This is what the lists ordered by the daemon
    already did. Words and addresses still start from A.
  - **The columns you can switch on can be ordered** like the others:
    country, device address, failure code, MAC address and so on.
  - **The address bar names the page within a tab**, so a link or F5 lands
    where you were.
    - For example `#traffic/web`, `#windows/events` or `#failed/radius`.
    - Back and Forward move between them.
  - **What the daemon has done**
    - It now has a Clear button and pages of 50, 100 or 250, like the other
      lists.
    - Each kind is named as the filter above names it ("bans", not
      "block").
  - **The time windows**:
    - The logins page now also offers *last hour*.
    - The domain events also offer *last year*.
  - **The same thing is drawn the same way**:
    - The person on the VPN is written in the font used for names.
    - The address inside the tunnel is named like the Traffic list's
      addresses.
    - A ban's end is drawn like its start.
    - A missing value is "–".
  - **Copying to the clipboard** works over plain HTTP from every button.
    Several buttons only worked over HTTPS.
  - **Ban, whitelist and the router buttons** cannot be pressed twice while
    the first press is still going.
  - **Pointing at a heading explains it** on the Traffic cards, *Worth
    looking at* and *The dumps it keeps*. Columns you switched on are
    explained too.
  - **Numbers are grouped the same way everywhere**, and one day is
    written "1 day".
- **Czech**
  - **Counts use the right Czech form**: "1 řádek", "3 řádky", "7 řádků".
  - **Better words for some columns:**
    - The column of user names is now "Jméno". It was "Název", which is the
      word for the name of a thing.
    - Where an address came from is "Odkud" and where it went is "Kam".
      They were "Od" and "Do", the words for dates.
    - Who made a ban is "Kdo".
  - **The ends of a chosen time span** now say *Since* and *Until* in
    English, so they are no longer confused with an address's *From*.
  - **The new texts are translated**, including the public lists'
    descriptions and the heading of a record's popup, which now says what
    kind of record it is.

1.10.159

Another round of looking for what was wrong, this time in reading the
logs, the daemon's own life (backups, restores, settings, jobs), the router
and the ban feed, the pages, and the speed of the big windows. Each item
was made to happen first, and `test/fixes159.py` checks them.

- **Settings → About**
  - **The settings that belong elsewhere are no longer shown here.**
    - The firewall log's folder, files and kind are the older form of the
      rows on *The firewall log*, which show them when no rows were ever
      saved.
    - The public lists in use are ticked on *Public lists*.
    - Two directory settings, *Ask about signed-in people again every* and
      *Watch what the directory says*, are now on *Active Directory*.
    - With nothing left, *Everything else* no longer appears. Nothing the
      daemon reads has changed.
- **Reading the logs**
  - **A file with a long stretch and no end of line** (a binary dropped in
    the folder) was read from the start again and again, for ever, and
    nothing after the stretch was read.
  - **A rotated file is followed for two minutes after it last grew.**
    - The lines written to it after the rename and before the writer
      reopened were lost.
    - It is now read a window a pass instead of all at once. A rotated file
      of half a gigabyte was a few hundred thousand records in one pass.
    - Where the reading of it got to is kept over a restart.
  - **A log path that is a link**: its rotated file is found beside the
    real file, so lines are no longer lost at each rotation.
  - **An ISE record split across a rotation** is put together. It was
    dropped, and it is the kind of record that bans.
  - **Domain and firewall events are written before the read positions
    are saved.** A stop in between, or a database refusing the write, lost
    them. A refused write is now tried again on the next pass.
  - **The same domain event read twice in one pass** (a syslog server
    writing per host and all together) was counted twice.
  - **Eduroam's accounting file at midnight**: the last records of the
    day's file are read before it is let go. A block half read survives a
    restart.
  - **The first seconds of January**, read in the last seconds of December
    from a clock a little ahead, were dated a year back.
  - **A FortiGate line with no zone on it** is read in the zone set for the
    logs, as every other log is. It was always this machine's zone.
  - **A line after a hole of NUL bytes** (a writer that kept its position
    after the file was emptied) is read.
  - **A user name with a sentence typed into it** could rewrite the
    address, port and verdict of a tac_plus line, or the address of a
    domain event. The daemon's own fields come first now.
- **The daemon's own life**
  - **A HUP while the database was briefly away** left the daemon on its
    built-in settings until a setting was saved. Retention then ran at 90
    days on a site that keeps everything. The settings running are now
    kept and the reading is tried again.
  - **Restoring a dump that fails part way** puts back what was there from
    the copy made first. On MariaDB a failed restore left most tables gone.
  - **On PostgreSQL, a dump of a database split by day** can be put back
    over it. `pg_restore --clean` was refused there.
  - **After a restore:**
    - New records are packed against the restored database's dictionary.
      Records written until the next restart could not be read after it.
    - The Traffic overview is worked out again; it showed the old database.
  - **Jobs that never stop when asked** (counting the domain events ahead,
    splitting, indexing, dumping) are no longer offered a stop.
  - **Half-written dumps** (`*.part`) older than six hours are deleted.
  - **The names of addresses** are kept as long as the records beside
    them. They were let go at 90 days while refusals were kept for ever.
- **The router and the ban feed**
  - **A login refused by the router is judged by ssh's exit code** and by a
    second password prompt. It was judged by words in the output, and a ban
    comment carrying a typed name of "permission denied" stopped every sync
    after it.
  - **The blacklist switched off, or Take ours off it, with one of a pair
    down**: the other is cleared all the same. The one that was away is
    cleared when it is back.
  - **The country list** can be filled with only the second firewall set
    up. Entries already on it by hand no longer make the router throw away
    the rest of a batch. Switching from both families to one clears the
    other.
  - **RouterOS timeouts of a week or more** (`4w1d23:59:00`) are read. A
    30-day ban made permanent here was never rewritten on the router.
  - **DShield** is read as the ranges it lists. Each /24 was one address.
  - **Undoing a folding** no longer bans again an address somebody let
    back in after the subnet was taken apart.
  - **Importing ranges**: a range sharing its start with the last of a page
    was dropped.
- **The pages**
  - **A hand ban or a whitelist entry is refused if it is too wide**
    (wider than a /8 for IPv4 or a /16 for IPv6), or if it is loopback or
    the unspecified address. `0.0.0.0/0` banned the whole internet.
  - **A read-only account**:
    - no longer sees the ban and whitelist boxes, the certificate box, the
      database and settings downloads, or a backup's Download (they
      replaced the page with a refusal);
    - no longer gets a 403 each time Settings opens.
  - **The ban ladder editor**:
    - Adding a step takes the next length on its list (it made 40 and 160
      minutes, which the list does not offer).
    - A length not on the list is shown as itself.
  - **The address bar is followed**: a pasted link, Back and Forward.
  - **Popups take focus** and give it back. Tab stays inside them, and
    Escape closes a help popup.
  - **Settings**:
    - An emptied number box is refused as empty, not saved as 0.
    - The refused box is marked, and the message uses its name.
    - Leaving the page with changes not saved asks first.
    - Making an account with no name says so beside the box.
  - **A search that finds nothing** in the ban history or the events says
    *Nothing matches*, not that the list is empty.
  - **Czech**:
    - Account names are no longer translated in the whitelist, the ban
      history and who is signed in.
    - The column menu names columns as they read.
    - How a ban ended and the update interval are translated.
    - The example `INVALID` stays as ISE writes it.
- **Speed**, measured on a year of 3 million refusals with identical
  answers:
  - **The month and year front page** is kept in the database. After a
    restart it is there at once (12 s on PostgreSQL, a minute on MariaDB,
    before) and a fresh one is worked out behind it.
  - **The busiest addresses**: one statement for all of them instead of one
    each. The bulk is counted off the index alone, so the year went from
    54 s to 21 s on MariaDB.
  - **The names tried** are ranked first, and the addresses are counted
    only for the ten shown. On MariaDB this no longer fills the disk with
    temporary files.
  - **The 802.1X and MAB cards** check each machine once, not each refusal.
  - **Smaller gains:** the year chart, the distinct addresses on PostgreSQL,
    the countries on the server engines, and the domain page asking the
    same per-account question again within ten seconds.
  - **Two indexes**, on PostgreSQL and SQLite: one name pressed on either
    list of authentications went from a second to a few milliseconds. They
    are built in the background on a big table.
  - MariaDB with its default 128 MB buffer pool reads a large table from
    disk every time. Give `innodb_buffer_pool_size` a large share of the
    machine's memory.

1.10.158

A round of looking for what was wrong: in the daemon, the database, the
API and the page. Every item below was made to happen first, and is checked
by `test/fixes158.py` on all three engines.

- **Security**
  - **Passwords saved with the settings are sealed.** The directory's
    service account, the routers' and the ban feed's passwords were in the
    settings table as typed, so every backup, nightly dump and copy
    downloaded from the page carried them.
    - They are now sealed with a key kept in `settings.key` in the state
      directory, beside `banfeed.key`. Those saved before are sealed the
      first time 1.10.158 starts; nothing has to be typed again.
    - Back up `settings.key` with the state directory. A key file that is
      there but cannot be read is never replaced; the log says so.
    - A database restored on another machine opens without them. Each is
      said in the log and asked for again; everything else is as it was.
    - Going back to an older version means typing these passwords again.
    - Backups made before 1.10.158 still hold them as they were.
  - **A local account is not taken over by a domain account of the same
    name.** A domain `admin` in the read-only group signing in turned the
    local emergency `admin` into a read-only directory account, for good.
    - A name that is a local account here now signs in as that local
      account, with its own password, and the directory's answer for it is
      not used. This is said in the events.
    - Domain accounts that already took over a local name before 1.10.158
      stay directory accounts.
  - **The ban feed's user name and password are counted like a sign-in.**
    Past `login_tries` wrong ones from an address, it answers 429 until
    `login_wait_min` has passed.
  - **The directory guard is exact.** The one extended operation that may
    be sent is StartTLS, byte for byte; one that only carried its name
    inside was let through.
  - **Device commands hide the secret, not the word before it.**
    `wpa-psk ascii 0 X`, `ntp authentication-key 1 md5 X`,
    `message-digest-key 1 md5 X` and SNMPv3 `auth sha X priv aes 128 Y`
    kept X and hid `ascii` or `md5`. A secret made only of digits
    (`community 4711`) is hidden as before. Commands already stored keep
    what they were stored with.
  - **Wrong input gets a 400, not a 500.** This covers `/api/ptr`,
    `/api/macs`, `/api/blocked/fold`, `/api/rescan`, the prune and the
    firewall search, given a non-list or a number like `1e400`.
- **Banning**
  - **An address hammering through its ban no longer stalls the reader.**
    Every refusal fetched everything since the ban, the square of the
    attempts: 4,000 took 86 s of the log reader. They are now counted where
    they are, each only as far as its bar.
  - **A ban by hand starts clean.** It picked up what an old automatic ban
    had been charged with, so one attempt after a 60-minute hand ban made
    it permanent.
  - **NPS addresses are written one way.** The same IPv6 address written
    six ways was six addresses, none at the bar. A range is not taken as
    an address.
  - **The notes kept beside each ban** (how it was earned, the attempts it
    was judged on) are let go a week after the address was let back in.
    Before, they were kept for ever.
- **Firewall and logs**
  - **One firewall line with a 64-bit counter lost its whole lot** of up
    to 5,000 lines, on every engine. Counters are now held to what a
    column carries. A lot refused for a value in it is written again line
    by line; one refused because the database is locked or gone is not.
  - **The night the clocks go back**, one NPS or token-server line a few
    seconds out of order moved every line after it an hour late.
- **Database**
  - **Retention never deleted a table whose oldest rows all shared one
    moment.** That was a "clear all" of the ban history, or a bulk import.
  - **Paging on PostgreSQL showed some rows twice and others never** where
    many share one second. Affected lists: firewall, domain events and ban
    history.
  - **Oldest first on Logins and the domain's events** started in the
    middle and could not reach the oldest rows.
  - **Search boxes**: a backslash (`DOMAIN\user`) found nothing on MariaDB
    and PostgreSQL, and `_` or `%` matched anything.
  - **Moving a SQLite database to MariaDB** cut long ids short and could
    drop a row. They are now shortened the way the live writing does.
- **The page**
  - **The page no longer redraws itself eight times a second.** The sort
    arrows were taken off and put back on every pass, which woke the pass
    again, on every tab, forever. It is now quiet when nothing changes.
  - **Clock times and MAC addresses are no longer sent to reverse DNS.**
    `09:29:58` passed as an IPv6 address.
  - **The Overview window**: picking a week then a day could draw the
    week under a selector that said a day.
  - **The log files table** is no longer rebuilt every five seconds while
    out of sight.
  - **On a phone**, Failed attempts and Logins scroll sideways again; their
    last columns could not be reached.
  - **Ctrl+K** no longer offers a tab or card that is switched off or
    hidden, and a card on a Traffic or Domain page opens that page.
  - **Czech**:
    - Account and device names are no longer translated ("service" read
      "služba").
    - The ban ladder and the log file states are translated.
    - The Events list shows what happened as the daemon wrote it. It was
      half translated.
  - "Add a entry" now reads "Add an entry".

1.10.157

- **A column you switch on looks like every other column.** The columns
  added in 1.10.156 showed their values as plain text. Each is now drawn
  the way the rest of the application draws the same thing:
  - **A country** has its flag and code, on Traffic too, where the
    firewall's own country names become the flag and private ranges say
    *private*.
  - **An address** is named the way every address is (its DNS name, its
    MAC vendor).
  - **A name** can be clicked to ask the directory, where the directory is
    on.
  - **A moment** shows the day and the time.
  - **Yes and no** are tags. **A door** is the VPN, TACACS+ or 802.1X.
  - **Bytes, durations and counts** are written as everywhere else and
    lined up on the right. Ports, codes, MACs and sessions are monospaced.
  - The ban history no longer offers *Attempts while banned*: its own
    *Turned away* column already shows it.
  - Nothing that shows by default has changed.

1.10.156

- **Many more columns, out of sight until you want them.** Every table
  looks exactly as it did. With *Edit the columns* on under your name,
  right-click a heading (or a row): the menu lists every column the table
  can show, the new ones unticked. Tick them on, then move and size them
  like any other. The choice is kept with your account, and *Put this
  table back as it comes* hides them again.
  - **Every Traffic page:**
    - **Source interface** and **Destination interface:** the interface or
      zone each side was on, as the firewall names it. It is still under
      the address as well.
    - **Other fields of the line:** source and destination port, protocol,
      both countries, service, application, policy, user, name asked for,
      category, URL, action, kind, sent, received, duration, session, unit,
      firewall and message.
    - A page whose own columns already show something does not offer it
      twice. Most of them can be sorted by.
  - **Failed attempts:** the device's address, the node, the access
    service, the protocol, the failure code, the door, the MAC, the port,
    the network, the machine and the session.
  - **Logins:** the same, plus the profile, the policy set, the groups, the
    downloadable ACL and more.
  - **The ban history, the daemon's events and the domain's events:** the
    fields of their records.
  - **Every smaller list** offers the named fields of its records the same
    way.
  - **Saved layouts stay:** a table is named by the columns it shows as it
    comes, so a layout saved before this is still yours, and adding more of
    these later will not lose it.
- **One popup, about the thing you point at.** Until now an element inside
  another that explains itself was folded into it. A Traffic row took in
  what every address, name and mark in it said, so pointing anywhere at a
  row showed a column of a dozen paragraphs, the same ones twice where both
  ends were private or nameless.
  - Each thing now says only what it is, and the popup is always the
    innermost thing under the pointer. Moving back onto the row shows the
    row's own again.
  - Every popup on every page was checked: none repeats itself.

1.10.155

A hunt for faults, and for time on very big data. The faults below were
each found by reading the code, then made to happen before they were put
right. `test/banning.py` is new and keeps the banning ones from coming back.

**The banning**
- **A burst read from a backlog is out for good again.** After a restart,
  or with logs arriving late, the attempts after the one that earned a ban
  were weighed against this machine's clock rather than the records' own
  time. They were thrown away, and a burst could never get past the first
  rung. A burst and a run of made-up names are now counted over everything
  since the ban was earned, not in fives between one lengthening and the
  next.
- **A whitelist changed outside the page takes effect.** A range put in
  `never_block` by the config file, a HUP, `isemon --set` or
  `isemon --allow` left the bans it covers in place until somebody saved
  something on the page. Meanwhile such a ban could even be held longer.
  The daemon now notices within a pass and lets them go, and an address
  that is spared is never held longer.
- **A ladder of `forever` alone bans for good.** It gave sixty minutes. A
  step written after `forever` is refused rather than silently dropped.
- **Folding only folds bans that are for good.** Four ten-minute bans became
  a whole /24 banned for good, including addresses that had done nothing.
- **Whitelisting one address inside a folded subnet** takes the subnet apart
  and lets go only what is spared. It used to free every attacker in it.
- **Erasing the ban history** keeps the last two days of "let back in"
  marks. Without them the next pass banned addresses again for attempts
  they had already served a ban for.
- **The expiry sweep** no longer deletes a ban that was lengthened while it
  was looking, and no longer logs it as having run out.

**The Traffic overview worked out ahead**
- An overview the database refused part of (a server restarting, a dropped
  connection) is not kept. Before, it was kept as "nothing let through,
  nothing refused" for the next five minutes. What was there before stays,
  and it is tried again in a minute.
- An overview worked out while the firewall's lines were being erased is
  not kept, and nothing is worked out while an erase runs.
- While nothing can be worked out behind the page (an index being built
  after an upgrade, a split, a copy, an erase), a window with nothing kept
  is worked out while the page waits, as before 1.10.154. It no longer
  says "being worked out" for hours.
- **One budget for all the windows:** after a window is worked out again,
  the thread rests twice as long as that took. A window somebody is
  waiting for the first time does not wait behind it. Five windows each
  kept to a third of their own time had added up to the database busy all
  the time.
- The VPN count, the open connections and what is kept are worked out once
  a minute or two for all windows, not once for each.
- The page waits 3 seconds rather than 20 for a window that has never been
  worked out, then says it is being worked out. A refresh no longer throws
  away an answer still on its way: on a busy firewall the card had never
  appeared at all. The cards of the window or firewall shown before are
  greyed out while the new one comes.

**Speed on big data** (measured on PostgreSQL with six million firewall
lines over three days)
- **The VPN as it stands now:** the few site-to-site lines it is made from
  (tunnels up and down, the negotiations that name networks) have an index
  of their own, `fw_s2s_ts`. It holds only those lines, so it costs a write
  only on them. On 900,000 site-to-site lines a week, that part went from
  1.9 s to a few milliseconds, and the whole VPN view from 2.2 s to 0.6 s. It is built behind the running daemon after the upgrade.
  MariaDB has no such index and goes on as before.
- **The busiest values of each dimension:** the database adds each value up
  and hands back one row a value rather than one a value and verdict. Only
  the few that make a list are asked how they were decided. The answer is
  identical.

**The page in another language**
- Names are never translated:
  - the installation's name, notes, user names, group names, the names
    of the people tried from an address, and the values in the pick
    lists;
  - one word in a pattern's slot (e.g. `Account “settings”` stays as
    written);
  - the page title.
- A pattern's slot no longer reaches across a ` · ` or ` — ` unless the
  pattern itself has one, or is a long sentence. "fw1 · blocked · written
  3 min ago" became "před fw1 · …".
- Sorting a column and the explanations of the columns use the English the
  page drew, not the translation. "před 3 min" did not sort as a time.
- The script no longer uses a lookbehind in a regular expression literal.
  On Safari before 16.4 that one literal stopped the whole page, in English
  too.
- "in" on a let-in row is now "let in", and the "In" beside a time window
  is "Window", each with a translation of its own.
- The pick lists were drawn again on every refresh in Czech; they are not.
- A language preference that is not an object is refused rather than
  failing. A settings file with one bad section changes nothing, rather
  than half.

**The page**
- An answer that broke off half way (a dropped line, Stop pressed late) no
  longer leaves "Searching…" up for ever.
- The find box (Ctrl+K):
  - typing a space no longer forgets the rows, so the arrows and Enter
    still work;
  - Enter on a name is remembered in the history, as a click is;
  - it opens above a popup, and Escape closes only it.
- Escape in the column menu no longer closes the popup under it.
- If editing the columns was switched off behind the page (a restart, a
  new sign-in), the page switches it off too and says the change was not
  kept. Before, it went on rearranging tables that came back at the next
  load.
- The "From" handle of the date window picker can be dragged when both
  handles are at the right end.
- Clear also clears a window chosen by its dates.
- A laid-out table of thousands of rows is redrawn in linear time.
- The tooltips of the groups in the account popup no longer show raw HTML.

1.10.154

- **The Traffic overview opens at once.** The cards, the chart and the lists
  of the busiest are now worked out behind the daemon and kept, so the page
  shows them immediately.
  - **Why it was slow:** on a big firewall, adding them up from the counted
    buckets took minutes on the first look, and again whenever nobody had
    looked for a while. The page could not show anything else on the
    Traffic tab until then either, because the numbers on its buttons come
    from the same answer.
  - **What is kept ready:** the last 24 hours of every firewall always, from
    the moment the daemon starts. Every other window of the drop-down (last
    hour, 6 hours, 3 days, week, for all firewalls or for one) is kept ready
    once somebody looks at it, and let go after three days nobody has.
  - **How often each is worked out again:**

    | Window | At least every |
    |---|---|
    | 1 h | 1 min |
    | 6 h | 2 min |
    | 24 h | 5 min |
    | 3 days | 10 min |
    | week | 15 min |

    Never more often than three times what it takes. One that takes four
    minutes is worked out every twelve, so the database is never busy with
    this more than a third of the time. One at a time, never two at once,
    and not while the database is being split, copied, restored or erased.
  - **What the page shows:** the line above the chart says when what you
    see was worked out, and its tooltip how long that took. The lists of
    lines on the other pages of the tab are always live.
  - **The first look at a window that has never been worked out** waits up
    to 20 seconds for it. After that the page says it is being worked out
    and fills in by itself. It never draws zeros.
  - **Windows chosen by their dates** (*choose dates…*) are worked out when
    asked, as before.
  - **Kept in the new table `fw_ready`.** Each row is one window: when it
    was worked out, how long it took, what the time went on, and the
    answer. It survives a restart, so the page is quick right after one
    too. Erasing the firewall's log erases it as well, and it is simply
    worked out again.
  - **The same commands as the Domain page's counting:**
    - `isemon --rollup` now also lists each kept window: how old it is, how
      long it took, and the parts the time went on (cards and chart, VPN
      now, its own events, connections in use, ...). On a slow site this
      says which part to look at.
    - `isemon --rollup-build` does both. `--rollup-build traffic` works out
      only the Traffic overviews now; `--rollup-build domain` only the
      Domain counting, as before.
    - `--rollup-check` is unchanged: the Traffic overview is the counted
      buckets added up, not a counting of its own, so there is nothing to
      read back.
  - **New setting:** *Settings → The firewall log → Work out the overview
    ahead of time* (`fwlog_ready`), on by default. Off is the old way.
  - In the daemon's log: a line for each overview that took a minute or
    more, with its three slowest parts.
- **The same card on the Domain page.** While the Domain page's answers are
  being counted ahead of time (after an upgrade, after *Count them all
  again*, or `isemon --rollup-build` at a terminal), the page shows a card
  like the Traffic one. It says how far the counting has got, when it
  started and about how long is left, and that until then the cards are
  worked out from the events themselves. The thin bar across the top no
  longer shows that job twice.
- Every new text is in `web/lang/en.json` and translated in `cs.json`.

1.10.153

- **The page in Czech, and in any language somebody adds a file for.**
  Under your name (top right) there is now *Language*. It is your own
  choice, kept with your account. A read-only account has one too, and so
  does the sign-in page, which remembers what this browser last chose.
  English is still what the page is written in, and it is what you get
  until you choose something else.
  - The words live in files beside the page, `web/lang/en.json` and
    `web/lang/cs.json`. Each text has an ID made of its first words and a
    short hash, e.g. `s.the-database.9a1b2c3d`, and the English it stands
    for (`source`) next to what to show instead (`text`). The file's head
    (`_meta`: code, name, English name, version) is what the page offers
    in the list. A new language is a new file with the same IDs.
  - Every file is optional. A file that is missing, broken or empty is
    simply not offered. Without the folder at all, the page is exactly
    what it was in 1.10.152, with nothing extra loaded.
  - The texts are swapped as the page draws them, before the browser shows
    anything. That covers every tab, popup, tooltip, button and message,
    the sign-in page and what the daemon says to the page (refusals, the
    descriptions of the settings).
  - Data is never translated: names, addresses, anything in an input, a
    code block or a monospaced cell, and what devices themselves wrote.
  - Not translated either: the log file, the stored events, the command
    line and the docs. They stay in English.
  - The language is in *Export my settings* and comes back with *Import*.
  - Column layouts are kept under the English headings, so one layout
    holds in every language.
  - `tools/i18n/build.py` rebuilds `en.json` from the page and the daemon,
    brings every other file up to it (new texts are added empty, and the
    page shows them in English until filled in), and with
    `--missing cs` lists what is not translated yet.
  - **Rollback**, any of these:
    1. choose *English* under your name;
    2. delete `web/lang/cs.json`, or the whole `web/lang` folder, from the
       web directory;
    3. install 1.10.152 again. The one new table, `user_prefs`, is ignored
       by older versions.
- `docs/languages.md`: the file format, adding a language, keeping a file
  up to date, and getting back to English.
- `docs/postgresql-write-speed.md`: how to retry a split that failed
  without waiting six hours (`DELETE FROM meta WHERE key='split_failed_...'`).

1.10.152

- **Any time window, by its dates, on every list searched over time.** The
  window drop-downs of *Failed attempts*, *Logins*, the domain's events
  (*Domain → Events*) and the *Traffic* tab have *choose dates…* below
  *last hour* and the rest. It opens a picker:
  - a bar from the first record this machine holds of that kind to this
    moment, with a handle at each end to drag;
  - the two moments, to the minute, to type or pick;
  - *until now*: the end of the window is the moment of each search, so a
    list refreshed an hour later has that hour in it. Pulling the right
    handle all the way to the right is the same;
  - ready-made windows: last hour, today, yesterday, this week, last 7
    days, this month, last 30 days, everything.
  What was chosen stands in the drop-down as its own line (`01-10 08:00 →
  now`), and choosing *choose dates…* again opens it where it was. On the
  Traffic tab the cards and the chart follow the window too, drawn over its
  own two ends. A new endpoint, `/api/first?what=failed|passed|win|fw`,
  says when the first record of each kind is (one indexed `MIN`, held for
  a minute). The overview charts keep their own drop-downs as they were.
- **The find box's history remembers what was picked, not only the
  words.** A search ends in something: an address opened, a user name
  looked up, a page or a setting gone to, a line of the firewall's or the
  domain's opened. That is what is remembered now, with its kind shown
  beside it (*address*, *user name*, *card · settings*...), and pressing it
  in *Your searches* does it again - opens that address, goes to that page,
  or searches the same words and presses the same line. A search only typed
  and Enter is remembered by its words as before. A history kept by
  1.10.151 is read as it is.
- **An upgrade no longer has the command line build indexes beside the
  daemon on PostgreSQL.** Seen on a site going from 1.10.139: `install.sh`
  asked for the status while the daemon it had just started was splitting
  `win_events` by day; the status command built a new index over that same
  table at the same moment, and the split's own index build ended in a
  deadlock. Nothing was harmed - the table stayed as it was - but the split
  waited six hours to try again.
  - A command at the prompt now builds none of the schema's ordinary
    indexes on a PostgreSQL database that is already there; the daemon
    does, at its start. (Unique ones, and everything on a database made
    from nothing, as before.)
  - A split beaten by something else at the same moment - a deadlock, a
    lock it could not have - is tried again at the next pass (ten
    minutes), not in six hours.
- **The right button opens the column menu anywhere in a table** while
  *Edit the columns* is on - on any cell, for that cell's column - not only
  on the heading.

1.10.151

- **The find box (Ctrl+K) remembers what you look for.** Under a line beneath
  the suggestions, when the box is empty: *Your searches*, the ones you make
  most first (then the most recent), eight at most, so the box never needs a
  scroll bar.
  - A search is remembered when it is acted on (a result pressed, Enter) or
    its answer has been on the screen for three seconds - not every letter
    typed on the way. The same search twice is counted, not listed twice.
  - Pressing one searches it again; the arrows and Enter reach them too.
  - A cross appears over each one under the pointer and takes it out.
  - Kept per person in the database (a new table, `user_finds`), up to 60 a
    person, the most used kept when room is needed. A read-only account has
    its own.
  - Part of *Export my settings* / *Import settings…* (the section
    `search`), and *Clear my search history* in the account popup takes all
    of it away (that goes into the events). Removing an account removes its
    history.

1.10.150

- **The bar along the top shows whenever the page is waiting on the
  daemon**, anywhere: a list, a popup, a save, a refresh, a database being
  put back. It appears once a wait has taken longer than a moment (0.4 s),
  so quick answers do not make it flicker, and goes when the last answer
  is in.
- **The pill with *Stop* at the foot of the window is only for what is safe
  to stop**: the searches, which are reads and whose statement on the
  database is stopped with them. That now includes a slow list's own
  refresh. A save, a ban, a change of settings or a database being put back
  gets the bar and never a Stop - half of one is worse than either.

1.10.149

- **The right button on a column's heading, while *Edit the columns* is on.**
  A menu, in the page's own style:
  - *Hide* that column. A hidden column is not drawn at all, edited or not,
    and takes no room.
  - Every column of the table, the hidden ones too, ticked where shown.
    Pressing one shows or hides it and leaves the menu open, so several can
    be done at once. The last column showing cannot be hidden.
  - *Add an empty column to the left / to the right*: a column with nothing
    in it, for room. It can be sized and moved like any other, and *Take
    this empty column away* is on its own right button. While editing, an
    empty column is lightly striped so it can be found.
  - *Put this table back as it comes*, for that one table.
  The empty columns the page already drew (beside an address, for its
  place and its country) are ordinary columns here: they can be hidden.
  With editing off, the right button is the browser's own as always.
- **The Logs table has what `isemon --status` prints as well**: *What is in
  it* in words, *Last read* to the second, *Not read yet* and *Trouble*.
  The columns it had stay as they were; any of them can be hidden. The
  table names itself, so a layout somebody gave it outlives a column added
  in a later version, and the layout given it before this one is carried
  over.
- **A directory account's groups, all of them and compact.** The account
  popup asks the directory for the whole list (as the find box does), spelled
  the way the domain spells it; what was written down at sign-in is shown
  until it answers, and if it cannot be asked. The groups that gave the role
  are cards at the top; the rest are one wrapping line of names, where each
  lives in its own popup, and past 18 the rest are behind *and N more*.
- **The logins of the other doors (*Everything else*) had two cells more
  in each row than headings** - the tunnel and the firewall - so every row
  ran past the end of the heading. They have their headings now.

1.10.148

- **Your own settings to a file and back.** The account popup (your name at
  the top right) has *Export my settings* and *Import settings…*, for every
  account, read-only included.
  - The file is JSON: what it is (`"kind": "isemon-user-settings"`), whose
    it was, which machine and version it came from, when, and `settings`
    by section. Today the one section is `columns`, the layout of the
    tables; more can join it later.
  - Never the password, the role or anything else about the account.
  - Importing says what the file holds and whose it was before it replaces
    anything. It works on another machine running this, and from another
    person's file, so a good layout can be handed round.
  - It does not need *Edit the columns* switched on: reading a file back is
    asked for on purpose.
  - A section this version does not know is left alone, and the import
    says so. A file with nothing this version keeps, or a layout that is
    not one, is refused and nothing changes.
  - The import goes into the events.
- **Sizing a column moves only the columns to its right.** What it gains,
  they give up (each down to its longest line, as before); what it lets go
  of, they take. Everything to its left stays exactly as it was, so a table
  is laid out from left to right. Still never a scroll bar under it.

1.10.147

- **The account popup is wider, and a directory account's groups read
  properly.**
  - Each group is shown once, by its name, with where it lives in the
    directory underneath (its folders and the domain). The full
    distinguished name is in its own popup. Before, the groups were cut up
    at every comma, so one group showed as five pieces.
  - The groups that gave the role (*Settings → Active Directory*) come
    first, marked *makes you full admin* or *makes you read only*.
  - *In the directory* is the account's place as a path, from the domain
    through its folders to the account, with the distinguished name under
    it.
  - A directory account's groups are now kept up to 4,000 characters
    rather than 600, which cut a long list off mid-name. The longer list
    is kept from the account's next sign-in.

1.10.146

- **Your name at the top right is a button.** It replaces the line
  "name · role · from the directory" and the *Change my password* button.
  Pressed, it opens your account:
  - who you are, your role, and whether the account is local or from AD;
  - what you may do, and where that comes from: for an AD account, the
    groups and the place in the directory it was worked out from at sign-in;
  - this sign-in: when, from where, and how many sign-ins of the account
    are open;
  - **Edit the columns**, a switch (see below), and *Put my columns back as
    they come*, for yourself only - a read-only account has both;
  - *Change my password*, for a local account only. A directory account's
    password is the domain's.
- **The columns can be changed only while "Edit the columns" is on.**
  - It is off at every sign-in. The daemon holds it for that one sign-in, in
    memory only: signing out, the sign-in running out and a restart of the
    service all turn it off again. The layout already kept is drawn just
    the same either way.
  - Off, every table looks and works exactly as before: no grips, nothing
    to carry, and the daemon refuses a layout sent from that sign-in.
  - On, every table that can be laid out shows where each column ends and
    where to take hold of it, and your name has a blue dot.
  - Each change is kept the moment the column is let go of.
- **Making a column wider never puts a scroll bar under the table.** The
  others give the room up, each only down to the width of its longest line
  (its heading included); once none of them has any to spare, the edge goes
  no further. Made narrower, a column's room goes to the columns short of
  their longest line first, then to the rest by their width. Widths are
  kept as shares of the table, so a layout fits a wider or narrower screen
  as well.
- **While a column is dragged, its width is shown** in a pill at the foot
  of the window, so two columns can be made the same width.

1.10.145

- **Every table can be laid out by whoever is looking, and keeps it.**
  - Drag the edge of a column's heading to make that column wider or
    narrower. Drag the heading itself to move the column somewhere else.
    Pressing a heading still orders the table by it, as before.
  - Twice on an edge puts that one table's widths back.
  - What somebody sets is kept with their account in the database (a new
    table, `user_cols`), not in one browser. It comes back wherever they
    sign in and is drawn from the first frame of the page. A read-only
    account keeps its own as well: it changes nothing anybody else sees.
  - Nothing changes for a table nobody has touched: it looks exactly as
    before. A table somebody has sized holds those widths whatever its
    rows say, so a refresh never moves it. The last column takes whatever
    room is left, and a table wider than its card scrolls sideways.
  - A table is known by where it is on the page and the words of its
    headings, so each of the Traffic tab's pages keeps a layout of its own.
  - *Settings → Accounts → Columns of the tables* puts every table back as
    it comes for whoever is signed in. A full admin can do the same for
    anybody from the list of accounts (*Columns*, shown on accounts that
    have laid something out). Both go into the events.
  - A layout is kept to what a layout can hold (names, whole pixels, an
    order) and to 60,000 characters a person. It goes with the account:
    removing the account removes it. Erasing collected data never touches
    it.
- **Ordering a table on the page no longer freezes it.** Pressing a heading
  of a table the page orders itself (the Logs tab's list of files, among
  others) set off a watcher that ordered the rows again every time it had
  just ordered them, and the page stopped answering. This was so since
  1.10.122 at least.

1.10.144

- **The Traffic lists hold still.** Their columns no longer move when the
  minute's refresh brings new rows, when a row's popup is closed, or when a
  name arrives for an address. Each column's width now depends only on which
  column it is and which list it is in (Sessions, Web, Threats, the VPN and
  firewall lines, Other), never on what the rows hold:
  - the time, the result, the ports, the data and how long it lasted are
    narrow and fixed;
  - where from and where to share what is left (on the lines of the
    firewall and its VPN, so does what it said);
  - an address that is longer than its column ends in an ellipsis, and the
    whole of it is in its popup and on the row's own page;
  - a window narrower than the list scrolls it sideways rather than
    squeezing it.

  Only the Traffic tab is changed. Every other table is laid out by the
  browser as before.
- **An address with a name looks as it did before the name was there.** A
  name from the reverse zone (1.10.137) is written above the address in
  smaller, quieter type. The address keeps its own line, bright as before,
  and *private*, the country and the interface stay on the line under it.
  1.10.137–1.10.143 put all three on one dimmed line under the name, and
  what used to stand out no longer did. A name the firewall wrote itself (a
  FortiGate's `hostname`) is shown as it always was.

1.10.143

- **Column widths are the browser's again, everywhere.** Both the widths
  held through a refresh (1.10.141) and the widths worked out from the
  contents (1.10.142) are taken out, at the site's request. Every table is
  laid out exactly as it was in 1.10.140. Nothing else changes: splitting by
  day, the index work and everything from 1.10.141 and 1.10.142 stay as
  they were.
- **On the Traffic list, where from and where to are never broken across
  lines.** This is done in the stylesheet alone, for that one table:
  - an address, its port and the name above it each stay on one line;
  - those two columns take the width they need before the others share
    what is left;
  - a name longer than 44 characters is cut short with an ellipsis, and the
    whole name is in its popup.

1.10.142

- **Index work only by the daemon, one piece at a time.** Seen on the first
  real upgrade to 1.10.141:
  - every `isemon …` command (even `--status`) checked the schema as it
    opened the database;
  - it found the index the daemon was building half-built, took it for the
    remains of a stopped build and took it away, and PostgreSQL ended the
    daemon's build with a deadlock;
  - the command then started the build itself, which died with it a second
    later.

  Now:
  - A command typed at the prompt builds no index, takes none away and
    splits no table. The daemon does all of that.
  - An index being built, by any process, is never taken for a half-built
    one.
  - Every piece of index work on PostgreSQL (the indexes put off, the word
    index, splitting a table) holds one lock, so no two of them ever run
    over a table at once. Splitting waits while any index is being built.
  - A build that is stopped is tried again while the daemon runs (five
    times, ten minutes apart), not only at the next start.
- **An index over a table split by day** is built a part at a time, each
  part `CONCURRENTLY`, and attached as it is done. Writes are not stopped.
- **Rows that arrive without their retention class** are given it. That
  covers a backup or a copy made before 1.10.141, restored or carried
  across: each row is marked with how long it is kept and, on PostgreSQL,
  moved to its part of the day. A domain event read again under a new kind
  moves with its kind.
- **Columns sized by what is in them, in every table.**
  - Each column is measured at the width its contents need on one line,
    and is never narrower than its heading.
  - The room left over goes to the columns with something long in them
    (addresses, names, policies, messages), not to ports, arrows and
    dashes.
  - When the contents do not fit, only the widest columns are narrowed,
    together.
  - The layout is then fixed. A refresh may widen a column but never
    narrows one, until you do something or resize the window.
- Also checked on split tables: *Erase the collected data*, *What is in it*
  and the copies and restores.

1.10.141

- **On PostgreSQL, the biggest tables split by day.**
  - The tables: `fw_events` (the firewall's lines), `fw_roll` (their counts)
    and `win_events` (the domain's events). Each day is split again by how
    long its rows are kept:
    - the sessions let through, apart from the rest;
    - the counted hours, apart from the counted days;
    - the sign-ins and the directory reads, apart from the rest.
  - **Letting old rows go:** an aged day goes in one step (`DROP`), and an
    aged kind of row within a day in one step (`TRUNCATE`). On the site that
    measured it, that is twenty million `DELETE`s a day fewer.
  - **Writing:** the day being written stays small enough to be in memory.
  - **Searching:** a search over a window reads only the days in it.
  - A domain event this program marked is kept as long as before. It is
    moved aside before its kind's day goes.
  - **An existing table is split in place, behind the running daemon,
    without copying it.**
    - A key is built beside it first, without stopping writes.
    - One short transaction then makes the table into the first part, up to
      a midnight at least six hours ahead.
    - That first part goes whole when its last day ages out.
    - If anything stops it, the table stays exactly as it was and it is
      tried again six hours later.
  - The switch is *Split the biggest tables by day* under The database
    (`db_split`, on by default). Nothing changes on SQLite or MariaDB.
  - The details are in
    [docs/postgresql-write-speed.md](docs/postgresql-write-speed.md) §5a.
  - Do not open a split database with an older version.
  - **How it was checked:** `test/split.py` fills two PostgreSQL databases
    with the same lines, one split and one not, and checks the following:
    - splitting a full table loses and changes nothing;
    - every row lands, whatever its time;
    - the lists, the searches and the counts read the same on both;
    - six days of letting go leave exactly the same rows on both;
    - the domain's counted answers still agree with its rows.
  - Every suite also ran a second time on PostgreSQL with the tables split.
- **The indexes on `fw_events`, by what was actually used.** These numbers
  are from a real FTD over a week:
  - the verdict index was used 2 times and the firewall index 5 times,
    against 67 million writes to each. Both are gone, together about 1.7 GB;
  - a new index over the person a line names (`fw_usr_ts`) covers only the
    lines that name somebody. `user:` over a day was 3 s without it;
  - checking whether a line is already there looks only in the days around
    it on a split table.
- **Column widths stay put.** In every table on every page, the page's own
  refresh no longer makes the columns jump. A column may grow but never
  shrink until you do something: press a button, a heading or a chip, pick
  from a list, press Enter, or resize the window.

1.10.140

- **A search no longer stays at *Searching…* for ever.** In 1.10.139, when
  the page's 5-second refresh came while a search was still running, the
  list waited for the refresh's answer instead of the search's. The
  refresh, holding back so as not to load the database, never got one.
  The pill went away when the search finished, but its rows were never
  drawn. Now a refresh that arrives while a search is running is handed
  that search's answer. A refresh after a slow search that has finished
  draws what is already there.

1.10.139

- **A long search can be seen, and stopped, everywhere.**
  - *The problem:* a search over a busy firewall's 24 hours (`user:` with
    `policyname~`, for example) took 3 seconds on PostgreSQL. All that showed
    it was a small grey *Searching…*. The page's own refresh then started
    the same search again every 3–5 seconds, while the last one was still
    running, for as long as the tab was open.
  - *Now:*
    - A bar runs along the top of the window, and a pill in the bottom
      corner shows how long the search has been going, with **Stop**.
    - On Traffic, the rows on the table are greyed until the new answer is
      in.
  - **Stop, Clear, or a newer search in the same list** stop the old one on
    the database as well as in the browser. Each search carries a name.
    `POST /api/stop` interrupts the statement it is running: SQLite's
    interrupt, PostgreSQL's cancel request, MariaDB's `KILL QUERY` on a
    connection of its own. No statement of that search starts after it.
    Only the session that asked may stop it, and a stopped search is not
    logged as a fault.
  - **The refresh waits.**
    - It never starts a search while the previous one in the same list is
      still going.
    - It repeats a search that took more than 1.5 seconds once a minute at
      most, not every 5 seconds.
  - Covered: Traffic, Failed attempts (and its Domain door), Logins (and its
    Domain door), Events, the Domain events, the ban history, the lists
    with their own search box, and Ctrl+K.
  - `test/stopping.py` starts a search that would take half a minute on
    the engine it runs against, stops it, and checks that it is over within
    seconds.

1.10.138

- **`isemon --status | head -15` without a traceback.** When `head` (or
  `less`, or anything else) stopped reading, Python printed a
  `BrokenPipeError` and *Exception ignored* when the rest of the output had
  nowhere to go. Now the rest is thrown away quietly. The exit code is 141,
  as for any other program `head` stops.
- **Checking whether lines are already there has a kind of its own.** In
  the list of where the database's time goes, `isemon --status` now shows
  `SELECT fw_events (already here?)` (and the same for `win_events`)
  separately from the pages reading `fw_events`. Both used to be `SELECT
  fw_events`, so it could not be told which of the two the time went on.

1.10.137

- **Names of addresses on the Traffic rows, for FTD as for FortiGate.**
  - A FortiGate writes the name that was asked for into most of its lines,
    and the rows showed it above the address. FTD writes none, so its rows
    were bare addresses.
  - Now every address on the rows has its reverse-zone (PTR) name written
    above it once it is known, from *Settings → Names of addresses*. The
    name is greyer than a name the firewall wrote, and its popup says
    where it came from.
  - Where the firewall named the host itself, that name stays.
- **Fewer questions of the table when allowed sessions are not kept.**
  - Each line was looked up in `fw_events` before it was written, so that
    it would not be counted twice.
  - A line that is only counted (the sessions let through, with
    `fwlog_keep_allowed` off) can never be found there, and is no longer
    looked for. That was nine lookups in ten.
  - Same rows and counts as 1.10.136: compared in `test/pour.py`, and on
    455,000 real FTD lines (69,448 rows and 255,996 counts, byte for byte).
  - If the table cannot be asked, the whole lot is still taken as already
    there, as before.
- **A new guide, [docs/postgresql-write-speed.md](docs/postgresql-write-speed.md).**
  It covers:
  - reading the database lines of `isemon --status`;
  - telling a backlog from a limit;
  - `synchronous_commit` off for isemon's own role, why that is safe here,
    and how to undo it;
  - fewer checkpoints;
  - not keeping allowed sessions as rows;
  - the indexes on `fw_events`.

1.10.136

- **Faster writing of the firewall's lines on PostgreSQL.** 1.10.135
  measured where the database's time goes. Two kinds took four tenths of
  it: firewall rows going in (about half a second a batch) and the counts
  beside them.
  - A batch of 200 rows or more now goes in with `COPY` into a table of
    the connection's own. One `INSERT ... SELECT` then moves the rows
    across, with the same `ON CONFLICT` as before and in the same order.
    That is three to four times quicker per batch.
  - What lands is exactly what the one long statement wrote. Two checks
    show it:
    - `test/pour.py` writes nine thousand lines both ways and compares
      every row and every count. It covers text with backslashes, tabs,
      line ends and `\N`, rows that are already there, and counts added
      twice.
    - On 455,000 real FTD lines, 1.10.135 and 1.10.136 left the same
      273,647 rows and 255,996 counts, byte for byte.
  - Anything it is not sure of goes the old way: another statement shape,
    another value type, or any refusal. The refusal is undone to a
    savepoint first, so the transaction around it carries on. That is
    logged once.
  - SQLite and MariaDB write exactly as before.
- **Countries are held in memory properly.** They were held for 8,000
  addresses and then forgotten all at once. A firewall sees more addresses
  than that in a minute, so the database was asked nearly 200 times a
  second. Now 100,000 addresses are held, and the one asked about longest
  ago is let go first. All of them are still forgotten when the country
  list is fetched again.
- **Fewer names asked about again.**
  - The memory of when to ask about an address again holds 200,000
    addresses instead of 50,000. Past that, only the ones due soonest are
    dropped, not all of them at once.
  - An address offered while the queue is full is offered again two
    minutes later, not on its very next line. Each of those offers was a
    question of the database.

1.10.135

- **Where the database's time goes.** Every statement is counted by its kind
  (what it does, to which table: `INSERT win_events`, `INSERT fw_roll
  (upsert)`, `SELECT fw_events`).
  - `isemon --status` lists, under *the database*, the kinds the last
    minute went on: their share of the minute, how many a second, and how
    long each took.
  - The header's tooltip shows the first four.
  - It is two additions a statement, and the kind is worked out once per
    statement text.
  - It is there to show which writes to merge into bigger batches next,
    measured on the machine itself rather than guessed.

1.10.134

- **Reading the firewall no longer holds up the VPN.**
  - *The problem:* an FTD writes about a hundred files and gigabytes a day,
    and each pass of the loop read up to 8 MB of every one of them. Behind
    on them, one pass took a minute. The ISE refusals, which are what this
    program bans on, were weighed once a minute instead of every few
    seconds.
  - *Now:* the firewall's files share 6 MB a pass, at most 2 MB of any one,
    taken in turn. The loop comes straight back while there is more. The
    firewall is read as fast as before (about 6,600 events a second on
    PostgreSQL here), and the VPN is weighed every few seconds however far
    behind the firewall is.
  - FTD's offload messages (805001–805003, a fifth of its lines, skipped
    anyway) are dropped before anything is made of them.
- **EPS while a pass is still going.** The records are counted as they are
  made and sampled every five seconds. A long pass no longer shows as
  `0.0 now`.
- **AMP (FTD 430004):**
  - A card *AMP: the sandbox*: what was sent to Threat Grid / Secure Malware
    Analytics, its threat score, and the files refused for their size.
  - A card *AMP: programs nobody knows*: executables, installers and scripts
    with no verdict in AMP's cloud, by name and where they came from.
    Windows Update's cabinets are left out.
- **Site-to-site tunnels (FTD):**
  - 750014 *initial contact* is a tunnel started over by its peer, not a
    failure.
  - A new card, *Site-to-site tunnels: up, down, started over*. It leaves out
    the rekeys.
  - Connected now: each tunnel's story (came up, rekeyed, started over, went
    down, with why), its rekeys and SAs made and deleted, and a tag on one
    started over.
  - *Up since* is the moment of a "New Connection Established", not of the
    first rekey seen.
- **More FTD message ids read:**
  - 717055 (certificate expired), with a card *Certificates expired*.
  - 405001 (ARP collision, both MACs), with a card *ARP collisions*.
  - 303002 (a file stored or fetched over FTP, by whom), counted with the
    files.
  - 500003 (bad TCP header) and 410001 (DNS reply too long), dropped on the
    way.
  - 113034 (ISE's dACL ignored, the group policy's used).
  - 725024 (TLS session purged).

1.10.133

- **`isemon --status` says how fast it reads**, as the page's header does:
  - *events a second*: now, over 1 min and over 5 min;
  - *the database*: statements a second, how long each takes, and how much
    of the minute was spent waiting on it;
  - *keeping up*: yes, busy or NOT keeping up, with what is still to read,
    how long a pass takes and why.

1.10.132

- **How fast it reads, in the header.** Small and grey under the sign-out
  button: `EPS 8,480 · 1 min 8,368 · 5 min 8,368 · DB 0.2 ms`.
  - That is events a second now (the last 15 s), over the last minute and
    over the last five, and how long a database statement takes on average.
  - The dot is green and faint while the daemon keeps up. It turns amber
    when it is *busy* and red when it is *not keeping up*. That is judged on
    what is still to read (16 MB / 256 MB), how long a pass over the logs
    takes (20 s / 60 s), a slow database (over 500 ms a statement, or most
    of the minute spent waiting on it), and page requests waiting over 10 s.
  - Hovering says all of it and why.
  - It costs nothing. The records made are added up once a pass, and the
    database's statements are counted where they are timed already (two
    additions). It all rides on the status the header asks for anyway.
- **A firewall's clock zone** (Settings → The firewall log, *The zone of its
  clock*, one per firewall).
  - An FTD writes its syslog stamps in UTC unless told otherwise. Read in
    this machine's zone, every line was two hours old in summer. Write `UTC`
    there.
  - A stamp that carries its own zone (RFC 5424) is read in that zone
    whatever this says.
  - A firewall whose newest lines arrive a whole number of hours old, five
    passes in a row, is said once in the log, and beside the firewall in the
    settings, with what to set.
  - Lines read before the zone was set keep their time. `isemon --erase
    firewall` reads them again in the new zone.

1.10.131

- **FTD: commands run on the firewall, read for what they changed**
  (111008 / 111010).
  - Each command is a *change* to the configuration, a *save* of it
    (`write memory`, 111001 / 111004), or a command that only looked
    (`show`, `more`, `dir`, `pager`, `failover exec … verify`).
  - It names the part of the configuration it touched:
    `access-list (dACL) AnyConnect_X`, `group-policy GP_X`,
    `ipv6 icmp permit`, `tunnel-group …`. FTD writing a command's first word
    twice (`ipv6 ipv6 icmp …`) is read as the one command.
  - A new card, *What the configuration changes touched*. The
    Administrators page's *changes* filter takes these, and `section:` is
    offered in the search and by the box at the top.
  - 111008 and 111010 say the same command twice. The one with the address
    it came from is the one kept. The address is taken from `from IP`, never
    from inside the command (`host 10.1.2.3`).
- **FTD: the box's own Linux side (199017).**
  - The management centre's deployment steps, run through sudo
    (`policy_apply.pl … PREPARE / SIGNAL`), are lines of the firewall
    itself, not of an administrator, with the step named.
  - SSH to the box says who got in, or who was refused and from where.

1.10.130

- **The page said "the daemon is not answering" after midnight while the
  daemon was reading, banning and answering `isemon --status`.**
  - *The cause:* the API token in `/run/isemon` was in the `isemon` group,
    not `isemon-web`. The daemon gives it to the web group only where it is
    in that group itself, and that had not taken. The web server's account
    (here apache) is only in `isemon-web`.
  - *Why midnight:* the PHP workers already running still read the token
    under groups they had kept, and the first ones started after the night's
    rotation could not.
- **What changes:**
  - Where the daemon cannot give the token to `isemon-web` by its group, it
    gives it by an ACL (`setfacl`). The owner of a file may always do that,
    whatever its own groups.
  - The watchdog checks the page's way in every minute, as the page would:
    the token is there, holds this daemon's token, and the web group may
    read it (by group or by ACL); and `/api/health` answers within the
    page's five seconds.
  - What can be put right is put right and said in the log. What cannot is
    said once, with the command that fixes it, or with every thread's stack.
  - An API thread that has gone is started again.

1.10.129

- **Traffic → Connected now: who is on the VPN and which tunnels are up at
  this moment.** FortiGate and FTD alike.
  - *Remote-access VPN:* the person, where from (with the flag), the address
    inside the VPN, group, group policy, DAP records, client and version,
    connected since and for how long, last heard of, connections dropped,
    packets too large, and the data carried (FortiGate).
  - *Site-to-site:* the peer, this side, tunnel name or group, IKE version,
    up since, last rekey, the live IPsec SAs (SPI, which way, when made) and
    the networks each side asked for.
  - *Pressing one* shows everything about it.
    - A person: what ISE gave them (groups, profile, policy set,
      downloadable ACL); what their VPN address did since they connected
      (sessions and data by what was done, where to, what was refused and
      by which rule); and the session's own lines.
    - A tunnel: what crossed between its networks in the last day, what
      failed with the peer, and its lines.
  - *How it is worked out:* a firewall's syslog says what happened, never
    what is up, so the page puts it together from the lines kept.
    - A session counts as up from its beginning until its end.
    - A tunnel counts as up from coming up or its SAs being made until it
      goes down or its SAs are deleted.
    - FortiGate says so every few minutes (`tunnel-stats`).
    - Something up since before the oldest line kept shows as "at least".
    - A remote-access session heard nothing of for days is marked "perhaps
      gone".
  - *On the overview:* a *Connected now* card. The page's button carries
    the two numbers.
- **The small cards are on the overview only again.** 1.10.128 also put them
  above the lists of the other pages; they did not belong there.
- **Site-to-site peers and *Why tunnels fail* count FortiGate too.**
  FortiOS's reasons get the same plain meaning, for example *peer SA proposal
  not match local policy* means no encryption both sides accept. The *VPN
  tunnels* card, which mixes SSL VPN with IPsec, is on the overview only.
- **More FTD message ids read:**
  - 109201, 721016, 722033, 737003 / 737006 / 737026 / 737029 / 737034: a
    session's address pool and handle, carried onto it. Also DTLS, and the
    `TunnelGroup <…> GroupPolicy <…>` form of 722041.
  - 750001 *request to rekey*: a tunnel's pairs of networks, each listed.
  - 720012: failover.
  - 113009 / 113011 (group policy) and 734001 (DAP records).
  - 411001–411004 (interfaces up and down), with a card *Interfaces up and
    down*.
  - 321001 / 321002 (resource limits), with a card *Resource limits
    reached*.
  - 202010 / 305006 (NAT pool exhausted), a session that could not be made.
  - 733101–733103 (threat detection: a host attacking or targeted, the shun
    list).
- **The VPN's own lines** are labelled as what they are. A session's
  *logout* is no longer called "an administrator signed out of the
  firewall".

1.10.128

- **Traffic: each page has its own cards above its list.** They are the
  overview's cards that belong to that page:
  - *Client VPN:* sessions by person, clients, how sessions ended,
    connections dropped, packets too large, refusals by a downloadable ACL.
  - *Site-to-site VPN:* peers, why tunnels fail, tunnels.
  - *Administrators.*
  - *The firewall:* names it cannot resolve, routes changed, failover,
    threat detection, TLS.
  - *Web* and *Threats.*

  A card shows only where there is something on it. *Sessions* keeps only its
  list. Every card is on the overview as before.
- **New cards (FTD):**
  - *Why tunnels fail:* the firewall's reason and what it means. Examples:
    no tunnel set up for this peer, the two sides ask for different
    networks, the peer stopped answering.
  - *How VPN sessions ended* (113019).
  - *VPN connections dropped:* DPD failure, transport closing, what the
    client said (722037, 722012).
  - *VPN packets too large:* by person, with the size and the tunnel's
    threshold (722035), which is an MTU problem.
  - *Refused by a person's downloadable ACL:* by the ACL's name in ISE and
    the person (106103).
  - *Names it cannot resolve* (746016): FQDN objects that match nothing.
  - *Routes changed* (317077 / 317078).
- **New card for both kinds of firewall:** *Administrators*, everyone who
  signed in to or changed the firewall itself, FortiGate and FTD alike.
- **More out of FTD's lines:**
  - IKE lines carry the reason, its meaning and the traffic selectors each
    side asked for (750001, 750003, 751002, 751022, 752012, 752015).
  - A peer's tunnel group is no longer its own address a second time.
  - 710003 keeps where the refused connection was going.
  - 113004 with two spaces before the server is read.
  - A refusal by the local user database says so.
  - 317077 / 317078 routes give the network, gateway and interface.
  - 324303 names the RADIUS server.
  - 716002 / 722037 / 722012 say why.
- **A card row's tooltip** showed a quoted search as `&quot;…&quot;`. It now
  shows it as typed. The same went for the quick filters and a popup's
  fields.

1.10.127

- **FTD: a remote-access session that drops and comes back.** 716058 (*session
  lost connection, waiting to resume*) and 716059 (*resumed*) are named and
  shown on the *Client VPN* page, with the person and the address.
- **FTD: SIP pinholes.** 607001 / 607002 write the far end without a port
  (`for IF:addr/port to IF:addr from REGISTER message`). Both addresses and
  interfaces are now read from those lines too.
- **Traffic: *Everything* is gone, *Other* is new.** The pages already hold
  every line between them, so a page of all of them again was only noise.
  *Other* holds what fits none of them (an FTD message id this version does
  not know, a kind of line no parser here reads) and its button shows only
  when there is something on it. The same for FortiGate and FTD. Lines put
  on *The firewall* before this version that belong on *Other* are moved
  there once at start. A search from the top for an address or a person
  still opens every line at once, under *Every line*, a button that shows
  only while it is open.
- **Traffic: the firewall switch and the time window** stay together on the
  right, and move to the next line together when the page is narrow.

1.10.126

- **The Traffic tab, a page for each part of the log.** This is the same
  for a FortiGate and an FTD, and holds older lines too. The pages:
  - *Sessions:* traffic only, where it used to be every line.
  - *Web.*
  - *Threats:* intrusions, antivirus, malware, files, Security
    Intelligence, application control. It shows only where a firewall sends
    any.
  - *Client VPN:* SSL VPN, FortiClient, AnyConnect.
  - *Site-to-site VPN:* IPsec, IKEv1 and IKEv2.
  - *Administrators.*
  - *The firewall:* failover, threat detection, TLS to its portal, health.
  - *Everything.*

  Each page has its own columns, its own quick filters and only its own
  kinds in the drop-down. Every line is filed under its page as it is read
  (column `area`, searchable as `area:`). A one-time repair files the
  firewall's own lines already stored. A FortiGate's IPsec tunnels go to
  the site-to-site page, FortiClient over IPsec (with an XAuth user) to the
  client VPN, and lines with an administrator's `ui` or `cfgpath` to
  Administrators.
- **More FTD messages.** IPsec SAs created and deleted (602303/602304),
  addresses given out to VPN users (109207, 722051), the AnyConnect client
  type (722055, with a card *VPN clients*), duplicate SYNs (419002) and
  routes added. Offload notices (805003) are skipped.
- **The box at the top (Ctrl+K)** finds on the firewall, besides addresses,
  names asked for, people and groups:
  - firewall rules and downloadable ACLs,
  - applications, intrusions, malware and Security Intelligence,
  - what the firewall said about itself,
  - VPN clients.

  Each opens on the page it belongs to. A plain word in the search box also
  looks in the unit's name and the action.
- **Faster on a very busy firewall.** About 1.6× faster in measurements on
  a 700,000-line sample of a failover pair:
  - Lines are written 5,000 to a transaction, not 1,000, with their counted
    buckets added up before they are written.
  - The live reader holds 10,000 lines before writing, where it held 3,000.
  - Addresses already looked at are not parsed again.
  - The syslog header's time is worked out once a second, not once a line.

1.10.125

- **Cards only FTD's own messages fill.** They appear on the Traffic tab
  when the firewall in view sends what fills them; a FortiGate never shows
  them.
  - *Dropped on the way, and why:* packets of sessions already closed by
    flag, no route, fragments, spoofing, inspection. A lot of RST or ACK
    here is asymmetric routing or a timeout set too short.
  - *Site-to-site peers:* who tries to build an IPsec tunnel and how much
    of it fails.
  - *VPN sessions, by person:* bytes carried by each person's sessions,
    from the line FTD writes when a session ends.
  - *Failover:* what the units said about each other, by interface.
  - *Threat detection:* which drop went over its rate.
  - *TLS to the firewall:* the TLS versions clients came with.
  - *Which unit wrote it.*
  - *Connections open:* how many connections each unit has open now, and
    the most it ever had.

1.10.124

- **More of what the management centre sends over FTD's syslog.** All of it
  is shown only where the management centre is told to send it; see
  [docs/ftd-logs.md](docs/ftd-logs.md).
  - **The intrusion policy (430001):** the signature (GID:SID:revision), its
    message, classification and priority, the intrusion policy, and whether
    it was blocked or only detected. New card: *Intrusions (IPS)*.
  - **The file and malware policy (AMP, 430004/430005):** the cloud's
    disposition, the file type, the malware's name, and what was done. New
    cards: *Files looked at* and *Malware*.
  - **The connection events (430002/430003):**
    - Security Intelligence (address, URL or DNS on a feed).
    - What the decryption policy did with the session, and the server's name
      it saw.
    - Both directions' bytes, the DNS query, the URL and its category.

    New cards: *Security Intelligence* and *SSL decryption*. Where the
    firewall also writes its own session end (302014), the session is still
    counted once.

1.10.123

- **Cisco FTD and ASA as a firewall for the Traffic tab.** *Settings → The
  firewall log* offers *Cisco FTD / ASA* as a kind. A firewall may now have
  several folders, so a pair in failover is one firewall with a folder for
  each unit. Every file in such a folder is followed, which suits the usual
  rsyslog file per message id (`%FTD-6-302014.log`). What is read:
  - **Sessions,** counted once, when they end. The line that opened a
    session gives it its direction and its address translation.
  - **Refusals** by the access group (with the rule's hash) and by
    downloadable ACLs (with the person).
  - **Drops on the way,** and packets of sessions already closed, kept apart
    from the refusals.
  - **The remote-access VPN:** sign-ins, refusals, session length and bytes
    each way, and the address inside the VPN.
  - **Site-to-site tunnels,** failover, threat detection and TLS to the
    firewall's own portal.
  - **The management centre's events** (430001–430005) where FTD sends them
    over syslog.

  The standby unit's copies of the active unit's sessions are left out.
  Countries come from this program's own database, because FTD writes none.
  FTD gives one byte figure for a session, so the page shows it as `⇅` and
  the *Carried* card does not split it into out and in. A new card, *How
  sessions ended*, shows why sessions were closed. See
  [docs/ftd-logs.md](docs/ftd-logs.md).
- **A name on the sessions of a VPN address.** A downloadable-ACL refusal
  "for user", an identity-firewall session or an address given out tie an
  address inside the VPN to a person. The sessions from that address are
  then counted under their name.
- **FTD and ISE, read together.** Each still works without the other.
  - A VPN sign-in FTD refused as `*****` is given the name ISE recorded for
    the same attempt.
  - A firewall line's popup shows the person's last ISE VPN sign-in, with
    their groups, profile and downloadable ACL.
  - A name looked up in the box at the top shows what the firewall saw of
    it: lines by verdict, bytes, addresses inside the VPN, how its last VPN
    sessions ended.

1.10.122

- **More than one firewall.** *Settings → The firewall log* now lists the
  firewalls one row each:
  - a **name** of its own,
  - the **kind** of firewall that writes the log,
  - **where its log is**,
  - **which files there are its**.

  This replaces the single kind and pattern that applied to every folder.
  An installation that never saves the list keeps reading exactly what it
  did: one firewall per folder, named after the folder. From the command
  line the list is JSON:
  `isemon --set fwlog_sources='[{"name":"hq","type":"fortigate","path":"/var/log/remote/hq","files":"*.log"}]'`.
- **The Traffic tab switches between them.** With two or more firewalls, a
  switch at the top reads *All firewalls · hq · branch*. Everything on the
  tab follows it: the cards, the chart, the three lists, the search box and
  what it offers. With *All firewalls*, each line in a list names the
  firewall it came from, and the search box knows `fw:` (or `firewall:`).
  Lines read before a firewall had a name carry none. Run
  `isemon --erase firewall` once to read them again with it.
- **A copy of the database carries every column.** Columns a table gained
  after it was first written down (the domain events' marks, for one) were
  left out of a copy, and the indexes on them with it.

1.10.121

- **A copy or a dump made by hand no longer floods the log.**
  - A database request that runs over a minute because of the work it was
    asked for now writes one line, for example "/api/db/backup has been
    running for 1 min while copying the database … – that is the work it
    was asked for". It used to dump every thread's stack and every database
    connection, about 80 lines. A request that is stuck for any other
    reason is still written out in full.
  - The indexes a copy builds at the end are no longer each a
    `[warn] sql took 7 s: CREATE INDEX …` line. The copy's own progress line
    already says "building its indexes".
  - The progress line names the table as a table ("— table failed, 2,000
    row(s)"). "— failed, 2,000 row(s)" read as if the copy had failed.
  - A job that reaches 100 % says so once, not twice.

1.10.120

- **Progress bars across the whole width, and their words on one line.**
  The bar for copies, tidying and the other database jobs on Settings → The
  database was a third of the card wide. Its words wrapped onto a second
  line under it ("…5% — 125 / of 2 300, 7 s so far"). Every progress bar
  now spans the whole card and its line of words stays on one line. On a
  screen too narrow for it, the line ends in "…" and shows whole on hover.

1.10.119

- **The dump being written now shows its bar where it was asked for.**
  "Make one now" under *The dumps it keeps* gets a progress bar in that
  card. The bar used to be drawn only in the card above, off screen. A dump
  program says nothing about how far along it is, so the bar fills against
  the size of the last dump of the same kind and says so ("the last one
  came out at 412 MB"). It never fills to the end before the dump is
  written. With no earlier dump it creeps, as before.
- **The complete export now carries the published ban list's key.** The key
  in the URL of the published ban list lives in a file beside the database
  and was left out. A machine built from a complete export gave the list a
  new key, and every firewall fetching the old URL was refused. The plain
  export still carries no secrets.
- **Fixed: "the daemon is not answering" while a copy was being made.** A
  copy was written straight under its final name. For the minutes it took,
  the half-made file was in *Copies kept*, with Restore and Delete beside
  it. Drawing that list opened the file to ask which engine it came from,
  and waited on the lock the copy held, so the page said the daemon was not
  answering. A copy is now written as `….db.part` and gets its name only
  when it is whole. A `.part` left behind by a copy that never finished is
  removed six hours later.

1.10.118

- **A progress bar while the firewall is read.** The Firewall page now shows
  a bar across the whole card while it reads what the firewall is
  carrying, in place of the small "reading…" beside the buttons. The
  firewall says nothing while it answers, so the bar is estimated from how
  long the last read took (it says so: "the last read took 12 s"). It never
  shows as finished before the answer is in. With no earlier read to go by,
  it sweeps instead. Answers the daemon already holds come back too quickly
  for the bar to show at all.
- **Fixed: "Try reaching it" showed the firewall's name one letter to a
  line.** RouterOS lays out `/system identity print` for a terminal, and
  over ssh without one it wrapped the name every character. The name is
  now asked for as a bare value (`:put [/system identity get name]`). On a
  router that refuses that, the old print is used and put back together.

1.10.117

- **Fixed: "Addresses on their way" stopped at exactly 200.** It was a
  limit, not the real number: the Banned page was given only 200 addresses
  and said "200 address(es) counting". The true count is now shown, and
  the list carries the 1,000 nearest to a ban (with "1,000 of N" in the
  heading when there are more). *Clear all* now reports the true number
  too, and the pass that bans whatever is over the bar reads every address
  in the window rather than the top 300.
- **Ban history: Clear instead of Erase.** The button beside the search
  now clears the search and the country and puts the order back to
  newest first. *Erase the ban history* moved to Settings → The database,
  under "Erase the collected data".
- **New: docs/growing-the-root-disk-almalinux9.md.** How to grow the root
  filesystem after the disk was enlarged in VMware (AlmaLinux 9, ext4
  without LVM, swap moved to the end of the disk).

1.10.116

- **Fixed: searching by `level:` failed with a database error** ("warnings
  and worse" on the VPN and administrators page). The level FortiOS gives a
  line was never kept: it is now kept with the rest of the line and
  searched there, so it works for every line read from this version on
  (`isemon --erase firewall` reads what is already here again, with it).
  A search the database cannot answer now says so under the box, rather
  than as an error at the bottom of the page.

1.10.115

- The **Clear** buttons on the Traffic page and on the Domain page's list
  look like every other Clear: the same size, with its icon, and they say
  what they do.

1.10.114

**Every list can be ordered by its headings.** Press a heading to order the
list by that column, press it again for the other way round; an arrow says
which. Rows with nothing in that column go last either way.

- **The long lists the server pages through** - failed attempts, logins
  (every door, the domain's included), the Domain page's events, the ban
  history, Events and the Traffic page - are ordered by the server, over
  every row that matches and not only the page on show. On the biggest
  tables a heading orders the newest 50,000 rows that match, which is
  quick on any size of database, and the count above the list says so
  when there are more.
- **Clear** puts the order back to the time, newest first, together with
  the search and the filters; so does choosing another door.
- **Every other table** - the cards on the Overview, the Logs tab, the
  router's entries, the popups - is ordered where it stands, and stays
  ordered when it is drawn again a moment later. A list the page holds
  whole and pages itself is ordered whole, before it is cut into pages.

**Clearing who fetched the published ban list.** Settings → Banning has a
button, *Clear who fetched it…*, that forgets the lines under *Fetched by*
and the count of refusals - a firewall long gone, an address that fetched
once while it was being set up. Nothing changes for the firewalls: the
list, its URL and who may fetch it stay as they are, and the next fetch
from each is written down as its first.

1.10.113

- On the Traffic page **Clear** also puts the order of the list back to the
  time, newest first, as well as the search and the filters.

1.10.112

**Reading the firewall's log again, and a false alarm about who runs the
domain.**

- **`isemon --rescan --logs fwlog`** reads the firewall's log again: every
  day still in its folder, oldest first, with whatever logrotate made of
  them (the reader itself follows only the newest two). A line already
  here is left alone and counted once, so this fills in what is missing -
  older days, a gap while the daemon was stopped. To count everything again
  from scratch, `isemon --erase firewall` erases it and reads it again by
  itself. A pass back over every log no longer reads the firewall's files
  as well, since nothing in them is judged. With `fwlog_keep_allowed` off
  the pass refuses and says to erase instead: the sessions it let through
  are not kept, so nothing would say they were read already.
- **The box at the top (Ctrl+K) searches the firewall too**, where its
  log is read: an address typed in says what the firewall saw of it in the
  last day (let through, refused, how much it carried), and a word finds
  the names asked through it, the people, their groups and the addresses
  that hold it. Pressing one opens the Traffic page on exactly that search.
  The popup about an address has a line "On the firewall" as well, each
  side of it one press into the list.
- **The lists on the Traffic page can be ordered by any column**: press a
  heading for that column, again for the other way round (the time, newest
  first, is where it starts). Ordered on the server, over every line that
  matches rather than the page in front of you. A search that reads fields
  out of each stored line stays in the order of time, and says so.
- **Fixed: a line could be counted twice** when the live reader and a pass
  back over the files wrote it at the same moment - both asked whether it
  was there before either wrote it. They now write one at a time.
- **Fixed: "administrators taken away" when nothing had changed.** When
  the question "who is in this group" failed for a moment - a timeout, a
  controller dropping the connection - the group was left out of that
  reading, and the watch on the directory took that as every one of its
  members removed; with a primary and a secondary directory, either one
  being slow one morning did it. A group that could not be asked now keeps
  what was known of it (and the log says so), a directory that did not
  answer or did not get as far as its groups says nothing about them, and
  a group said to be emptied that way is taken off the bar by itself once
  the directory answers again as it was remembered.

1.10.111

**More of the FortiGate's log, now that it writes more.**

- **The DNS filter** (`utm/dns`): the name asked is the host on the
  cards and in the lists, what DNS answered is in the line's popup, and
  the Web page has it as a kind of its own.
- **Single sign-on on the sessions themselves**: the person, their group
  and the server that said so are written on the traffic lines now. The
  People card counts them, a new **Groups** card counts the groups, and
  `group:` searches them (narrowed to the lines that name somebody).
- **IPsec**: phase 1 negotiations, their errors and stray ESP packets are
  read. A negotiation from outside that fails is a failed attempt, from
  the address it came from; a new **VPN tunnels** card counts what was
  said about each tunnel and how much of it failed.
- **What the firewall said about itself** is a card of its own, by what
  each line is - FSSO status, central management, SSL VPN, Security
  Rating, automation stitches, local-in policies added or changed.
- **Security Rating** lines read as one sentence (score and findings),
  automation stitches say what ran and what it did, and an administrator
  adding or changing a local-in policy shows the policy itself.
- The popup knows what the new fields are - the DNS question and answer,
  the referrer of a web request, the IKE exchange, the destination's MAC
  and maker, destination NAT - and groups them.
- **Fixed: data carried by long sessions was counted many times over.** A
  session that lasts is written every few minutes (log id 20) with its
  running total; the cards now add only what each line adds (`sentdelta`)
  and count the session once, when it ends. A VPN tunnel's own figures are
  no longer added on top of the sessions inside it, and neither are the
  web filter's lines, which write the session's bytes so far on every
  request they look at (one address showed 318 GB where its sessions
  carried 1.1 GB). Cards counted before
  this version keep their old figures until *the firewall's own log* is
  erased under Settings → The database, which reads the files again.
- **Fixed: the firewall failing to reach its own cloud counted as a failed
  sign-in.** Only a sign-in, a VPN login or a tunnel negotiation that fails
  is a failed attempt now; the rest is a warning it said.
- Quick filters for the DNS filter, IPsec, warnings and worse, single
  sign-on and Security Rating.

1.10.110

**The Traffic page, reworked: whole names, a search box that understands
fields, and what is kept.**

- **Search with fields.** The box on Sessions, Web and VPN and
  administrators now takes `field:value` terms as well as plain words:
  `srcip:10.1.2.3 -dstport:443`, `verdict:deny,block`,
  `ip:192.168.0.0/16`, `host:*.microsoft.com`, `msg~login`,
  `bytes>100M duration>1h`, `dstport:1-1024`. Terms side by side must all
  hold; `OR` (or `|`) is either, `-`, `!` or `NOT` turns a term round,
  `!=` is "is not", brackets group, `*` is a wildcard, `~` means contains,
  a comma means any of these. Any field FortiOS writes can be searched by
  its own name - `crlevel:high`, `agent~curl`, `osname:*windows*`; the
  ones without a column of their own are read out of each stored line, for
  at most a few seconds, and the page says how far back that got.
- **It offers as you type**: the field names with what each is, then the
  values the field holds, busiest first (`dstport:` offers 443, 53, …
  with their counts, `policy:` the policies with their names). Arrow keys,
  Tab and Enter.
- **"How to search"** opens a popup with the syntax, examples that run
  when pressed, and every field - the fast ones and the ones read out of
  the lines.
- **Under the box it says what the search was understood to mean**, or
  what is wrong with it while it is being typed.
- **Quick filters** for what is asked most (refused or blocked, from
  outside, more than 10 MB, failed sign-ins, settings changed, …), each
  only words put into the box.
- **Only the rows scroll** on Sessions, Web and VPN and administrators:
  the tabs, the search and the filters stay at the top and the pages at
  the bottom, with the column headings held above the rows.
- **Every field in a line's popup can be pressed** to find every other
  line with the same value.
- Cards and bars now open the list as a search that can be read and
  changed, e.g. `srcip:203.0.113.5 verdict:deny,block,fail`.
- **Whole names, never cut short**: the busiest cards are laid out again -
  the name and its number on one line, its bar and what was done under it -
  and the lists wrap long names and URLs rather than hiding them.
- **Private addresses are said to be private** rather than given the
  country "ZZ" and marked as on a public list (the lists of reserved
  ranges named every one of them).
- **What is kept** is said under the chart: how many lines, since when,
  how many counted buckets, for how long - with the way to Settings → The
  database, where the tables' sizes are listed and *the firewall's own
  log* can be erased.
- **Fixed: the country list read "out of sync" for good once every
  country was taken off.** It was compared with what the last fill - made
  while countries were still chosen - had put on the router. With no
  country chosen nothing is expected on it: an emptied list is in sync, and
  one that still holds entries says to use *Empty it on the router…*
  (filling never sends anything without a country).
- **Fixed: letting an address back in did not show in the ban history**
  where anybody would look. The history was ordered by when each ban
  began, so lifting one from last week changed a row far down the list.
  It is now ordered by the newest change - a ban lifted a minute ago is at
  the top with how it ended.
- The web category is searched as `category:` (FortiOS's `catdesc`); `cat`
  is FortiOS's own number for it.

1.10.109

**A new page: what crossed the firewall, out of the firewall's own log.**

Settings has a new pane, *The firewall log*: turn it on, pick which firewall
writes the log (FortiGate for now - the choice is there so that the next kind
is a reader, not a new page), and say where its syslog files are. A new tab,
**Traffic**, then appears between Logins and the Domain. Nothing on it is
ever judged and nothing on it can earn anybody a ban; it shows what the
firewall did.

- **Overview**: what was let through, how much it carried, what was refused,
  what the web filter blocked and the sign-ins to the VPN and to the
  firewall that failed; an hour-by-hour chart with what was let through
  above the line and what was refused below it, so a burst of somebody
  knocking stands out of a busy day; and the busiest of everything - who
  talks the most, the names asked for, who was refused and at which port,
  who moved the most data and where to, services, applications, countries
  reached and knocking, policies, interfaces, web categories, people. The
  addresses carry their flag and say whether this program keeps them out
  already or a public list names them. Every row, card and bar opens the
  lines behind it.
- **Sessions**, **Web** and **VPN and administrators**: the lines themselves,
  newest first, filtered by anything - a word, what was done, the kind of
  line, an address, a port, a policy, a way through the firewall, a session,
  an hour.
- **One line, read out**: a sentence saying what happened, the source, the
  firewall and its policy and the destination side by side, every field
  grouped by what it is about (the decision, the traffic, translation, the
  web, TLS, the VPN, the administrator's change) with what each of FortiOS's
  fields means, what this program knows of both addresses and how much else
  they did in the day, and the other lines of the same session.
- **It is built for a firewall's volume**: three and a half million lines a
  day on the site it was made with. The cards and the chart are counted as
  the lines arrive, so the page costs the same on a busy day as on a quiet
  one. The sessions it let through are kept a day (`fwlog_allowed_days`),
  everything else a week (`fwlog_keep_days`), and keeping the let-through
  sessions at all can be turned off (`fwlog_keep_allowed`) - they are
  counted on the cards either way. *Database* can erase all of it.
- A FortiGate that sends its log to a syslog server writes one file a day
  (`date=2026-10-01.log` and the like); `fwlog_name` is the pattern, and the
  newest two files in the folder are read, as with NPS.

1.10.108

**Why one site's dashboard said "the daemon is not answering" after
midnight - found, reproduced and put right - and a pass over the whole
program for faults.**

*The night at midnight.* Every request the dashboard makes was answered
on a thread of its own, and each opened a fresh connection to the database
server for itself - including `/api/health`, the one question whose whole
point is "is the daemon there?". Opening a connection waits on a name
server to turn `db_host` into an address, and nothing bounds that wait.
The night the name server was slow, every new connection hung, every
request with it, and the page said the daemon was not answering - while
the daemon was reading its logs and banning as usual on the connections it
already had, which is why it stopped cleanly a moment later and why its
log had nothing to say. Reproduced here by making every new connection
hang: the old version shows exactly that page; this one does not.

- **`/api/health` answers out of memory**, with no statement and no
  connection. The number of accounts on it is counted behind it once a
  minute.
- **Connections to a database server are pooled.** A request's thread
  hands its connection back when it is done and the next thread takes it,
  rather than each one opening, signing in and dropping its own several
  times a second while a page is open. The threads behind the kept answers
  do the same.
- **The server's address is looked up once and kept**, so opening a
  connection never waits on a name server again (`hostaddr` on
  PostgreSQL; the address itself on MariaDB). Both get TCP keepalives, so
  a server that goes away without a word is noticed in a minute rather
  than at the kernel's own retransmission limit.
- **The watchdog from 1.10.107 also watches the requests**: one that has
  been running for a minute is written to the log with what every thread
  is doing, so the next such night explains itself.
- **A write on a connection the server dropped is tried once more** on a
  fresh one. Every long-lived thread lost its first write after a server
  restart - the reader a record, the judge a verdict.
- A driver's own error on opening a connection is now the one error the
  rest of the program catches; a transaction is committed on the
  connection it was begun on and never on a replacement.

*Put right elsewhere (the review found sixty-odd things; these are the
ones that changed what a site saw):*

- **Setting `log_zone` or `winsec_zone` stopped the controllers' logs
  being read at all** - the zone's name was handed where a zone was
  wanted, every chunk raised, and the reader had already moved past it.
- **"One account's password used to reach another machine" was never
  raised**: the two names compared were always the same name.
- **Every status poll counted the day afresh.** The kept answers for the
  front page's counts carried the second in their key, so no poll ever
  found one, and each poll left a key behind that pushed the hour-long
  answers out.
- **Emptying "the other" database could empty the one in use**: the guard
  compared the words of the address, so another account name or
  `localhost` for `127.0.0.1` slipped past it. Two settings are now the
  same database when engine, host, port and name are, however spelt.
- **The firewall sync stopped when the first firewall was switched off**,
  even with the second on and ready - every ban, every expiry, the
  minute's sync - against what its help text promised.
- **A sync could skip addresses whose bans were lengthened** when the
  router chunk was set above forty: stepped by the setting, sliced by
  forty. Those kept the short timeout on the router and were let back in.
- **Five identical refusals in one second could be three rows** when the
  reader's look fell inside that second; the count is carried across
  reads now.
- **A rotated log with more than eight megabytes unread** had the rest
  dropped without a word; it is read to the end.
- **A tac_plus line two days behind its file's clock landed a year
  ahead**, and dragged the file's clock there with it.
- **A re-read of the domain events that changed nothing** still threw the
  counted answers away and recounted a billion rows.
- **Re-sorting the refusals wrote the token log's plainer words over the
  RADIUS server's verdict** on every token refusal, every upgrade.
- **The Banned page was two thousand statements a poll** on three hundred
  bans (seven per row); the page's notes, counts and proofs are read in
  one statement each now, and the whitelist is not asked for on every row
  and every record.
- **A retention walk could stop for good at a wall of rows stamped with
  one moment** (a "clear all" ends every ban at once), and the table was
  never tidied again.
- **Two unsaved settings changes were thrown away** by a look at another
  page; the Logs tab's job poll was every second and a half; a popup
  closed while its answer was on the way reopened itself; "ask about one
  address" with a word that is not one showed a JavaScript error; a
  mistyped name in "set a password for" made a new account; the daemon's
  log was read whole for its last three hundred lines; a restore's upload
  went to the system's temporary folder rather than the disk that was
  measured; `kill -USR1` and the watchdog each wrote their dump every
  thirty seconds when both conditions held; `#windows` did not survive a
  reload.
- Smaller: a gzip bomb in a downloaded list could not be stopped before it
  was unpacked; a hand-unfolded subnet climbed every member a rung of the
  ladder; an account the directory owns was counted a wrong password when
  the directory was away; a PostgreSQL index check never ran (its
  statement was refused); a MariaDB account already there kept its old
  password after "set it up"; the catalogue let go of values whose rows
  were still there on an upgraded database; the search box could show
  nothing for an address prefix on PostgreSQL; several races between the
  page's threads and the reader's.

1.10.107

- **When the daemon stops without dying, it now says why.** One site's
  daemon went quiet a few minutes after midnight: no error, no line in the
  log, the page saying the daemon was not answering, and the restart that
  put it right threw away everything that would have said what it was stuck
  on. Now, when the main loop has not come round for five minutes, the log
  gets what every thread is doing - the file, the line and the function -
  and, on PostgreSQL or MariaDB, what the server says each of this
  program's connections is doing and what it is waiting on. Once for each
  time it sticks, never while it is merely busy.
- **`kill -USR1 <pid>` writes the same thing down on demand**, with nothing
  to install and without stopping anything:
  `kill -USR1 $(systemctl show -p MainPID --value isemon)`.

1.10.106

- **The Logs page has a *Last 24 h* column**: beside each file, how much the
  machine it comes from wrote in the last day - the refusals and sign-ins
  it sent, or the events a domain controller wrote. One column holds any
  number of logs, where the same numbers strung along the heading could not
  hold them all: the controllers were left out of it, and a site with many
  logs would have had a heading wider than the card.
- **"DC03 613 · dc03 0" was one machine.** NPS writes its own name, `DC03`;
  the syslog folder is `dc03`. They are now folded into one and shown the
  way the folder spells it.
- **Past six machines, the heading is one line** - "8 machines · 1,036 in
  24 h · 1 quiet" - with the whole list behind it.

1.10.105

- **A page of its own for the logs: *Logs*, between Events and Settings.**
  *The logs being read* was half of a row on the Overview, under the VPN's
  own cards, and went away with them whenever another door was picked. It
  is on its own page now, always there whatever is switched on, and opens
  straight from `#logs`.
- **`isemon-api.php` answers a direct request with 404 itself.** It is only
  ever included by `index.php` and `banfeed.php`. The nginx vhost shipped
  with this refuses it by name, but a site's own vhost is never replaced on
  an upgrade, and one from before that line had the installer print a yellow
  line on every upgrade that nothing here could make go away. It is now a
  quiet note with the line to add.
- **The installer says when the ban feed cannot be fetched**: a vhost that
  hands only `index.php` to PHP answers `/banfeed.php` with 404, or with the
  file itself.

1.10.104

- **"the logs have not been read lately" at night, while every log had
  been read two seconds before.** The header asked when ISE's refusal log
  last had something NEW in it, and with the VPN quiet for eleven minutes
  that was a warning. It now asks whether the reader is still going: when
  any log was last looked at, new lines or not. A reader that has stopped
  stops looking at every file at once, and that is still a warning after
  five minutes.
- **The domain controllers' logs read "0" in the line of who has been busy**
  on the Overview, beside logs of 800,000 events. That line counts sign-ins
  and refusals per ISE node, token server and RADIUS server, which a
  controller never writes, and the command line has always left them out.
  The page leaves them out too.

1.10.103

**A pass over the whole program for faults, and a day of a real domain
(three controllers, 2.9 million events) used to time it.**

*Faster:*

- **The Domain page, opened cold on that day: 11.6 s, now 0.9 s.** Two
  questions every reading asks - "does this account sign in anyway?" and
  "did it ask for a ticket to that server?" - were answered by walking every
  sign-in of the day, because the engine picked the index on the kind over
  the one on the account. They are asked of the account's index now, by
  every spelling of the name.
- **The search box and a text search of the events: 5.4 s and 7.5 s, now
  2.5 s and 2.7 s** on SQLite. Its `LIKE` already ignores case, so the extra
  `LOWER()` on every column of every row is left out there. The answers are
  the same; the other two engines are unchanged.
- **Reading a controller's log is about a third faster.** The fields of an
  event are found at the colons rather than by trying every label at every
  position, and a field asked for by its label alone is looked up once per
  event. Checked against the old reading on 290,000 real events: the same
  fields, the same rows, to the character.

*Put right:*

- **The PDC's copy of a refusal could hide the refusal itself.** The copy is
  now recognised as the controller that forwarded it, at that controller's
  own address, and only the copy is left out - also in the counted-ahead
  cards and in the list a card opens, so the number and the list agree.
- **An account spelt several ways was not "being hammered".** The bar was
  applied to each spelling (`jnovak`, `EXAMPLE\jnovak`, `jnovak@...`) before
  they were put together. Now they are put together first.
- **A site that audits only Kerberos authentication (4768) and not service
  tickets (4769) had no realm**, so `jnovak@EXAMPLE.CZ` was never matched
  with `jnovak`. The realm is read from either. `Administrator@...` is also
  asked for as `Administrator`, the way the controllers write it, not only
  in lower and upper case.
- **The matching with ISE, NPS, tac_plus and the others missed names written
  with a domain in front** (`EXAMPLE\jnovak` in ISE's log against `jnovak`
  on the controller). It now asks by the moment and compares the names
  folded, and one-time passwords get their own wording.
- **"Read the logs again" with only NPS logs** did nothing even when the
  NPS VPN is judged. It now reads them.
- **Importing settings failed** when the ban feed was set to a password but
  the file (rightly) held none. A missing password is reported as missing.
- **The machine-password reading said "stale password"** on a site that does
  not keep sign-ins, where it cannot tell. It now says it cannot tell, and
  what to switch on.
- **An address was not named after its machine** when no controller address
  was known yet.
- **The ban feed:** two firewalls fetching at the same moment could lose one
  of the "last fetched" notes, and an address allowed to fetch did not match
  when it arrived as IPv4-in-IPv6 (`::ffff:192.0.2.1`).
- Two callers starting the background database repair at the same moment
  could start it twice.
- Settings that were listed twice in the program's own tables (the database
  connection) are listed once. What they did does not change: the second
  listing was the one in force.

1.10.102

**The ISE and domain matching of 1.10.101, checked against a real site.**

A day of a real site's three controllers (2.9 million
events) and its two ISE nodes. 168 refusals of `Administrator@...` that the
controllers wrote as coming from the ISE node were all found in ISE's log: a
spray on the VPN from twenty addresses on the internet. The TACACS+ sign-ins
through the same node were found as well, with the router and the admin's
address.

*Also found in those logs, and put right:*

- **`\\PROXY01` and `PROXY01` were two machines.** An NTLM client
  that names itself UNC-style is now read without the backslashes, and rows
  already stored are matched either way.
- **A proxy was called "one of your own domain controllers".** When a proxy
  binds to LDAP with a service account, the controller writes its own name as
  the workstation (4624, logon type 8). The address was then named after the
  controller. A controller's name is no longer given to an address that is
  not a controller's. The address is named after the machine account that
  signs in from it, and placeholders like `localhost` are skipped.
- **The same proxy was then "a desk: two accounts sign in from it".** Twelve
  more people's passwords passed through it by NTLM, which names the machine
  and not its address. A machine is now counted by its name as well as by its
  address, and it reads as the server it is.
- The configuration-mode commands from `aaa authorization config-commands`
  were checked against the same ISE log: a session that removes an access
  group, replaces a 330-line access list and puts it back is shown whole and
  in order. The access-list line and the first `deny` under it arrive in the
  same second and are told apart by the milliseconds.

1.10.101

**The domain's side of an attempt, matched with ISE's, NPS's, tac_plus's and
eduroam's side.** When ISE checks a VPN or 802.1X password against Active
Directory, the controller writes down the ISE node's name and address, never
the person's. NPS, an eduroam server and tac_plus are the same. The system
that asked wrote the rest: which door, which VPN gateway, switch or access
point, the device's MAC, the address on the internet. The two are one attempt
seen from two sides, and what they share is the name and the moment. They are
now matched by exactly that, within ten seconds, using the index on the name.

- **A card or a row about refusals that another system asked about now says
  so, and says from where.** For example: *"ISEA is ISE checking these
  passwords with the domain on somebody's behalf ... At the VPN (FTD-VPN): 8
  refusals, from 198.51.100.9. That address is not kept out yet."* For the
  Wi-Fi and the sockets it gives the switch or access point and the MAC,
  and a private MAC is said to be one. For TACACS+ it gives the device and
  the address the person signed in from. The *desk or server* reading is left
  out there, because the machine the domain names is the one that asked.
- **"One machine failing against many accounts"** where the machine is an
  ISE node or an NPS server is a spray from outside, and the card now says
  from which addresses and how many are already kept out.
- The NPS reading from 1.10.100 goes through the same matching: by moment as
  well as by name, and counted as NPS's own rows (one Wi-Fi refusal is two
  events on the controller and one row in NPS's log).
- **Nothing depends on it.** With only the controllers' logs, only ISE's or
  only NPS's, each reads exactly as it did. The matching is added where both
  sides are there, and it only speaks when at least half of the refusals
  have a partner.

1.10.100

**The Domain page, read against a real site's controllers.** Five hours of
two domain controllers' Security logs, with the same afternoon's NPS log,
gone through event by event. Every card was compared with what the events
actually said. Several readings were wrong, and some things in the logs were
not read at all.

*What was read wrongly.*

- **One wrong password was counted twice, and the second copy read as
  something running on a domain controller.** A controller that refuses a
  password asks the one holding the PDC emulator role before it answers, and
  the PDC writes the refusal again with the first controller's address as
  where it came from. The Domain page now leaves the PDC's copy out. The
  controllers' own addresses are learned from how they sign in to each other,
  so nothing has to be typed in.
- **One person was two cards.** `jnovak` and `jnovak@example.cz` were counted
  apart, with two different readings of the same server. They are one card
  now, naming both forms, and pressing it opens both.
- **Bursts were read as a clock.** Eleven tries inside one second, then
  eleven more thirteen minutes later, then eight minutes after that, was said
  as "eleven tries every ten minutes, to the second". The test for a clock now
  also needs the tries spread over most rounds, not all in one. Bursts are
  said as bursts: a program retrying the moment it is refused.
- **A machine with no address was called "a desk".** An NTLM refusal names
  the workstation and never its address, and with nothing to go on the page
  said "looks like one machine rather than a server". The address is now
  worked out from the machine's own account (shown as *by its name*). Where
  even that is missing, the page says it cannot tell.
- **A terminal server was read as "not where the password is".** That is
  right for a web or mail server signing in for somebody elsewhere, and wrong
  for a server people sit on. When the account asked for tickets to that
  server, the reading says so and points at the person's own session there:
  the mail client, the Credential Manager, a mapped drive.
- **A GUID was taken for a machine's name.** Azure AD Connect's replication
  addresses a controller by its GUID, and the controller's address was then
  called "a SERVER called" a GUID.
- **`TS01$@EXAMPLE.CZ`, a computer as a service ticket names it, was
  counted among the people.** It is a machine account from this version on.
- "every an hour" is now "every hour".

*What was not read at all.*

- **A computer's own password refused** is a card of its own. Kerberos
  refuses the computer account with a wrong password, and straight after,
  NTLM refuses an "account" with the computer's name and no `$`. That second
  half used to be the only card, as "no such account". The reading says
  whether the machine itself still signs in: if it does, something else is
  using an older copy of its password; if it does not, its trust with the
  domain is broken. It also says what to run to check.
- **What NPS asked the domain about is read out of NPS's own rows.** A
  controller writes those refusals with no machine and no address (logon
  process IAS, svchost.exe). NPS wrote which door it was, which access point
  or VPN gateway asked, the device's MAC and, for the VPN, the address on the
  internet. A private (randomised) MAC is said to be one, so nobody goes
  looking it up.
- **Names that do not exist, asked about by NPS** is a card of its own: a
  password spray on the VPN as the domain sees it, with the addresses NPS saw
  and how many of them are already kept out.
- **The same person signing in fine** is said on the card. It is the
  difference between a forgotten password and an old copy saved somewhere.
  When every refusal writes the name like an e-mail address while Windows'
  own sign-ins use the bare name, that is said too.
- **One attempt written twice** (Kerberos and NTLM, or the password check and
  the failed sign-in) is said, with the number of attempts it really was.

*TACACS+: what is typed inside `configure terminal`.* A session whose list
goes into configuration mode and holds nothing but exec commands now says
why. The device asks the server about configuration-mode commands only with
`aaa authorization config-commands`, and writes them to accounting only with
command accounting at level 15. Nothing was lost here: a week of one site's
ISE logs, across every device, held no configuration-mode command at all.
[docs/tacplus-logs.md](docs/tacplus-logs.md) section 4 has the lines.

*The audit policy.* [docs/windows-security-log.md](docs/windows-security-log.md)
now says which audit subcategories the controllers should have switched on,
which card each one feeds, and which the site's own logs showed to be off.

1.10.99

**The VPN through NPS is judged, and the ban list is published for other
firewalls.**

*The VPN through a Windows NPS.* A FortiGate, an ASA or any gateway that asks
NPS about a password is now counted and banned exactly as the VPN through ISE
is: the same bar, the same window, the same ladder, the same front-page lists.
NPS itself says which requests are a VPN (a *Virtual* port asking for a
network, never a shell at a switch's prompt), and the address the person came
from is the one the gateway puts in *Calling-Station-Id*. The sockets and the
Wi-Fi are never judged. An EAP conversation the client walked away from
decided nothing and is not counted. `watch_devices` names ISE's devices and
does not apply to NPS, because its default of `FTD-VPN` would otherwise have
switched this off everywhere without a word. *Settings → Banning → Judge the
VPN through NPS as well* turns it off. Checked against a day of a real
site's log: a password spray on a FortiGate's SSL VPN from a dozen addresses,
names such as `admin`, `manager` and `linkedin`, and five of the addresses
banned with the default settings. One more address paced itself at two
attempts every seven minutes, which stays under five in ten; a longer window
catches it.

Lines forwarded by rsyslog end in `#015`, rsyslog's way of writing the
carriage return NPS ends every line with. That text was read as the value of
the last column; it is dropped now.

*The ban list, published.* *Settings → Banning → Publish the ban list for
other firewalls* puts the addresses being kept out at
`https://<this server>/banfeed.php`, for a firewall this machine never logs in
to:

- **Cisco FTD**, through its FMC's Security Intelligence: one address or
  range per line, and an MD5 URL beside it (`&md5=1`), which the FMC asks for
  when it fetches more often than once an hour.
- **FortiGate**, as an external threat feed of IP addresses.
- A **plain list** with a few comments for a person, or **JSON** for a script.

What goes in is what the router gets: nothing while the blacklist is off,
nothing whitelisted, nothing whose time has run out, and folded ranges as
ranges. The bans on a clock can be left out (`banfeed_temporary`) for a
firewall that fetches seldom, and one address family can be chosen.

By default the URL asks for nothing, which is what a firewall fetching a list
expects. Who may fetch it is the web server's allow list, and optionally a
list of addresses (`banfeed_from`). `banfeed_auth` can ask for **a key in the
URL** (the one way for an FMC, whose feed has nowhere to type a password; *New
key* changes it) or for **a user name and a password** by HTTP basic
authentication (a FortiGate sends them). The key is kept in
`/var/lib/isemon/banfeed.key`, and the password is kept like the router's.
Neither goes into a log: the web server hands the key to the daemon in the
body of a request, never in a query string that the debug log writes out.

The settings page shows the URL for the chosen firewall (a click copies it),
who has been fetching it and when, and anything refused. A button opens a
step-by-step guide for that firewall, for the chosen way of proving it may
fetch, with the commands to copy. The guide says plainly what the list does
not reach. On an FTD, Security Intelligence filters traffic *through* the
box, not the remote-access VPN that ends *on* it. On a FortiGate it is a
local-in policy, or the SSL VPN's own source-address setting, that stands in
front of the VPN portal.

`banfeed.php` is a new file beside `index.php`. The installer copies it on an
install and on an upgrade. nginx serves it through the `location ~ \.php$`
that is already there, so the vhost does not change.

*Also.* A setting found by the search box on the settings page that lives
inside another pane (the second firewall, the published list) opens that
pane; it showed an empty page before. A drop-down whose values are codes
shows words for them.

1.10.98

**The third pass: how logs are read, how the program is installed, and a
catalogue of values so that searching years of data does not read years of
data.** As before, every finding was checked against the code and most against
a test before anything changed, and nothing that worked changes what it does.

*Holes closed.*

- **A value in a log can no longer make a record of its own.** Log text was cut
  into lines by Python's `splitlines`, which also cuts at characters that are
  not line ends in a log file (U+2028, U+0085, form feed and others). A user
  name or a typed command holding one of them was cut in two there, and the
  second half was read as a separate line, so whoever chose the name could
  write a record that ISE, NPS or tac_plus never wrote. Lines are now cut only
  at `\n`; a `\r` before it and a byte-order mark at the start of a file are
  dropped.
- **A log rotated by `copytruncate` is no longer skipped.** When the file had
  been emptied and refilled past the point already read before the next look,
  the program compared its mark against what it had just read, found it
  "unchanged", and carried on from the old offset, so the new start of the
  file was never read. The mark is now taken from the file itself.
- **Files the program writes are replaced whole, never half-written.**
  The token, `known_hosts` and the saved settings are written to a temporary
  file with their final permissions and then renamed into place, so nobody
  can open them in between.
- **The web page reads the token through its own group.** The installer makes
  an `isemon-web` group holding only the web server's user, and the token and
  `/run/isemon` belong to that group. Before, the web server had to be in the
  `isemon` group, which could read the whole configuration. On an upgrade the
  web user is taken out of `isemon` only after the token has been checked to be
  readable through the new group; if it is not, nothing is taken away.
- **The service runs with `UMask=0027`.** Nothing it creates is readable by
  other users of the machine.

*The installer.*

- The first account is made before the service starts, as the `isemon` user,
  and its password is passed in the environment (`ISEMON_PASSWORD`), not on a
  command line where `ps` shows it. `isemon add-user` and `isemon passwd`
  accept it the same way.
- `--allow` never failed when it did not change anything; an address list the
  installer could not place now stops it with a message. The list is checked
  before use.
- `--log-from` names the machines allowed to send syslog, as `--allow` names
  those allowed onto the page.
- The web server's configuration is tested (`nginx -t`, `rsyslogd -N1`)
  before any service is restarted with it, so a mistake does not take down a
  web server that was running.
- An upgrade keeps the previous version beside the new one
  (`isemon.py.<version>` and `web.<version>`), carries `known_hosts` across,
  and brings the web group, the SELinux switch and the web server's
  configuration up to date as an installation does.
- Files are not written through symbolic links, and uninstalling lists what it
  left behind.
- Log rotation also rotates at 200 MB, so a debug switch left on does not
  fill the disk, and after rotating it tells the daemon alone to reopen its
  log (`systemctl reload`), not every process of the service.

*The speed, on years of data.*

- **A catalogue of values (`seen_values`).** The search box and the drop-downs
  over the lists (devices, servers, ports, reasons, profiles, VLANs, groups,
  MAC addresses, clients, commands) had to read every row to find which
  values exist. The catalogue keeps each value once per door, with how many
  times it was seen and when first and last. It is kept up to date as records
  are written. After the upgrade, it is filled from the rows already in the
  database by a background thread, an hour of data at a time. The log says how
  far along it is, and until it is complete everything is asked of the tables
  as before. Values whose rows have all been deleted are dropped once a day.
  Anything that rewrites stored values (erasing records, renaming NPS ports,
  filling in doors) empties it and fills it again. A column holding a value
  longer than 190 characters goes back to being asked of the table, so no
  answer is ever shortened.
- **Indexes that a wider index already covers are dropped.** This happens only
  once the wider index exists, so a database whose upgrade was interrupted
  keeps the narrow ones. The MAC address index now also covers the door,
  which is how the lists ask for it.
- Equal counts in the list of doors are ordered by name, so the same question
  gives the same answer from the tables and from the catalogue.

*Known and not yet changed.* The 4 GB upload limit for restoring a backup;
the SELinux label of `/run/isemon` on systems that enforce it; the
front-page counters of failed and passed sign-ins, which are still counted
from the rows rather than from a rollup; live records are written one at a
time rather than in batches.

1.10.97

**A second pass over the whole program: bugs, holes, and what years of data
in the database do to it.** Three separate reviews, each finding checked
against the code (and most against a test) before anything was changed.
Nothing that worked changes what it does.

*Holes closed.*

- **Secrets typed on a switch are gone from the records, not only from the
  command column.** 1.10.93 kept `username admin secret X` out of the command
  column, but the raw record beside it (ISE's `CmdSet`, tac_plus's `cmd`)
  was kept whole, and anybody who could open a row read the secret in the
  list of fields. They are taken out as records are written, when an older
  record is shown, and once from every record already in the database, in the
  background after the upgrade. *Copies of the database made before this
  version still hold them.*
- **The router's ssh key is remembered across restarts.** It was kept in
  `/run/isemon`, which systemd empties at every restart, so after each one the
  router was accepted afresh from whoever answered first. With password sign-in,
  whoever that was received the router's password. The key now lives in
  `/var/lib/isemon/known_hosts` (what `/run` had learned is carried across
  once), and a router that answers with a different key is refused with
  instructions: if it was replaced on purpose, delete its line from that
  file.
- **The stored session hash is no longer a way in.** A copy of the database
  holds each session's hash, and sending that hash back signed its holder in
  as that person. Sessions opened before 1.10.93 still work until they end.
- **Adding an account never overwrites one that exists.** "Adding" the only
  full administrator as read-only demoted them, and adding a name the
  directory owns gave it a local password.
- **"Try a server" in the database settings uses the saved password only for
  the saved server.** Any other server named in the request needs its password
  typed; before, the saved one could be sent to any host.
- **Before sign-in, nothing about the directory is shown.** The sign-in page's
  reply no longer carries the domain controller's name, its TLS errors, or
  whether a name belongs to the directory. The details are in *Events*.
- **Failed sign-ins no longer lock an account for good.** An attempt made while
  already waiting is refused but not counted, so the wait ends a quarter of
  an hour after the attempts that earned it. The counters are capped, so
  made-up names cannot grow them without end.
- **Testing a directory sign-in from Settings** is counted like any sign-in
  and recorded in *Events*, instead of being an unlimited way to guess a
  domain user's password.
- **Read-only users** get only a job's progress (not its output, which can
  hold router or driver error text), and the router's list is kept 15
  seconds instead of being fetched over ssh on every click.
- **Log file-name settings** (`nps_name`, `winsec_name`, …) may not be paths
  (`/`, `..`). **Passwords** in settings may not contain line breaks, the
  MariaDB client password file quotes the password, and restoring a MariaDB
  dump refuses `LOAD DATA LOCAL`.
- **A directory read without TLS** is flagged at every start: sign-in
  passwords cross the network in the clear. The setting itself is left as it
  is (a certificate is needed to change it).

*Bugs.*

- **PostgreSQL / MariaDB: a dropped connection is replaced on every thread.**
  After a database restart, the main loop's connection (used every few
  seconds, never idle for a minute) was never checked again: every write on
  it failed until isemon was restarted. The driver's own errors from
  BEGIN/COMMIT are now the program's, and a connection the driver knows is
  gone is replaced at once.
- **NPS: busy servers no longer lose answers.** Only 120 requests could wait
  for their answer; past that the oldest were dropped, and their answers then
  wrote no row, with nothing said. The limit is now 5,000, anything dropped
  is logged, and across a restart the newest 500 waiting requests are kept
  (it used to be none once more than 200 were waiting).
- **PostgreSQL: an index build that was interrupted is rebuilt.** A background
  index build stopped by a restart left an invalid index that was never
  used and never rebuilt. It is dropped and built again at the next start.
- **An index that is still being built is not a reason to answer nought.**
  Statements naming an index that does not exist yet (it can take hours to
  build on a big table) run without the hint instead of failing. The totals
  on the front page read 0 until the build was done.
- **One-time repairs are marked done once they are done**, not before. One
  that failed or was stopped half way now runs again.
- **The clean-up's low-water mark** only moves as far as the deleting really
  got.
- **Answers overtaken by a change are not kept as fresh.** After an erase,
  the cards showed the erased data for up to half an hour. Kept answers,
  lists and filter values are now let go at an erase.
- **The Domain page's event list for one bar of the chart** ends where the bar
  ends. An event on the hour was in two bars' lists.
- **The night the clocks go back** (25 October), the NPS, token-server and
  eduroam lines of the second 02:00–02:59 got a time an hour too early. They
  now get the right hour.
- **The address search on PostgreSQL** follows the address, not the database's
  collation (`10.1` no longer finds `101.x`).
- **Two Domain pages open at once** no longer reset each other's "still
  working" state.
- **The page:** a filter or search changed while a list was loading is not
  lost any more; the Events list does not draw an older answer over a newer
  one; the tab counts re-asked after a restart keep the list's own window.

*Speed, with years of data.*

- **Filter drop-downs and tab counts** are kept in proportion to their cost
  (up to half an hour), instead of being worked out again every two minutes
  whatever they cost. On a big table that was a full scan every two minutes
  for as long as a list page was open. The same for searches in the lists.
- **The search box (Ctrl+K)** keeps its name and address answers per word, and
  runs the searches that read whole tables (MACs, devices, commands, the
  domain) only from three characters on.
- **Counts.** SQLite estimates huge tables from their row ids instead of
  counting a billion rows; the "ever" totals on the front page are exact up
  to two million rows and estimated past that. The ban history and *Events*
  count up to 20,000 and then say *more than*.
- **The Bans tab** no longer asks for the whole history twice on every
  poll, and its country breakdown is kept for a minute. The Events list has
  a `(kind, ts)` index.
- **The domain band of the front-page chart** is read from the hourly counts
  (when those are verified), not from every sign-in in the window: over a
  year that was hundreds of millions of rows.
- **One person's domain events** have an index on `LOWER(account)` on SQLite and
  PostgreSQL (MariaDB has no index on an expression). It is built in the
  background on big tables.
- **Re-weighing every log** reads refusals a few thousand at a time along
  an index, instead of one statement that pulled every VPN refusal into
  memory (PostgreSQL / MariaDB) or held one read open for hours (SQLite).
- **`--rescan` writes 500 records per transaction** instead of one, falling
  back to one at a time if anything in a batch fails.
- **A browser tab nobody is looking at** asks once a minute instead of every
  five seconds, and catches up the moment it is shown.

*Seen, and left for a later version.* These are larger changes that need a
data migration of their own: a distinct-values table behind the search boxes
and filter lists (so a search stops reading hundreds of millions of rows);
hourly counts for the failed/passed records like the ones the domain events
have (for front-page cards over a year); a table of MACs that got on, for the
"never got on" cards; removing seven indexes that duplicate the start of
another one; batched writes for the live reading. Also left: the status
shows the log paths to read-only users (the paths can no longer lead out of
the log folders); a log chunk the parser throws on is skipped, not retried.

1.10.96

**NPS ports are named by the setting that is saved, not by the default.**
Since 1.10.93 the ports already stored were renamed at the start, while the
database was still being opened, before the settings saved in it had been
read: by the default, `GigabitEthernet`, whatever *What the switches call
their ports* said. A site that had emptied that setting got every port
renamed `GigabitEthernet6/0/9` at the start, and back to `6/0/9` the moment
the settings were saved (122,371 rows each way). The renaming now happens
once the daemon has read the saved settings, and again only when that
setting changes. The first start of this version puts the ports back to
what the setting says, once; every start after that does nothing. That
repair's statements are written down as the expected work they are, not as
slow statements.

An empty *What the switches call their ports* means the switch's number
alone (`1/0/24`); the default, `GigabitEthernet`, writes them the way ISE
does (`GigabitEthernet1/0/24`).

1.10.95

**NPS: the EAP conversations a machine walked away from are shown, as
ISE's 5440.** All ten months of the NPS server's logs this was written
against were read again, every one of their 21,037,472 lines. Every line was
the shape NPS writes, and every answer found the request it answered. The
one thing in them isemon did not show was 109,750 conversations NPS had
answered with a challenge (the next question of 802.1X) and that never
went any further: zero clients about a hundred times a month each, and in
June one Aruba access point 23,599 times. ISE writes the same thing as its
own refusal, *5440 Endpoint abandoned EAP session*, and isemon has always
shown that one.

They are now refusals at their door, reading *the machine
stopped answering in the middle of EAP; nothing was decided*, reason
code `abandoned`, with the machine, the switch and the port. A challenge is
known to be the end only once nothing has followed it, so each is written
down five minutes after it was read. A conversation that was challenged and
then did finish is only its answer. The front page treats them as it treats
MAB first: a machine that walked away and got on a moment later raises no
card, and one that never got on is on the card of machines that never got
on. Nothing is judged. The eduroam page does not count them, because
FreeRADIUS does not write them either.

**`docs/nxlog-nps.conf` no longer drops the challenges.** The one shipped
before did, so a site that ships NPS's log with it should take the new file
(or delete the `,11,` line from its `Exec`). What is already stored stays;
`isemon --rescan --logs nps` reads the months still in the folders again and
adds the abandoned conversations to them, without doubling anything.

What the ten months hold, for the record:

| | lines |
|---|---|
| requests | 6,578,491 |
| refused | 6,441,601, of which 6,346,106 the switches' `testaccount` probes |
| accepted | 27,140 |
| challenges, every one an abandoned conversation | 109,750 |
| accounting | 7,880,490, of which about 600,000 a month the probes' own |

The VMware View gateway (`VIEW_Public2`) asked NPS five times in the ten
months, all five on 21 September, so the five rows under *NPS other* are the
whole of it.

1.10.94

**Signing in works again on PostgreSQL after a refusal from the directory.**
1.10.93 began writing the directory's own words into *Events* when it
refused somebody. A domain controller ends those words with a NUL
character, PostgreSQL refuses to store any text with one in it, and the
refusal of the event became a refusal of the whole sign-in: *something went
wrong (DbError)* for everybody who had the directory check them. Three
things now stand in the way of that:

- a NUL is taken out of every value before it reaches the database, on every
  engine, for every table: nothing this program stores means anything by one;
- the directory's error text has it taken out where it is first read;
- an event that cannot be written down is logged and let go. It no longer
  stops what it was describing.

The mock directory in the tests now ends its refusals with a NUL, as a real
one does, and the directory tests are run on PostgreSQL and MariaDB.

**Every change an upgrade makes to the database is written in `isemon.log`**,
at the first start after the upgrade (or by whatever command opens the
database first, including `install.sh --upgrade`'s own check). Any version
still upgrades straight to this one: what is done is decided by what the
database has, not by which version it came from. The log says:

```
database: last opened by isemon 1.10.87, this is 1.10.94 - checking what the schema is missing and bringing it up to date
database: made the table win_rollup, which this version adds
database: adding the column failed.asked_as (TEXT) - starting
database: adding the column failed.asked_as - done in 0.1 s
database: building the index passed_mac_ts on passed - starting
database: building the index passed_mac_ts - done in 4.2 s
database: 1 index(es) will be built behind the running daemon rather than now, because the tables are big: win_ts_kind - each says when it starts and when it is done
database: the schema brought up to date in 4.5 s - 1 table(s), 1 column(s), 1 index(es) made, 1 index(es) to be built behind the daemon
database: building the index win_ts_kind over win_events behind the daemon - starting (412 million rows)
database: building the index win_ts_kind over win_events behind the daemon - done in 38 min
database: a one-time repair, nps ports - starting
database: a one-time repair, nps ports - done in 0.3 s, 12 row(s) now name their switch port the way the switch does
```

and on every start after that, one line:
`database: the schema has everything isemon 1.10.94 needs - nothing to change`.
The rewriting of stored rows that some versions need ("working out which
door … refused attempt(s) knocked on") says when it starts and what it did,
as before. The database now remembers which version last opened it
(`version_opened`), so the first line can say how far it came; a database
from before this version says "does not say which version last used it"
once. On PostgreSQL an index built behind the daemon that fails part way is
taken away again, so that the next start builds it rather than trusting a
half-built one.

1.10.93

**A pass over the whole program for bugs, for holes, and for what a database
of a billion domain events would do to it.** Nothing that worked is changed
in what it does; what follows is what was found and put right.

*Holes closed.*

- **Signing in says the same thing whichever half was wrong.** "No such
  account" and "wrong password" were two different answers, which told a
  guesser which names exist. Both are now *that name and password do not go
  together*; the real reason is in *Events* for the administrator. A name
  that does not exist costs the same quarter of a second as a wrong password
  for one that does, so the time taken does not tell either. An account
  that is switched off still says so, but only to the right password.
- **Wrong passwords are counted against the name as well as the address.**
  Five from one address made it wait; the same five from each of a hundred
  addresses did not. The name now waits too, after four times the
  address's allowance, and is let go the moment its password is right.
- **Session tokens are stored as a hash.** A copy of the database no longer
  contains anybody's live session. Sessions open before the upgrade go on
  working until they end; nothing has to sign in again.
- **A password that has to be changed has to be changed.** An account marked
  *must change* could still use every page; it can now use only the
  password page until it does.
- **Things that change the program are no longer reachable by GET.** Reading
  the windows again, reading and watching the directory: all three took a
  link, which is what a picture in a mail is. They take a form now.
- **Settings that end up on a command line are checked first.** The
  Mikrotik host and user and the database host could carry an ssh option
  (`-oProxyCommand=…`); they are now a name or an address and nothing else,
  and ssh is told where the options end.
- **Commands typed on the kit are kept without their secrets.** A line with
  a key, a password or a community in it is stored with that part replaced
  before it reaches the database.
- **The door names in a request are checked** before they go anywhere near a
  query; an error page no longer carries the text of the exception; a
  MariaDB dump is loaded in the mode that cannot run a command.

*A billion domain events.*

- **The ahead-of-time counting is built a day at a time**, each day its own
  transaction, and only checked over the last three days at each hour.
  Before, the check counted the whole table every hour and the first build
  held one transaction over the whole of history — on a big site, a lock for
  the length of the afternoon.
- **The clean-up remembers how far it got.** Throwing old rows away began
  from the start of the table at every run; it now starts where it last
  finished, with one full walk a day to catch anything left behind.
- **Once is once.** Mending the NPS ports and the tac_plus refusals walked
  every row at every start; each is now done once per version and setting.
  Sorting the refusals no longer starts again at every restart because of a
  single row that will not decode.
- **The heaviest sums are held**: the addresses behind the totals for an
  hour, the lists of kept-out addresses for half an hour and at most 1,500
  rows.
- **Counts stop counting at twenty thousand** (two thousand for a search
  through words). A list over the domain events says *more than 20,000*
  rather than counting a billion rows to put the exact number in a corner.
  The rows themselves come first, the count after.
- **Indexes over millions of rows are built after the program is up**, in
  the background, and without a lock on PostgreSQL and MariaDB. Erasing a
  table on those two truncates it rather than deleting row by row. SQLite
  is given a larger cache, memory for its temporary tables, a memory-mapped
  window, and `PRAGMA optimize` once a day.
- **A retention that is shortened** now takes exactly the buckets before its
  cut, where it took the one on the boundary too.

*Bugs.*

- NPS: a probe's answer was thrown away with its request, which also lost
  the same Class's real answer when the two shared a line; a probe is now
  dropped only when it is a refusal. NPS accounting kept the realm off the
  name. A `Called-Station-Id` with a colon in the SSID split wrongly. A VPN
  request with a Service-Type of Framed, Callback or Authenticate-Only is
  *NPS other*, not a VPN.
- The "machines that never got on" test compared a MAC against an empty one
  and so let a nameless row match everything; the Find box compared a
  client's address with the case it was typed in; a failed column lookup
  was remembered as if it were an answer; `--rescan` of a file named on the
  command line rescanned its folder instead; "natural" sorting counted a
  superscript as a digit.

*Seen, and left for a later version*, so that nobody thinks they were
missed: the search boxes still read through the whole of a table for a
name; the counting of the busiest names wants an index of its own on the
biggest sites; and the per-row transactions of the readers would go faster
in batches.

1.10.92

**Every popup on the front page and on the Domain page opens exactly what was
pressed.** Everything on both pages that can be pressed was pressed by a
script, and each popup's number and rows were compared with the thing it was
opened from. What did not agree now does:

- **The two cards along the top** say *last 24 hours* but opened the chart's
  window, so a card reading 6 opened a list of 20,000 when the chart was set to
  a year. They now open their own 24 hours. *Passed* also counted the firewall
  lists and commands its popup leaves out; it now counts sign-ins only, as the
  popup does.
- **A name on *Names being tried*** opened every door and every name that
  merely contained it: `jan` opened jana and jan.novak too. It now opens that
  name exactly, at the VPN, which is what the card counts.
- **A bar of the chart** listed ISE's own packet handling beside what the bar
  was drawn from, and its first bar opened the whole hour when only part of
  it is inside the window. It now opens exactly the doors and the span the bar
  stands for. Where the domain is part of the bar, the popup opens the
  domain's half of that span too, and a bar that is only the domain can be
  pressed at all.
- **A row on a network card** (*Machines that never got on*, *Where they are
  stuck*), on ISE or NPS, opened every refusal of that machine or switch,
  including the ordinary MAB half of every PC that got on a second later. It
  now opens only what the card counted.
- **The domain's cards on the front page** opened the Domain page's window
  (24 hours) instead of the front page's: "21,810" over a popup reading
  nought. They now follow the window they are drawn in. The Domain page's own
  popups said *last 24 hours* whatever its window was; they now name the
  window they counted.
- **A machine's name on the Domain page** opened the story of an account
  called `C0033715` or `\ISE1`, which does not exist. It now opens the
  account the domain keeps for that machine, `C0033715$`.
- **"since …" beside the Domain page's counts** could be pressed and did
  nothing but raise an error in the page. It now opens everything read since
  then.

**eduroam answered by a Windows NPS.** *Settings → The eduroam logs → Which
server writes the eduroam logs* is `freeradius` by default, and eduroam is read
exactly as before. Set it to `nps` and NPS's own log is read instead (the
"ODBC (Legacy)" format the NPS module reads), and the same eduroam page is
built from it:

- the account, with the institution;
- whether it was one of ours, checked by the directory, or a visitor whose
  request was passed on to the national servers, and to which one;
- the reason for a refusal, in words;
- from NPS's accounting, the machine's access point and the address it was
  given.

Where the same NPS also answers the switches, *Which of NPS's answers are
eduroam's* names the eduroam policies (`eduroam*`). The rest stays the NPS
module's. See `docs/eduroam-nps.md`, written against eduroam.cz's own NPS
guide.

1.10.91

**NPS no longer raises the alarm ISE never raised: MAB first, 802.1X a
second later.** A switch asks about every machine by its MAC first. A PC's
MAC is in no list, so it is refused, and the PC authenticates with its
certificate a moment later. Only printers, telephones, cameras and the like
are meant to get on by MAB. ISE's network door on the front page has always
left those ordinary refusals out, and NPS's cards of machines and switches
did too. The card of reasons added in 1.10.88 did not: it counted every MAB
half of every PC joining ("wrong password, or an account that does not exist
— 81"), each of them a PC that was on the network a second later. It now
counts only the machines that were refused and did not get on afterwards, the
same as the cards beside it. On the site's own data that is all 26 refused
machines got on, so there are no cards at all, only the line saying so.

1.10.90

**Drop-downs over every list, for what a row actually is.** Device, node and
country were the only filters on *Failed attempts* and *Logins*. Each door now
adds its own, filled from what is really behind it:

| Door | Failed attempts | Logins |
|---|---|---|
| VPN | reason, tunnel group, domain | profile, group, tunnel group, policy set |
| TACACS | reason | shell profile, policy set |
| TAC_Plus | reason, line | — |
| 802.1X / MAB on the LAN (ISE and NPS) | port, reason | port, VLAN, profile or network policy, group, method |
| 802.1X / MAB on Wi-Fi (ISE and NPS) | access point, network, reason | access point, network, VLAN, profile, group, method |
| OTP | reason | — |
| eduroam | reason, institution | institution |
| NPS VPN, NPS other, everything else | reason | network policy or profile, VLAN |

Several at once are ANDed, and the search box searches what is left. Each
drop-down offers only what goes with the others already chosen, so no pair of
choices can be made that is known to leave nothing. Choosing
the switch narrows the port list to that switch's ports: port 1/0/24 exists
on every switch in the building. A VLAN that ISE writes as a number on some
records and as a name on others is one VLAN in the list. A group matches
every row that has it among its groups, never half a name. Clear lets go of
all of them, and so does moving to another door.

**The box at the top (Ctrl K) finds everything, in every module.** It found
addresses, user names, bans and the domain. It now also finds:

- a machine by its MAC, however it is typed (`b00c.d1e0`, `B0:0C:D1`);
- the address a machine was *given*, which NPS and ISE network rows keep
  apart from the source address;
- a switch, controller or head end by name;
- a command typed on a switch, through ISE or tac_plus.

Each result goes to the door it is busiest at: an NPS machine to its NPS
door, a tac_plus command to TAC_Plus, with what was typed already in that
list's search box. A user name likewise opens the list at the door the name
is actually at, instead of whichever door was open last.

**NPS Wi-Fi rows can show the address the machine was given.** A wireless
sign-in does not carry the address the machine will get, because the address
is handed out after it. A controller says it only in its RADIUS accounting.
NPS's accounting lines are now read for that alone: the newest line per
machine is kept and put beside that machine's sign-ins of the same day, and
the hover says where the address came from. On the site this was checked
against, the wireless controller sends no accounting to NPS, so there is
nothing yet. `docs/nps-logs.md` §3.1 says what to switch on. The VLAN shown
is what NPS itself handed down. A wireless policy that hands down none leaves
the column empty, because the VLAN is then decided on the controller. The
NXLog configuration now sends accounting that carries an address and still
drops the rest.

**NPS ports are written the way ISE writes them.** NPS's log carries a port's
number, never its name. *Settings → The NPS logs → What the switches call their
ports* says what they are called: `GigabitEthernet` by default, with a
pattern for switches that differ (`SW_OLD_*=FastEthernet, GigabitEthernet`).
The ports then read `GigabitEthernet1/0/24`, like ISE's. Changing the setting
renames the ones already stored.

1.10.89

**An NXLog configuration for the NPS servers, ready to use.** It sits beside
the domain controllers' one, as `docs/nxlog-nps.conf`. NXLog reads NPS's own
log files as they are written and sends every line unchanged over TCP. It
drops the accounting and challenge lines on the NPS server already, because
isemon never reads them. The receiving rule, `deploy/nps/06-nps-store.conf`,
files the lines under `/var/log/remote/<server>/IN.log`, where the module's
default pattern finds them. `isemon --rescan --logs nps` now also reads the
copies logrotate makes of that file, so the whole history can be read again.
The procedure is in `docs/nps-logs.md`, §2.

**NPS's switch ports are written the way the switch writes them.** A Cisco
switch numbers a port for RADIUS as five digits, 5, 0, the stack member and
the port, so `50124` is port 24 on member 1: `1/0/24`, GigabitEthernet1/0/24
on a gigabit switch. 1.10.88 showed the number. NPS's "ODBC (Legacy)" log
has no column for the port's name, so what kind of port it is cannot be known
from it, and the row's hover says so. Rows 1.10.88 already wrote are put
right at the next start, without reading anything again.

**Every other number NPS writes is in words too.** The make of the device
that asked (Cisco, Aruba …), who checked the credentials, the packet, what was
handed to the switch (VLAN, 802), the tunnel, the accounting fields, the
session limits in hours and minutes, and the data in megabytes. The NPS
server that answered and when its service started are read out of the Class.
The domain MS-CHAP writes as hex (`0x014D555A…`) is shown as text, and a MAC
written as bare hex as a MAC. Every reason code in Microsoft's list has words,
not only the common ones: certificates, proxies, clocks, cryptobinding. All of
it is in the opened record, beside the columns as NPS wrote them.

**The token server's package brings its own yum repositories.** The patches
need `patch`, which a minimal CentOS 6 does not have, and on CentOS 6 yum no
longer finds anything with the repositories it was installed with.
`docs/otp-radius-detail/centos6-yum/` holds the repository files that point
at vault.centos.org. `otp-radius-detail.md`, §1.1, says how to put them in and
what to do when EPEL 6 does not answer. `otp-radius-setup.sh` now checks for
`patch` and stops with that advice before it touches anything, instead of
stopping half way through.

1.10.88

**A Windows NPS server's logs are read, as a module of their own.** Network
Policy Server is the RADIUS server that comes with Windows. Where it answers
the switches, the wireless or the VPN instead of ISE, *Settings → The NPS
logs* reads the log it writes of every request and every answer (format
"ODBC (Legacy)"). What it decided is shown beside what ISE decided, under
buttons of its own on *Failed attempts* and *Logins*: **NPS VPN**, **NPS
802.1X LAN**, **NPS 802.1X Wi-Fi**, **NPS MAB LAN**, **NPS MAB Wi-Fi**.
**Each appears only once NPS has actually answered something through that
door**, so a site with no VPN behind its NPS is never shown one. The rows look
and behave like ISE's: the MAC, the address the machine had, the switch and
its port, the network policy, the VLAN, NPS's reason in words, the whole
request and answer when a row is opened, and names looked up in the
directory. The front page gets **802.1X / MAB · NPS** and **VPN · NPS** doors
under the chart on the same rule, and the chart gets two bands of NPS's own.

A request and its answer are two lines, joined by the `Class` NPS stamps on
both. Only the request says which door it was and only the answer says yes
or no, so they are read together, including across a restart. The switches'
own "is the server there" probes are recognised and left out: on the site
this was written against they were six million of 21 million lines, and none
of them was anybody signing in. Any other account can be left out by name
in *Accounts to leave out altogether* (`testaccount`, a scanner's service
account); nothing it does is then written down anywhere. Ten months of that site's log, read end to
end, gave exactly the counts worked out by hand from it, at about 13 seconds
a month.

The database page counts NPS's rows and has a group to erase them. `isemon
--rescan --logs nps` reads every month still in the folders, and `isemon
--passed --kind nps` lists them. **Nothing read from NPS is ever judged**, a
VPN refusal included: the banning weighs ISE's VPN and nothing else. With the
module off, which is the default, nothing anywhere behaves differently.
See [docs/nps-logs.md](docs/nps-logs.md).

1.10.87

**One sitting on a switch through tac_plus took the whole front-page chart
down.** tac_plus was named as a band of the chart and never given a place in
its bars, so the first sitting inside the window was a `KeyError` and nothing
was drawn — not tac_plus, not the VPN, not anything. On a site whose logs had
not started arriving yet the chart was simply empty, which is why it went
unseen. It has its own band now, in its own colours, and a band nobody gave a
place to can no longer take the chart down. The page had the other half of
the same fault: left off the list of bands it cuts out of each bar, every
sitting would have been drawn in green as somebody getting on to the VPN.

**A tac_plus refusal was filed against the switch's own address.** The daemon
writes a refusal as `login failure: admin 192.9.212.254 (192.9.212.254) tty1`,
and both of the things after the name are the switch. The one in brackets was
read as where the person came from, so every refusal named the switch as the
machine that had been knocking. Where the person sat is on no such line, so the
source is left empty and the switch is the device. Refusals already written
that way by 1.10.83 to 1.10.86 are put right at the next start, without reading
anything again. Found on the site's own server, set up by
`docs/tacplus-setup.md` — which also showed that this build of tac_plus does
write refusals, so the TAC_Plus button on *Failed attempts* fills.

**The front page follows the ISE switch as the two lists do.** With *Read the
ISE logs* off, the **VPN · ISE** door under the chart is not offered, its four
cards go with it, and the page opens on the first door that something is
arriving through. The chart's legend shows only what is being read: ISE's six
colours while ISE is, tac_plus's two while it is. **TAC_Plus** is a door here
too, with who sits down at the kit and which devices they sit down at.

1.10.86

**Switching the ISE logs off takes ISE's buttons away.** A site whose switches
answer to a tac_plus of its own and which reads no ISE whatever was still shown
VPN and TACACS on *Failed attempts* and *Logins* — and both lists opened on the
VPN one: an empty list, under a door to a system it does not have. With
*Read the ISE logs* off, ISE's doors (VPN, TACACS, 802.1X, MAB and everything
else ISE writes) are not offered, and the lists open on the first door that
something is actually arriving through. The same rule holds for every module:
the token logs, eduroam, the domain and tac_plus each offer their door while
they are switched on. It follows the switch as it moves — turned off with a
list open, the list moves to a door that is on, without a reload.

Nothing is deleted by it. What ISE wrote before stays, is still searched and
still counted, and switching the logs back on shows it again.

**The tac_plus set-up as a procedure.**
[docs/tacplus-setup.md](docs/tacplus-setup.md) is the whole of it in the order
it is done — finding where the daemon really writes, finding out whether it
writes refusals at all, the sending side, the receiving side, the settings, the
switches — with what to check after every step and a table of what each
symptom means. The three rsyslog files are in `deploy/tacplus/`, ready to copy.

1.10.85

**Two things rsyslog does to a tac_plus line on the way, each of which on its
own would have ruined the first import.** Both measured on the site's own log:

* **It turns every TAB into `#011`** unless it is told not to, and the tabs are
  the only thing between one field of an accounting line and the next. Every
  one of 251,533 lines would have been unread. `#011` is read as a tab now; a
  real `#011` inside a line that has its tabs is never second-guessed.
* **The first time imfile is pointed at a file, it sends all of it**, and every
  line arrives stamped with the moment it was *sent*. 1.10.84 believed a stamp
  in front over the one tac_plus wrote, so the 15,356 lines with no
  `start_time` would all have been filed as the afternoon they were shipped.
  The order is now: `start_time`; then tac_plus's own stamp with the year
  taken from where the file has got to; and the shipper's stamp only where
  tac_plus's own is not on the line at all — otherwise it only says the line
  was written no later than that. A line written just before New Year and
  sent just after it is last year's.

**Where the file has got to survives the pieces it is read in, and a
restart.** A file is read eight megabytes at a time; the year of a line at
the top of a piece used to be worked out as though nothing came before it.
It is kept beside the tail's own position now, written down and read back, and
an exact moment puts it right even when what was inferred before it had run
ahead.

**The daemon's own log is read however the line reached here**: as the daemon
wrote it, with no host, or behind the full stamp and host the receiving rsyslog
writes with `RSYSLOG_FileFormat` — a clock has colons in it, which the words
before the daemon's name were not allowed to have.

[docs/tacplus-logs.md](docs/tacplus-logs.md) says how to set both machines up
for it, written against CentOS 7's rsyslog 8.24: the daemon's messages
forwarded as they happen, the accounting file read by imfile, disk-backed
queues so a reboot loses nothing, and the receiving side writing one folder per
host exactly as the ISE logs are written.

1.10.84

**tac_plus cannot write a year, so the shipper is given a way to.** Its
accounting file says `Sep 16 11:56:52` and nothing more, which in a file
holding five years is a date that could be any of them. A site can now put a
full RFC 3339 stamp in front of each line on the way here — rsyslog's
`date-rfc3339`, which carries the year and the zone — and this reads it,
uses it for the moment, and goes on reading the rest of the line exactly as
before. A `<86>` priority in front of that, a stamp in UTC, an offset written
`+0200`, milliseconds: all read, and all meaning the same second. The daemon's
own log takes the same treatment, and keeps the name of the machine it was
written on.

Where no stamp is added, nothing changes: `start_time` from the device is used
where it is there, and where it is not, the year comes from where the file has
got to.

[docs/tacplus-logs.md](docs/tacplus-logs.md) now says how to set the server up
rather than only how the file is read — the accounting file, the daemon's
own log through rsyslog, NTP on the devices for `start_time`, the shipping with
a stamp in front, and the `aaa accounting exec` that makes the sitting a record
of its own instead of something this has to work out from the commands.

1.10.83

**A TACACS+ daemon of your own, read beside ISE's.** Not every site puts its
switches behind ISE. Where `tac_plus` — Shrubbery's, or the `tac_plus-ng` that
came after it — answers them instead, switching the module on under *Settings →
The tac_plus logs* puts a **TAC_Plus** button on Logins and on Failed attempts,
beside the TACACS+ one that is ISE's. It draws what that button always drew:
who sat down at which switch, coming from where, and **every command they ran**,
inside the sitting they were typed in.

The two are never mixed. Either daemon may be in front of any switch, and which
of them answered is most of what somebody wants to know.

Two files are read, and either may be missing: the **accounting log**, which is
what people did, and the **daemon's own log**, which is the only place a sign-in
that was *turned away* is written down. One reader answers for what a line is
rather than for which file it came out of, so a site writing both into one file
need say nothing about it.

Three things in it are worth saying out loud, because they are what the real log
turned out to be:

* **The sitting is usually not in the log at all.** The log this was written
  against is 251,533 lines, five years of three accounts on eighteen switches,
  and every single one of them a command. So the sitting is read out of the
  commands — a gap at the prompt, and then somebody is back — which is what a
  person reading down the log does. The row says which it is, and where the
  daemon does write sessions, those are used instead.
* **A stamp with no year lands in the wrong one.** Syslog leaves the year out,
  and everywhere else in this program that is answered by taking this year,
  because the line was written a moment ago. An accounting log left to run is a
  switch's whole life in one file: read as this year, its first line lands next
  week. Where the device sent `start_time` that is believed — it is seconds and
  cannot be a year or a zone out — and where it did not, the year is taken from
  where the file has got to.
* **Nothing here is ever judged.** Signing in to a switch never has been, through
  ISE either, and the address on one of these lines is as often as not the jump
  host the whole of the network staff comes through. There is no ban button on
  the row.

**The database page says how much of it there is, and it has a group of its own
to erase.** *What is in it* now also breaks out what lives **inside** the two big
tables rather than in a table of its own — tac_plus, TACACS+, the token logs,
eduroam — with the parts of each and how far back they go. A card counting
tables could not answer the one question a site asks after switching a module on:
the whole of a tac_plus history read as "successful logins".

**`isemon --rescan` takes the logs to go back over.** `--logs tacplus` reads that
module's files from the beginning and nothing else, and because nothing in them
is ever judged, nothing is weighed and nothing can be banned by it. Named
nothing, it is exactly what it always was. This is also the only way the logs
that are never judged get read again at all — until now that meant erasing the
module's records first.

**Three filters had two popups.** The device, node and country pickers over
both lists are re-worded when the door changes — and re-worded by setting a
`title` on selects that already explain themselves, which is the browser's pale
box opening beside ours a second later, saying the same thing in a different
place. Found on the Active Directory door of both lists, where all three of
them had two. Words that change are said the page's own way now, and the sweep
that catches this is part of the checks.

**And the sign-in page has a picture on it.** The one page anybody sees before
they are anybody now says, without a sentence to read, what this program is:
lines out of the logs on the left, weighed in the middle, and what they earn
carried to the firewall on the right. It is drawn in the page's own colours and
fetched from nowhere.

1.10.82

**`isemon --rollup` said two things at once.** A site in use was told, in the
same breath, that it was in use and that it had never been counted. The
counting was right and the page was right; the words were wrong. A line
saying whether a counting is running *right now* had been put inside the
chain that says which of the three states it is in, and it took the last
arm's `else` with it — so the "never counted yet" sentence was printed
whenever nothing happened to be running, whatever the state.

The line is said beside the state now, never instead of it. And the command's
own words are read by a check for the first time: it is run for real, in each
of its three states, and must say exactly one of them. Nothing had ever read
what this command printed, which is why nothing noticed.

1.10.81

**The Domain page said it was still working something out, for ever.** What
the page keeps about the domain is thrown away whenever something worth
waking it for arrives, so that the very next ask works the answer out afresh
— and thrown away meant *gone*: that ask got nothing at all, the card was
drawn empty, and the page said it was still working. On a domain where
something worth waking for arrives every couple of minutes, which is oftener
than one of those cards takes to build, the page was never once drawn whole
and the same twenty walks were done again and again for nothing.

Three things were wrong and all three are mended. What is kept is now marked
**stale** rather than dropped — the fresh answer arrives on exactly the same
poll as before, and until it does the card holds what it held a moment ago
instead of nothing. What a change throws away is now only what the change was
**about**: one number for the whole program meant that forgetting what was
known about the jobs also discarded work in flight about the domain. And an
answer that finishes just after a change is kept as stale instead of being
thrown on the floor.

**Reading the counting back was twenty-two seconds of Python.** A site timed
`isemon --rollup-check` at twenty-five seconds, twenty-two of them this
program's own processor: proving a day meant reading every event of that day
out of the database and adding them up here. It is one statement now — the
events grouped as buckets, the buckets as they stand, added together in the
engine and only the disagreements read back. The row-by-row reading stays,
and the tests hold the two to each other on real rows, including on rows
deliberately made wrong: two readings that agree about nothing being wrong
while disagreeing about what *is* wrong would have proved nothing.

**A counting running at somebody's terminal is not invisible any more.**
`isemon --rollup-build` is its own process holding the same table the daemon
writes into, so the daemon's own writing waits on it — and said so as
`[warn] sql took 3.0 s ... 123 row(s)`, with nothing about what it waited
for. A counting now writes down that it is running, where every process can
see it: the waiting is logged as what it is, `--rollup` says the numbers are
moving while you read them, and a second counting is no longer started on top
of the first.

1.10.80

**"Every sum adds up." — "It has agreed with the events 0 time(s)."** Both
true, a second apart, about the same counting. A reading was only ever
written down when the *daemon* asked for one: `isemon --rollup-check` and the
button on the page each did the whole proof, said what they found, and threw
the answer away. So the one thing a site does after an upgrade — read it back
by hand, then ask what state it is in — answered itself with a number that
never moved.

Whoever asks, the answer counts. There is now one place that writes down what
a reading found, and the terminal, the page and the daemon all go through it.
**A reading that passes in full also brings a counting back from being put
aside** — it is the same proof a fresh counting has to pass before it is
believed, so a fault mended in an upgrade need not also make every site that
met it count a billion rows again to be allowed to say so. The daemon's
hourly reading is one finished hour: enough to catch a fault, not enough to
clear one, and it stays that way. A reading taken before anything has been
counted is about an empty table, so it is not written down at all.

**Work that is meant to take a while is no longer reported as a fault.** An
upgrade that builds an index over two million rows, and a counting that
collapses them in one pass, are seconds of real work each — and both
announced themselves as `[warn] sql took 4.7 s`, which is how people are
taught to scroll past warnings. They are still timed and still written down,
because a site wants to know what its build cost; they are written down as
information, saying which piece of work it was. The counting holds every
other writer while it runs, by design, so the daemon's own `167 row(s)`
waiting behind it now says that is what it was doing rather than reporting
itself.

1.10.79

**A group kept for FEWER days had its counted answers thrown away at every
age, every night.** `roll_forget` is what keeps the counting honest when
events are deleted, and it could not tell two things apart: a group switched
off, whose events go at every age, and a group that is kept but for less time
than the rest. It treated the second like the first. On a site that had given
the sign-ins seven days, every nightly clean-up threw away **every sign-in
bucket there was** while the events themselves stayed, and what was left was
whatever had arrived since. The counting then read a fifth of the events the
table held, and the page was put aside as untrustworthy — correctly, and for
a reason that was in the throwing-away rather than in the counting.

It now takes exactly what the deleting took: at every age for a group
switched off, and only before the cut for a group kept for fewer days. **And
the hourly watch asks the sums over the whole table, not only one hour read
line for line** — an hour that happens to be intact says nothing about a
swathe of buckets having gone missing, which is the fault that actually
happened.

**The rebuild and the read-back are on the page now, not only at a
terminal.** *Settings → The domain controllers* has a card that says which of
the three states the counting is in — in use, never counted, or put aside
(with what was found, by which version, and when) — how many counted rows
stand for how many events, and when it was last read back against them. Two
buttons: **Count them all again**, which is `isemon --rollup-build`, and
**Read it back against the events**, which is `--rollup-check`. The first
runs as a job with the same bar as everything else, and the page goes on
working throughout: it simply asks the events themselves until the counting
is done and proved.

**And the card says outright the thing that was worth asking.** Nothing waits
for any of it. An event is counted in the same transaction that writes it
down, so the Domain page shows what the database holds this second. The
counting only decides *how* the page asks — never how old its answer is.

1.10.78

**Two popups over one row, and which of them you saw came down to where the
pointer crossed.** The rule has always been that one thing pointed at is one
panel, with everything about it in the one box — and the folding that made
that true was only ever applied in one direction. A line joined the panel it
was part of, which works when the panel is drawn first and not at all when it
is drawn second. Worse, a thing given its words *before* it is put on the
page — built, explained, then appended into a row that was made pressable a
moment earlier — has no parent to look up through at the time, and the row
has nothing to look down at.

It is looked at from both ends now: whichever is explained second takes in
the other, and after each redraw the page is swept once more, when everything
is finally where it belongs. The browser's own pale tooltip counted as the
second box too, and it was coming back: the health pill and the clock beside
it are given a fresh `title` on every poll, long after ours was attached. A
title put back on something that already explains itself now becomes what our
own panel says, rather than a second box under it saying the same thing a
moment later.

**Checked rather than asserted.** A new browser check walks every tab, every
settings pane and every sub-tab and asks the page itself whether anything is
explaining itself inside something else that also is, or carrying a browser
tooltip beside our panel. It found **3,435 places** on the version before
this one. It finds **none** on this one, and it runs with the rest of the
checks from now on.

**Once the counting had been put aside, it stayed put aside for ever — even
after the upgrade that mended it.** A verdict about the counting is a verdict
about the *program* that reached it, and it was stored without one: the state
stopped the hourly checking, and the checking was the only thing that could
have cleared the state. A site read the same sentence about the same numbers
hours after the version that wrote it had been replaced. A verdict now
records which version reached it, a newer version counts everything again and
proves it afresh rather than inheriting somebody else's finding, and
`isemon --rollup` says plainly that what it is showing is **what was found
then and written down** rather than something being checked now.

**A line whose whole group this site does not keep is no longer read at
all.** Turning a line into an event is the expensive half of the write path —
measured on a real domain's day of 704,456 lines, **53% of all the time it
took**, more than making the rows and giving them to the database put
together. On a site that has switched the sign-ins off, most of that work was
being done to decide the answer was to be thrown away. The decision is made
first now, off the event number and a look at the line.

Measured on that same day, reading it twice over and comparing event for
event:

| | events kept | reading every line | deciding first | |
|---|---|---|---|---|
| everything kept | 704,456 | 6,888 a second | 7,073 a second | 1.03× |
| sign-ins off | 161,641 | 7,662 a second | 16,252 a second | **2.12×** |
| sign-ins and reads off | 72,958 | 7,853 a second | 21,653 a second | **2.76×** |

**Exactly the same events came out every time, and exactly the same marks.**
That comparison is what this is worth: the first attempt at it lost 1,074
events — every failed NTLM validation in the day — because a 4776 is an NTLM
validation when it worked and a REFUSAL when it did not, and a refusal is
never one of the kinds a switch can reach. Nothing whose kind depends on the
answer it got is dropped, nor anything whose number alone can earn a mark,
nor any line carrying one of the two words that earn one. The checks hold it
to that.

**And the help under those switches now says what switching one off really
costs.** It said the Logins page loses a tab. What actually goes is the
sign-ins and sign-outs *around* an incident — who was on that machine when
the lockout happened, whether the account got in afterwards — which is
exactly what somebody wants when they press an alarm and ask for the whole
story of an account. The alarm is still there; the context is not. So on most
sites the answer is not the switch at all: leave it on and give it a **short
number of days**. Seven days of sign-ins against ninety of everything else
keeps every investigation anybody actually does and costs a fraction of the
room. Switching it off altogether is for a domain so large that even a week
of them is too much.

1.10.77

**The Domain page went dark in 1.10.76, and the lint that should have caught
it could not see where the fault was.** A function written for that page
landed inside the `<style>` block instead of the script block. A browser
reads `function sayWhyNoDc(dc) {` in a stylesheet as a selector it does not
understand, throws the rule away and says nothing at all — so the function
was never defined, and the first thing to call it took the whole page down
with `sayWhyNoDc is not defined`. The JavaScript check passed, because it
reads the `<script>` blocks and that code was not in one. It now also reads
the stylesheets and refuses any that hold JavaScript, which catches exactly
this and would have caught it before it shipped.

**The counting is done by the database, not by walking the table through
Python** — and it was not only slow, it was quietly wrong. The build used to
read five thousand rows at a time into this program, add them up here and
write them back: four minutes for two million events, and hours for the
billion this has to be able to hold. It also raced the writing. The walk went
in id order, an id is a hash of the event rather than a clock, and an event
arriving mid-walk could land either side of where the walk had got to — on the
far side it was counted twice, once by the writing and once by the walk. On a
live domain that is exactly what appeared: the counting a handful higher than
the rows, and a larger handful the longer the build took.

It is now seven `INSERT … SELECT … GROUP BY` statements, one per column, in
one transaction. Not a row leaves the database: PostgreSQL groups the events
where they already are, which is what it is for, and hands back the few
thousand rows they collapse to. Nothing may be written into the middle of it,
so it cannot be a few out. **Measured on one real domain's day: 704,456
events counted in 2.1 seconds, against about 85 seconds the old way** — and
the same buckets to the row. On seven and a half million that is twenty
seconds rather than a quarter of an hour.

`roll_deltas` remains the same rule written in Python, because that is what
counts an event as it arrives, and the checks now hold the two to each other
on real rows on all three engines — including the awkward ones, a name longer
than its column and a name that is nothing but spaces, which is exactly where
two ways of cutting a string part company. Two implementations of one rule is
a thing to be uneasy about; two that must agree, and are made to prove it, is
stronger than one used twice.

**And the reading-back no longer races the writing either.** It asked the
events, then asked the counting, and the daemon went on writing between the
two questions — so the second was about a larger database than the first and
the counting looked a few high, every time, on any busy domain. Both halves
are asked inside one statement now, bounded to the hours that are finished,
and a disagreement is asked again before it is believed. The cost of getting
that wrong is a site losing the quick page for nothing.

*Still to come, and deliberately not in this release: the events themselves
are written with `executemany` in batches, where PostgreSQL's own `COPY` is
several times quicker. That is the last place this program stands between the
logs and the database.*

1.10.76

**The Domain page's answers are counted as the events arrive, instead of
being worked out afresh from millions of rows every time somebody looks.**
Every card on that page is "in this window, the busiest twelve accounts /
machines / addresses / reasons, and how many of each". Asked of the events
themselves, each one is a walk of the whole window — and the window holds
more every day, so the page was getting slower for ever.

The answer is not a faster query. It is that the QUESTION stops growing.
Measured on one real domain's day of 704,456 events off six controllers: in
its busiest hour there were 388,244 events and 4,515 distinct accounts, 2,520
addresses and 303 machines. **Forty-eight events to a counted row** — and
that ratio only improves, because the number of accounts in a domain is the
number of people who work there and cannot run away, while the number of
events has nothing holding it down at all. On the whole day, 704,456 events
became 26,910 counted rows. Asked of PostgreSQL with `EXPLAIN (ANALYZE,
BUFFERS)`, one card's question went from **11,651 pages and 58 ms to 484
pages and 3.9 ms** — and the gap widens with every event that arrives, since
one side grows with the traffic and the other with the size of the domain.

Four things make it safe to rely on:

- **It is written in the same transaction as the events it counts**, so the
  two cannot part company — not after a crash, not halfway through a batch.
  The events are asked for by their ids first, so an event that was already
  there is never counted twice.
- **Nothing waits for it.** The counting happens as the event is stored, so
  an event is in the answer the instant it is written. There is no rebuild to
  wait for: the only building there is happens once, after this upgrade, and
  while it runs the page works exactly as it did before.
- **A lockout does not even wait for the page's own few seconds.** The
  answers a page has already worked out are kept briefly, which is thrift on
  a page of counts and a fault on an alarm — so a lockout, an audit log
  cleared, or somebody put into a group that runs the domain throws away what
  the page was holding the moment it is written, and the very next poll is
  fresh. A wrong password does not, because a domain writes thousands an hour
  and those come up on the next poll anyway, which is seconds.
- **The program reads it back against the events every hour**, and proves it
  completely before believing it at all: every sum over the whole table, then
  the last twenty-four hours line for line. If they ever disagree the page
  goes straight back to asking the events themselves, says so in the log and
  in the event list, and nobody is shown a wrong number. `isemon --rollup`
  says which state it is in, `--rollup-check` reads it back now, and
  `--rollup-build` counts everything again from nothing. Switching it off
  under Settings → The domain controllers is the old behaviour exactly.

**The window now begins on the hour**, and the page says which hour. Outwards,
so "the last 24 hours" always holds at least twenty-four of them and never
less. It also makes the figures reproducible: two people looking a minute
apart used to get two slightly different windows.

**One lockout was drawn twice, and the alarm about lockouts went off one
account early.** A domain records a lockout on the controller that saw the
last wrong password AND on the one holding the PDC emulator role, because
lockouts are its business — so on a site shipping every controller's log here,
one lockout is two events. The card drew both, identical but for the
controller named on them. It is one row now, naming every controller that
wrote it, taking the earliest of their moments and filling in the machine and
address from whichever of them recorded one. And *Lockouts, several of them*
counted events where it says accounts, so two accounts read as four and it
fired at two; it counts accounts now.

**A directory that named no controllers was believed for a whole day, and
overwrote a good answer.** The marking of domain controllers is not a list in
this program and never has been: it comes from asking the domain for computer
accounts whose primary group is Domain Controllers (516) or read-only ones
(521), plus the directory's own host, the folders the logs arrive in, and
which machines have written a log lately. But an answer of *none* — which is
what a base DN that does not contain the controllers gives, or an account
that may not read computer objects — was cached like any other, so nothing was
marked and nothing was asked again until tomorrow. Worse, it replaced a full
answer from yesterday. Now an empty answer never replaces a full one, it is
asked again every half hour rather than every day, and **the Domain page says
which of the three states it is in** — the directory is off, the directory is
on but has named none (with what is asked and where to put it right), or all
is well. A page that marks nothing looked exactly like a domain with nothing
to mark.

1.10.75

**Two fifths of a real domain's Security log was falling through into
"everything else", where no switch could reach it.** Measured on a day of
704,456 events off six controllers: **4627** — the groups an account signed
in with, written beside every single 4624 — was 153,213 of them; **4663**, an
object being accessed, was 88,346 against 501 of the 4662 it accompanies; and
**4689**, a program ending, was 8,420 beside 8,414 programs starting. None of
the three was named, so all three were read as `other`: kept whatever a site
switched off, shown on no card, and counted in nothing. They are named now,
each with the family it belongs to, so the switches reach them. On that same
day the share of the log under a switch goes from just over half to **92%**,
and "everything else" from 258,565 rows to 8,586.

**Each of those two groups can now be kept for LESS time than everything
else.** *Settings → Windows security logs* has two new numbers beside the
switches: **…but the sign-ins and sign-outs only for (days)** and **…and the
directory reads only for (days)**, with 0 meaning "as long as everything
else", which is what they did before. The middle answer between keeping them
and not: what this page is for — the refusals, the lockouts, the accounts and
groups being changed — is worth three months, because "when did this start"
is a question somebody really asks, and every machine in the building signing
in is not. Seven days here against ninety above is the shape most sites want.
Anything this program has marked is kept for the full time regardless, so no
alarm ever loses the events behind it, and a number longer than the main one
does nothing because nothing outlives that one.

**"A SPNEGO or NTLM blob" was a guess, and it was wrong.** When something
puts an encoded blob where a user name goes, this page said what protocol it
thought the blob was. A real domain's logs say otherwise: the events are
4768 — Kerberos ticket requests — answered 0x6 with a user ID of S-1-0-0, and
a SPNEGO wrapper does not go in a Kerberos client name. It now says only what
it can see, and says the thing those logs make plain and the guess never did:
it is **one constant value per machine**, repeated hundreds of times from that
one address, while that same machine's own accounts sign in beside it
perfectly well. That is a component configured on one client — not a person,
not an attack, and something that can never let anybody in.

**The lookup panel takes the room it is given.** What a name lookup answers
with is a card of a dozen facts from both directories, what the person did at
every door, and the addresses they were last seen at — and it was being drawn
into a panel 760 wide and 660 tall, so it was a scrollbar from the first
answer onwards with the addresses under the fold on a screen with room for
all of it. It is 1100 wide now and as tall as the window allows.

**The bar while data is being erased sat at "0 of 3" for four minutes.** The
copy that 1.10.74 moved inside the job says exactly how far along it is — it
is in the log, table by table, and the database page draws it — and the job's
own bar could see none of it, because they are two different reporters. It
reads the copy's now: the rows it is on, the indexes it is building
afterwards, and the rebuild at the end, each given a share of the bar so that
it walks up once instead of three times from nought, and never backwards
whatever any of them says. On a 300,000-row copy the bar goes 0 → 29 → 44 →
60 → 97 → 100 with the table and the row count beside each.

**How to make a PostgreSQL quick enough for this, written down.**
[docs/postgresql-tuning.md](docs/postgresql-tuning.md): what to measure
first (this program logs its own slow queries, so the question is already
answered), the per-table autovacuum settings that are worth more than
everything else put together on a table taking millions of rows a day, the
server settings with the arithmetic and a worked example for 32 GB and 8
cores, how to put them in and how to take them out again, what not to do —
and, last, what the daemon already does about size itself, because a tuned
server over a table three times larger than it needs to be is the slower of
the two.

**And the logrotate pair for a controller writing a couple of gigabytes a
day.** `deploy/logrotate-split-dc/` — one site's working files, which rotate
the controllers apart from everything else so that one three-gigabyte gzip
does not hold up the reload for every other source. With the rule that makes
it work written beside them: logrotate refuses two stanzas that match the
same file and refuses the whole run when they do, so the directories in one
must be absent from the other.

1.10.74

**Erasing made a copy for four minutes and then erased nothing.** Found on a
real install: the tick was put against the domain events, *Erase* was
pressed, the log showed a copy of the database being made — three minutes and
forty-five seconds of it — and then every one of the 3,928,396 rows was still
there, with no error on the page and nothing in the log to say why. The page
was asking for the copy, **waiting for the answer**, and only then asking for
the erasing. On a five gigabyte database that copy is four minutes inside one
request, and nothing between a browser and this daemon waits four minutes:
the proxy gives up after one, PHP after thirty seconds. The copy finished,
the answer went nowhere, and the second request was never sent. The copy is
now the erasing job's own first step: the page asks once, the bar says which
half of the work it is on, and closing the page loses nothing — which is what
the page had been promising all along.

**The Domain page asked twelve questions per card that no index could
answer.** Each card is "the busiest twelve, with the newest row of each
beside it", and the newest row was fetched one subject at a time: `WHERE ts
>= ? AND said = ? ORDER BY ts DESC LIMIT 1`, twelve times. For *account*,
*machine* and *address* that is an index seek. For *the answer given*, *what
was changed*, *done by* and *program* there is no index, so each of the
twelve walked the window until it found that subject's newest row — and a
subject whose rows are hours back walks the whole of it. On a domain of seven
and a half million events this was **3.4 to 3.8 seconds each, twelve of them,
for one card**, and the page draws four. The counting query already returns
`MAX(ts)` for every subject, which is exactly the row wanted, so those twelve
moments are now asked for together through the index on time: one seek, 39
pages touched, 0.07 ms, whatever the size of the table. Nothing needed a new
index. What the fast way does not find still falls through to the old
question, asked only for the subjects it missed — so it cannot be wrong, at
worst it is not faster.

**An answer that cost four seconds is no longer thrown away after ten.** The
Domain page's answers were kept for ten to twenty seconds each. Where one of
them takes four seconds to work out, the rebuild has not finished when the
next is already due: the database never stops working and the page is never
once looking at a whole answer. Each answer is now kept in proportion to what
it cost — thirty times as long as it took to make, never more than five
minutes — with the number the page asks for as the floor. On every
installation where these are quick, and that is all of them until the domain
events run to millions, nothing changes at all.

1.10.73

**"Apply what is kept, now" left half the volume where it was, and said
nothing about why.** A site switched the successful sign-ins off, pressed the
button, and read `0 in 0 s` in the log with thousands of rows still on the
page. Three faults, all of them mended:

- **The sign-outs were under no switch at all.** Every 4624 is followed by a
  4634 or a 4647, and on one real domain that was 284,653 sign-outs against
  284,395 sign-ins — the biggest group in the whole table, and not in the
  group the switch turns off. A sign-out exists only because the sign-in did;
  a site that has stopped keeping one has not asked to keep the other. Both
  are now under *Keep the successful sign-ins and sign-outs*, and so are the
  programs started under them, which a domain with process auditing writes
  one of for every program every person starts all day. On the measured
  database this was 284,653 rows the button had been walking straight past.
- **A mark that only said "this is the machinery" was sparing rows from a
  group that had been switched off.** A mark keeps a row whatever the
  switches say, because a mark is this program having *found* something —
  but `routine` and `expected` are the two that mean the opposite, and a site
  running virtual desktops marks the machinery `routine` precisely so that
  nobody is ever shown it. Those two now spare nothing, at the reading and at
  the clean-up alike. Every other mark still keeps its row at any age.
- **A clean-up that takes nothing now says why.** `0 in 0 s` is what "there
  was nothing here to remove" looks like and it is also what "I decided to
  remove nothing" looks like, and those are different faults with different
  cures. The log now names, before it starts, which kinds are no longer kept
  and whether anything is kept by age at all; afterwards it says how many
  went and how many stayed **because this program has marked them**; and when
  the whole pass takes nothing it reads back the settings that kept
  everything — *refused attempts, sign-ins and the domain events are kept for
  ever (0 days), and the domain still keeps the sign-ins and the directory
  reads*. The same sentence is written into the event the button leaves
  behind, so it is on the page as well as in the log.

**Erase the collected data had gone stale, and what it was missing was the
biggest thing in the database.** The domain events were not offered at all,
so a site wanting the room back could erase the country database and the
whole of the ISE records and still be looking at nine gigabytes. Four groups
added: **the events the domain controllers wrote** (with the notes that say
how they were read, so the next start does not believe an empty table has
already been read), **what the directory last said** (the daily read-only
answers, and what the watching was weighing against), **the names behind
addresses**, and **the MAC vendor registers**. There is now a check that no
table of records can be left with no way to erase it — the only ones not
offered are the accounts, the settings, the sessions and the whitelist, which
the card promises never to touch.

**...and the same for "What is in it".** It counted eleven tables and the
domain events were not among them, so the card said a site was holding a
million rows while the disk said nine gigabytes. Every table of records is
counted now, biggest first, because the question that card is asked is what
is taking the room.

**An "account" that is 250 characters of base64 is said as what it is.** Seen
on a real domain: 3,104 refusals against `@@CyBAAAAUBQYAMHArBwUAMGAo…`. That
is not an account — something put its authentication token, a SPNEGO or NTLM
blob, in the user name field, which is why the domain refuses every one of
them and always will. The card said *"3,104 refusal(s) against"* and then
three lines of gibberish with the answer pushed off the end. It now reads
*"3,104 refusal(s) against an authentication token sent as a user name"*, the
name itself is drawn short with the whole of it under the pointer, and the
reading says there is no such account and no point chasing it — go to the
address and find what is authenticating.

1.10.72

**`/api/status` raised `KeyError: 'id'` on every poll and the whole dashboard
went dark.** 1.10.70 added a method called `jobs` for the long table walks —
and `jobs` was already this daemon's register of the things a button starts
and a page watches by id. The second definition silently replaced the first,
and everything that called the first went on calling it. The new one is
`long_jobs`, and the checks now refuse any class that defines one name twice,
which is what should have caught it.

**Do not store what nobody looks at.** Measured on a real domain: of 756,000
events in one day, **500,000 were successful sign-ins** and **241,000 were
objects being read** out of the directory. The refusals, the lockouts and the
accounts and groups being changed — everything the Domain page exists for —
were **2,083**. Three tenths of one percent. Keeping the rest costs a
gigabyte a day, and every question the page asks has to walk past all of it.

Settings → The domain controllers now has **Keep the successful sign-ins**
and **Keep the directory being read**. Both on by default, so nothing changes
by upgrading. Switched off, those events are still read and weighed and then
thrown away instead of written down — and **an event this program has marked
is kept whichever way they are set**, so no alarm depends on them: a member
server asking to replicate every password in the domain is a read, and it
stays. The clean-up then lets go of the ones already stored, at any age,
because waiting thirty days for the retention is not an answer on a domain
writing millions a day.

**The Domain page comes back with what is ready.** It is twenty walks of a
window of that table; asked one after another it took half a minute to build
and a browser gave up long before, then asked again and set the twenty going
a second time — so the tab never filled in at all. There is a three-second
budget now: what is quick is waited for, what is not is set going behind and
arrives on the next poll, and the page says so instead of looking empty. On
any site where all of it is quick, nothing about this is visible.

1.10.71

**The Domain tab would not load at all on a large site, and the reason was in
the log four times over.** Four identical `GROUP BY kind` queries, nineteen
seconds each, running side by side in the same second — four things on one
page all wanting the same answer at a moment when nothing was kept, each
going and asking the database for itself. The page gave up waiting before any
of them finished, so the tab stayed empty, and the next poll started another
four. **An answer is now worked out once**: whoever asks first does the work
and everybody else waits for that answer.

**...and the table is settled after a pass that rewrites it.** On PostgreSQL
an `UPDATE` does not change a row, it writes a second version and leaves the
first for the server to collect later — so a pass over millions of them
leaves the table holding twice what it holds, and the planner counting rows
that are no longer there. That is exactly how a page that answered in two
seconds comes back in twenty the morning after an upgrade, with nothing in
the log to say why. A pass that rewrites more than twenty thousand rows now
runs `VACUUM (ANALYZE)` on the table afterwards — the online one, which takes
no lock and holds nothing shut.

**A narrowed pass says how many it is going to walk.** It knew the size of
the whole table and the plan was a slice of it, so `--jobs` said "252,000 so
far" with no fraction and nothing to make an estimate from. The count is
worked out behind the walk, so a cold count never delays the start.

**Three buttons that all sounded like tidying now say which is which.**
*Apply what is kept, now* throws away exactly what the "keep for" numbers
already say is too old. *Forget records older than…* forgets authentications
at an age chosen there and then, whatever those numbers say. *Give the disk
back* rebuilds the database so the freed room goes back to the operating
system — which none of the others do, on any of the three engines.

1.10.70

**The pass that reads the stored domain events again is hours faster, and it
finishes.** Measured on a real site: seven and a half million events, five
hundred rows taking two and a half seconds to write, ten hours of work — and
every restart began it again from the first row, so it could never finish,
never write down that it was done, and started over on the next start for
ever. Three things:

* **A row that reads exactly as it already reads is not written.** That is
  almost all of them: a version that changed its mind about two event numbers
  leaves every other row saying what it said, and rewriting one costs a new
  row version plus an entry in each of the eight indexes on that table —
  including the word index, which is nine expressions of trigrams. Measured
  here on 830,000 events: **76 seconds for the whole table**, 11,000 rows a
  second, with 1,403 rows actually rewritten.
* **It picks up where it stopped.** The cursor is written down as it goes, so
  a restart continues rather than beginning again.
* **The note from before this version is read rather than thrown away.** It
  carries which version last read the rows, so upgrading a site whose note
  says "3" reads the two event numbers version 4 changed and nothing else:
  the same 830,000 events, **6.8 seconds**.

**A question about a mark no longer walks the whole table.** The breakdown
behind the directory-narrowed alarms asked `(marks & 1024) <> 0` without
saying `marks <> 0` as well, so PostgreSQL could not prove the partial index
covered it and read seven and a half million rows instead — twenty seconds,
every time the page's own answer fell out of its cache. It is also kept for
half a minute now.

**`isemon --jobs` and `isemon --stop-job`.** A daemon walking a million rows
and a daemon that has stopped look exactly the same from a terminal, and the
bar that said which was on a web page. `--jobs` says what is running, how far
along, how long it has been and how long is left at the rate it is going;
`--stop-job NAME` asks one to put itself down. It stops after the batch it is
in and keeps what it has already done — the re-read then resumes from there
next time. A restore cannot be stopped half way and says so rather than
pretending.

1.10.69

**The last three keepings that were numbers written into this program are
settings.** How long a machine seen on eduroam is remembered, how long the
RADIUS packets behind the token log are kept, and how long the name an
address once had is kept — all three were fixed at a fortnight, a month and
four hundred days, and none of them could be reached. They are on
Settings → The database with the others now. The row ceilings underneath them
stay in the program, because those are a floor under a machine filling its
disk rather than a policy; and a name is still never let go sooner than the
records it is shown beside, whatever the number says.

1.10.68

**Reading the stored domain events again no longer means reading all of
them.** This is what stood between this program and a site with a billion
events in it. Three things make a stored row's reading stale, and only one of
them was ever about the whole table:

* **A new version reading events differently.** Which events each version
  changed is now written down, so the upgrade to 1.10.64 — which changed how
  two event numbers are read — rewrites those two event numbers and leaves
  the rest alone. A version that really does change everything says so.
* **A controller being named, or the domain adding one.** By far the
  commonest, and the one that cost the most: it was a full walk every time.
  What changes is whether the directory's own work is excused, and that can
  only change for rows **about the machines whose names moved** — so those
  are what is read, found by name, and every other row is left exactly as it
  is. Naming a controller on a table of hundreds of millions is now seconds.
* **The desktop-pool setting**, which really is about every row, and says so.

Two more bounds on top: nothing older than the retention is ever re-read (it
is about to be deleted and no page here can show it), and a pass that met an
unreadable row is still written down as done — that one alone used to send
the whole table round again on **every restart**, for ever.

**Throwing the old rows away is one thing now, with a button and a clock.**
Every "keep for" setting — the refused attempts, the sign-ins, this program's
own event log and ban history, the domain events — is applied in one place.
Settings → The database has **Clean up now**, which applies all of them at
once instead of waiting; and **Throw the old rows away once a day**, with a
time, for a site that would rather have one delete at four in the morning
than a trickle every five minutes. Lowering one of the numbers still deletes
nothing by itself — the next clean-up does it, and now there is a button that
is the next clean-up. The ban history is kept by when a ban **ended**, so a
ban that is still running is never old.

1.10.67

**A popup no longer closes by itself while it is being read.** The lists on
these pages redraw themselves every few seconds, and a redraw took the row
out from under a still pointer: the panel was left pointing at nothing, and a
second later a sweeper took it away. Now nothing redraws under a pointer at
all — a list that finds somebody pointing into it waits, and draws the moment
they move. The `mouseleave` a vanishing row fires on its way out is no longer
read as somebody leaving, and a panel that does lose what it was over stays
until the pointer actually moves.

**An address is no longer broken in half.** The hover panel was set to break a
word the moment the line was full, wherever it happened to be — `172.29.2.38`
came out as `172.29.2.3 / 8`, which is not an address any more. It now breaks
only a word that will not fit on a line of its own, so a session id still
wraps and an address stays whole. The socket and the switch it is a socket
*on* are two lines rather than one long one.

1.10.66

**The counts along the heading of *The logs being read* are left alone too.**
`isea 17 856 · iseb 5 · otp 2 · dc01 0 · dc02 0` is how many records
came out of each file, not a controller doing something — it was already
inside the card that asks not to be marked, and there is now a test that says
so, heading and rows both.

1.10.65

**The switch and the Remember button are on the foot of the popup they are
about.** They were on the Domain page's card; what they watch — who is in
each group that runs the domain, the rules, the controllers, the trusts — is
inside *What the directory says*, and a switch three cards away from the
values it marks red is a switch nobody connects to them. They now sit beside
**Close**, with what changed named on the same line.

**The stored domain events are read again once, not on every restart.** The
note that says "these have been read by this version" was withheld whenever a
single event would not decode — and a row that will not decode today will not
decode tomorrow either, so the note was never written and the whole table was
walked again on every single start, for ever, on any site with one unreadable
event in it. Minutes of work and a page that crawls while it happens, for an
answer that cannot change. The unreadable rows keep exactly what they had, as
they always did, and the count of them is still said out loud.

**One popup over a word, not two.** The `DC` mark carried a `title` as well as
the page's own panel, so the browser drew its white tooltip on top of the
dark one. Same on the sign-in page, where the full error had both. Everything
here uses the page's own panel now.

**...and the mark stays out of file paths.** `/var/log/remote/dc01/WinSecurity.log`
says where a controller's log lives; the machine is not doing anything in it,
and two letters in the middle of a path make the path hard to read. A name
with a slash on both sides is left alone, while `host/dc01@EXAMPLE.INT`
— a machine being talked about — is still marked. A distinguished name is
left alone for the same reason: `DC=DC03,DC=example.int,cn=MicrosoftDNS,…`
is where one DNS record lives, not a controller doing something, and a mark
in the middle of it turns a hard line into a puzzle. *The logs being read* is
left alone altogether.

1.10.64

**Watching what Active Directory says about itself.** The one change worth
waking somebody for is not in any log: an account that is in the group which
runs the domain this morning and was not in it last night. Only the directory
knows, and only against what it said before — so *What the directory says* on
the Domain page has grown a switch and, with it on, a **Remember** button.
Press it and who is in each of those groups, the password and lockout policy,
the policies that apply to some accounts rather than all of them, which
machines the domain says are its controllers, which domains it trusts and the
handful of counts that mean an account has been made easier to get into are
all written down *here*. Anything that moves after that is red on that page,
says what it was and when it first changed under the pointer, and puts a red
band across the top of every page until somebody switches the watching off or
remembers what the directory says now. The band's own button takes it off the
page for whoever pressed it, on that browser, until something else changes —
it clears nothing and hides nothing from anybody else.

The day's work is deliberately not watched: accounts made and deleted, people
joining ordinary groups, how *many* administrators there are. A page that goes
red for the helpdesk working is a page nobody reads by Thursday. It reads and
never writes: what is remembered goes into this database and never into Active
Directory.

**The domain's own controllers are marked wherever they appear.** A page full
of refusals in and out of a domain controller is the directory doing its work;
the same page about a desk is an old password saved on it, and telling the two
apart meant knowing the site's naming by heart. A controller's name is now
blue with a small `DC` after it **everywhere in this dashboard** — in a card's
rows, in the Failed attempts table, in every popup, under an address on the
front page — however it is written: `DC02`, `DC02$`,
`EXAMPLE\DC02`, `dc02.example.int` or its address. Found
by asking the directory which machines are its controllers and looking those
names up in DNS, never from a list written into this program; and the two
letters are drawn by the stylesheet rather than put into the page as words, so
what a row says when it is searched, read back or copied is exactly what it
was.

**An alarm now opens exactly what it counted, including the ones the directory
narrows.** *A ticket asked for with no pre-authentication* counted every
account behind the mark, named three of them in its own sentence — the ones
the directory says do **not** have it switched off — and then opened all of
them, leaving somebody to find those three by eye. The count, the newest, and
the filter the popup opens with now move together, for that alarm, for RC4
against service accounts and for an account replicating the directory while
being in no group that runs it.

**...and that alarm was counting the ordinary morning.** Every Windows client
on the domain opens its Kerberos sign-in with a pre-authentication-less
request and is told to do it properly; every request that fails for any other
reason — no such account, wrong password, switched off — never reaches
pre-authentication either, so it names none. All of them were marked. What
matters is a ticket the domain actually **handed over** without asking the
account to prove anything, which is the one somebody takes away and cracks at
home, and only happens where pre-authentication really is switched off. RC4 is
now read the same way: a service ticket the domain refused hands nothing over.
Every stored event is read again once, on the first start after this upgrade,
so the old marks go with it.

**A switch is named with the address it answered from.** ISE writes both
down — the name somebody typed into it and the address the packet came from —
and the name alone is half an answer: only the address is any use at three in
the morning. So every popup that names a device now names it as
`sw1rco8np · 172.29.167.81`, the socket says which switch it is a socket *on*
(there is a GigabitEthernet1/0/16 on every switch in the building), the cards
carry it on their rows, and the Device column in every table says it on the
hover.

**A button that asks the directory and nothing else.** *Read every stored
event again* asks the directory too and then walks every stored event with the
answer, which is minutes on a domain of a million. Settings → The domain
controllers now also has **Ask the directory again now**: one round of
searches — the domain's rules, its controllers, its trusts, its sites, who is
in the groups that run it — and nothing stored is touched. It is exactly what
the *Ask it again every (hours)* clock does on its own; that clock has never
re-read the logs either.

**The sign-in page says what happened in one sentence.** A wrong password
said `80090308: LdapErr: DSID-0C090451, comment: AcceptSecurityContext error,
data 52e` at somebody who had mistyped it. Now it says *the password is not
right*, or *the directory could not be reached*, and the whole of what the
directory said waits under the pointer for whoever set the site up. Where the
directory could not be asked at all and a local password was used instead,
that is under the pointer too — which is the difference between "I typed it
wrong" and "a controller is down".

**The word index no longer deadlocks against an upgrade.** On a real upgrade
the background `CREATE INDEX CONCURRENTLY` that makes the search box quick
met the ordinary index work of the daemon starting up, PostgreSQL killed one
of them, and the site was left without the index until somebody restarted —
with `win_ts` having waited thirty seconds for it. It now waits for the shape
of the database to settle, drops what PostgreSQL leaves behind when it is
beaten to the table anyway, and tries again.

**The Domain page is for reading.** The *Read everything again* button and
the read-only line under it have moved to Settings → The domain controllers,
beside the settings they obey. What stays on the Domain page is the progress
bar, now the full width of the page with what it is doing on the line under
it — and the same bar is drawn in the settings pane, off the same answer, so
whoever pressed the button there can watch it there.

1.10.63

**A second audit, from angles the first did not take** — the ISE and banning
core, the LDAP client, the page's JavaScript — and a live run of the whole
application (daemon, PHP, browser) over the 2.9-million-event database with
every request timed.

### The core

**A ban made longer here never reached the router.** An address that went on
trying from behind the door was made *for good* in the database — and the
router kept the ten minutes it had first been given, let the address back in
when they ran out, and the page went on saying it was banned. Two halves: the
escalation never told the router, and the sync skipped anything already on the
list without looking at how long the router was still going to hold it. The
sync now reads the router's own remaining time and rewrites an entry the
database means to hold longer.

**A hand-banned subnet went straight past the whitelist.** `10.0.0.0/8` was
judged by its first address alone, so it took a whitelisted `10.1.2.3` onto
the router with it — and the other way round, whitelisting an address inside
a banned subnet freed nothing. A subnet is spared when it takes in anything
that is.

**"Behaves for a month and starts again" was true of the database and false
of the memory beside it.** The bans this program remembered making were a
plain count that only ever went up, and the larger of the two won: an address
banned three times in January and quiet since was put out for good in April.
They are remembered with their moment now. And the ladder's last rung —
*for good* — was read as another day by the escalation.

**Failures on devices nobody watches counted towards a ban.** The record that
triggered the judging was checked against `watch_devices`; the count then
took every failure from that address on any device. Four tries on a lab
appliance plus one on the real head end was a ban. Only the watched devices
count now. And a switch from another maker — which sends no Cisco av-pairs —
had its failed 802.1X read as *the VPN*, because a socket with no method fell
through to the VPN's own fallback. A socket is the network, whatever it says
about how.

### The directory client

**StartTLS took whatever arrived in the clear along with it.** Bytes sitting
in the read buffer after the server's StartTLS reply were read back
afterwards as if they had come over TLS — so somebody on the path could
append a forged *bind succeeded* and the next person to sign in was let in
with any password. Anything in the buffer at that moment is refused and the
connection dropped. Only StartTLS may be sent as an extended operation, by
name.

**Names were being escaped into filters that go on the wire as BER**, where a
value is raw bytes and escaping *corrupts* it: a user whose distinguished name
has a comma in it (`CN=Novak\, Jan`) was never found inside a nested group and
was refused or downgraded; a name with a bracket in it was never found at all.
A search that ran to the page limit came back as *nothing* rather than what it
had read, so a big domain's count of switched-off accounts was written down as
nought; a paged search given up on early was not let go of properly; and the
*smart card required* flag was the wrong bit.

### The page

A door card stuck on *"Counting…"*; the directory's answer about one name
landing in the card for the next name typed; an address's story drawn over a
popup somebody had since opened for another; *"2 min ago"* frozen for an hour;
status questions piling up on a slow server; and a job's progress bar giving
up on the tenth scattered miss. Each fixed at its cause: a host that is
emptied forgets what it had drawn, every popup that asks the daemon holds a
ticket and draws only while it is current, and one status question is in
flight at a time.

### What the live run found

**Letting old rows go took six to nine seconds a stride, and got slower.**
Each stride's edge was looked for from the very beginning of the table — which
was the rows the previous stride had just deleted — so every stride re-walked
everything already gone. On 830,000 events: 0.21 s a stride now. **And the
list of controllers was read out of the whole table every five minutes** —
seven seconds on three million rows — for a machine that is not added twice a
day. It is read out of the last month and kept for an hour.

Measured against the daemon directly on 2.9 million events: `status` 10–150
ms, the Domain page 0.5–1.5 s cold and 10 ms from the cache, a word typed into
the box 60–120 ms, everything else under 70 ms. A browser was driven through
every tab and window with no page errors.

1.10.62

**A whole-application audit, and the performance work behind it, measured on
2.9 million domain events in PostgreSQL** — bigger than the site this runs on.

### The worst of what the audit found

**A refusal was being counted as somebody getting in.** Windows writes 4768,
4769 and 4776 whether the answer was yes or no; the number alone does not say
which, the code inside does. This program filed them by the number. So a
member server or a telephone with a stale password doing an NTLM check — which
the controller writes as **4776 with `Error Code: 0xC000006A` and nothing
else**, no 4625 at all — was filed as `ntlm`, drawn in the *let through* band
of the chart, and invisible to every card about what keeps trying an old
password. The account locked out and the page had no answer, which is the one
question a lockout leaves behind. On one of your own controller logs, 26
refusals were being counted as successes. The kind now comes from the outcome,
and the walk that reads stored events again puts the old rows right.

**Every reboot raised a critical alarm.** The `audit` mark was set for any
event of that kind, which is also *Windows started up*, *the event log service
was shut down* and *the system time was changed*. Patch night on three
controllers is six of those, so the page put up a crimson **"The audit log was
cleared — 6 of them"** about three machines rebooting on schedule. Only an
emptied log (1102) raises it now.

**Cards that opened something other than what they counted.** The page copied
six filter names by hand, so a card counted with a seventh opened something
else: the machine-account alarms counted the machines and their popups hid
them (a crimson "an account asked to replicate", pressed, showing no events at
all), and the spray, brute-force and dead-account cards counted only the
*refusals* while their popups opened every event about that name — a card
reading 147 over a popup reading 8,432. The page now passes on whatever
filters the daemon counted with, and "cannot sign in anyway" is a filter the
rows can actually be asked for. Checked by pressing every card on real
controller logs: every number now agrees with the list behind it.

**A lockout said the machine and the program were unknown while the table
below it listed both.** It asked for the newest twenty-five events of any kind
around the lock and threw away what it did not want, so an account whose
workstation logged forty successful tickets in that half hour got twenty-five
tickets and no refusals. The filter is in the query now.

**Eleven of twelve card rows drew a count and no detail.** The newest row of
each was fetched as "the newest 480 of any of them", so whenever one subject
had more than that in the window — and *the password was wrong* always does —
every other row came back empty. One seek per row instead, which is also
faster.

Also: a copy of the loopback address written as `::ffff:127.0.0.1` survived
the check that drops `127.0.0.1` and was then reported as a server to go and
visit; a ticket with no pre-authentication type named at all was never marked,
because the test for it could not be reached; a restore on MariaDB or
PostgreSQL committed after each table, so one that failed half way left eleven
tables restored and eight emptied; `POST /api/db/prune` with `{"days": -1}`
put the cut-off in *tomorrow* and erased every recorded authentication; a
thread whose connection the database server dropped never opened another, so
that thread stopped reading and writing until somebody restarted the daemon;
the answer cache stamped an entry with the time *before* the work ran, so the
one query slow enough to need a cache never got a hit; two jobs of the same
kind overwrote each other's progress and the first to finish deleted the bar
of the one still running; MariaDB's sampled row estimate was shown as a count,
so the same table read 3.1 million one poll and 1.9 million the next; and one
failed poll left a job's progress bar frozen and red over work that then
succeeded.

### ...and the speed, on 2.9 million events

```
                                   before     after
the box at the top (CTRL+K)         0.86 s    0.05 s
the filters over the events         0.78 s    0.30 s
the alarms, counted both ways       0.20 s    0.09 s
the whole Domain page, a month      1.4  s    0.94 s
...and every poll after it          1.4  s    0.00 s
```

**Searching for a word is a lookup where the engine can make it one.**
`LIKE '%novak%'` cannot use an ordinary index — there is nothing to seek to —
so a word typed into the box was a walk of every row in the window testing
nine patterns on each. PostgreSQL has an answer for exactly this: `pg_trgm`
indexes the three-letter pieces of a value. The index is built once, in the
background, `CONCURRENTLY` so nothing waits for it, and where the account may
not create the extension it says so once and searching goes on working exactly
as it did.

**Three walks of the window became one.** The filters asked how many of each
kind, how many of each event number, and which controllers wrote anything —
three separate scans of the same rows on every page load. The alarms walked
the window twice because four of them count machine accounts and six do not.
Both are now one pass grouped by everything at once. And the kind counts,
which three parts of the page each asked for separately, are worked out once
and handed down.

**The list of events stopped fetching what it threw away.** It selected every
column and dropped the packed record a line later — megabytes over the wire
per page turn — and counted by wrapping that same select in a subquery.

1.10.61

**The dump says how far along it is.** `pg_dump` and `mariadb-dump` are
somebody else's programs and say nothing about their own progress — fifty
seconds of silence and then "done" tells nobody whether it is working or
wedged. What they do do is write a file, and that file getting bigger *is* the
progress, so it is watched and reported: `writing the dump isemon-….pgc: 418.4
MB so far`, in the log and on the bar. No total, because a dump is a fraction
of the database and which fraction depends on what is in it — a bar with
nothing honest to compare against creeps rather than filling, which is the
truth.

**A bar that says it has finished has finished.** The copy reached 100% and
then spent another minute building indexes; a bar that claims to be done and
goes on working for a minute is when somebody decides the thing has hung.
Building the indexes is its own counted phase now. It is also quicker: a copy
under construction is not a database anybody is relying on yet — it is written
from beginning to end and only then is it a copy at all — so it is told not to
wait for the disk after every write and given room to sort an index in.

**"Read everything again" no longer makes every page crawl.** The walk paused
twenty milliseconds between batches, which is a promise about a machine rather
than about the job: where a batch takes twenty milliseconds it is half the
time, and where a batch takes three seconds it is nothing at all and the walk
takes the whole machine. It now pauses for as long as the batch itself took,
so the rest of the program gets half of whatever machine it is on, and it
reads on a connection of its own rather than down the middle of the one the
page is using. Measured on 120,000 events with the page asking questions
throughout: 453 answered, the worst waiting 0.05 s.

1.10.60

**Pressing "make a copy now" no longer stops the whole installation.** On a
1.1 GB PostgreSQL database it froze everything for five minutes. The copy
held the write lock for the whole of itself, so the log reader, every page
and anyone signing in queued behind it — and from outside, a daemon that is
holding a lock and a daemon that has died look exactly the same.

It doesn't need the lock. Both servers will hold a connection still for a
long read — a repeatable-read snapshot sees the database as it was when the
copy started and costs no writer anything — and SQLite's own online backup
was already consistent while the daemon wrote. Measured on the same 205 MB
database, with another thread writing throughout:

```
                              1.10.59      1.10.60
the copy took                  12.3 s       12.5 s
writes that got through            2          233
the worst one waited          12.21 s       0.22 s
```

Two more things the log showed. The copy read `SELECT … FROM win_events` with
psycopg2's ordinary cursor, which fetches **every row into memory** before the
first batch comes back — a million and a half domain events carrying their
packed records, which on a machine without a spare gigabyte is not a slow copy
but a machine swapping. It now reads a batch at a time off the server. And the
copy built all twenty-five indexes on the far side *before* the rows went in,
so every row maintained every index; they are built once at the end now.

**Every database job says itself in the log, from beginning to end.** A copy,
a dump, a restore, a check, a tidy, forgetting old records: `database: making
a copy: isemon-…db - starting` and, at the other end, `- done in 4 min 12 s,
1.1 GB`, or `- FAILED after 3 s: …`. The long ones say how far along they are
as they go, and that bar is now drawn on the database pane as well as on the
Domain page — off the daemon, so it survives a reload and is there for
somebody watching from another machine. The buttons that would start a second
long job are held while one is running.

**A table is only rewritten when there is room to get back.** `VACUUM FULL`
takes an exclusive lock — nothing may read the table, let alone write to it —
and every table was being rewritten whether it held a dead row or none. That
is where the other 28 seconds in the log went, and why a 500-row UPDATE beside
it took 28 seconds too: it was queued behind the lock. PostgreSQL is now asked
what each table is actually holding, in dead rows *and* in room on disk
(because its counters lag behind an erase by minutes, and the room does not),
and a table with nothing to give back gets the ordinary online VACUUM, which
locks nobody out. A rewrite that does happen says so first, and says that
nothing can read the table until it is done.

1.10.59

**An upgrade goes from any version to any version.** It always was meant to —
the columns and indexes a version adds after the fact are listed and added on
first open — but it was proved by hand for one old shape and on one engine.
It is now proved for real: every one of the **71 releases from 1.1.0 to
1.10.58** builds a database with its own code, and this version opens it,
keeps every row, and answers every page. Nobody upgrades version by version
and nothing here asks them to.

The engine tests got the same treatment. They used to take away two columns,
one index and a table; they now take away **every** column and **every** index
this version adds after the fact — written from the program's own lists, so a
column added next year is in the test the day it is added — and check each one
comes back, on PostgreSQL and on MariaDB.

**Five index warnings on a sound database.** An upgrade ended with

```
the index win_ts_event could not be made: duplicate key value violates
unique constraint "pg_class_relname_nsp_index"
…
5 parts of the database could not be brought up to date
```

about a database where all five indexes were present and correct.
PostgreSQL's `CREATE INDEX IF NOT EXISTS` is not atomic: two connections both
find an index missing, both go ahead, and the second is refused — and an
upgrade is exactly when that happens, because the new daemon starts while the
one it replaces is still finishing. Each engine can now say what indexes it
has, so one that is already there is not made again, and one that is refused
is looked for again before anybody is told: an index that is there is there.
An expected refusal no longer prints the statement either.

**The installer announced the wrong version.** `./install.sh --upgrade` said
*"Upgrading isemon to 1.10.43"* while installing 1.10.58, because the number
was written down in a line of its own and never changed. It is read out of
the program now, and a check makes the installer print its version and
compares it — so it cannot drift again.

1.10.58

**Where each of those things was done from.** Windows writes no address and no
machine name on an account change — not on 4720, not on 4724, not on 5136.
What it writes is the *Logon ID* of the session that made it, and the sign-in
for that session, on the same controller, is where the workstation name and
the source address are. Nothing else joins the two, so the session is now kept
beside every event and the story says `Done from NB-MDOLEZAL (172.29.6.100)`.
Events already stored have the session in their packed fields and nowhere
else, so the re-read fills it in — which is the whole reason its version
number went up.

**A deletion ends a lockout, and the page says so.** A lockout on an account
that was then deleted read *"still locked, as far as these logs go"*, which is
the page arguing with its own data: the events two rows down name who deleted
it. Now: `never unlocked — the account was deleted 27-09-2026 21:10:10, 2 min
later, by mdolezal`. The deletion is found both ways round, because Windows
writes it as an account event naming the account and as a directory event
naming only the administrator.

**"Through" is drawn when there is something to draw.** That column says which
*program* used the password, and it is the best answer a lockout has — when
Windows fills it in. On a domain controller it usually does not: a lockout
carries no process of its own, and the refusals before it are Kerberos and
NTLM events, which name a machine and not a program. A column of dashes all
the way down takes width from one that is saying something, so it appears only
where the data has it. The popup leaves out an empty fact for the same reason.

**No dead ends.** Pressing an account that is merely being *refused* — `pdf`,
say — opened a story with nothing in it and no way onward, because the two
buttons were drawn after the rows and there were no rows. It now says so
plainly and offers both: everything the controllers wrote about it, and the
directory. A popup also no longer offers *"Open the domain page"* when that is
the page you are already on; pressing it there closed the popup and did
nothing, which reads as a button that is broken rather than one with nowhere
to go. Every pressable thing on the Domain page was then pressed in turn —
twenty-five of them — and every one opens something.

**The directory popup, made readable.** Thirty-five names beside a heading
wrap into four ragged lines and read as one wall of text with the heading
floating somewhere inside it. Each set of names now has a heading of its own
and the names sit under it as pills that look like what they always were:
pressable, each one opening what the directory holds about that account. The
blocks — the counts, the controllers, the trusts, the groups, the sites, the
per-account password policies, the top of the tree — all carry the same kind
of heading now instead of a mixture of headings and grey sentences.

1.10.57

**The whole life of one account, including one that no longer exists.**

Who made it, who changed it, who reset its password, who unlocked it, who
deleted it — in order, with a name against each. None of that was reachable
before: every list on the Domain page is newest-first and one kind at a time,
and the events that say who created and who deleted an account name the
*administrator* in the account column and put the account itself inside a
distinguished name, so looking for it by name found nothing at all. It is
looked for both ways now and the two are one story.

The account this matters most about is the one that has been deleted, and
there the directory holds not one word: `testlock` was created, unlocked and
deleted inside seven minutes, and asking Active Directory about it afterwards
answers "no such account". The controllers wrote all of it down, so that is
where the answer comes from — and the story says so out loud when the account
is gone.

```
Made 27-09-2026 21:03:48 (18 min ago) by mdolezal.
Unlocked once, the last time 27-09-2026 21:07:21 (15 min ago) by mdolezal.
Its password was set once, the last time 27-09-2026 21:03:49, by mdolezal.
Deleted 27-09-2026 21:10:10 (12 min ago) by mdolezal. Asking the directory
about it now would find nothing — this is the whole of what is left.
All of that was mdolezal, and nobody else.
```

It opens from everywhere a name appears: every account name on the Domain
page, a name typed into the box at the top — which is the point, because a
name typed into that box is usually one somebody is chasing and no longer
exists — the lockout, the new *Accounts made, changed and deleted* card, and
the directory card, which offers it precisely when the directory has just said
there is no such account. Machine accounts are left out of "everybody who did
something to it": the subject of a lockout is the controller that noticed it.

**A lockout says how it ended, and who ended it.** A lockout somebody cleared
two minutes later and one that is locked still read identically on this page
before — and which of the two it is is the first thing anybody asks. The
unlock that ended a given lock is the first one after it, so the row now says
`unlocked 27-09-2026 21:07:21, 1 h 40 min later, by mdolezal`, or `still locked,
as far as these logs go`.

**Every event is named by what it says.** "an account was deleted (4726)"
rather than "an account changed (4726)". The daemon has known the exact words
for every event number all along and the page only knew the twenty groups, so
a table of eleven account events all read the same. A check keeps the two
tables equal entry for entry.

**Two things off a live 1.10.56 log.** `reltuples` was asked with a literal
`%s` in it, which PostgreSQL reads as the start of a format and refuses, so
every table fell back to being counted properly. And the one-off walk that
fills in the marks ran twice at once on a restart — it now holds a lock while
it walks.

1.10.56

**Built for a database that gets very large, and measured on one.**

Twenty copies of a real site's data in PostgreSQL — 4.8 million domain events
and 1.2 million refusals — and the same questions asked before and after:

```
                        before    after
the Domain page, a week  12.2 s    1.9 s
the Domain page, a day    3.3 s    0.9 s
the patterns worth looking at
             (a week)    10.8 s    0.9 s
the box at the top        7.6 s    1.1 s
the front page, a month   2.2 s    2.0 s
```

**The marks are a number as well as words.** What an event IS beyond what it
says — a member server asking to replicate, somebody listing who is in which
group, a ticket in RC4 — is written beside the row as words, and asking the
database "which rows are marked replication" of a word list means
`LIKE '%replication%'`, which no index in any engine can answer. The Domain
page asks that question ten times over, so the page was ten walks of every
row in the window. The same answer is now also written as a number, one bit a
mark, with an index over the rows that are marked at all — one row in seven on
a real site. The words are untouched: they are what is drawn, searched and
exported.

Two things had to be right for that to help. The index's own rule
(`WHERE marks <> 0`) is said out loud in the query, because PostgreSQL will
only use a partial index where it can prove the query cannot want anything
outside it — `(marks & 1) <> 0` implies that to a person and to nothing else.
And the ten questions are now one: one pass grouping by the number comes back
with the handful of combinations that occur, and every card is a sum over
them.

**The window first, then what is in it.** Every count on these pages is
"how many of each kind in this window", and with an index that starts with the
kind the engine walks every kind from the beginning of time and throws away
all but the window. Four indexes now start with the time — the kinds, the
event numbers, the controllers, and the countries on the front page — so what
a page costs is what the window costs, however many years are behind it.

**The box at the top reads the window once, not once a column.** Six questions
of six columns was six walks of the same rows; it reads them once and counts
in the program, over the few hundred rows a word matches rather than the
millions it does not.

**A number in the corner of a page is not worth reading a hundred million
rows for.** Past a couple of million, "how many are there" is answered with
the engine's own figure — PostgreSQL's statistics, MariaDB's table figures —
which is within a fraction of a per cent and costs nothing.

**Old rows are let go a stride at a time.** A site that turns retention on
after a year was asking for one DELETE the size of the year: minutes of write
lock with the page waiting behind it, and a write-ahead log the size of the
table. Twenty thousand at a time, each one a range over the index on time,
with a breath between them.

**An existing database brings itself up** behind the page: one walk that
writes the numbers beside the words it already has, in strides, without
unpacking a single record — two minutes for 4.8 million rows, once, and a note
so a restart does not do it again.

**Every account on the Domain page opens what the directory holds about it.**
That page is what the controllers wrote down; the other half of every account
on it — who the person is, which groups they are in, whether it is switched
off, locked or expired, when the password was last set — was one press away
from a single event and nowhere else. A name is now marked wherever it
appears: in the lockouts and their whole story, in the list of events, in
what was holding the password, on the cards, and on the alarms. It asks the
directory the ROW's own domain, because a site with two of them has two
places to look. Machines too, which a domain holds as accounts.

**And in what the directory said: nothing is shortened and all of it opens.**
Every count is pressable and opens the names behind it; every name opens what
the directory holds about that account; every member of every group that runs
the domain is listed rather than "and 23 more", and each of them is pressable
too, as is each controller.


1.10.55

**It can never change anything in Active Directory, and now it cannot even
try.** This program reads a directory and does nothing else — that has always
been true of what the code does, and it is now true of the socket. Every LDAP
message is checked on its way out against the four that read (bind, search,
unbind, StartTLS); an add, a modify, a delete, a rename or a compare is
refused before a byte leaves this program, whoever writes the code to build
one. A check proves the list, and another proves each of those five is
actually refused while a search still goes through.

**A big domain is read whole.** Active Directory hands back its MaxPageSize —
a thousand on an ordinary domain — and says nothing about the rest, and these
searches were not asking page by page: a domain with four thousand service
accounts had a thousand of them read and three thousand quietly missing.
Every question is now asked a page at a time, through one place that counts
as well as keeps: the NAMES stop at eight thousand, because what they are for
is matching an account seen in a log, and the COUNT is the domain's own
however large. Where a list was cut short the page says which. The group
walks are paged too — Domain Users is every account there is.

**And a great deal more than four numbers.** Besides the service accounts,
the ones with pre-authentication off and the ones switched off, it now reads:
accounts that were in a group that runs the domain at some point (Windows
stamps `adminCount` and never takes it off); passwords that never expire;
accounts that need no password; accounts trusted for unconstrained
delegation, and for delegation with a protocol change; accounts that must use
a smart card; who is in each privileged group with its true count; the
domain's password and lockout rules, its functional level and its machine
account quota; which machines it says are its controllers and what they run;
which other domains it trusts and which way round; the password policies that
cover only some accounts; and the sites with the address ranges that belong
to them — which is what turns an address in a log into a place.

**Two domains read into one of these stay two domains.** A site can send the
logs of the controllers of two domains here, and the same name in both is two
accounts: they can be in different groups, and one of them can run the domain
while the other is nobody. What each directory says is now kept under its own
domain — under every name an event might write it as, the DNS one and the
flat one — and an alarm is weighed against the domain the event said it
happened in. Each domain's own lockout rule is the one used, and a suffix
claimed by two directories never takes a name away from the directory whose
own domain it is. The counts on the page are per directory rather than summed.

**Both directories are drawn the same way** in the popup about a person: the
directory, its domain and its marks; then the person; then every fact. They
were two different shapes, and two accounts read side by side have to be one
shape or the eye cannot compare them.

**An answer from a version that asked fewer questions is asked again.** A site
that upgraded carried yesterday's answer for a day and saw none of what this
version reads.


1.10.54

**What the directory is asked, and what it is for.**

Switching the reading on added four counts and some sentences inside alarms,
and there was no way to see what it had actually read. It now reads the shape
of the domain as well as its accounts — all of it read, none of it written —
and there is a button under the counts that opens the lot:

* **After how many wrong passwords this domain locks an account**, for how
  long, and over what window. This is the fact that decides what a hundred
  refusals MEAN: a domain that locks after five is locking somebody out over
  and over, and a domain whose threshold is nought never stops a slow guess
  at all. The alarm now says which of the two it is, and the second makes it
  worse.
* **The password rules**: shortest length, how long one lasts, how many old
  ones are kept, whether complexity is required — and whether reversible
  encryption is on, which means the passwords are recoverable.
* **What the domain is running as**, which is not the version of Windows on
  the controllers: a domain raised no higher than 2003 cannot be told to stop
  handing out RC4 tickets.
* **Which machines the domain itself says are its controllers**, what they
  are running and when each was last seen.
* **Which other domains it trusts**, which way round, whether the trust
  reaches across the forest, whether SIDs are filtered and whether it is
  RC4-only. A name nobody here has heard of signing in is a different thing
  where there is a trust and where there is not.
* **Who is in each group that runs the domain**, group by group rather than
  one flat list, following groups inside groups.
* **Password policies that cover SOME accounts** rather than all of them,
  because "the domain locks after five" is not true of an account one of
  those covers.
* **How many machines one account may join**, and the top of the tree, which
  is what a distinguished name in a log is read against.

**The bar under the button appears when the button is pressed.** It appeared
at the end, or not at all. Three faults, one after another: the page asked
once, 700 ms after the press, was handed the answer worked out ten seconds
BEFORE it, saw no job in it and stopped asking; the job begins by asking two
domain controllers about their groups, which is a minute with nothing to
count and so nothing to show; and a second press during that minute walked
straight past the guard and started a second pass over the same table, with
both of them writing the same progress. Now: the press starts a watch that
does not depend on the first answer, the kept answer is thrown away the
moment the button is pressed, a job with nothing to count still says it is
going, and one pass at a time is decided before the thread that does it
starts.

**Both directories say which domain they are.** The second one had its domain
in a blue chip and the first did not.

**Domain and Firewall have swapped places** in the strip across the top. A
check holds the strip and the list that shows the panels to the same order.


1.10.53

Everything below, and it supersedes the 1.10.52 builds: three of those went out carrying the same number, which is exactly what a version number is for.

**The directory itself, asked about the accounts in the logs.**

The logs say what happened; the directory says what it happened TO, and only
the two together say whether anybody should care. Four small read-only
searches a day against each connected directory, and every alarm about an
account is read against them:

* **A ticket asked for in RC4** is kerberoasting when the account it names is
  a SERVICE account and an old application when it is not — the directory
  knows which, because it knows which accounts have a service principal name.
* **A ticket asked for with no pre-authentication** is ordinary against an
  account that really has it switched off and is somebody trying every
  account in turn to find one that does against an account that does not.
* **An account asking to replicate** that is in no group that runs the domain
  is a different thing from one that is.
* **An account being hammered, or locked over and over**, that is in Domain
  Admins or one of its neighbours is worth waking somebody for; the same
  shape against a mailbox is not.
* And an account the directory says is switched off altogether is said to be.

Where any of that makes the alarm worse, the alarm gets worse — info
becomes a warning, a warning becomes critical — and it says in words which
fact did it. Read only, always; nothing is ever written back, and a directory
that will not answer leaves what was known exactly as it was.

**A progress bar under the button.** The re-reading runs in the daemon and
says where it has got to THERE, so the bar is still there after a reload,
still there on another tab, and there on somebody else's screen at the same
moment. While something is going the page asks more often and stops as soon
as it is done.

**Why naming the controllers did not work — the real reason.**

The rows carry what this program made of them, and what it makes of a domain
event depends on WHO THE CONTROLLERS ARE. That re-reading ran while the
database was being opened: before there was a daemon, before the settings had
been read, before a directory had been asked. So every row was re-marked as
though no machine in the domain were a controller and no site ran a desktop
pool — and then the settings were read, a moment too late, and nothing
read them again.

A site could name its controllers, switch the desktops on, press the button,
upgrade, and be told all over again that its own domain controllers were
replicating the directory. **That is the fault behind every "it still alerts"
of the last hour**, and it is why it looked right here and wrong there: the
tests set the settings before opening the database, and a real installation
cannot. The re-reading now waits until the daemon knows who is who
(`Daemon.sort_the_domain_out`).

Run over this site's own database, opened exactly as the daemon opens it and
with nothing pressed:

```
WORTH LOOKING AT
  crit  An account asked to replicate the directory   101   SPSInstallTest
  warn  One account failing over and over             300   pdf
```

Two alarms, both real. Before: three, two of them a domain controller doing
its job, and a card of five thousand reads called "What was changed".

**And a version that changes its mind now says so.** 1.10.51 moved event 4662
to a kind of its own and excused a controller from two more things without
raising the note that decides whether stored rows are read again — so on a
site that upgraded, every row kept yesterday's answer and every card looked
exactly as it had. The note carries the version as well as the settings, and
`WIN_SORT_VERSION` is 2.

**One thing pointed at is one panel, everywhere.** The rule was written for
hardware addresses; it now lives in `explain` itself, so the name over an
address, a tag, a heading — anything drawn inside a row that already
explains itself — joins that panel rather than opening a second one on top
of it.

**Pressing a card opens what that card counted.**

A row reading *"the password was wrong — 65628adm — 118"* opened a list that
was a mixture of accounts, and the count at the top of it was not 118. Two
faults, both of them everywhere rather than on that one card:

* **A card was pressed as a SEARCH.** Only some of the columns a card can be
  grouped by could be asked for by name — the answer the domain gave, who
  did it, the program, the object, a hardware address, an institution, a
  reason had none — so pressing one of those fell through to a free-text
  search over nine columns. Every one of them is a filter of its own now, a
  name is asked for exactly rather than through the search box's LIKE, and
  the list a card opens drops the same machinery the card dropped. A check
  reads the columns off the daemon and off the page and fails if a card can
  ever again be grouped by something nothing can ask for.
* **A row was read as a sentence.** The line under the name was the newest of
  what the row counted, drawn as though it were the whole of it. A row that
  covers more than one account, machine or address now says how many before
  it names anything, and what follows is marked *newest:* — so "the password
  was wrong · 2 accounts · 4 addresses · newest: pdf · 172.29.153.5 · 302"
  can only be read the way it is meant.

While it was being looked at: the list of kinds asked for was held in a local
called `said`, which is also the name of the column holding the answer the
domain gave. The moment that column became a filter, every press sent the
list of kinds as its value and opened nothing at all.

**The domain on the front page's chart.** Where the controller logs are being
read, what the controllers refused and what they let through stand beside
this site's own doors — refusals against the same scale, because a refusal is
a refusal whoever wrote it down, and sign-ins against a scale of their own on
the right, because one person signing in once writes a Kerberos ticket, an
NTLM validation and a logon on a controller, and every service they open
writes another. On this site that is thirty thousand an hour against nine
hundred refusals at the doors: on one ruler the chart this page exists for
would be an inch of red under a wall of blue. Nothing of it is added into the
doors' own bars — that sign-in is already counted at the door it came
through.

**Debug, one switch a thing.** The debug switch is still "everything"; under
it are five that say WHAT: the statements put to the database, the questions
put to Active Directory, the requests the dashboard makes, the passes over
the log files, and the commands sent to a firewall. A machine being chased
for a directory need not carry a thousand statements a minute as well.

The directory half is new, and it writes the filter **as it went on to the
wire** — read back off the BER rather than passed down beside it, so what
appears in the log is what the directory was asked and cannot say otherwise —
with where it was asked, how long it took and the entries that came back. A
password is never written: the sign-in line names the account and says so.

**The box at the top looks in the domain too.**

It says it looks through everything this machine has recorded, and on a site
reading its controllers that is another quarter of a million events — the
half of a refusal that is written down on a controller and nowhere else. A
name that had never touched the VPN and was being hammered on the domain came
back *"nothing here matches"*.

It now looks in six columns of the controller logs at once — the account, the
machine, the address, who did it, the program, the object — over the last
week, and each line is an ANSWER rather than a place to go and look:

```
IN THE DOMAIN, THE LAST 7 DAY(S)
  pdf        300 refused · never got in · 2 addresses · 27-09-2026 17:17   account
  PVEXC05    508 signed in                                                machine
```

Pressing one opens exactly those events, the same way pressing a card does,
over the window the box searched — so the count in the popup is the count on
the line. The machinery is left out, for the reason the cards leave it out.

**Asking the directory has a switch, and it shows on the page.**

The reading above went in unswitchable and invisible, which is half a
feature: a reading that is quietly not happening looks exactly like a domain
where nothing is wrong. There are now two settings under *The domain
controllers* — whether to ask at all, and how often (a day by default) — and
a line under the patterns on the Domain page saying whether it is being
asked, of which directory, when it last answered and how much came back, with
what each count is FOR on the hover. *"Read everything again"* asks the
directory at once rather than waiting for the clock. Counts and never names:
which accounts a domain's administrators are is the domain's business and
stays on the domain's side of the wire.

Two faults came out of writing that down:

* **It had never once run.** The method that asks a whole domain its four
  questions was called `directory_facts`, and so was the one that reads the
  facts off a single entry — the second definition replaced the first, every
  call raised a `TypeError`, and the `except` around it swallowed every one.
  The feature was dead from the hour it was written. A check that asks the
  mock directory and looks at what came back is what found it; the mock
  learned to answer `memberOf:1.2.840.113556.1.4.1941` in the direction
  Active Directory answers it, which is how "who is in the groups that run
  the domain" is asked.
* **A directory that would not answer looked like one that had.** The failure
  wrote the clock that says when it last ANSWERED, so the page read *"last
  answered 48 seconds ago"* over four noughts — which says the domain has no
  service accounts and nobody runs it. Two clocks now: when it answered and
  when this last knocked, and a directory that has never answered is said to
  have never answered. An answer holding nothing at all is treated as no
  answer, whatever clock is written beside it — every domain has service
  accounts, krbtgt alone has a service principal name — so a site that
  carried one of those clocks over from the version before mends itself on
  the next tick.
* **The button asked nothing at all.** It cleared the clock that says when
  the directory last answered and left the one that says when this last
  knocked, so pressing it threw away the answer and then refused to go and
  get another for fifteen minutes: the page said *"nothing has answered
  yet"* and, with the LDAP debug on, there was not one query in the log. The
  clocks are skipped properly now, and the button does its asking on a thread
  of this program's own rather than on the one drawing the page — thirty-odd
  searches of somebody else's domain controller belong nowhere near a page
  being drawn. A page only ever reads what is already stored; the asking is
  the daemon's, on its own minute.
* **And when it does not get through, it says so over the answer it is
  showing.** "It answered on Tuesday and has not been reachable since" is a
  different state from "it answered".

**The groups somebody is in, one to a line.** They were pills in a row, and
most group names have spaces in them: *"Certificate users Disk J - OVSÚ Disk
Q M365_WO_booking"* reads as one long name with spaces in it and there is no
telling where one group ends and the next begins. A line each, with the
distinguished name beside it — which is the half that says WHICH "Disk Q"
this is, and which was on a hover nobody would find.

**A directory that was slow for ten seconds no longer re-reads the lot.**
What the domain says its controllers are is half of the note that decides
whether every stored event is read again. A lookup that failed used to shrink
that set, change the note, and send a quarter of a million rows back through
the reading — on every restart where the network happened to be slow. What
the domain last said now stands until the domain says something else.

1.10.51

**Reading the directory is not changing it.**

*What was changed* was counting `firepower` READING a group five and a half
thousand times. Event 4662 is object-access auditing — a service reading a
group, a controller touching the domain object, somebody's own account being
read as they sign in — and on a controller with that auditing on it is
most of the log. None of it is a change to anything, so a card headed "What
was changed" that counts it is a card whose title is not true. Reading has a
kind of its own now (`read`, with 4798 and 4799 beside it) and a tab of its
own; the cards about changes leave it alone, and what makes one of these
worth looking at is still found, because that is a MARK and not a kind. On
this site's own database the card went from five thousand reads to the
Exchange server object and an SCCM registration — things that really were
changed.

**A controller doing what a controller does is not an alarm.** Naming the
controllers excused them from replicating the directory and from nothing
else, so *"somebody is listing who is in which group — 748, the newest by
DC03$"* went on being reported about a domain controller asking which
accounts are in its own groups. A named controller is now excused from
replication, from listing and from holding the rights every service on it
holds — and from NOTHING else. The audit log being cleared and somebody
being put into a group that runs the domain are never excused, whoever did
them: they are the two things an attacker with a controller's credentials
would do first.

**What the daemon is doing, in the log, with a percentage.** Anything that
walks a whole table says so every tenth of the way, and never twice within
two seconds. A job that turns out to have nothing to do says nothing at all.

```
reading the domain events again: starting on 241,957
reading the domain events again: 11% (28,000 of 241,957)
...
reading the domain events again: done, 241,957 in 42 s
```

**`isemon --status` again.** 1.10.50 fixed the reading; the re-read still held
the write lock for half a second at a time, a hundred and twenty times over,
and anything else that wanted to write queued behind each of them. Smaller
batches with a breath between: the job takes a little longer and nothing
waits on it. The status line also called a controller's log `winsec` and
listed the controllers among the ISE nodes at nought, then warned that they
had gone quiet — a warning about three machines that were working
perfectly.

**Active Directory on both lists.** A tab on Failed attempts and now on
Logins too, each carrying a count of its own from the daemon, both drawing
into that page's own table with that page's own search and pager.

1.10.50

**A page that would not draw, and a daemon that spent its life committing.**

**The page.** 1.10.49 shipped with a stray brace in it: the browser stopped
at the syntax error, half the script never ran, and the page drew nothing.
`php -l` reads the PHP and says NOTHING about the JavaScript inside it, which
on this page is most of what there is — so the lint passed, every check
passed, and the page was broken. The script blocks are now handed to a real
JavaScript parser in `test/doors.py`, with a count of the braces as the
fallback where there is no such parser on the machine. It was proved against
the same brace.

**The daemon.** `isemon --status` took half a minute to answer. Nothing was
slow: a domain controller writes tens of thousands of lines an hour and every
one of them was a transaction of its own — a lock taken and let go, a
round trip and a commit, thirty thousand times an hour — and anything
else that wanted to write, a person at the command line included, queued
behind a stream that never stopped. A pass over the logs is now ONE write in
chunks rather than one write per line: reading this site's 118,309 events
into PostgreSQL went from **86 seconds to 24**, and the write lock is taken a
hundred and twenty times instead of a hundred and eighteen thousand. The page
itself was never the slow part and is not changed: the whole Domain page is
0.34 s over those events.

1.10.49

**A controller named in the settings was never a controller.**

The fault that made 1.10.47's whole point not work: the list of controllers
was read through `same_address()`, which is a NORMALISER and not a test —
handed a name it hands the name straight back. So every controller anybody
typed was taken for an address, not one of them was added to the list, the
setting looked filled in, the page went on crying wolf about two domain
controllers talking to each other, and nothing anywhere said why. On this
site's own logs: **2 442 replication alarms before, 24 after**. A check for it
is in `test/domain.py`, and it is a check that a normaliser is not a test.

### The alarm carries the answer

*"147 refusals against pdf"* is a fact somebody then has to go and work on.
The same alarm now reads:

> **147 refusal(s) against pdf, 120 of them from PVEXC05**
> 5 tries every five minutes, to the second
> → PVEXC05 is a SERVER, not a desk: 5 different accounts sign in through
> it. The old password is almost certainly NOT on it — it is signing in on
> behalf of whatever is talking to it, and Windows writes down its address
> rather than the real one.

### The rest of it

* **A list setting is a list**: one row per entry, a bin beside each and a
  button underneath, for the controllers, the log folders of every module and
  the device lists. A line reading three paths separated by commas in a box
  eighty pixels wide was a list nobody could read, edit or count. Empty rows
  are dropped rather than saved as an entry called "".
* **Filters that cannot narrow anything are put away and cleared.** "Every
  country" over a list of MAB refusals filters an address no machine on a
  socket has; "both nodes" over the token logs names the wrong pair of
  servers; "every device" over a token attempt is a network device that was
  never in it. Each door says which filters it has and what the ones it keeps
  are called — *every switch*, *every controller*, *every token server*.
  A filter being put away is also cleared, because a hidden filter that is
  still set is a list quietly narrowed by something nobody can see.
* **No page ever has two scrollbars.** A card measures where it sits on the
  PAGE rather than in the window — measured while scrolled down, the top
  of the card is a small number, the room comes out too big, the page grows a
  scrollbar and scrolling makes the next measurement worse. Whatever overflow
  is left is then measured after the fact and taken off the card, which is the
  only thing on the page that can give the room back.
* **The machinery is left out of every card, not only of the alarms.** "What
  was changed" was still counting *the directory's own replication rights,
  12,887* — two controllers talking to each other, which is what a domain
  does all day. What is marked as machinery is now left out of every card,
  every count of things worth looking at and every pattern, in one place so
  that a new kind of machinery is left out of all of them at once. It stays
  in the events themselves, whole and searchable.
* **A switch for a domain that rebuilds its desktops every day.** Horizon
  instant clones and their like rebuild thousands of computer accounts a day,
  and every one is an account created, an account changed and a directory
  object written — the machinery running, and on a page of things worth
  looking at the only thing anybody can see. Switched on, events of THAT
  SHAPE become machinery. The shape is narrow in two directions at once: the
  thing doing it must be a MACHINE account, and the thing done must be a
  COMPUTER or a machine's own connection point. A person doing any of it is
  drawn. A machine account writing a USER or a GROUP is drawn. The audit log
  being cleared is drawn. On this site's own logs it takes 8,159 events off
  the cards and not one of them was done by a person. It hides the noise, not
  the threats — and there are checks for each half of that sentence.
* **The Domain page has no row of tiles either.** "In no tab" was said once
  and asked about twice; it is the same answer here as it was on the doors.
  The four numbers are one line under the window picker, each still opening
  the events it stands for.
* **The reading is on the card, not only in the popup behind it.** A card
  that says "pdf, 120" and makes somebody open a popup to find out whether
  that is a person or a program has not answered anything, so the row now
  carries the short of it and the hover the whole of it.
* **The access lists moved into a popup** behind a button on the logins,
  which is what let that page's card take the window like the others.
* **One scrollbar, told rather than measured.** While a card is holding,
  everything above it is chrome that stays put and the card's own table is
  the one thing with anywhere to go, so the page is told not to scroll.
  Measuring the overflow was right to within a pixel or two, and a pixel or
  two is a scrollbar down the whole window.
* **A filter offers what is behind its own door.** The lists of devices,
  servers and countries were distinct over the whole table, so the filter
  over the token attempts offered sixty switches that were never in one and
  picking any of them emptied the list. A choice made behind the last door
  is cleared when the door changes, for the same reason.
* **Two more things worth looking at**, out of the new logs: a burst of "who
  is in this group" from one program, which is what drawing a map of a domain
  looks like before anybody uses it; and one account's password used to reach
  another machine. Both have a floor under them, because one of either is a
  backup agent doing its job.
* **The line under the door strip stopped vanishing.** It holds the words AND
  the counts AND what they open, and the tab strip was rewriting it with the
  words alone on every refresh — invisible while the card underneath
  redrew every few seconds and put them back, and a line that disappears a
  moment after every load as soon as it does not.
* **A card that has not changed is not drawn again.** The live update asks
  every few seconds and most of the time the answer is the one already on the
  page; clearing a card and building the same card back is, on a page
  somebody has scrolled down, a visible flicker every few seconds. The answer
  is compared with the one drawn, and holding the box at its old height while
  it swapped — which made it worse, because the release was the jump —
  is gone: the scroll position is what has to stay still, so that is what is
  put back.
* **Less chrome, more rows.** The header, the tabs and everything above a
  table are tighter, and on a card whose rows scroll the explanation is cut to
  two lines with the rest one press away — the press being the paragraph
  itself.

1.10.47

**The page says what it means, not only what happened.**

A card full of refusals still leaves somebody standing in front of it working
out two things nothing in Windows says: whether a person is typing a password
wrong or a program is holding an old one, and then which machine to walk to.
Both are in the data. Neither is in any single event. So they are worked out
and written in words, on every row of *What keeps trying an old password* and
in every account's popup.

**Is it a person or a program?** A person retries when they notice; a program
retries on a clock. The clock is in the timestamps and nowhere else — so
the times are folded onto each beat a program might be set to and asked
whether they land in the same place every round. On this site's own logs that
reads: *"five tries every five minutes, to the second"*. Nobody types a
password on a clock. It is measured by phase rather than by gaps, because a
client that tries five times and then waits has gaps of five different lengths
and one period.

**Which machine, and is the password even on it?** A refusal from a
workstation means the password is on that workstation. A refusal from a
SERVER usually does not: the server is signing in on behalf of whatever is
talking to *it*, and Windows writes down the server's address. The difference
is countable — a server is a machine many different accounts pass through
— and a controller is known outright. So the card now ends with a sentence
like *"PVEXC05 is a SERVER, not a desk … go to it and ask who is using this
account: its own access log, its sessions, its scheduled tasks. That is where
the address of the real device is."*

### The rest of it

* **The controllers are a list**, one a line with a button to add one, and the
  short name is enough: `dc01`, `DC01$`, `DC01.example.com` and
  `EXAMPLE\DC01$` are understood as one machine, and an address on its own is
  looked up here.
* **A button that reads every stored event again** with the settings as they
  stand — under *Settings → The domain controllers* and on the Domain
  page. It happens on its own when those settings are saved; this is for
  watching it happen, because a controller named at four o'clock and a page
  that says the same thing at five past is a page nobody trusts.
* **One search box, one pager, one scrollbar.** The long lists — failed
  attempts, logins, the ban history, the events, the domain's own — are as
  tall as the window with their head and their pager fixed, and the rows move
  inside them. A card may only take the whole window where it is alone on its
  page: the logins have the access lists below them, and a card capped to the
  window there would put them below the fold for ever behind a second
  scrollbar. The Active Directory tab under Failed attempts draws into that
  page's own table rather than bringing a second search box and a second
  pager with it.
* The Active Directory tab is on the refusals and not on the logins, where it
  had nothing of its own to draw.

1.10.46

**The directory doing its own work is not an alarm; what holds the old
password now has a name.**

### The controllers, and what is normal for them

`Settings → The domain controllers` has two new fields. **The controllers
themselves** names the machines that ARE the directory; **accounts that are
meant to read the directory whole** names the rest — Entra Connect signs in
as `MSOL_` and a hex tail and replicates every password by design, and ships in
that field out of the box.

It matters because of one alarm in particular. The three rights behind *"an
account asked to replicate the directory"* are how every password in a domain
is read at once: worth waking somebody for from a member server, and simply
what two controllers do all day. On this site's own logs that alarm said
**7 871**, every one of them a controller or the synchroniser. It now says
**49**, and they are all one account that is neither. Nothing is hidden: the
events are read, kept, counted and searchable exactly as before, the record
still says what it was, and the one thing that does not happen is somebody
being told that two domain controllers talked to each other.

Left empty, the controllers are worked out rather than asked for — the
servers these logs come from, the directory servers this signs in against, and
the machines the domain itself says are its controllers, which a directory is
asked once a day. Name one later and the events already stored are read again
by the new answer rather than keeping the old one for ever.

Two alarms changed shape with it: pressing one now opens exactly the events it
counted rather than every event of that shape, and the four that mean
*somebody is taking this domain* count machine accounts whatever the page has
been told — a member server asking to replicate IS a machine account, and
the tick box that hides the noise of ticket renewals was never meant to hide
an alarm.

### What is holding the old password

The question a lockout actually leaves behind. No single Windows event answers
it: the refusal says which machine and which address, and the
explicit-credential event beside it says which program on that machine went
and used the password. They are now counted together — one row per machine
and program, with what the domain kept answering — on every lockout, in
every account's popup, and in a card of its own on the Domain page.

And where Windows wrote an address and no name at all, which is every Kerberos
refusal, the database answers its own question: a server signs in as itself, so
the machine account seen at that address names it. On this site that turned
*"172.29.153.5 got the password wrong 120 times"* into **PVEXC05** — the
Exchange server, which is the commonest lockout there is. The row says when a
name was worked out rather than written down.

### The rest of it

* **The Domain page is two pages**: the overview, and the events themselves,
  with the strip between them pinned to the top of the window. The list is
  only asked for while it is being looked at.
* **A Domain card on the front page**, beside the other doors, whenever the
  controllers' logs are read: what is worth looking at, who was locked out and
  from where, and who the domain turned away.
* **An Active Directory tab under Failed attempts**, for the same reason: that
  is the page somebody is on when the question occurs to them. Never counted
  into anything there — a sign-in checked against the directory is one
  attempt and it is already counted at the door it came through.
* **Keep the events for: 0 means keep them all.** A number that cannot be
  nought is a setting that says no to the one person who needs a year of the
  domain in here.
* Every table on the page lights the row under the pointer, the strip of event
  groups says which of them is chosen, a domain controller's log is called a
  domain controller's log rather than *"the VPN logins and the TACACS
  sign-ins"*, and the field dump no longer puts one letter of *"Security ID"*
  on each of eleven lines.
* **The panels follow the pointer.** A row that says a dozen things about
  itself is a panel the size of a card, and anchored to the row it landed on
  the header, the row, or the card next door. Next to the pointer is where
  every tooltip anybody has used appears. Cards redrawn by the live update
  hold their height while they change, so the column no longer jumps every few
  seconds.

1.10.45

**One thing pointed at is one panel.**

A row of a door card says everything about itself on hover — who, which
machine, which socket, which switch, what the server answered. The hardware
address written in that row opened a SECOND panel saying who made the machine,
and the two of them raced each other for the same corner of the screen. The
maker is now a LINE of the panel that is already there: a bit of text inside
something that explains itself joins in rather than talking over it, wherever
on this page that happens.

And a panel of a dozen lines is half the height of the window, so under the
row it ran off the bottom and over the row it landed on the header, the tabs
and the row itself. A tall one now goes BESIDE the row, level with it, where
there is room — and nothing is covered at all. Small panels are exactly where
they have always been.

1.10.44

**The domain controllers' settings had nowhere to be drawn.**

A settings pane on this page is three things in three places: a button on the
rail, a panel for the rail to show, and a box inside it for the fields. 1.10.43
shipped the first and the third and not the second — so pressing **The domain
controllers** hid every other pane, found none of its own to show, and left a
page with nothing on it but the two buttons at the top. The feature underneath
was whole and the daemon had every setting; there was simply no panel. It is
there now, with what the page says about the thing before the fields: that the
logs are read the way the ISE logs are, that a **Domain** tab appears when they
are, that nothing read there is ever judged, and where the NXLog configuration
that ships them is.

The check that would have caught it is in `test/doors.py`: every button on the
rail must have a panel, every group of settings a box, no panel may be there
that nothing opens, and every setting the panes name must be one the daemon
really keeps. None of the other suites could see this — they ask the daemon,
and the daemon was right.

1.10.43

**What the domain controllers saw, and doors that answer something.**

The four tiles a door used to draw across the top of itself are gone: the four
along the top of the page are about the whole installation, and four more
saying the same four things about one door pushed the cards that answer
something below the fold. What was worth keeping out of them — how many, both
ways, and when the last one was — is on the one line under the door strip, and
pressing either count still opens the records it stands for.

### The domain

Half of what a VPN refusal means is written on a Windows domain controller and
nowhere else. "The VPN refused them four times" and "the domain locked the
account at 08:12, from NB-NOVAK, through Outlook, because the password saved
there is the old one" are the same morning, and only one of them is in an ISE
log. This version reads the other one.

Switch it on under **Settings → The domain controllers**, point it at the
folders rsyslog files them into — one per controller, all of them read into one
timeline the way both ISE nodes are — and a **Domain** page appears. Off, it
changes nothing anywhere, and the tab is not drawn at all.

* **Nothing here is ever judged and nothing here can earn anybody a ban.** A
  VPN sign-in checked against Active Directory is ONE attempt; the ISE record
  and the domain’s own event are two views of it, and counting both would
  double every person on every page. The events live in a table of their own,
  are never a row in the refusals or the sign-ins, and the chart on the front
  page does not know they exist.
* **The lockouts, with what led to them.** A lockout says only that it
  happened. The answer everybody actually wants — which machine, which program,
  which password — is in the refusals in the half hour before it, so they are
  fetched with it and the machine and the program are lifted onto the row even
  where the lock itself did not say.
* **Patterns worth looking at**, counted rather than guessed: the audit log
  being cleared, an account asking to replicate the directory (which is how a
  domain is taken whole), somebody put into a group that runs the domain, one
  machine failing against many accounts, one account failing over and over,
  lockouts several at a time, service tickets asked for in RC4, tickets asked
  for with no pre-authentication, passwords sent in the clear, anonymous
  sign-ins, and things still trying accounts that are switched off. Each one
  says what it is, how serious it is and why it might be nothing, and opens the
  events it is made of.
* **The events themselves are a page like the others** — the same filters, the
  same server-side paging, tabs across the top for the groups of events, and a
  row that opens the whole record: every field Windows wrote, what else
  happened to that account either side of it, and a button that asks the
  directory who the account belongs to.
* **Two directories are two directories.** A Windows event carries its domain
  in the short form (`EXAMPLE`) where the directory calls itself
  `example.int`, so the two are joined and the right one of the two
  connectors is asked. Where the domain is neither, both are asked, which is
  what this program does everywhere else. Read only, always.
* Machine accounts are **counted apart rather than hidden**: on a domain
  controller nine events in ten are one machine renewing a ticket, and a page
  of those is a page about nothing. They are always read, always searchable,
  and one tick box away.
* The reading is worth a paragraph of its own. NXLog flattens a Windows event
  onto one syslog line, so the only thing between one field and the next is a
  run of spaces — and a value may hold spaces, colons and the name of the next
  field. `Source Workstation: DC01 Error Code: 0x0` is two fields to a
  person and one long name to anything that guesses, so the fields are found by
  NAME out of the Windows vocabulary rather than by cutting on whitespace. The
  paragraph of explanation Windows puts at the end of every event is cut before
  the fields are read. An event’s id is made from the LINE, so the same
  file read again — after a rotation, a restart, or the pass back over every
  log — writes nothing; and because the id is the line rather than this
  program’s reading of it, a better reading later changes the rows that are
  there instead of writing them all again beside themselves.

`docs/nxlog.conf` and `docs/windows-security-log.md`, added in 1.10.42, are how
the logs get here in the first place.

### The doors, rebuilt

The doors added in 1.10.42 answered nothing. A list of sockets saying
"GigabitEthernet1/0/41 — 1,152" does not say which machine that was, what it
wanted or why it did not get it, and every one of those is on the same row in
the database. Four lists of disconnected columns have become cards whose rows
are **subjects**:

* **802.1X / MAB**: one row is one machine — its hardware address with the
  maker’s name over it, or the name its supplicant gave; where it is
  plugged in or which radio it is on; and why it was refused. Beside it, the
  switches and ports it is stuck on, by how many different machines each is
  turning away. **Only machines that never got on are on this card**, and that
  is the whole point of it: on a real network every PC offers its hardware
  address first, is refused because that address is in no register, and
  authenticates with its certificate a second later — so most of a day’s MAB
  refusals are the ordinary morning of machines that are perfectly fine, and a
  card that counts them is a card of noise. A machine is drawn only if nothing
  anywhere in the window let it on, which leaves the phones, cameras, door
  stations and printers that really do live by MAB and really are not getting
  in. The line under the strip says how many machines were refused, how many of
  those sorted themselves out, and how many attempts that was in total, so the
  number that was taken away is still visible rather than quietly missing.
* **TACACS+**: one row is one person, with how many devices they have been on
  and the last one; and the devices themselves, by how many people.
* **One-time passwords** and **eduroam**: one row is one account, with what the
  server last said to it, from where, and both sides of the count.

Every row now carries its own detail: point at one and it says everything known
about the newest attempt — the person, the machine, the socket, the radio, the
switch, the program, the words the server answered with. Press one and it opens
the records themselves, searchable and paged, with a button on to the page that
holds all of them. Pressing a row of the 802.1X card used to open a popup of
everything on the site, because a door that stands for four kinds at once was
not a filter the records knew: it is now, and a hardware address is searchable
on that door as well.

1.10.42

**Every door gets its own front page.** This page has always been about the
VPN, because the VPN is the only thing that is ever banned — and everything
else this daemon reads went into one chart and nowhere else. A site with a
token server and a visitors’ network has two whole systems in here whose
shape nobody could see: which institutions are arriving, which access points,
what the token server keeps saying no to, which switch has been refusing
machines all morning. Same rows, same window, a question that could not be
asked.

Under the chart there is now a row of doors, and each one has its own cards:

* **VPN · ISE** is where the page opens and is exactly what it was — the
  busiest addresses, the names being tried, where they come from, the logs
  being read. Nothing about the door that earns bans has moved.
* **TACACS+** and **802.1X / MAB** are offered whenever the ISE logs are being
  read, because they are ISE’s own doors and have no switch of their own.
* **One-time passwords** and **eduroam** are offered when those modules are
  switched on — whether or not anything came through them today, because a
  quiet night at a door is an answer and a tab that comes and goes with the
  hours is a tab nobody can rely on.

Each door is counted by what matters behind it rather than by what matters at
the VPN: institutions and networks and access points for eduroam, accounts and
what the token server said for the tokens, switches and sockets and hardware
addresses for the network, who signs in to the kit for TACACS+. Every card is
pressable the same way the VPN cards always were — a row opens what it is
counting, listed, searchable and paged, with a button on to the page that
holds all of it. A column no record on this site fills is not drawn at all,
so a door shows what it has rather than a wall of empty cards.

It is one answer from the daemon (`/api/door`), kept for a few seconds the way
the front page is, and it follows the window chosen above the chart and the
live updates like everything else. The columns each door counts are named in
the daemon, not asked for by the page, because a column name is written into a
statement.

Also: the long explanation behind the **Authentications** card is about a
third of its former length and says the same things; and the NXLog
configuration for shipping a Windows domain controller’s Security log to
the same rsyslog is now in the package, as `docs/nxlog.conf`, with
[docs/windows-security-log.md](docs/windows-security-log.md) beside it —
what it does, the two defines to change, why event 4662 is most of the volume
and why a long event over UDP can vanish without trace.

1.10.41

**The hunt continued, and it was the right thing to keep doing.** Fifteen more
faults, found by taking the two extreme bugs of 1.10.37 and 1.10.39 as lenses
and pointing them at everything: *what else stops the banning without a word,
and what else does the wrong thing to a whole batch?* Every one below was
reproduced before it was fixed and has a check in the suites that fails without
the fix. Two of them would have emptied the counting of an entire site.

*Things that stopped the banning, silently.*

* **A re-sort could take every VPN refusal out of the counting.** On the first
  start after an upgrade the whole `failed` table is put through the current
  rule for working out which door each refusal knocked on. That rule reads the
  ISE record kept beside the row — and where the record would not decode it got
  an empty one and wrote down the answer anyway: `other`, which is the one door
  counted by *nothing*. Not the bans, not the counting, not the safety net that
  judges what was missed. Two ordinary things got there: a record longer than
  the column, which was cut with a slice and so stopped being JSON at all; and
  a record packed against a compression dictionary the database no longer has.
  Either one, and every refusal it touched became invisible to the banning, in
  one pass, for good — reported in a line that reads like a success. A record
  that cannot be read now keeps the door it had, is counted, and is said out
  loud as unread; the sorting is not marked done, so it is put right when the
  record can be read again. And a record too long to keep is now shortened by
  dropping its longest fields rather than by cutting the middle out of its
  JSON, so it stays readable.
* **A setting nobody could read became something else, quietly.** A number
  written as `"three"`, or arriving as `null` or empty, was replaced by the
  built-in value and the save reported as having worked: a site running
  `block_tries=3` silently ran on 5, `block_window_min=1440` collapsed to 10,
  `block_lots=20` became 0 which switches that rule off, `judge_max_age_h=0`
  became 24. Worse on the filters: `watch_devices: null` became the *string*
  `"None"` and `watch_devices: ["ftd1"]` became `"['ftd1']"` — a list of
  devices matching nothing, which turns every VPN refusal away from the
  judging and bans nobody. That is the same shape as the fault that stopped a
  site banning at midnight. Nothing is substituted now: a value that cannot be
  read is refused with the reason in words, and one already in a file is left
  at what it was with the key named on stderr and on the page.
* **A device list typed one per line was one device with a newline in it.**
  The box invites a name a line and the splitter cut only on commas and
  semicolons. A newline now means the same as a comma, and a name with
  whitespace still in it is refused rather than kept as a name nothing has.
* **Nothing said when the watch list matched nothing.** A filter that names
  nothing real looks exactly like a filter that is off — every page full of
  refusals, every count right, the light green, and nothing ever banned. The
  page now asks the question out loud: of the refusals of the last day, did any
  come from a device this list names? None, on a site where refusals are
  arriving, is drawn as a warning with the names there really are.
* **A clock could stop all judging, and only the token logs were ever
  checked.** Nothing older than `judge_max_age_h` is judged, which is right.
  But the check that notices a log whose times make no sense was only ever
  asked about the logs that carry no zone — so an ISE node with the wrong date,
  or this machine's clock stepping after a snapshot restore, made every arriving
  record too old to judge while everything else looked perfect. Every log is
  checked now, with the advice a record that carries its own zone actually
  needs, and the records the age gate turns away are counted, drawn on the page
  and said out loud once an hour.
* **One thread that would not start stopped the firewall for ever.** The flag
  that says "a sync is already coming" is cleared by the sync thread's own
  exit. A thread that never started — one `RuntimeError` on a machine briefly
  out of them — left it set for the life of the process, and every later change
  including the once-a-minute catch-up turned round at the door. Bans went on
  being recorded correctly and nothing on the network ever refused them again.
* **The header pill was green while nothing was being done.** It was worked out
  in the browser from four of the twenty facts the daemon reports, so it said
  "watching", in green, while the database was refusing every write, while a log
  was there but unreadable, while no ISE log was configured at all, while the
  logs had produced not one record, and while every record arriving was too old
  to judge. Each of those was already in the answer and nothing looked at it.
  There is one verdict now, worked out in the daemon out of all of it, and the
  page draws only that. Whether writes are working is newly tracked, because
  nothing tracked it: a database that opened and then started refusing writes
  left the daemon reading, judging and throwing every row away.

*Things that did the wrong thing to a whole batch.*

* **`mend()` could throw away every index it had just made.** The schema
  repairs shared one transaction with a `try` around each statement, which reads
  as "whatever fails, the rest still happens". On PostgreSQL it is the
  opposite: one failed statement poisons the transaction, everything after it is
  refused, and the commit at the end acts as a rollback — so the fourteen
  indexes that *had* worked were discarded along with the one that did not. One
  row too long for one index and a site came up with none of its twenty-three
  performance indexes, every page walking whole tables, and one line in the log
  to say so. Each repair is its own transaction now, and what could not be done
  is counted and named at the end.
* **A nested write committed the outer one halfway.** The write lock is
  reentrant, so a second `db_write` reached from inside the first was let
  straight through and its exit committed the transaction around it. Everything
  written before it was committed halfway; everything after was on a connection
  back in autocommit; and a failure then rolled back nothing. Where that bit was
  the country-range tidy-up: it emptied `geo_ranges`, that commit landed on its
  own, and a connection dropped during the refill left the table committed
  **empty** — with no country named again and no way back, because the flag that
  says the tidying was done is set after the block and the next start found
  nothing to tidy. Only the outermost block owns the transaction now.
* **On MariaDB, nothing was ever tidied out of the eduroam table.** The cap was
  a `LIMIT` inside an `IN`, which that engine refuses outright — and because
  both deletes shared one transaction, the refusal rolled back the fortnight
  expiry above it too. Past twenty thousand machines the table was never tidied
  at all, by age or by count, saying so in one line a day.
* **On PostgreSQL, the search boxes could not find a name in the wrong case.**
  Whether `LIKE` ignores case is the *server's* business: SQLite folds ASCII,
  MariaDB collates case-insensitively, PostgreSQL compares exactly. So the same
  search, on the same records, found a person on two engines and nothing at all
  on the third. Both sides are folded in the program now, at every box that
  looks for words, so all three answer alike — and the find box still never
  leaves its index.
* **On MariaDB, `alice` and `ALICE` were one person.** A database made by this
  program collated `utf8mb4_unicode_ci`, which folds case *and* accents, so on
  that engine alone the per-name counts, the "how many names tried from this
  address" column, `COUNT(DISTINCT)`, the country tabs and the ACL grouping were
  all wrong, and a session token authenticated with its case flipped. New
  databases are byte-comparing now, and an existing one is converted once, out
  loud, at start-up. Folding is asked for where it is wanted, which is the
  search boxes.
* **On MariaDB, a long name was truncated and a long id could lose a record.**
  Every indexed text column is `VARCHAR(191)` there, and `INSERT OR IGNORE`
  turns "data too long" into a warning nobody reads. A 199-character machine
  identity was stored as 191, and then every page that looked it up by the name
  the log carried found nothing — the attempt recorded, the account page empty.
  Worse for the session id, which is the primary key: two ids differing only
  past character 191 became one and the second row was dropped without a word.
  Shortening is done in the program now — out loud for a value, by hashing for
  an id, so two ids can never become one — and a name is looked up the same way
  it was written down.

*Things a person at a login prompt could do.*

* **A typed name could invent the fields around it.** The token log writes
  `user=<what was typed>, mode=..., host=..., rid=...` — the typed name first,
  and the *first* value of each field was taken. So a name containing
  `, rid=<somebody else's>, host=<somebody else's address>` put its own id and
  its own address on the line ahead of the real ones: this attempt filed under
  another person's address, and joined to another person's RADIUS packet. The
  RADIUS detail log had the same hole through a quote: its splitter toggled on
  every `"` with no notion of `\"`, which FreeRADIUS writes for a quote inside
  a value. Both readers now take the *last* of each field the server writes
  about itself — everything the server writes comes after the name it was
  handed — and an escaped quote stays inside its value. (The ISE reader was
  already hardened against exactly this; these two were simply never given the
  same treatment.)
* **The id alone decided whose row a refusal was written onto.** Even honestly
  come by, an id is `<head end>:<port>` — one address for a whole site and a
  port a head end walks in order, so it is guessable. The join now requires the
  account to agree as well: an id says which conversation, the name says whose.
* **The login throttle allowed six times what it said.** The count of wrong
  passwords was read, then a quarter of a second of PBKDF2 happened, then it
  was written back — from a fresh list, so concurrent failures overwrote each
  other's counts as well as all passing the test together. Measured: thirty
  guesses per fifteen minutes where five were configured, repeatable for ever,
  against every account including the administrator's. The whole read-test-write
  is one hold of one lock now, and the attempt is written down *before* the
  password is checked. The password-change endpoint, which had no throttle at
  all, has the same one.
* **A new account's password hash was sent to the browser.** Every other answer
  about an account strips it; the one that makes an account did not, so the
  PBKDF2 hash of every account ever created from the dashboard was written into
  a reply the browser keeps. Nothing on the page ever used it.
* **A read-only account was shown the last two characters of three passwords.**
  A secret is shown back as its length and its last two letters, which is
  enough to tell "the one I set" from "something else" — to somebody who can
  set it. To somebody who may only look it is a large piece of the router's,
  the directory's and the database's passwords. They get whether one is set.
* **A cross-origin form could fire admin actions.** The rule that a write must
  be JSON is what turns one cookie flag into a rule the browser enforces —
  and `multipart/form-data`, one of the three kinds a plain form can send
  without asking permission, was allowed everywhere. Only the one endpoint that
  restores a database is multipart now.
* **A name could put markup on everybody's Banned page**, through the one
  unescaped join left in the page. The content-security policy stopped it
  becoming script; it is escaped now, like every value beside it.
* **A quadratic regular expression in the eduroam reader.** Two `\s*` either
  side of an optional group gave a run of *n* spaces *n+1* ways to be divided,
  each retrying the tail. Inside the brackets is the name somebody typed. 190
  ms became 0.1 ms.

*Two lists that could get the daemon killed.*

* **The country database and the threat feeds were read whole into memory.**
  Downloaded whole, decompressed whole — up to half a gigabyte was permitted —
  decoded whole, split into lines whole, then one Python tuple per line: about
  870 bytes a range. Three quarters of a million ranges, which is what that
  file *is*, came to 693 MB in a unit allowed 768, and the hundred megabytes
  the program's own comments say the file is were an out-of-memory kill. A
  monthly refresh that is killed is a crash loop that stops the log reading with
  it. Both are read, decompressed, parsed and written a piece at a time now,
  merged by walking a sorted index in pages rather than by sorting one list of
  everything: the same ranges to the byte, on all three engines, in 84 MB
  instead of 295 — and 3.7 million ranges, which used to die under the real
  limit, now finish in 61 MB.

*And three smaller ones.*

* **`copytruncate` skipped everything up to the old position.** The two tests
  for "this is not the file I was reading" are a changed inode and a file
  shorter than the position. That rotation style defeats both: nothing is
  moved, and a busy writer refills past the old position before the next pass.
  A fingerprint of the bytes just before the position now tells them apart.
* **Two askers could both start the same walk of a million rows**, because the
  "already working on it" flag was read in one breath and claimed in another.
  Claimed under the lock now, the way the two caches beside it already were.
* **The whitelist cache published its key before its value**, so a reader in
  that instant got the previous list — and two rebuilders interleaving could
  leave the new key on the old list, which never puts itself right. Value
  first now.

Also: a fold could break a promise about a country, because the guard in front
of it asked the whitelist and the never-block ranges but never the never-block
*countries*; an unbounded `offset` from a request reached the engine to be
refused there; `/api/macs` refused a read-only account the vendor names it
needs on every long page; and the log is closed and opened again under one hold
rather than two, so no line falls between them.

Two test-harness faults of my own were fixed as well: a block in the eduroam
suite asked a store whose database had been emptied by the next installation,
which had been failing on both server engines since 1.10.28, and the whole
suite set now passes on SQLite, MariaDB and PostgreSQL with nothing skipped.

1.10.40

**An audit for more of the same, after two bad ones in one night.** The two
faults fixed in 1.10.37 and 1.10.39 were not two unrelated accidents; each had
a shape, and a shape can be looked for. This version is what that hunt found.

*The first shape: a thing rebuilt from only some of its sources, quietly.*

* **A signal could stop the daemon dead, for good.** `log()` holds a lock
  while it writes a line; `close_log()` wants that lock. A signal handler
  runs in the middle of whatever the main thread was doing, in that same
  thread — so a signal landing while that thread was inside the lock was a
  handler waiting for a lock its own thread holds. Nothing would ever run
  again: no reading, no banning, no dashboard, and no line saying so, because
  the log is the thing that is stuck. It needed a `kill -9`. Rare, and rare
  is the worst kind: logrotate sends a HUP every night and a stop signal
  arrives at every restart. Both handlers now set a flag and return; the loop
  reopens the log and says what the handler wanted said. Measured in the
  suite, not argued: the lock is held, the handler is called, and it has to
  come back at once.
* **`--debug` was thrown away by the first reload.** The command line is a
  fourth layer over the three below it, and the only one written down
  nowhere. A run started with `--debug` to watch something went quiet at the
  first HUP or the first hand edit of `config.json`. It is now kept where the
  two functions that rebuild the settings both lay it back over, rather than
  set once by whoever remembered.
* **A restored database kept the old machine's settings.** Restoring replaces
  everything — including the table the saved settings live in — and the
  daemon rebuilt the tails and the bans from the new file but went on obeying
  the settings of the file that was no longer there. The Settings page showed
  one set and the daemon another. It now adopts the restored settings first,
  because the two things below it read them: the tails come out of the
  folders the settings name, and the bans are pushed to the router they name.
* **A carried never-banned list left the bans it spares standing.** Adding an
  address on the page lets out whatever is banned inside it, at the same
  moment; carrying a configuration to another machine wrote the rows and
  stopped there. A list saying "never" beside a rule on the firewall saying
  otherwise is two answers to one question. The import now does both halves
  and says how many it let back in.
* **Shortening how often names are looked up did nothing for a day.** Every
  address already asked about carries "ask again at", worked out from the
  interval as it was then. Somebody who found the names stale and shortened
  the interval went on waiting the old one out while the page showed the new
  number. A change to any of those settings now clears those deadlines.

*The second shape: a batch that answers per item, where the answer depends on
which other items were in the batch.*

* **A refusal could be written onto the wrong person's sign-in.** This is the
  same fault as 1.10.39's, in the writing direction, and it is worse because
  it writes. A sign-in the token server accepted and the RADIUS server then
  refused is moved into the refusals with the RADIUS server's words on it,
  and the attempt it belongs to is found by the id both logs carry. That
  lookup took *the newest attempt with that id, over all time, with no window
  at all*. On a site where the id repeats — a head end walking its source
  ports, or a token server passing on the NAS rather than the client — that
  is whoever signed in last. Their good sign-in was moved into the refusals
  wearing somebody else's reason, and the person actually refused was left
  standing as a success, which is the one lie the whole thing exists to
  stop. It now takes the nearest attempt carrying that id, inside a window.

Everything else the audit turned up is written down and is not this: the
full read of every function that answers per item from a batch found no
other instance, and that list — the safe ones, by line number — was checked
rather than assumed.

1.10.39

**A page of token sign-ins was wearing one person's address.** On the Logins
page, under OTP, every row showed the same address, the same machine, the
same tunnel group and the same box that asked — whoever had signed in last.
The popup behind a row showed the right one, so the two disagreed about the
same record, which is how it was found.

The join between a token line and the RADIUS packet that caused it is made by
an id both logs carry, where a site's token server passes one on. An id says
*which conversation*; it does not say which packet, because a pair of address
and port is reused all day — a head end walks its source ports and comes back
round, and a token server that passes on the NAS rather than the client
writes one id on every line it ever writes. The matching kept, per id, the
newest packet *in the window it had asked for* — and that window is the whole
page. On a page covering a day, "the newest" is the newest on the page. One
row at a time, which is what the popup asks for, the window is that row's own
few minutes, and the answer was right.

Now the id narrows it and the clock decides, per attempt: the nearest packet
carrying that id, within fifteen minutes, and a packet handed to one attempt
is never handed to another. Nothing was ever wrong in the database — this was
only ever what the page drew.

**Looking a name up asks every directory, and says when it is in both.**
Where a site has a second directory switched on, both are asked — they were
already asked side by side, and one of the two answers was thrown away the
moment the other said yes. A name in two domains is two accounts, not one
seen twice: different groups, different passwords, and one of them can be
locked out while the other signs in perfectly well. The card now shows the
first directory's account as before, says *and in the second directory*, and
draws that account underneath with its own domain, its own marks and its own
groups. Where the record names a domain, that domain's account is the one
shown first — and the other is asked all the same, because "she is in both"
is usually the thing being looked for.

1.10.38

**The access list for a Cisco router is now yours to write.** Both families,
the name and the ending, under *Settings → Reaching the firewall*.

Everything above the ending is this machine's and always was: one deny line
per address that is banned for good, made afresh at the moment somebody asks
for the file. What follows them used to be two lines written into the source
— `deny udp any any eq snmp`, `permit ip any any` — which are a reasonable
guess at what a list ends with and are nobody's actual list.

Now there are four settings. A name for the IPv4 list and a name for the
IPv6 one, because on a router those are two different access lists and one
pasted over the other is an afternoon nobody wants. And an ending for each:
a box, not a line, holding as many lines as your own list needs, in the order
they are to be pasted. Anything an access list body may hold — `remark`,
`permit`, `deny`, a sequence number in front, a `!` comment — goes in it.

**Every line is read before it is saved.** A router that meets a line it will
not take stops there: half the list on it, the rest refused, at a console,
usually at the worst possible moment. So the daemon reads it first and says
which line and why —

```
line 2: permt ip any any — "permt" is not how a line of an access list
        starts - it is permit, deny, remark or evaluate
line 3: permit ip 10.0.0.0 any — "any" is not a wildcard mask
line 5: permit ipv6 any any — "ipv6" is the other family's word, an IPv4
        list says "ip"
```

It is the same reading in all three places it can happen: as you type on the
settings page, when the page saves, and behind `isemon --set`. What it checks
is the shape every line of an access list has — what it starts with, the
protocol, the source and the destination — and it lets through whatever
follows the two addresses, because the options there differ from one IOS
release to the next and none of them is this program's business.

Under the box, as you type, is the ending as it will actually be written,
with the line that opens the list above it. The *Firewall* page's own button
shows the whole thing, and says how many lines at the bottom of it are yours.

An ending left empty is not an access list that stops everything: the two
lines this ships with are used instead. An access list ends with an implicit
deny, and that is the one mistake here that cannot be allowed to be silent.

1.10.37

**Every night at midnight, this went back to factory settings.** Install this
one. It is one fault and it has been there for a long time.

logrotate sends the daemon a HUP when it moves the log out from under it —
that is what the `postrotate` line in `/etc/logrotate.d/isemon` is for, and it
is right. The handler for that signal reopened the log and *also* read
`config.json` again. Reading the config file makes `CONFIG` afresh out of the
two bottom layers, the built-in defaults and the file; the third layer —
everything anybody has ever saved on the dashboard, which lives in the
database — was not laid back over it. Nothing said so. The log line even
claimed the settings had been read again, and two of the three had.

So from 00:00:01 until the next restart, a machine ran on the defaults for
every setting saved on the dashboard: the token logs off, the RADIUS log
beside them off, eduroam off, the names of addresses off, the ISE folders
back to the two this ships with. And `retain_failed_days` and
`retain_passed_days` back to **90 days**, with the housekeeping five minutes
behind them — so a site that keeps its records for ever spent the night with
a daemon that did not, and deleting.

The records themselves were never in doubt: what is read out of a log is
written to the database and read back from there, and none of that changed.
What was lost was the settings that say which logs to read.

The signal handler now does what a signal handler may do and no more: it
reopens the log and asks. The daemon's own loop reads the config file and
lays the saved settings back over it a few seconds later — the same path an
edited `config.json` and an `isemon --set` already went through, which had
been right all along. A handler is also the wrong place to touch the
database: it runs in the middle of whatever the main thread was doing, which
is regularly a statement half-built on the very connection the settings would
have to be read from.

Checked with a real daemon and a real signal, not only in the unit tests: the
suite starts one, saves four settings on it, sends it a HUP and reads back
what it is running on.

**If you are on 1.10.36 or older and cannot install this yet**, a
`systemctl restart isemon` puts the settings back — they are in the database
and were never gone — and commenting the `systemctl kill -s HUP` line out of
`/etc/logrotate.d/isemon` stops it happening tonight. The cost of doing that
is that the daemon's own log keeps writing into the rotated file for a day.

1.10.36

**Three things 1.10.35 broke or left half-said, all on the page.**

* **The gaps between the cards were gone, and so was every other inline
  style on the page.** The Content-Security-Policy added in 1.10.35 named a
  nonce for styles. A `style="..."` written into the markup cannot carry a
  nonce — there is nowhere to put one on an attribute — and naming a nonce
  for styles switches `unsafe-inline` off for the attributes as well as for
  the tags. This page lays itself out with seventy of them, and a browser
  was refusing all seventy: the spacing between the cards, the widths of the
  bars, everything, silently, with nothing on the page saying why. The policy
  now says the two separately: `style-src-elem` still demands the nonce, so an
  injected stylesheet is still refused, and the attributes are allowed. A
  browser too old to know `style-src-elem` allows both, which is where the
  page stood before any of this — and never a page with no styling at all.
* **A column of pills did not line up with its own heading.** A pill is
  pulled back by its own padding where it starts a cell, so the word under a
  heading starts where the heading does. That was written as "where the pill
  is the only thing in the cell", so every row that happens to have a second
  pill beside the first — an account that is the directory's is `full admin`
  and `from AD` — sat seven pixels to the right of the rows that have one. The
  rule is now about the first pill in the cell, whatever follows it.
* **An address with no reverse name said nothing at all.** The popup showed
  the row's own words and stopped, which looks exactly like an address nobody
  has got round to asking about — and on a page of foreign scanners, which
  mostly have no reverse record, that reads as the whole feature being
  broken. It now says so: *the reverse zone has no name for this address*,
  with what that means. An address that genuinely has not been asked about
  yet still says nothing, because there is nothing yet to say.

1.10.35

**A pass over the whole of it, for faults and for speed.** Nothing here is a
new feature. Every line of the daemon and of the page was read looking for two
things - something that is wrong, and something that is slow - and this is
what was found. All of it is measured against a test database of 1.8 million
refused attempts, which is about a year of a busy site.

*What was wrong.*

* **A blank password was accepted.** Setting a password anywhere other than
  the form that asks for one - the command line, the import of a carried
  configuration - went straight to the store, and the store took whatever it
  was given. An empty string hashes like any other string, and the account it
  made signed in to everything with nothing typed at all. Eight characters is
  now the floor wherever a password is set.
* **The debug switch wrote the secrets to a file.** With it on, every
  statement was written to the log with the values it was given - which for
  the four tables that hold the secrets meant session tokens, password
  hashes, the router's private key and the passwords this machine signs in to
  other things with, in a file kept for as long as anybody keeps logs. Those
  four tables now say how many values a statement had and not what they were.
* **The sign-in page told anybody the database account.** `/api/health` is
  answered before any session on purpose, so the sign-in page can explain why
  no password will work. The answer carried the database user, the server,
  the port, the name and the driver's own error text, and the page printed all
  of it to whoever loaded the URL. Signed in it is still all there, which is
  the whole of the fix when something is wrong; signed out it is now four
  empty strings.
* **The second firewall's key download handed over the first one's key.**
  `?api=mikrotik-key-download&fw=mikrotik2` dropped the `fw`, so somebody
  asking for the second router's private key was given the first router's,
  with nothing anywhere saying so.
* **A name server that refused threw away another one's answer.** Where one
  server is authoritative for a zone and refuses everything else - which is
  the ordinary way to run a pair - a real "nobody has a name for this" from
  the other was discarded, nothing was ever written down, and every unnamed
  address was asked about again every couple of minutes for ever.
* **Three faults that only MariaDB had.** `AS rows` is a reserved word there
  and the statement using it failed silently as a nought; a `LIMIT` inside an
  `IN` is not allowed, which rolled back the tidying of the names table every
  time it ran; and two columns were being truncated at 191 characters, so an
  address whose record did not fit was asked about again for ever.
* **One that only PostgreSQL had.** `SELECT DISTINCT ... ORDER BY ts` is
  refused outright there, and what that query answered was the token half of
  every address's own list: the refusals were shown, the chips above them
  counted the token attempts, and the list itself had none of them.
* **A day chart that was wrong in four time zones.** India, Nepal and South
  Australia are a half or three quarters of an hour from UTC, so a local day
  does not start on a UTC hour boundary. Everything in the first half hour of
  every day was counted on the day before, and everything in the first half
  hour of the window was dropped outright.
* **A log file with no line ending in it wedged the reader for ever.** A
  binary dropped in the folder, or two logs joined wrongly: with no newline
  in eight megabytes the reader waited for the rest of the line, read the same
  eight megabytes again a few seconds later, and never read that log again. It
  now steps over it and says so.
* **The page's own tags now carry a number that lets them run.** A
  Content-Security-Policy with a nonce, so a tag this page wrote runs and a
  tag anything else wrote does not; a cap on how big a body it will read; a
  refusal of anything that does not say it is JSON or that the browser says
  came from another site; and the one function everything on the page is
  escaped through now escapes the apostrophe as well as the quote.
* **A file off the internet is no longer unpacked without a ceiling.** The
  country list and the address feeds are fetched compressed and were unpacked
  into memory however large they turned out to be: a few hundred kilobytes of
  zeroes unpack to tens of gigabytes.
* Nine caps where there was none: how many addresses the ISE reader holds at
  once, how many pages a directory search will walk, how big a downloaded MAC
  register may be, how many kept answers and remembered names are held.

*What was slow.* Each of these is one measurement, before and after, on that
same database of 1.8 million:

| | before | after |
|---|---|---|
| everything one address has failed at | 160 ms | 3 ms |
| the whole story of one address | 386 ms | 104 ms |
| the find box, typing an address | 1,675 ms | 374 ms |
| the Banned page, on every poll | 262 ms | 14 ms |
| the countries of a year of refusals | 477 ms | 78 ms |
| the chart over a month | 972 ms | 732 ms |
| a door on the Logins page | 43 ms | 6 ms |
| a search left open, on every poll | 1,336 ms | 5 ms |

The three that matter most are not a faster query but a question asked less
often. The **Banned page** is re-drawn every time anything anywhere moves,
and on a site with hundreds of addresses out it is the most expensive answer
there is - what each one was guessing is a count over every refusal that
address ever made. It is now worked out once per change rather than once per
poll, with the bans themselves as the key rather than the clock, so a ban
made by hand is on the page at once and a poll that changed nothing costs
nothing. A **search through words** is the one question here no index can
answer - what somebody types is looked for anywhere inside half a dozen
columns - and it was being answered again every five seconds for as long as
the box had words in it; it is now worked out once and handed over for the
next few seconds, and nobody waits for it twice. The **front page over a
year** is six counts over everything there has ever been, and a bar standing
for a whole day cannot visibly move in a minute, so it is kept for one.

Underneath them, seven new indexes and a handful of statements written
differently. The indexes put the time next to the address, the name next to
the address on the sign-ins as well as on the refusals, and the country and
the door next to the time - so a page of the newest hundred from one address
is the end of a slice rather than a sort of a table, and a year of countries
is a walk of an index rather than a year of scattered reads. Several of the
statements are the same shape of mistake: `COALESCE(kind,'vpn') = 'vpn'` and
`(kind = 'vpn' OR kind IS NULL)` mean exactly the same thing to the row and
nothing like the same thing to the engine, which can seek the second and must
walk the whole table for the first.

An upgrade builds the seven indexes as it opens the database, which on a year
of a busy site is a few seconds longer to start and nothing afterwards.

1.10.34

**A way to go back and fill in the names.** The daemon learns what an
address is called when a record arrives from it and when a page carrying it
is drawn — which covers everything since the day it was switched on and
nothing at all from before. A database with a year in it is therefore mostly
addresses nobody has ever asked about, and until now the only way to fill
them in was to open enough pages.

```bash
isemon --ptr-fill              # every address in the records that has no name yet
isemon --ptr-fill --days 30    # ...seen in the last thirty days
isemon --ptr 10.20.30.40       # one address, asked of every server in turn
```

It runs as a job, so it can be watched, left alone, or started from
*Settings → Names of addresses*, where the button says how many addresses
are waiting before anybody presses it. It asks at the same few a second as
everything else — a year of a busy site is a long slow trickle rather than a
burst at somebody's name servers — and an address that turns out to have no
name is written down as having none, so the next pass has nothing to do.
Measured on the test installation: 965 addresses, one pass, and the second
pass found nothing left.

`isemon --ptr` is the other half: one address, asked of **every** server in
the list rather than stopping at the first, with what each of them said and
how long it took. It is the quickest way to find out which server holds
which zone.

1.10.33

**The name is the answer, so it is written like one.** Both of the popups
that say what something is — who made the machine behind a MAC, what a
reverse zone calls an address — had the name in the middle of a sentence,
in a block set in monospace and broken *anywhere*. That rule is right for a
session id and wrong for a company: `Apple, Inc.` came out as "Appl /
e, Inc.", and `nb0004w11.example.int` split after "example.in".

The name now has a line of its own at the top of the panel, at a size worth
looking at, and it is never broken across two lines — one too long for the
panel ends in an ellipsis instead, and the whole of it is in the popup about
that address. The sentence under it reads as a sentence: the page's own
face, broken at spaces like prose rather than mid-word like an id.

1.10.32

**Every address on the page is named now, not only the ones drawn as
addresses.** The name went over the address column and the cards; it did not
go over the half-dozen places where an address is simply text in a cell —
where a token packet came from, the box that asked the token server, the
address a machine was given, the node that answered. Those are addresses to
whoever is reading them and there was no reason for them to be the one kind
without a name. So after anything is drawn, whatever *is* an address in it
is found by looking, and asked about as at the moment of the row it sits in.
Measured on this release: 583 addresses named across the pages, where
before it was the address column alone.

Strict about what counts: a VLAN, a MAC, a version number and a port are
digits and dots and colons too, and a range — an address with a prefix on it
— is left alone, because a reverse zone has nothing to say about a whole
street. Anything that already had words of its own keeps them and gets the
name underneath rather than instead.

**And the MACs say who made the machine.** The first half of a MAC is an
assignment out of the IEEE's own registers, and those are published:
`BC-FC-E7` is Apple, `00-50-56` is VMware. With *Say who made the machine
behind a MAC* on — it ships on — the registers are fetched with the country
database and the public lists, on the same schedule and through the same
button, and pointing at any MAC anywhere says who made it. A page of MAB
refusals stops being a page of hex and becomes a page of printers, phones
and laptops.

All three registers are read, not just the first. A 24-bit block belongs to
one company outright, but 28- and 36-bit blocks are slices of a block
somebody else administers — so `8C-1F-64` is the IEEE's own registration
authority while `8C-1F-64-A2-…` is the small maker that was given a slice of
it. The longest assignment that covers an address wins, which is the only
order that names the maker rather than the landlord.

Nothing waits for any of this either, and nothing is ever judged by it. The
registers live in a table of their own, a page's worth of MACs is one
question, and an answer — including "nobody has registered this" — is
remembered until the registers are fetched again.

1.10.31

**"? earns ?"** — the window that asks before going back over every log was
offering to weigh <b>0</b> records under a rule made of two question marks.
It was not a wording problem. One line of that card wrote into a box that
had been taken out of the page months ago; that threw, the throw landed in
the card's own `catch`, and the card was left blank with the answer the
daemon had just given it thrown away. Nothing looked wrong anywhere,
because everything it broke was a blank rather than an error.

Three things came out of it. The card no longer trusts what it was told
when the pane was drawn: it asks the daemon again when the button is
pressed, so the rule and the count in that window are the rule and the
count at that moment. A box that is missing now costs that box and nothing
else. And the guard that should have existed first: every `$('...')` the
page writes into is checked against the page, and there are 221 of them.

**And it has a page of its own.** *Go back over the logs* is the one button
on this dashboard that reaches into the past and changes who is kept out,
and it was the bottom card of *Banning*. It is its own place in the rail
now, and it says up front what it would weigh by: the rule, how far back
counts, and how many records are in the database.

1.10.30

**The addresses are machines again.** Switched on under *Settings -> Names of
addresses*, every address on these pages is turned back into what the
reverse zone calls it: `nb-novak.example.loc` over `10.20.30.40`, on hover
wherever an address is shown, said outright on the card that finds things
and in the popup about one address — and, the half nothing else could do, a
machine can now be **found by the name people call it**. Nothing in any
record holds that name, so the box at the top turns `nb-novak` into the
addresses that have ever been called that and searches those; the lists
behind it do the same, so typing a machine's name into *Failed attempts*
finds its records.

**Asked of your name servers, in your order — never this machine's
resolver.** A site keeps more than one reverse zone and they are not on the
same server: the offices in the domain controllers, the DMZ somewhere else.
The servers are listed a row at a time on that page, asked in the order they
are written, and **the first one that hands over a name is the answer**. One
that does not answer, refuses, or says it has never heard of the address is
passed over rather than believed — because the next one along may be the one
holding that zone. A button on the page asks every server about one address
and shows what each of them said, which is the only way to tell a server
that holds the zone from one that has never heard of it.

**Nothing waits for it.** Not a page, not the reading of a log, not the
judging. The asking happens on threads of its own with a queue of its own; a
page is drawn from the names already known and whatever was missing appears
on the next draw. A name server that has gone away leaves a name blank and
changes nothing else. Switched off — which is how it ships — not one packet
is sent.

**And an answer is written down with its time, because a lease moves.** The
address one machine had this morning is another machine's this afternoon, so
a name is kept as a name *and the two ends of the time it had it*: a record
from March is shown the name its address had in March, not the name it has
now, and the popup about an address lists every machine it has been, newest
first. The same address asked about twice inside the hour is one question,
an address nobody has a name for is written down as having none rather than
asked about again on every page, and the whole table is tidied with the
records it belongs to.

The servers are listed a row at a time, the way the places under *The ISE
logs* and *The OTP logs* are, with the order they are asked in on the left
and a button to move one up: which server is asked first is a decision, not
a detail, and a decision belongs somewhere it can be seen and moved rather
than in the middle of a line of text. The address boxes in all three of
those editors are the width of an address now rather than the width of the
card, which also brings the button at the end of each row back beside the
row it belongs to.

It is a few dozen lines of DNS packet rather than a library, for the reason
every other dependency here was turned down for. `test/names.py` puts all of
it through `test/mockdns.py`: two servers with two different zones, a server
that never answers, one that refuses, one that has never heard of the
address, a reply cut short so it has to be asked again over TCP — and the
rule the feature lives under, checked rather than promised: reading a log
sends no packet, and switched off nothing is sent at all.

1.10.29

**The country filter still slid the page — inside a popup.** 1.10.27 taught
the panel to pick its side from where the button really is, and it measured
the window to do it. Inside a popup the window is not what is holding it: a
popup is its own scrolling box, and a panel that runs past *its* right edge
makes that box wider, so the popup slides sideways exactly the way the page
used to. Measured in a browser on the popup for a name: 1318px of popup
became 1379px and it scrolled 52px the moment the filter opened. It now
measures every box between the button and the page that clips or scrolls,
and stays inside all of them.

And the same complaint had a second cause, which the first fix would never
have touched: a browser scrolls whatever is holding a box it has just
focused, and the panel focuses its own search box the moment it opens.
Where the popup's lists are wider than the popup — which is most of them —
that alone slid it 52px. The box is focused without being scrolled to now;
the panel has already been put somewhere it can be seen.

Every country filter in the application was then opened in a real browser,
on every page and in the popups, and what moved was measured rather than
looked at: six of them, nothing moved.

**Every window of that kind now goes out to a year.** The chart, the refused
attempts and the logins: `last year` after `last month`. A year asked for in
hours would be 8,760 bars — a megabyte of counts to draw a line nobody can
make out a single bar of — so the bar widens with the window instead: five
minutes over six hours, an hour up to a month, a day over a year. A year
costs the same to draw as a month does.

A bar a day wide is a day on the clock of whoever is reading it, not a day
in UTC: the hours are folded into days here, where there is a calendar, so
a bar labelled `14-09` holds the 14th and not two hours of the 15th — and a
year with a clock change in it still has every bar starting at midnight.

1.10.28

**Typing a name into the find box now answers the question somebody was
actually asking.** Press Enter on a name and the card says, in one place:
what it looks like — a person or a machine — every door it has been seen
at with the numbers under each, where it was last seen anywhere, the
addresses it has come from, and what the directory says about the account.
Each of those is a press: a door opens that door's own records with the row
lit, an address opens the address, and `Everything about it` opens the whole
record.

It is asked on Enter rather than while somebody types. It is several
queries and a question to somebody else's directory, and it is the answer
to a question that has been finished rather than to half of one. Escape
clears what was typed first and only closes the box on the second press,
because the card is there to be read and then pressed.

**Looking a machine up says what it did on the network.** The switch, the
socket it was plugged into, the VLAN it was put into, the MAC that did it,
the address it was given and the node that decided — off both lists at
once, so a machine that is *being refused* is exactly the one that can be
looked up. Nothing in a log says whether a name is a person or a machine:
`host/PC1.example.int` and `jnovak` are both just names. The door it came
through is the sign — only a machine authenticates at a socket or on the
wireless — and the directory, asked next, has the last word, because it is
the one place the difference is written down.

**Both directories are asked, where there are two.** The card says which of
them answered, and a name in neither says *neither directory has such an
account* rather than the one-directory sentence, which is a different
statement about a person. Where both hold the name — one domain under two
names is the ordinary shape of this, not the exception — the first wins,
once, and trouble at either is said out loud rather than read as "no such
account". Nothing in any of this writes to a directory: every one of these
is a search and nothing else.

**An address's own list was missing its token half.** A token row carries
the token server's loopback, because that is who asked the token software;
the person's address is on the RADIUS packet beside it. So "everything this
address has failed at" left out every token refusal ever made from it — the
chips above that list counted them and the list below did not show them.
Both of its lists now say which door each row came through, since the rows
under one address are no longer all the same kind.

**And the filters are one row again.** The country filter is a button
rather than a select — a list of two-letter codes is a filter nobody can
use — and being a button it had a size of its own: 29px beside 40.3px, at a
lighter weight, in a row of four. It is the same box as the selects beside
it now, to the pixel, and the find box keeps its words clear of the `Ctrl K`
badge in its corner, which two rules of equal weight had been taking turns
over.

1.10.27

**Pressing a door on the OTP refusals ended in an error.** `tkey` — the
whole account, realm and all — is a column of the sign-ins and of no other
table, and 1.10.24 added it to the search for *both*. Asking `failed` for a
column it has not got is not a query that comes back wrong; it is a query
that cannot run, so **every** search of the OTP refusals failed outright.
It says which table it means now.

The guard is the one that should have been there first: every door, on
both lists, with words in the box, and with every filter on at once —
asked of SQLite, of MariaDB and of PostgreSQL, since which columns exist is
the engine's own question. It fails on the bug it was written for.

**And the rows were not sitting straight.** The height of a row in those two
lists is set by the button on the end of it, not by the words — and the
cells disagreed about where their contents sat, some at the top and some in
the middle. So the date, the name and the reason ended seven pixels above
the button beside them. Measured in a browser: `content mid=17` against a
row middle of 24. Said once on the table now instead of cell by cell, which
is how half of them came to be one way and half the other. The lists whose
rows really are several lines — the bans — keep the top, where it belongs.

1.10.26

**A certificate failure was moving somebody else's successful sign-in into
the refusals.** Found in a real log, one minute after 1.10.25 shipped. When
the handler cannot reach the token software over HTTPS there is no token
line for that attempt anywhere — so the search for one, allowed two minutes
either side, found the *next* attempt, which had worked, and relabelled it
as a failure.

Two changes, either of which alone would have stopped it:

* a refusal whose words say the token software was never reached no longer
  looks for a token line at all. There cannot be one, so anything found
  belongs to somebody else.
* and where there is no id to go by, a token line must now be within
  **three seconds** rather than two minutes. The line and the packet are
  written for the same transaction in the same second; a wider window does
  not find more of them, it finds the wrong ones.

Proved on the log it was found in: the two refused attempts become refusals
of their own, and the two that really worked stay where they belong.

**The certificate errors themselves now arrive whole.** The handler patch
cut its reply at 180 characters, and an SSL failure names the trouble at the
*end* of the line — so `…SSL3_GET_SERVER_CERTIFICATE:certi` arrived without
the words `certificate verify failed` on it. The whole line is now cut to
250, which is what one Reply-Message holds.

**And the two marks in *Why it was refused* line up.** The second one sat
beside the first and started wherever that one happened to end, so a column
of them was ragged. It has a cell of its own now — the same answer the
addresses got, for the same reason.

1.10.25

**The number was right, the person was refused, and this page called it a
successful login.** The handler in front of the token software asks it
**first** and checks the directory **afterwards** — so an account that is
not in the group the head end insists on is told `Valid token used` and
kept out anyway. Until now that attempt was listed among the sign-ins,
which is the page telling a lie about the one thing it is for. It was found
in a real log: one line saying the token was accepted, and the reply beside
it saying `account does not pass LDAP group filter(s)`.

Such an attempt is now moved to the refusals, with the RADIUS server's own
words as the reason and a green mark saying **the token was right** — so
nobody goes off to resynchronise a token that is perfectly well. The row is
marked down its edge, because it is the row most easily read wrongly.

**Every refusal that handler can make is known by name**, taken from the
handler itself rather than guessed: not in the allowed group, not an
account that may sign in at all, the directory gone away, the directory
refusing the token server's own account, and a refusal with no reason on
it.

**And the ones where the token software was never reached at all.** The
handler talks to it over HTTPS, and when that request does not arrive —
an expired certificate, a name that will not resolve, a service that is
down — there is no token line anywhere, because nothing got as far as the
thing that writes them. Those refusals existed only as a RADIUS reply and
were shown nowhere. They are rows now, saying *the token server's
certificate was refused* or *the token server could not be reached*, with
the whole of what was said kept behind them. It is the shape that matters
most: while it lasts, nobody can sign in at all.

Only a four-hundred is dropped, and only because it is the token software
answering with its own refusal — which it wrote on its own log line, where
this page already reads it.

None of it is judged, in either list: a token record has no address of the
person on it, and only the VPN is ever weighed.

1.10.24

**The doors on an address are pressable now, and they land on a row.** Each
chip's counts are what is pressed rather than the door — `2 in` opens the
sign-ins, `1 refused` opens the refusals — so there is never a question
about which of the two a press meant. It opens that page, picks that door,
fills its search box, widens the window to all of time, and **lights the row
it sent you to for four seconds**. The *Last seen* line is a press of its
own and goes to that exact record.

A row is lit by its background rather than by a shadow, because a shadow on
a table row is drawn faintly or not at all depending on the browser, and a
mark nobody can see is the same as no mark.

**The token door is searched by the account, not by the address**, because a
token row carries the token server's own loopback — that is who asks the
token software — and the address would find nothing there. It uses the name
without its realm, which is how that log writes it down; the whole account,
realm and all, is now searchable at that door too.

**The address popup carries all of it as well** — the same chips, the same
*Last seen* line, and a new section, *What the token server was asked from
it*: the RADIUS packets that carried a one-time password from that address.
Those are in neither of the lists above them and cannot be, for the reason
just given. Its `Here it has` line is counted off the doors now, so the
popup no longer says one thing at the top and another underneath.

**Ctrl-K's placeholder ran under the badge.** `.findbox input` and
`input[type=search]` are worth exactly the same to a browser, so the one
written later won and the 52 pixels that keep the words clear of the
`Ctrl K` badge were thrown away. The rule now carries the type as well,
which cannot be lost that way again.

**And then every input in the application was measured**, on every tab and
every settings pane, at five widths, against the room its padding really
leaves and against anything drawn on top of it. Four placeholders did not
fit and are shorter now — no box was widened, and the full wording was
already in the tooltip beside each one.

1.10.23

**Opening a country filter moved the whole page sideways.** The panel is
290px wide and hangs off a button that is the last thing in a toolbar,
hard against the right edge of a card. Anchored at the button's left — which
is the ordinary way to write a dropdown — it ended 290px further right than
the button started, which is off the end of the window. Nothing clipped it:
the document simply became that much wider, a horizontal scrollbar appeared,
and the page slid sideways under it. It now picks its side when it opens,
from where the button really is, and pins itself to the window on a screen
too narrow for either side.

It was measured rather than reasoned about: in a real browser the page grew
by 127 pixels. Afterwards, every country filter on every tab from 1920px
down to 420px stays inside the window and the page does not move. Every
other rule in the stylesheet that could do the same thing was checked — it
was the only one — and there is now a test that reads the stylesheet and
fails on any new panel written the same way.

**The find box (Ctrl-K) looked in one table and said it looked everywhere.**
It searched the refusals, and only the refusals. So:

* a person who has never failed at anything — nearly everybody — was not
  findable at all by the one box on the page that says it finds anything;
* and an address that signed in with a token was findable nowhere, because a
  token row carries the token server's own loopback and the person's address
  is only ever on the RADIUS packet beside it.

It now looks in the refusals, the sign-ins and those packets: the VPN,
TACACS, 802.1X and MAB, eduroam and the token server, all of it.

**Without becoming a wall of text.** Still one card per thing found. The
card gained two short lines that answer what somebody typing an address into
it is actually asking:

* a chip per door, and only the doors with something behind them —
  `VPN 1 in · 1 refused` `OTP 1 in` `eduroam 1 in` `TACACS 1 in`. Eleven
  sign-ins over a VPN, a wireless network and a token server are three facts
  about a person and one number about none of them.
* **where it was last seen, anywhere** — `Last seen 26-09 16:54 · OTP ·
  jnovak@example.cz · let in`.

The suggestion lines under it say how many records in all rather than how
many failures, and which doors, so two addresses can be told apart without
opening either. A name now opens the page it actually has something on.

1.10.22

**A token attempt's details used to sit there longer than they had any need
to, and a third of that was this program's fault.** The RADIUS packet beside
a token line always arrives after it — it goes through a file and a shipper
on a timer — but when it did arrive, nothing told the page. The packet is
deliberately not a record: counting it would count every VPN sign-in twice.
It was therefore also not a change, so the page went on showing the row it
already had until some *other* record happened to come in. On an
installation with nothing but a token server that could be an hour. It is a
change now, without being a record, and only when it really wrote something
— the same packet read twice still moves nothing.

**The other two thirds were the shipper, and the cron line says so now.**
Cron's finest interval is a minute, so a record written just after a run
waited nearly a whole one. The line shipped is now
`radacct-syslog-ship.py --every 5 --seconds 55` — one run a minute that
sweeps the minute and is gone before the next is due. Up to sixty seconds
becomes up to five.

**Which turned up a bug that had been harmless until this week.** The
shipper takes a lock so two runs can never overlap, and it never held one:
the handle was thrown away as soon as it was taken, and Python closed the
file — and released the lock — on the spot. It cost nothing while a run
lasted milliseconds. With a run that sweeps for fifty-five seconds, cron
would have started a second one on top of it every minute, both reading and
writing one set of offset files. Fixed, and the lock now demonstrably holds.

The guide has a table of where the wait actually comes from, so that "slow"
and "stopped" can be told apart without guessing.

1.10.21

**The exact join is working on a live token server, and the last thing in
its way was a name.** With the three parts in — the two configuration lines,
the handler patch and the CGI patch — one sign-in now leaves this behind:

```
totp.cgi[9499]:      Success: user=…, rid=127.0.0.1:43537, message=Valid token used
radius-detail[9512]: … Packet-Src-IP-Port = 43537, … Totp-Request-Id = "127.0.0.1:43537"
```

and isemon says *matched by the id both logs carry* — no window, no
tie-breaking, no clocks.

Getting there turned up one thing worth writing down: **FreeRADIUS uses both
spellings of the same value, in one run.** The configuration expands
`%{Packet-Src-Port}`, with no `IP` in it; the detail module writes that same
value into the log as `Packet-Src-IP-Port`. Ask for the wrong one in the
configuration and the token line reads `rid=127.0.0.1:` — an address, a
colon and nothing. The rule is: `Packet-Src-Port` when you are asking the
server, `Packet-Src-IP-Port` when you are reading its log, and isemon reads
both. Those three real lines are now a test, verbatim, so that no later
tidying can quietly break what a day was spent proving.

1.10.20

**The ISE logs can be switched off altogether.** *Settings → The ISE logs →
Read the ISE logs*, or `isemon --set ise=0`. On by default, because this
program was written around them; off is for the installation that has no ISE
at all — a token server on its own, eduroam on its own — where the ISE half
of the page is a set of doors with nothing behind them. No ISE file is
opened, the health check stops looking for logs that are not meant to be
there, and the token and eduroam readers carry on exactly as they were.

It stops the **reading** and nothing else. Everything already written down
stays where it is, is still shown, still searched and still counted. Nothing
anywhere is deleted by a switch.

**The machine's name fills itself in for the rows that already exist.** It
was in the ISE record all along — every row keeps the whole record it came
from — and was simply not in a column, so the pass that works out what each
record is now takes it out of what is already stored. On a real copy of a
live installation's logs that filled 132 of 168 VPN sign-ins; the other 36
are records that never carried one, and nothing is invented for those. It
happens once, behind the page, and re-reads no log.

**And the machine's name is plain words now**, not a mark. A mark is for
something the eye should go to first — a name somebody gave an address, a
sign-in that was refused — and a machine's own name is neither.

1.10.19

**The token server's side is a script now, and it shows its work before it
does any.** `docs/otp-radius-detail/otp-radius-setup.sh` does everything that
document describes — the detail and reply logs, the shared id, both patches,
the shipping to syslog — and it asks where the records are to be forwarded
to, because there is no sensible guess and nothing in the package has one
built in. Before it writes a single byte it prints every file it is about to
change or create and puts a copy of all of them into one `.tar.gz` **in the
folder it was started from**, not somewhere under `/etc` where a mistake in
the next ten minutes could take the copy with it; `tar -xzf … -C /` puts them
all back. That list is not written down in the script either: the raddb files
are read out of the patches, so what it shows is what it will really write on
whatever server it is run on. It is safe to run twice and on a server that is
half-way there, and it was run both ways against a real copy of a live token
server's configuration: the two came out identical.

**And it went out with somebody's address in it.** `31-forward-radacct.conf`
carried a real collector — so every site installing it would have forwarded
its RADIUS records to one particular machine that is not theirs. It says
`COLLECTOR` now and the script fills it in from the answer. There is a test
that reads every file shipped for somebody else's server and fails on any
address that is not the loopback or a documentation range, because a rule
like that must never be able to go out twice.

1.10.18

**The machine now has a column of its own, on the VPN and beside every
token attempt.** AnyConnect tells the head end what the machine is called
and ISE writes it down — `mdm-tlv=computer-name=NB-Example-2` — and it was
in the record all along, readable only by opening one. It is a column on the
VPN sign-ins, on the VPN refusals and on both OTP lists, where it comes out
of the RADIUS packet beside the token line exactly as the address does. It
is the machine's own word for itself: nothing checks it, **nothing is ever
judged on it**, and the search box on the VPN door now looks in it, so
"which sign-ins came from that laptop" is a question the page can answer.

**Every token verdict wears its own mark.** `the token was right` was said
quietly, on the grounds that a column of a hundred bright marks is all
anybody sees; but a quiet row and a row with nothing in it read the same at
a glance, and that column is the one thing a token record is about. It is
green now, beside `right, a step out of time` in blue.

**The id the two logs were to share was an address and a colon.** The
`update request` in §6.1 asked for `%{Packet-Src-IP-Port}`, and there is no
such attribute: FreeRADIUS's own internal dictionary has
`Packet-Src-IP-Address` and `Packet-Src-Port` under names that do not match
each other. The server does not complain about an attribute that is not
there — it expands it to nothing — so the token log read
`rid=127.0.0.1:, message=Valid token used`, and an id that is only the
address is no id at all, because every packet from one head end carries the
same one. The guide says `Packet-Src-Port` now, the handler patch falls back
to both spellings, and isemon reads a detail record written under either.

**And the guide says all three things out loud.** The id has to be *made*,
*passed on* and *written down*, one of the three patches or config lines
each, and leaving any out is not half of it but none of it — §6.1 opens with
a table of which is which and what a token line looks like when one is
missing. §6.2 is new: the whole page as one block of commands to paste, with
no checks in it, which refuses to take a patch that is already in for a
failure and can be pasted on a fresh server, on a half-done one, and twice.

1.10.17

**The id the two logs were to share was empty, and now it is not.** The pair
the client asked from is what makes one RADIUS packet different from every
other, and the handler was asking `rlm_perl` for it directly — but
`Packet-Src-IP-Address` is not a RADIUS attribute. The server can expand it
in its own configuration; it is not in the list a module is handed. What
came out was a token log line reading `rid=:`, which is a fact about
nothing.

So the configuration is asked to write it down where a module can read it,
in two lines that `docs/otp-radius-detail.md` §6.1 now spells out — an
internal attribute in `/etc/raddb/dictionary` and one `update request` at the
top of `authorize`. The handler reads that, falls back to the two names
directly in case a server does offer them, and **sends no id at all** when
neither yields anything: a field that says nothing is worse than a field
that is not there, because only in the second case can the reader tell "no
id" from "an id that means nothing". isemon reads the attribute out of the
detail record as well, for a site whose detail log does not carry the packet
header.

**The other half of that patch was right, and is worth saying out loud.**
The token server's own reason now reaches the RADIUS reply, proved on a live
one:

```
Reply-Message = "Denied by the token server: Not a valid token"
```

— where every refusal used to arrive as the same `ERROR: 400 BAD REQUEST`.

1.10.16

**Applying the token-server patch broke the token server, and the patch was
not what was wrong with it.** `patch` does not edit a file in place: it
writes a new one and renames it over the old, so the file that lands there
belongs to whoever ran the command — root. Apache serves that CGI through
**suexec**, and suexec refuses to run a script it does not own:

```
target uid/gid (500/500) mismatch with directory (500/500) or program (0/500)
```

What reaches the person signing in is a bare 500 with an empty body; what
reaches `cat index.cgi` is a file that looks perfectly correct, because it
is. Two hours of looking in the wrong places, and the log that had the
answer was the one nobody had opened: that CGI is a vhost of its own on
another port and writes to a log of its own, and suexec writes its refusals
somewhere else again.

`docs/otp-radius-detail.md` §6.1 now patches a **copy** and pours it back
through the original file — `cat work > index.cgi` — which leaves the inode,
its owner, its mode and its SELinux context exactly as they were; names the
one command that puts an already-broken one right; and, when a sign-in fails
afterwards, says which two logs to open and what each answer means. The
shell test it gives now sends a user and a token, because the one printed
before stopped at *Missing field* long before it reached any of the new code
and proved nothing.

1.10.15

**The two patches for the token server, put right.** Both were wrong in a
way that only shows on the machine they are for, and the first attempt at
them took a live token server down; this is what was wrong and what it is
now.

* **The CGI patch used Python newer than the CGI's own.** A conditional
  expression (`a if b else c`, Python 2.5) and a generator expression inside
  a call (2.4) are a `SyntaxError` on anything older, the script never
  compiles, and Apache answers **500 with an empty body** for every request
  — including the ones that used to be refused properly. Everything the
  patch adds is now within Python 2.4, and the suite that builds it checks
  every added line for anything newer.
* **Neither addition may refuse a sign-in.** Both sit behind a `try` now:
  they exist for whoever reads the logs afterwards, and nothing a
  convenience does may be the reason somebody cannot get in. The body it
  writes is turned into bytes first, because a unicode object handed to
  `sys.stdout` on Python 2 is encoded as ASCII and raises.
* **An HTML error page must not end up in a RADIUS reply.** With the first
  handler patch, a token server answering 500 put its web server's error
  page into `Reply-Message`, where it was truncated at 250 bytes and hid
  the one thing worth knowing. The body is now used only when it is the
  CGI's own answer — which begins with `ERR` — and anything else reads
  `Denied by the token server: the token server answered 500 Internal Server
  Error`.

Both patched files were applied with `patch` and run: the CGI against a
token that works, one that does not, one whose reason has a comma in it and
a request with no id at all; the handler against a token server refusing, a
token server answering with an HTML error page, and one answering nothing.

`docs/otp-radius-detail.md` §6.1 now takes a copy of both files first,
checks the syntax with the token server's **own** `python` and `perl`, runs
the CGI by hand before anything is restarted, and says what each kind of
refusal in the reply means afterwards.

1.10.14

**The two OTP logs can now be joined by name rather than by judgement.** The
token server's own application ships two patches in
`docs/otp-radius-detail/`, and between them they turn the matching from a
weighing-up into a lookup:

* the `rlm_perl` handler passes the RADIUS client's **own address and port**
  through to `totp.cgi` as one more form field, and `totp.cgi` writes it on
  its own log line. That pair is what makes one packet different from every
  other — the detail log writes it as `Packet-Src-IP-Address` and
  `Packet-Src-Port`, and the reply goes back to it — so both logs end up
  carrying the same `172.22.0.137:48603` and the join is a lookup with no
  window, no tie-breaking and no clocks in it. It survives the two machines
  being minutes apart, which nothing else here can.
* the same handler **puts the token server's own reason into the reply**. It
  already had the CGI's answer in its hands and was throwing the body away
  to report the HTTP status, so every refusal reached the RADIUS log as the
  same sentence: `Denied access by rlm_perl authenticate function. ERROR:
  400 BAD REQUEST`. Now it says `Denied by the token server: Token has
  already been used once` — and that reaches the RADIUS record, where
  everything else about the attempt already is.

Both are optional and reversible, and everything works without them: a token
attempt with no id is matched the way 1.10.13 matched it, and the record says
which of the two it was. The record now says *matched by the id both logs
carry* when it was exact.

**A refusal whose reason had a comma in it was being cut in half.** The token
server writes `message=Rate-limit reached, please try again later` and this
stored `Rate-limit reached` — five times a day on one real site, and the half
it threw away is the half that says what to do. Fields are now cut only where
what follows really is another field.

**The OTP columns line up.** A row was putting the person's address and the
tunnel group in one cell and the name of the box that asked in another, so
every address started at a different place on the line. Each of the three now
has a tight column of its own in the same shape the TACACS rows have used all
along: the address, its flag, the group, the box, its name.

**The page had been drawing the wrong row function.** A second copy of it was
left in the file under the same name, and in JavaScript the later definition
wins silently. It is gone, and the suite now checks the page for a function
defined twice and for a row whose cells and headers have stopped agreeing —
which is exactly how both of today's faults would have been caught.

**Two lists in one popup no longer draw on top of each other.** Opening an
address gave each of them "whatever room is left" and squeezed both to
nothing, leaving their search bars standing outside their boxes with the next
heading printed over them.

1.10.13

**Three questions, three columns.** A token attempt was answering "where did
this come from" in one cell, with the person's address and the tunnel group
crammed together and the name of the box that asked shown only when there was
no tunnel group to show instead. They are three different questions and they
now have three columns: **Where from** (the person's own address and its
country), **VPN group** (the tunnel group, as the head end named it) and
**The box that asked**.

*Where OTP sign-ins come from* is matched against that third one and against
nothing else — the address of the box that carried the question, which is
what that setting was always about. The person's address in the first column
is wherever they happen to be sitting and is not a place anybody names.

**The token page had been running the wrong function.** While the columns
were being put in, a second copy of the row-drawing function was left in the
page under the same name, and in JavaScript the later definition wins
silently: the page drew the old row and nothing anywhere said so. It is gone,
and the file is now checked for a second definition of anything — 244
functions, none defined twice.

**Two lists in one popup no longer draw on top of each other.** Opening an
address showed *everything it has failed at* and *everything that did get in
from it*, and each of them was told to take whatever room was left: both were
squeezed to thirty pixels while their search bars, which cannot shrink, stood
outside their boxes with the next heading printed over them. They now have a
floor, and the popup scrolls when the two of them want more room than it has.

**Joining a token attempt to its RADIUS packet is now as hard to get wrong as
those two logs allow.** Neither writes anything the other writes — no shared
id, no shared number — so it is done by who, where and when, and:

* **the whole account wins over the bare name**, so two people whose names
  differ only by their realm are two people;
* **a verdict that agrees wins over one that does not**;
* **one packet belongs to one attempt** — three tries in ten seconds get
  three packets in the order they happened, not the same one three times;
* matches are keyed by the token row's own id rather than by its name and
  second, so two rows that share both still get their own answers;
* **and where it is still a guess, the record says so** rather than letting
  one read as a fact.

**The shipper names every record it sends.** `id=` on each line is a hash of
the NAS, the file and the record itself: the same record always hashes to the
same name and no two records share one, so a detail file read again from the
beginning arrives as the records already held rather than as new ones that
merely look the same. Older shippers that send no `id=` work exactly as
before.

`docs/otp-radius-detail.md` gained a section on how the two logs are put
together, what it costs when they cannot be, and the one line upstream — the
token's own reason in the RADIUS `Reply-Message` — that would make the join
unnecessary altogether. It also now says why both logs are read at all,
counted on real traffic: fifteen refusals in two days, every one of them the
same Access-Reject in RADIUS, and seven different reasons in the token log,
among them a passcode being replayed and a rate limit being hit.

1.10.12

**A token attempt now says whose address it really was.** The token log
answers one question — was the number right — and it cannot answer any other,
because the token software is asked over the loopback by whatever stands in
front of it. Every token row on this page has said *the server itself* in the
address column since the day the token logs were first read, and that was the
honest answer to a question the file could not answer.

The RADIUS server the token software sits behind writes the rest, in its own
detail log, and a script on the token server ships it a record to a line.
Switch it on — Settings → The OTP logs → *Read the RADIUS log beside it* —
and every token attempt shows:

* the **person's own public address**, with its country;
* the **tunnel group** they came through, decoded out of the hex the head end
  writes it in — which is what says the VPN from the virtual desktops when
  one token server answers for both;
* the **box that asked**, with the name you gave it;
* the **machine**: what it calls itself, its platform and version, its MAC,
  the model, and which AnyConnect it was running;
* the **ISE `audit-session-id`** — the same session id ISE wrote about the
  other half of that very sign-in;
* what the RADIUS server **answered**, and its own words on a refusal;
* and every attribute on the packet, for somebody who knows RADIUS.

**It is never a row.** One VPN sign-in is one token attempt, and counting the
packet that caused it as a second one would count every sign-in twice. The
packets are kept beside the token records, in a table of their own, for a
month.

**It arrives late, and that is said out loud.** The shipper runs once a
minute, so an attempt from the last minute or two normally has nothing beside
it yet — the record says so, and says how far behind the shipping is
actually running, because "not here yet" and "the script has stopped" look
identical otherwise.

**Where OTP sign-ins come from** is the new twin of *Where TACACS sign-ins
come from*: `172.22.0.137=VPN, 192.168.4.0/24=VDI`, an address or a range,
optionally named, and a switch that marks anything asking from somewhere
else — so a new box appearing in front of the token server is something
somebody sees.

**A password on one of those packets is dropped unread**, by name, before the
record is ever written down. FreeRADIUS suppresses it, the shipper suppresses
it again, and this is the third place: the promise this program makes about
passwords is this program's to keep, whatever anybody upstream did or did not
do.

Setting it up on the token server is `docs/otp-radius-detail.md`, and the
files to do it with — the FreeRADIUS patch, the shipper, the cron entry and
the rsyslog rule — are in `docs/otp-radius-detail/` beside it.

**And the fact boxes in every popup are the same height again.** They were
laid out to hug their contents, so one box whose value wrapped onto a second
line stood taller than the ones beside it, and a row of boxes of four
different heights is the first thing the eye lands on.

1.10.11

**The nightly copy is now the engine's own dump.** It was a portable SQLite
file on all three engines, which is the right thing for a copy and the wrong
thing to make fourteen of: on this program's own 238 MB PostgreSQL database,
the copy is **100 MB and the dump is 10 MB**. So the one that is made every
night is now what the engine makes of itself - `pg_dump --format=custom` on
PostgreSQL, `mariadb-dump --single-transaction --quick` piped through gzip on
MariaDB, and on the file SQLite's own online backup, which is that engine's
dump format and needs nothing installed. All three are consistent while the
daemon carries on writing.

The second reason is the one that matters on the day: a `.pgc` or a
`.sql.gz` is what a database administrator already knows how to read. It goes
back with `pg_restore` or the `mariadb` client, **without this program being
involved at all**.

**The portable copy has not gone anywhere**, because the two are for two
different things and always were:

| | the copy | the dump |
|---|---|---|
| where | `/var/lib/isemon/backups` | `/var/lib/isemon/dumps` |
| what it is | a SQLite file, always | `.pgc`, `.sql.gz`, or a `.db` on the file |
| goes back into | any of the three engines | the engine it came off |
| on 238 MB of PostgreSQL | 100 MB | 10 MB |
| made when | *Make a copy now*, before every restore and move | every night, *Make one now* |

**The dumps get the same card the copies have**, under the three settings
that switch the nightly one on: every dump listed with what it is, how big it
is and when it was made, with **Download**, **Restore** and **Delete** against
each one, and a box to drop one into that was saved somewhere else.

Whatever is dropped on either box is **read before anything happens** - by
its first bytes, not by the name it was saved under, because a browser upload
arrives with none of it. A MariaDB dump offered to a PostgreSQL installation
is refused with both ways out named; a file with no full administrator in it
is refused for the same reason a copy always was. What is in a dump is read
**without a server**: `pg_restore --list` for the tables and
`pg_restore --data-only --table=users` for whether anybody could sign in
afterwards, so the promise made about a copy is kept about a dump too. And a
portable copy of what is being replaced is still made first, every time,
whichever of the two is going back.

On PostgreSQL the whole of a dump goes back **inside one transaction**
(`pg_restore --single-transaction --clean --if-exists`): it all arrives, or
none of it does and the database is exactly as it was.

Proved on this program's own data, both engines, both directions: 37,546
failed attempts deleted and a whole table dropped, the dump put back, and
every count identical again - 9 seconds on PostgreSQL. Downloaded from the
page, uploaded again, and put back the same way.

**None of it needs anything installed to keep working.** The dump wants the
engine's client on the isemon machine (`dnf install postgresql` or
`dnf install mariadb` - the clients, which `./install.sh --with-db` now
installs beside the driver). Without it the night falls back to a portable
copy rather than to nothing, and says so on the page and in the log once a
day.

1.10.10

**Set it up now makes the password, and doubles as the upgrade check.** It
used to refuse until `db_password` had been filled in by hand, which got the
order backwards: somebody standing there has an administrator on a new server
and nothing else, and the account isemon signs in as is one that nothing else
in the world ever signs in as. Being asked to invent a second password for it
earns nothing and is exactly where a weak one gets typed.

So it makes one - 24 characters, letters and digits only, so that it survives
being pasted into `psql`, a shell or a backup script - writes it into
`config.json`, which is the only place it lives, and prints it once on the
page and on the command line, with a **Copy it** button beside it:

```
The password made for isemon
  xSlEPfBoJGKlm38bHk1rNxKx
  It is in /etc/isemon/config.json and nowhere else. Keep a copy if you want
  one; this is the only time it is printed.
```

And because the same button is now the only one anybody has to remember, it
does the other half of the job too. **Press it again and it wants no
administrator at all**: it signs in as isemon's own account, finds everything
already there, and then goes over the tables the way every start of the
daemon does - adding any table, column or index this version wants that an
older one never made, and naming anything it could not add. Proved by taking
a database apart by hand: an index, a column and a whole table dropped, and
one press put all three back, ending on 15 tables and 42 indexes with nothing
short. Both positions of it are in `test/engines.py` now, against both
servers, and both guides have been rewritten around it - §4.1 says to leave
the password empty.

*Start using it* also has its icon back; it was asking for one the icon table
never had.

1.10.9

**Tidy it up did nothing on PostgreSQL.** Measured on this program's own
data: half the country ranges deleted, the button pressed, and the database
**344.4 MB before and 344.4 MB after**, with 357,326 dead rows still in it.

`VACUUM` on its own marks that room reusable inside the table and gives
nothing back to the disk. That is the right default for a server and the
wrong answer for a button whose whole promise is the disk. It now rebuilds,
which is what the other two engines were already doing here - SQLite's
`VACUUM` and MariaDB's `OPTIMIZE TABLE` are both rebuilds - so the same
database, the same button: **344.4 MB to 130.9 MB in 3 seconds.** It costs
what a rebuild costs on any of the three, and the button says so: the table
is held while it happens and there has to be room for a second copy of the
biggest one.

**Check it now reads the whole of a PostgreSQL database**, every row of
every table, and checks every index with `amcheck` where the server has it -
rather than counting rows and calling it a check. The extension and the
rights it needs are not always there, and their absence is not a fault.

Both buttons, and erasing, are now held on every engine by
`test/engines.py`: that a database says whether it is sound, that tidying it
really gives the room back, and that what is left afterwards is what was
left - checked against MariaDB and PostgreSQL as well as the file.

---

1.10.8

**Every copy says which database it was taken off.**

A copy is a SQLite file whichever engine it was made on. That is deliberate
and it is what makes one useful: a copy taken off PostgreSQL goes back into
PostgreSQL, into MariaDB, or onto a machine with no database server at all,
and it is the same thing `--restore` reads and the same thing moving between
engines does - so all three are as tested as each other. But it does mean a
folder of copies looks identical on every engine, and an installation that
has just moved to PostgreSQL shows a list of `.db` files that reads as
though nothing had moved at all.

So each copy now carries, inside itself, which engine it came off, where
that was, when, and which version made it - and *Copies kept* has a **Taken
off** column: `PostgreSQL`, `MariaDB`, `the file on this machine`. Copies
made before this say *not said*, with a note that they are still whole
copies and still go back into any of the three.

---

1.10.7

Three things on Settings → The database that were still answering as though
the installation had not moved.

* **"This database has been growing 27.4 MB a day"** was two series laid end
  to end. The same installation is about 105 MB as a file and about 250 MB
  on a server - the same rows, counted differently - so the day of a move
  read as a day on which the database grew by half of itself, and "how long
  will the disk hold" came out of a step that is not growth at all. Each
  daily measurement now carries the engine it was taken on and only the
  current one's are used; right after a move the page says the slope is not
  known yet rather than implying it is flat.
* **The counts under "What is in it" are every row in every table**, which
  is not the number on the tabs above - those count what their own page is
  showing, a window of time and the doors that page is about. On a site
  reading eduroam the difference is thousands, and it read as the old
  database still being shown. The card now says which it is.
* **PostgreSQL refused `CHECKPOINT` once a day, in the log, as a warning.**
  Only a superuser may ask for it, and this program signs in as an account
  with rights on one database and no more - which is right, so the asking
  was wrong. It does not ask any more.

---

1.10.6

**Nobody would have been banned on PostgreSQL.** Found within minutes of an
installation moving there, by the logging 1.10.4 added — which is the whole
argument for it.

* The statement that decides whether an address is over the bar picked a
  plain column beside an aggregate with no `GROUP BY`. SQLite and MariaDB
  allow that and hand back whichever value they were holding; PostgreSQL
  refuses the statement outright. So on that engine the daemon read the
  logs, recorded every refusal, and **banned nobody at all** — with one line
  in its log saying so and nothing on the page. The address was already
  known from the WHERE and is put back on the row afterwards, so it is
  simply not asked for any more.
* **The suites can now be run against a server**, which is what would have
  caught it. Two sections of `checks.py` build a database in the shape an
  older version left behind — as a file, by hand — and they now say they
  were skipped rather than stopping the run; a count that is answered from a
  cache is waited for rather than assumed instant, because how long that
  takes is engine and machine; and a short record packs to words on the file
  engine and to the bytes those words spell on the other two, which the
  check now states rather than assuming one of them. **372 of the 390
  checks now run against MariaDB and PostgreSQL as well**, the banning path
  among them.

* **Nine indexes could go missing on MariaDB.** The indexes this program
  adds to a database that already exists are not in the schema, and on an
  engine that counts an index key in bytes they decide how wide a column has
  to be declared. The dialect was told about them by whoever built the
  database first — so a database built any other way declared those columns
  unlimited, MariaDB refused to index them (*"key was too long"*), and every
  count standing on one of them answered nought. It is now true of every
  dialect from the moment there is one. The installation's own path was
  always right; this is about anything else that opens the same database.

And the pages that had not noticed the move:

* **Settings → The database** described the SQLite file whatever the
  installation was running on: the size, the parts, the disk, the header
  line. It now says where the database actually is, and on a server the
  disk card says plainly that what is on *this* machine is the copies —
  the database is on the server, and "years left" is not this disk's
  question to answer.
* **Settings → About showed nothing of its own.** The three settings that
  belong to it — what to call this installation, the port the daemon
  answers on, and **the debug switch** — were drawn into a card that was
  then cleared and filled with "everything else", so they were not on the
  page at all and the only way to change any of them was the command line.
  The leftovers now have a card of their own.
* The wording that said SQLite where it no longer only means SQLite, and
  the wording that still means it — the copy is a portable SQLite file on
  every engine — now say which they are.

---

1.10.5

Guards on the switch that says everything, because measuring what it writes
made the risk plain: **2.4 MB in two minutes on a machine doing almost
nothing.** On a busy one that is gigabytes overnight, and the way somebody
finds out is a disk with nothing left on it.

* **The daemon's own log now rotates at 200 MB as well as daily.** "Daily"
  is no guard against the switch being turned on at four in the afternoon.
* **`isemon --check` says the switch is on**, and how big the log has got.
  Not counted as a fault - it is a choice - but never silent.
* **And the daemon says so in its own log once an hour**, with the size,
  rather than only when somebody goes looking.

Seven checks in `test/engines.py` hold what the switch actually writes: that
a read writes nothing with it off, that with it on every statement is
written down with its values and how long it took, and that a statement
which **failed** is written down either way, naming the engine that refused
it.

---

1.10.4

A move that could not finish, one that looked like it had stopped, and a
switch for finding out which.

* **Moving a real database into PostgreSQL stopped half way.** SQLite is
  typeless and this program leans on it: the ISE record kept beside an
  authentication goes in as words when it is short and as packed bytes when
  it is long, in the same column. A real installation is a mix — on the one
  that found this, 16,245 of 37,546 refusals and 20,012 of 21,450 logins
  held words. PostgreSQL's `bytea` takes one of those and refuses the other,
  so the copy stopped on the first short record with `invalid input syntax
  for type bytea`. Which column holds bytes is now read out of the schema
  and each value is carried into the type the far side actually has. **Every
  test passed throughout**, because every fixture wrote records long enough
  to be packed; the fixtures now write both kinds, and six checks hold the
  conversion in both directions.
* **It looked like it had hung.** The move reported three steps, and the
  middle one covered the whole copy — six minutes on 123 MB with nothing
  moving. It now reports the table it is on and how far through it is, for
  every batch: `geo_ranges: 482,000 of 717,170`.
* **And it was slower than it needed to be.** psycopg2 sends one statement
  per row, so three quarters of a million country ranges were three quarters
  of a million round trips. Sent as one statement per batch instead:
  **359 s → 17 s** on a real 104 MB installation, identical data either side.
  MariaDB does this for itself and is unchanged at 18 s.
* **The debug switch now says everything**, which is what it always claimed:
  Settings → About → *Write down everything it does*, or `isemon --set
  debug=1`. Every decision, every command sent to the router, every read of
  the logs, **every request the dashboard makes and every statement put to
  the database with how long it took**. It is loud, and it is for finding
  one thing and then switching off again.
* Whatever that switch says, two kinds of statement are **always** written
  down: one that failed, with the values it was given, and one that took
  more than two seconds. On a database server a single slow statement is the
  difference between a page that draws and a page that hangs, and from the
  outside those look the same.

---

1.10.3

The two AlmaLinux 9 guides, corrected by an installation doing it.

* **AlmaLinux 9 gives you PostgreSQL 13**, not the newest one — the guide
  said 16. `dnf module list postgresql` shows what a machine is offered and
  15 and 16 are usually there, but 13 is what `dnf install postgresql-server`
  installs, and which one you get decides the next point.
* **PostgreSQL 13 stores passwords as md5** unless it is told otherwise:
  upstream only changed that default in 14. Set a password first and turn on
  `scram-sha-256` in `pg_hba.conf` afterwards and every sign-in fails with
  `FATAL: password authentication failed` - which reads exactly like a wrong
  password and is not one. Worse, **changing `password_encryption` does not
  rewrite a password that is already stored**, so the obvious fix appears not
  to work either. The guide now does the setting first and the password
  second, with the one query that says which of the two you are looking at,
  and the troubleshooting table names this as the usual one on AlmaLinux.
* **Both guides now show how to skip the administrator password entirely**
  on a server that is on the same machine: make the role and the database
  through the unix socket, where being root is the credential, and isemon is
  never given an administrator at all. Checked end to end - a role made that
  way takes `test`, `move` and everything after it.
* **And how to prove it on your own server before moving anything**:
  `test/engines.py`, pointed at a spare database, carries a whole small
  installation in and back out and holds it against what went in.
* Smaller: `SERVER` in an example is now said to be a placeholder in the
  first paragraph rather than assumed; the `could not change directory to
  "/root/..."` noise from `sudo -u postgres psql` is explained where it
  appears; and `psql -h SERVER` says to use `127.0.0.1` for a local server.

Nothing in the program itself changed in this version.

---

1.10.2

The nightly copy, on a machine whose database has gone.

A machine set to a database server that will not answer opens an empty one
in its place and says so everywhere — and then, every night at half past
three, copied **that**. The copy is followed by throwing the oldest ones
away, so a week of an outage nobody had noticed would have quietly replaced
every real copy with a copy of nothing, and the first anybody would know of
it is the day they needed one. Measured on 1.10.0: three nights, three
copies, nought records in every one of them.

It now makes no copy at all while it is standing in, says so in its log once
a day rather than every five minutes, and leaves the copies it already has
exactly where they are. Four checks in `test/engines.py` hold it there.

Everything else about the daily copy is unchanged and works the same on all
three engines — it is the same button and the same schedule, and what it
writes is a portable SQLite file whatever the installation runs on, so a
copy made on MariaDB restores onto PostgreSQL or onto a machine with no
server at all. Measured on a real installation: 104.5 MB in 2 s from the
file, 109.3 MB in 13 s from MariaDB, 109.3 MB in 9 s from PostgreSQL, each
opening as a plain file holding all 37,546 records, 714 bans and 4 accounts.

---

1.10.1

Two things 1.10.0 got wrong on a real machine, both found within the hour of
it being installed on one.

* **The dashboard could not save which database to use.** The settings went
  in, *Save the changes* answered `[Errno 30] Read-only file system:
  /etc/isemon/config.json.new`, and nothing happened. Two causes at once, and
  the unit file said so itself: `ProtectSystem=strict` with `/etc` closed,
  under a comment reading *"nothing here ever needs to write to
  /etc/isemon/config.json"* - which stopped being true the moment those
  settings were put on the page - and a directory owned `root:root 0755`,
  which the daemon's own account cannot create a file in either way. The unit
  now names `/etc/isemon` in `ReadWritePaths`, the installer makes that
  directory `2770 root:isemon` on install **and on upgrade**, and
  `config.json` stays `0640` because it holds a database password. When it
  still cannot be written - a machine set up by hand, SELinux - the page says
  the three commands that put it right instead of an errno.
* **`./install.sh --upgrade --with-db both` quietly did nothing about the
  drivers.** The upgrade path exits long before the section that installs
  packages, so the option was accepted and ignored. It is now carried out on
  both paths, a wrong value is refused before anything is touched, and a
  `--dry-run` upgrade no longer reports a restart that never happened.

Also: `isemon --settings` now says *config.json* for those seven settings
rather than implying they are saved in the database, and the title line names
the database actually in use rather than always the file.

---

1.10.0

Everything can be kept in MariaDB or PostgreSQL instead of in the file on
this machine, and moved either way without losing a row or editing anything
by hand.

The file is still what it keeps by default and still the faster of the two -
measured on this program's own data, 4,889 writes a second against MariaDB's
2,325 and PostgreSQL's 1,847. A server buys separation and somebody else's
backups, not speed, and that is what it is offered for.

* **Settings -> The database** now has the engine, the address and the
  account at the top of it, and five buttons that happen in an order: **try
  it**, **set it up** (which makes the database, the account and its rights
  on the server, asking for an administrator it uses once and stores
  nowhere), **carry everything across**, **empty it** if a first attempt
  left something behind, and **start using it**. Until that last button this
  installation carries on exactly as it is.
* **The same from the command line**: `isemon --database show|test|setup|
  move|empty --to mariadb`. `--to` never changes which database is in use -
  that is `--set db_engine`, and a restart.
* **Which database, and how to reach it, are the only settings kept in
  `config.json`** rather than in the database. A database cannot hold the
  address of itself, and a machine whose database will not open has to be
  able to be put right from the page - so it opens, says what is wrong in a
  red banner, and reads nothing and bans nobody until it is.
* **A configuration export carries no database address**, in either shape.
  It is this machine's own answer; carried elsewhere it would point a second
  machine at the first one's database.
* **Everything else is unchanged on all three**: the daily copy (always
  written as a portable file, so a copy made on MariaDB restores onto
  PostgreSQL or onto the file), restoring, checking, tidying up, erasing,
  folding, retention.
* `./install.sh --with-db mariadb|postgres|both` puts the driver in place.
* `docs/the-database.md` is the whole of it, including what to do when the
  server is not there; `docs/mariadb-on-almalinux9.md` and
  `docs/postgresql-on-almalinux9.md` stand one of those up on AlmaLinux 9
  from nothing - install, initialise, firewall, SELinux, the settings worth
  having - and then do the move, command by command.

Three things the file had never made anybody think about, each of which was
found by running this program's own tests against a real server:

* **A reader that never stopped reading saw the same rows for ever.** A
  database server keeps a connection that has read inside a transaction
  looking at one frozen view until it is told otherwise, and this daemon has
  threads that live for months. Every connection now commits as it goes, and
  the places that need several statements to be all-or-nothing say so.
* **One page took 166 seconds.** MariaDB's `USE INDEX` is a suggestion where
  SQLite's `INDEXED BY` is an instruction, so on 700,000 country ranges it
  walked half of them for every address the Banned page draws. Told properly,
  1.9 seconds.
* **Equal counts now have an order.** Every "busiest" list puts the most
  recent of equals first rather than leaving it to whatever the engine
  happens to hold - which used to read differently on every engine, and
  differently from itself.

---

1.9.9

Which node has been doing the work, said out loud.

An HA pair is two nodes and one of them is doing the authenticating at any
moment. Which one changes without warning, and from every other part of this
page the quiet one looks exactly like a node that has stopped talking to this
machine: its file stops growing, its *last read* goes hours old, its record
count stands still. The difference between a failover and a lost node is
whether the other one picked the same work up in the same hour — two numbers,
and until now they were only obtainable by writing SQL against the database.

* **The front page** says it in the heading of *The logs being read*:
  `ise1 11,421 · ise2 139`, the last 24 hours, each machine that writes one of
  these logs counted on its own. Pointing at it explains which shape is
  ordinary and which is not.
* **`isemon --status`** prints the same line, and where a machine wrote
  nothing at all it says so and what that does and does not mean.
* Folders that are configured and have never appeared are left out. A path
  nobody has written to is not a machine standing by, and listing it at nought
  beside the real ones is how a line stops being read.

It is counted off the time index and grouped: **40 ms on 1.8 million rows**,
and kept for a minute like the rest of the header. Nothing is judged by it and
nothing is banned for it — it is a count of who wrote what.

Found by an installation, again: a node had been silent for twenty-four hours
and nothing on the page could say whether that was a failover or a fault. It
was a failover — 24 September at 15:53, ise2 stopped at ~420 refusals an hour
and ise1 went from nothing to ~520 in the same hour.

---

1.9.8

Switching an installation that is already running over to compressed rotated
copies, which 1.9.7 described the end state of without saying how to get
there from a folder full of plain ones.

* **`docs/log-rotation-and-permissions.md` §5** — the migration, in four
  steps: `compress` and `delaycompress` into the logrotate file, one `find`
  to pack the copies already on disk, what to look at afterwards, and
  `--rescan` where the history is wanted in the database too. Including why
  the `find` waits three days (logrotate's own `delaycompress` means it
  intends to pack yesterday's copy itself, and two things reaching for one
  file is `error: destination already exists`), and why `logrotate -f` twice
  in one day with `dateext` refuses the second time.

* **The nightly tidy packs them too.** `deploy/isemon-logs-tidy` now gzips
  rotated copies left plain — the ones from before `compress` went into the
  file — so a machine that has the script migrates itself overnight. Copies
  only: the pattern ends in `.N` or `-YYYYMMDD`, and a live `x.log` cannot
  match it.

**Tested rather than described.** Ten days of rotation with the shipped
logrotate file and the shipped tidy script running beside each other, from a
folder in the state a machine switching over is really in — two naming series,
nothing packed: **no errors from either, on any day**. Afterwards: the live
file plain, `.1` plain because of `delaycompress`, twelve packed copies, 485
records across them — and a full import put **485** in the database, none of
them twice, with a second full import reading all 485 again and adding none.
Every logrotate stanza and every shell command printed in either guide is run
for real against a copy of an installation's log tree as part of this.

---

1.9.7

The logs that arrive here, rotated — which is a thing this program had
opinions about in three separate comments and shipped no file for.

* **`docs/log-rotation-and-permissions.md`** — the whole procedure, tested
  against a real installation's log tree with a real `logrotate` and the
  daemon reading as its own account across the rotation. What decides a
  permission (four things, and they undo each other), setting it up, putting
  right a machine that is already running, proving the rotation rather than
  waiting a day for it, and what each way of being wrong looks like on the
  screen.

* **Three files to put in place, rather than three comments saying somebody
  should.** `deploy/remote-logs.logrotate` rotates `/var/log/remote/*/*.log`
  daily with `create 0640 root isemon` — the group is the whole point, and
  `./install.sh --with-syslog` writes the daemon's real account into it.
  `deploy/rsyslog-permissions.conf` makes every file and **folder** rsyslog
  creates from now on readable the same way, which is what covers the sender
  nobody has thought of yet. `deploy/isemon-logs-tidy` handles the two things
  logrotate cannot: the FreeRADIUS accounting files, which are named for the
  day and which logrotate would rotate while the day is still being written,
  and rotated copies orphaned by a change of naming. The installer puts all
  three in place and leaves any that already exists exactly as it is.

* **One stanza, not two.** logrotate refuses two stanzas matching one file
  (`error: duplicate log entry`), so the tempting split into "the folders
  isemon reads" and "everything else" does not work; it is one rule with the
  group on all of it, which is also what makes it cover a folder that appears
  tomorrow.

And one thing in the program, found while testing the above:

* **A full import read twelve rotated copies of a log and no more.** Always
  twelve, whatever was there. A site keeping `rotate 30` — which is what the
  shipped file says, and what anybody wanting a month of history sets — had
  eighteen of its thirty days silently left out of the one operation meant to
  recover them, and a machine carrying two naming series side by side (which
  is every machine where `dateext` was ever added or removed) was worse.
  Measured on a folder holding 23 rotated copies: **340 of 630 records**
  imported. It takes all of them now, sorted by when they were last written,
  which is the one ordering that means the same thing in every naming scheme.

  On 240 MB of real ISE log left as 84 MB plain and 11 MB gzipped, across
  eight files and two naming schemes: **421,758 records in the files, 421,758
  in the database**, 174 s, RSS flat at 207 MB — and a second full import
  read all 421,758 again and added none of them. Compression is worth having:
  40 MB of ISE syslog gzips to 1.78 MB, about 23 to one.

---

1.9.6

A pass over 1.9.5 by somebody who had not seen it being written — the change and
both real databases handed to a reviewer with fresh eyes — and a set of
measurements on big logs and a big database. Everything here was found that way,
verified, and fixed.

* **A rotated log that has been compressed was read in part and nobody was
  told.** The pass back over every log unpacked the first 256 MB of one into
  memory and worked from that copy — and stopped there. Measured on a 300 MB
  rotated log: **377,103 records in the file, 337,441 read, 39,662 silently
  missing**, and 593 MB of memory to do it. It is read a block at a time out
  of the file now: **all 377,103, and 199 MB.** A year of a busy VPN
  compresses to well under 256 MB and unpacks to several times it, so this
  was a site's first year quietly going missing from the one operation meant
  to recover it.

* **A zone that cannot be used now says so.** `config.json` is not checked by
  anything — it is the way a fleet is configured from outside — so
  `log_zone: "Europe/Praha"` was accepted, ignored, and then confirmed back
  to the operator by `isemon --check`. It is said out loud when the settings
  are taken up, in `--status`, in `--check`, and in the status the dashboard
  reads.

* **"Go back over every log" no longer reads the two logs that carry no
  zone.** Nothing in either is ever judged, so there was nothing for that
  pass to apply — and because what one of their records is called carries the
  second its line says, reading them again after the zone had been corrected
  would have written every one of them a second time, once at the old time
  and once at the new.

* **Erasing the token or eduroam records goes by the door the record came in
  by** (`kind`), not by the shape of its session id. An ISE node named `otp`
  writes session ids beginning `otp/`, and real VPN records would have gone
  with the token ones. On all three databases the two agree today; the column
  cannot ever disagree.

* **Forgetting where a log was read up to goes by which log it is**, which
  each stored position now records. It was a prefix match on the folder, and
  a site whose token folder is the parent of its ISE folders would have had
  its ISE logs re-read — by an erase that never mentioned them.

* **A partial erase is done in pieces.** 296,127 rows in one statement holds
  the write lock for 15.3 s, and the daemon reading the logs is a writer too:
  on a bigger table it would have given up with *database is locked*. In
  pieces it costs about a sixth more in all and never holds the lock for more
  than **1.45 s**. On a real customer database: 35,169 eduroam rows in 0.5 s,
  with something writing beside it the whole time and nothing refused.

* **`isemon --check` no longer prints an all-clear about something it could
  not ask.** It read the reply from `/api/status` without looking at whether
  the call had worked, so an unauthorised or failed call printed *every log
  is dated at or before the moment it was read*.

* **A clock that is hours fast stays where it can be seen.** A line more than
  a day in the future was read as last year's — the rule that makes 31
  December work when read on 1 January — so a token server 30 hours fast had
  its lines filed a year back instead of being reported. The year only rolls
  over now when the line is more than a week ahead, which no clock is and
  every year-rollover is.

* **Small ones.** `+02:75` was quietly read as `+03:15` rather than refused as
  the typo it is. A clock a day out was reported as *those lines look like
  they are written at +16:00*, which is not a place and which the setting
  itself would refuse. The dashboard and `isemon --status` printed the same
  number differently — *5 h 60 min* against *5 h 59 min* — because one
  rounded and the other did not; both cut off now, exactly as the command
  line always did. The empty-group rule on the erase card greyed out the two
  groups whose whole point is the side effect. A file both dated ahead and
  behind showed only the first. The eduroam session cache outlived an erase
  of the records it belongs to. And the log table on the front page called an
  eduroam file "logins" with ISE's explanation beside it.

### What it does on big data

Measured on this version, on this machine:

| | |
|---|---|
| 600,000 ISE records from a 477 MB log | 4 min (~2,340/s, judging and banning as it goes), RSS flat **138 MB** |
| 300,000 eduroam records from a 166 MB pair | 112 s (~2,680/s), RSS flat 214 MB, 0 banned |
| the page while either is running | **0–8 ms** |
| 377,103 records out of a 300 MB compressed rotated log | 23 s to read, 199 MB |
| weighing 600,000 recorded refusals again | 157 s, **3 MB** of memory |
| 1.78 M rows: signing in, the front page | 643 ms cold |
| the chart over 30 days · a page of 100 · the doors | 1.9 s · 152 ms · 30 ms (cold) |
| a name searched across 1.78 M rows | 48 ms |
| what can be erased, listed | 5 ms on the real database, 59 ms on 1.78 M rows |
| counting one door's rows to erase (296,127 of them) | 14 ms |

And on both of his real databases again: the chart draws **18** logins as the
VPN at one site and **141** at the other, which is exactly how many VPN logins each one
holds; the 19,907 eduroam sign-ins and the 524 records that are not sign-ins
at all are drawn as themselves.

---

1.9.5

A log line with no zone in it, read on a machine in the wrong one.

ISE writes the offset that was in force on every record it writes —
`2026-09-25 10:21:25.123 +02:00` — so an ISE record says exactly which second
it happened in and nothing on the machine reading it can move it. The token
log and the eduroam log write

    Sep 25 10:21:25 otp totp.cgi[4182]: Success: user=...

and nothing else. A time like that is not a moment until somebody says where
it was written, and the reader has one thing to go on: the zone of the machine
doing the reading. Where the two agree — nearly everywhere — that is right and
costs nothing, which is exactly why nobody looks at it. Where they do not, on
an installation whose machine had been left on `America/New_York` while its
syslog carried Prague time, every one of those records was **six hours from
where it belonged** and nothing looked wrong: the lines parsed, the rows
arrived, the counts counted, the page drew. The screen said 17:32 and the log
said 11:32, and the only way to see it was to hold one up beside the other.

* **A log dated in the future is now noticed and said out loud.** Nothing
  writes a line before the thing happens, so a line dated after the moment it
  was read is proof that either the machine writing it is ahead or this one is
  reading it in the wrong zone. The daemon watches for it on the two logs that
  carry no zone — never on ISE's, which cannot be wrong this way — marks the
  file on the Overview and in `isemon --status`, and writes it once rather
  than every five seconds. Where the difference is one a zone could actually
  be, it names the offset those lines are really written at: *it is being read
  as -04:00, those lines look like they are written at +02:00*. Where it is
  not a difference any zone explains it says so instead, rather than sending
  somebody to change the one thing that is right.

  The eduroam accounting file is not affected either: the controller writes
  `Timestamp = 1790328768` in it, which is a moment and not a reading of a
  clock.

* **The zone those logs are written in can be set** — Settings → The ISE logs,
  or `isemon --set log_zone=Europe/Prague`. A name out of the zone database,
  which knows when summer time starts, or a fixed offset (`+02:00`) for a
  machine without one. Empty means this machine's own zone, which is what it
  has always done and what a site whose clocks agree wants. It cannot move an
  ISE record by a second, whatever it is set to.

* **The token records and the eduroam records can be erased on their own,**
  and erasing either also forgets where those files were read up to — so the
  next pass reads what is still in them again, with the clock as it now is.
  That is what puts a month of misfiled records right after a machine's zone
  has been corrected. Neither is ever judged and no address is ever banned for
  either, so nothing in this can let anybody in or keep anybody out. Lines
  that have already been rotated away do not come back.

Found by an installation, not by a test: the times on the token page did not
match the token server's own log. Both real databases were read again
afterwards and neither had any other second out of place.

---

1.9.4

A pass over the whole of it for bugs, for lag and for what happens when the
database and the logs are big. Nothing was added but the guide below.

* **The counts at the top of the front page were capped and said so nowhere.**
  A list stops counting at twenty thousand on purpose — past that the number
  is no use to somebody paging through it and counting further costs a walk
  of the table — but the two numbers at the top took the same capped count,
  so a busy site read *20,001 failed in the last 24 hours* for ever with the
  real number several times that. They are counted properly now, off an
  index: 1.8 million rows in 14 ms.

* **The window's counts were worked out afresh on every request and kept for
  ever.** "The last 24 hours" is `now - 86400`, and `now` moves every second,
  so the answer was filed under a name nothing ever asked for again: every
  request recomputed it, waited for it, and left it in memory — 121 ms added
  to every list at a month's window, and about 17 MB a day of memory held by
  one open dashboard. Windows are rounded to the minute, so the page that
  refreshes every five seconds asks one question rather than twelve.

* **A pass back over every log no longer holds the whole table in memory.**
  It read every refusal into a list before weighing any of them: a quarter of
  a gigabyte for 600,000 rows, and on a year of a busy VPN enough to have the
  daemon killed on a small machine — during the one operation somebody runs
  when things already look wrong. The rows are walked one at a time now.
  Measured: 209 MB for 600,000 rows before, 1 MB after.

* **A passed record that is nobody signing in is no longer drawn as a VPN
  login.** The bands of the chart are cut out of the bar and whatever is left
  over is the VPN, and "everything else" — a change of authorisation, which
  has no name and no address in it — was not one of the bands. On the
  installation this was found on, an hour held 4,222 eduroam logins, 11 real
  VPN logins and 131 records that are nobody signing in; the first and the
  last are now where they belong.

* **An empty list blamed the window for what the search was doing.** "This
  door holds 1,577,477 in all — look at everything" appeared whenever a
  search matched nothing, and widening the window found nothing either. It
  says that only when the window really is the reason.

* **Whether the counts are ready is asked of the window being drawn.** It was
  asked of any window at all, so the first page ever drawn made the all-time
  counts and every window after it was called ready while it held noughts.

* The places TACACS sign-ins come from are **parsed once per page** rather
  than once per row: a thousand rows against twenty places was 20,000 turns
  through the address library, 115 ms, on a column most of those rows do not
  draw. They are also only worked out for the lists that draw it.

* **The guide for shipping FreeRADIUS logs here is in the box**, at
  [docs/freeradius-rsyslog-forwarding.md](docs/freeradius-rsyslog-forwarding.md):
  imfile and RELP over TLS from the RADIUS server to the log server, and — the
  part that costs an afternoon — the file permissions on the receiving end,
  where the mode rsyslog is configured with is not the mode that reaches the
  disk.

**What it does with a lot of data.** Measured on this release: 600,000 ISE
refusals read out of a 477 MB log in 4 minutes (about 2,200 a second, judged
and banned as they arrive) with memory flat at 136 MB throughout; 300,000
eduroam records out of 166 MB of logs in under 2 minutes at 213 MB; the page
answering in 0–8 ms the whole time. On a 1.8-million-row database: the front
page 24 hours in 53 ms and a month in 1.3 s, the lists 3 ms, a name searched
for over a month 418 ms and over everything 1.6 s, the doors 20 ms for a
window and 525 ms for all of it, the accounting joined for a page of 250
eduroam logins in 4 ms.

1.9.3

* **A tab saying 2 over a page saying nothing matches.** The number on each
  door counted everything ever while the list under it showed the window
  somebody had chosen, so a door whose records were older than that window
  offered a number and then an empty page, with nothing anywhere to say why.
  The number now counts the same window the list is showing — and because a
  door that vanished for having nothing today would be a door nobody could
  find, which doors exist at all is still everything ever. A door with
  nothing in the window simply carries no number.

* **An empty list says why it is empty.** Where the records are there but
  outside the window: *Nothing in this window. This door holds 5 in all*,
  with a button that widens it. Where they are behind the search or the
  filters, it says that instead.

* Counting the logins by door no longer reads the whole table: it walks the
  index over (kind, ts) as the refusals already did. On 109,000 logins that
  is 26 ms where it was 5.4 seconds, and counting one window of it is 21 ms.

* **Where TACACS sign-ins come from takes a subnet.** It only ever matched an
  address outright, so a site whose administrators work from a management
  network had to list every address in it by hand — and every one it missed
  was marked as coming from somewhere unusual. An entry is now one address, a
  subnet (`172.22.22.0/24=VLAN500`) or a run of them
  (`10.9.0.0-10.9.0.63=Jump`), IPv4 or IPv6, and every address inside one is
  shown under that name. Where an address falls in more than one, the
  narrowest wins, so a jump box named inside a subnet that is also named
  keeps its own name. Which place an address is in is worked out by the
  daemon and handed to the page with the rows, because whether an address is
  inside a prefix is not a question a browser should be answering.

1.9.2

* **eduroam was being drawn as the VPN.** Every bar of the chart on the front
  page is cut into bands — a switch over TACACS+, the network, the token
  server — and whatever is left over after those is drawn as the VPN.
  eduroam had no band, so on a site reading it every visitor let on to the
  wireless appeared as a successful VPN sign-in, in the green of the one door
  this program bans on. On the installation that found it that was twelve
  thousand a day against a couple of hundred real ones. It has a band and a
  colour of its own now, on both halves of the bar, and a refused eduroam
  sign-in is counted as an attempt in that band rather than disappearing into
  "not an attempt". Bands are now listed in one place, so a door added later
  cannot silently become the VPN again.

* **Nothing was ever banned for it**, and the tests now prove it where before
  they only said it: forty eduroam refusals in a row earn nobody anything,
  the pass that goes back over every log does not see one of them, the
  busiest addresses and the names being tried are the VPN's alone. The only
  address on such a record is the wireless controller, and it is never
  written down as one.

* **The two counts at the top say what they count.** "Passed, last 24 h" said
  it was everybody who got on to the VPN and was in fact everybody who got on
  to anything — which on a site with eduroam is mostly other institutions'
  visitors. Both cards now say underneath how many of that number were the
  VPN, wherever the two differ.

* `read_records` — the way a check or a replay hands lines straight in — now
  reads them with the reader that belongs to the log they came from. Handed
  eduroam lines it used ISE's rules, found nothing, and reported no records
  rather than saying it could not read them.

1.9.1

A pass over the whole of it for bugs, for markup showing where words should
be, and for lag. Nothing was added.

* **The dashboard answers while a database is being brought up to date.**
  Everything an older database is missing is mended when it is opened, and
  part of that mending rewrites every row — which on a busy site is a
  million and a half of them and takes minutes. It happened before the API
  had opened its socket, so upgrading a busy machine gave a dashboard that
  answered nothing at all: not a slow page, a refused connection and a 502
  from nginx, for as long as it took, with nothing anywhere saying why.
  The page now comes up at once and that work goes on behind it. Measured
  on 1.8 million records: refused for four minutes before, answering
  throughout after — the front page in 67 ms and every list drawn while it
  ran. The part that cannot wait still does not: a row with no door worked
  out at all is counted as a VPN attempt by everything that decides who is
  banned, so those are filled in before the daemon reads a single line.

* **A restored backup is put through this version's rules.** Restoring a
  database made by an older version left its rows exactly as that version
  wrote them — which, on a backup from before the doors were told apart,
  means every refusal on a switch counted towards somebody's VPN ban until
  the daemon was restarted. A restore now finishes the job, and it no longer
  races the mending going on behind the page.

* **A MAC is one machine however it is spelled.** `98-FC-84-E0-29-D6`,
  `98:FC:84:E0:29:D6` and `98fc.84e0.29d6` are the same machine, and only
  the first was being read as one. A controller that writes colons — which
  is most of them that are not Cisco — had every eduroam session thrown away
  silently: the accounting was read, found nothing to attach itself to, and
  said nothing. Every database sorts its old rows out on the way up.

* **Two tooltips were showing their own markup.** The name of a downloadable
  ACL and the level beside every event opened boxes reading `<span
  class="mono">…</span>` rather than the words. Everything on every page and
  in every tooltip — fifty thousand of them — was read as a person reads it,
  and nothing else was doing it.

* **What FreeRADIUS writes about eduroam, read more carefully.** A password
  with a slash in it no longer leaves half of itself in the name; a Windows
  machine signing in as `host/PC1234@example.int` is still that machine and
  not an account called `host`; `<CHAP-Password>` is kept where it is
  written; a log with no request numbers in it no longer folds six tries at
  one account into one; a request number that comes round again after a
  restart is no longer mistaken for the same request; the accounting file
  being followed is the live one rather than the compressed copy beside it;
  the last record in it is written down at once rather than waiting for the
  next one; an account on the ignore list written with an institution means
  that account and not somebody with the same name elsewhere.

1.9.0

* **The eduroam logs, when a site has them.** *Settings → **The eduroam
  logs*** is a page of its own beside the ISE and the token logs. The
  visitors' network is not ISE at all — it is a FreeRADIUS of the site's own,
  carrying our people when they are elsewhere and other institutions' people
  when they are here — and none of it appears in any ISE log. Switched on, it
  gets a tab of its own under Logins and under Failed attempts. Switched off,
  not one file is opened and nothing anywhere behaves differently.

  **Two files per server are read, and they say different things.** The
  authentication log says who got in and who did not, and is where the rows
  come from. The accounting files are where the session actually is: the
  access point that heard the machine — which is the room it was in — the
  network, the VLAN, the address it was given and the name the machine calls
  itself. The controller writes those minutes after the sign-in, so they are
  joined to the row by the machine's MAC when the page is drawn rather than
  frozen into it, and a row that has only just appeared says the machine
  without yet saying where. The accounting file is named for the day it
  covers, and the newest one is followed across midnight on its own.

  **One authentication is one record.** FreeRADIUS writes two lines about
  each refusal — the reason, and then the bare refusal, both under the same
  request number — and two about each EAP login, one for the identity inside
  the tunnel and one for the sign-in itself. Counting the lines would double
  every number on the page; what is counted is the authentications.

  **A password is never kept.** FreeRADIUS writes what was offered on a
  refusal — `[somebody/hunter2]` — and the half after the slash is dropped
  where the line is read. It is in no row, no record and no log this program
  writes, and the tests look for it in all three.

  **None of it is ever judged.** The only address on one of these lines is
  the wireless controller the request came through; banning it would take the
  whole of eduroam off the air.

* **Accounts that may be left out altogether.** Every wireless controller
  tests its RADIUS server by trying to sign in as somebody who does not
  exist, every few seconds, for ever — on the log this was written against
  that is two thirds of everything in it. *Settings → The eduroam logs →
  **Accounts to leave out altogether*** takes a comma-separated list, and
  nothing those accounts do is written down anywhere: not a row, not a count,
  not a tab, not a remembered machine. A name is matched whole and without
  regard to case, with or without its institution on the end.

* **An opened record says what it is.** The heading over one used to be read
  off the protocol alone, so every 802.1X login, every MAB refusal, every
  token and every change of authorisation opened under a heading saying *A
  successful VPN login*. It now says which door the record came through.

* The command offered for a log file this daemon may not read now reaches
  **every file in the folder** rather than the ones ending in `.log` — an
  accounting file is called `detail-20260924`, and a pattern that only
  matched logs left it exactly as unreadable as it was.

1.8.2

* **The address the machine has, on the 802.1X and MAB rows.** A record about
  a machine on a socket or a radio had a MAC on it and nothing a person could
  reach: "which PC is 98-FC-84-E0-29-D6" was a question to answer somewhere
  else. The address the switch or the controller reported for that endpoint
  is now a column of its own, on the logins and on the refusals, and the
  lists can be searched by it. It is the endpoint's address and never the
  network device's — that one is the *Switch* column beside it, and a record
  where the two agree is a record whose field is about the device, so nothing
  is printed. A record made before the machine had asked for an address
  carries none, which is most MAB failures and a good few first handshakes:
  the column says so with a dash rather than guessing one. There is no ban
  button and no history beside it on purpose — that address is what the
  machine was given inside the network, not what knocked at the door, and it
  is never counted towards anybody's ban. Databases made by an older version
  fill the column in from the records they already hold, without re-reading a
  log.

* Three of the lists — the two about machines and the one about tokens — had
  **one empty column too many** on the right: a heading with nothing under it,
  left where the lists with a ban button keep theirs.

1.8.1

A pass over the whole of it for bugs, lag and latency. Nothing was added; what
follows is what that pass found.

* **A value in a log is a value, whatever is typed into it.** ISE separates
  the fields of a record with a comma and a space, and escapes a comma inside
  a value as `\,` — and the reading of that escape was missing. A user name
  is typed by whoever is knocking, so a name could bring its own fields with
  it: `bob\, Calling-Station-ID=198.51.100.7` put an address of the
  attacker's choosing in front of the record's real one, and a name carrying
  `\, CoAType=x` was read as a change of authorisation and so never judged at
  all — a way to fail at the VPN for ever without earning a ban. Both are
  closed, a name with a comma in it still reads as one name, and the tests
  hold it there. Read against both installations' logs, 21,537 records are
  read exactly as before.

* **The tabs come back with their numbers on.** The counts behind them are
  worked out behind whoever asked, and on the first page drawn after a
  restart they could arrive as noughts — which draws a page with no numbers
  on the tabs and whole doors missing, and is not something anybody would
  think to reload. They are given a moment longer now, and a page that gets
  them empty asks once more.

* A **stale answer could be drawn in the wrong shape**: two door tabs pressed
  quickly, and the slower answer landed last and was drawn with the newer
  tab's columns — an attacker's address under a heading saying it is the
  token server's own. Each list now ignores an answer to a question nobody is
  asking any more.

* The **directory popup** no longer reopens itself over whatever you are
  looking at when a slow answer arrives after you closed it, and *What this
  name has been doing here* opens the history instead of closing itself.

* A **name searched for** over a long window is read once rather than twice:
  a month of a busy site went from 0.75 s to 0.45 s, everything ever from
  2.8 s to 1.7 s. A box with nothing but spaces in it is an empty box again,
  not a search for spaces that matches nothing.

* The **front page asks its six questions at once** rather than one after
  another: a month of 1.8 million records went from 1.9 s to 1.3 s.

* A **re-sort keeps what a record said** where the record itself can no
  longer be read, rather than replacing it with nothing.

* The **settings of a second directory are greyed out** while it is switched
  off, the **key for a firewall** can be made before its address is typed
  again, and the **access list button** follows the banning switch while the
  page is open.

1.8.0

* **A second directory, for the names that are not in the first.** A site may
  sign its administrators in against one domain while the people in its ISE
  logs live in another. *Settings → **A second directory*** is that other
  domain: when a name is not in the first, this one is asked, and the card
  says which of them answered. **It is never a way in** — nobody signs in
  against it, no role comes from its groups, no account is made from it, and
  it is asked nothing but "who is this name". Like the first, it is only ever
  read. It has its own check, its own certificate authority and a *Look a
  name up…* button that asks both, in order. Switched off, nothing anywhere
  changes.

* **Which directory to ask is read off the record, not guessed.** ISE writes
  down the domain it resolved somebody in — `AD-User-Resolved-Identities:
  jk@example.int` — and that is kept with the attempt. Looking that person up
  then asks the directory that domain belongs to and no other. Which names
  belong to which directory is asked of the directory itself: Active
  Directory publishes the suffixes its forest answers for, so a domain called
  `example.local` whose people sign in as `somebody@example.cz` is handled
  without anybody typing anything, and nothing about any particular site is
  written into this program. Where a directory will not say, the domains may
  be named by hand beside it. Records with no domain in them — a token log
  is one — fall back to asking every directory at once, which is quick even
  when one of them is not answering.

* **A change of authorisation is not a login.** When an endpoint has just
  been profiled, or its group has changed, ISE tells the switch to ask that
  endpoint again — and writes the telling into the log of successful
  authentications. There is nobody in one of those: no name, no address, and
  the device is the switch being told. They were being drawn as VPN logins
  with a dash in every column. They are now what they are, under *Everything
  else*, and every database sorts its old ones out on the way up.

1.7.0

* **The one-time password logs, when there are any.** *Settings → **The OTP
  logs*** is a page of its own beside the ISE logs. A VPN sign-in on a site
  that asks for a token is two doors, and the half that happens at the token
  is in no ISE log anywhere — somebody whose password was right and whose
  token was refused looks, in ISE alone, like somebody who simply did not
  finish. One folder per token server, two of them read into one list exactly
  as the two ISE nodes are, and a tab of their own under Logins and under
  Failed attempts. Each line is
  put in words a person can act on — *the token was wrong*, *a one-off
  recovery code*, *right, a step out of time*, *nothing enrolled for this
  account* — and the ordinary case is said quietly so the ones worth reading
  stand out. **None of it is ever judged**: the address on such a record is
  the machine that asked, which is the token server itself. Switched off, not
  one file is opened and nothing anywhere behaves differently.

* **The directory, asked who somebody is.** A name in a log is a string until
  somebody knows whose it is. Where Active Directory is configured, a small
  button beside every name asks it: whether the account is **locked out** or
  **switched off**, whether the **password has expired** and when it was set,
  when the domain last saw it sign in anywhere, how many wrong passwords that
  controller has counted, who the person is, and which groups they are in. A
  machine is in there too, so an 802.1X login says what it runs and when it
  last spoke to the domain. **It only ever reads.** There is no write to a
  directory anywhere in this program — no unlock, no password reset, no group
  change, not one attribute — and the tests prove the client has no way to
  send one. With the directory switched off, none of it appears and every
  page is exactly what it was.

* **An access list for a router this machine does not talk to.** On the
  Firewall page, *Access list for a Cisco router* writes the addresses banned
  **for good** as an IOS extended access list — `deny ip host …` for single
  addresses, `deny ip … 0.0.0.255 …` for ranges, always ending with the SNMP
  line and `permit ip any any` — to save as a file or copy. Addresses on a
  clock are left out on purpose: they lapse here and nothing goes back to
  that router to take one off. The list's name is a setting, IPv6 gets its
  own list, and `isemon --ios-acl` does the same from the command line.

* **The first firewall has a switch of its own.** Before this the only way to
  stop writing to it was to delete its address, which loses the account, the
  port and the key with it. Now it switches off like the second one does and
  everything about how to reach it stays exactly where it was. A
  configuration written before this key existed still means what it always
  meant.

* **Wi-Fi rows say which access point heard it**, which is the only thing in
  those records that says where in the building the machine actually was —
  the "port" a controller reports is one tunnel for the whole of it. A
  controller writes both facts in one field as
  `Called-Station-ID=AP-HQ-8F-EAST:CORPWIFI`: the access point before the
  colon and the network after it, and ISE copies that into `SSID` on some
  records and not on others, so both fields are read and neither is trusted
  to be there. The where-it-came-in column is now one fact per column on
  every network tab: **Switch · Port** on the wire, **Controller · Access
  point · Network** on a radio.

* **What ISE says is said the way it was written.** ISE escapes the
  characters it separates fields with, so a reason arrived as *"…unsupported
  EAP protocol\; EAP-negotiation failed"*. Those are taken back out, on the
  way in and, for rows already here, on the way up.

* **A log file this daemon may not read says so in words**, with the command
  that ends it: *"this daemon runs as isemon and may not read that file"*
  rather than `[Errno 13] Permission denied`, and `isemon --status` prints
  the `chgrp`/`chmod` for each folder it cannot get into. A folder made by
  hand is usually `0700 root:root`, and this daemon has never run as root.
  `deploy/rsyslog-otp.conf` creates the token logs readable from the start.

* **The VLAN column says one thing per VLAN.** ISE writes the VLAN as a
  number on some records and as a name on others, for the same assignment, so
  the column used to show `VLAN 607` on one line and `LAN_Odbor_informatiky`
  on the next. Both are now kept, and where a record named a VLAN without
  numbering it the number is taken from the records of the same site that
  said both — ISE's own pairing rather than a guess, drawn dimmed and saying
  so.

1.6.0

* **The other things ISE answers for are read, kept apart, and never judged.**
  One ISE is rarely only a VPN: the same pair of nodes authenticates 802.1X on
  the LAN and on the wireless, MAB for everything with no supplicant, and
  TACACS+ on the switches — and writes all of it into the same two log files.
  Each record now says which door it knocked on, and the Failed attempts and
  Logins pages have a button per door, the way the Logins page always had:
  **VPN · TACACS · 802.1X LAN · 802.1X Wi-Fi · MAB LAN · MAB Wi-Fi**, each
  with its own count, each showing only its own.

* **Banning is for the VPN and for nothing else.** This is the point of the
  rest of it. A printer that has been failing MAB since Christmas is a
  printer; a laptop with an expired certificate is somebody's Monday morning;
  and the address on such a record is as often as not the switch's own, so
  banning it would take a floor of the building off the network. Nothing but
  a VPN attempt is counted towards a ban, can trip the burst rule or the
  invalid-name rule, or appears under *Busiest addresses*, *Names being
  tried* or *Counting up to a ban*. The pages say so where somebody would
  otherwise wonder where their thousand MAB failures went.

* **A machine is shown as a machine.** For these doors the columns are the
  ones that mean something about an endpoint rather than a person: the MAC,
  the address the network device reported for it, the switch and the socket
  it is plugged into, or the controller, the access point that heard it and
  the network name on the wireless, the VLAN it was put into, what profiled it,
  and how it proved itself. A MAB row has no name to show and says *its MAC*
  rather than an empty cell, which is what MAB is.

* **The chart has three bands to a bar** instead of one: the VPN, the
  switches over TACACS+, and the network — a socket or a radio, with or
  without a supplicant. A thousand unknown MACs on a Monday morning is a
  normal Monday morning on the LAN and would be an emergency on a VPN, and a
  single red bar covering both says neither.

* **A database written by an earlier version sorts itself out on the way up.**
  Every row already here is worked out again from the ISE record kept beside
  it — which is the only reason it can be done at all — and both pages fill
  in behind you while the daemon carries on reading.

1.5.4

* **A directory with more than a thousand groups in it is read properly.**
  Active Directory hands back at most its MaxPageSize - a thousand entries
  unless somebody has lowered it - however many are asked for, and says
  "there is more" with a cookie rather than by sending them. Nothing here was
  handing that cookie back, and the list was capped at four hundred on top of
  that: a domain of three thousand groups looked like a domain of four
  hundred, and nobody could tell which four hundred. The groups are now
  fetched a page at a time until the directory says there is no more, up to
  five thousand at once - and past that the page says so and points at the
  box to type part of a name into.

* **Whole countries can be spared.** *Settings → Whitelist → Never ban these
  countries*: an address the country database puts in one of them is
  recorded, counted and never banned — not by the counting, not by a public
  list, not by a name that was never an account. It is for the country your
  own people dial in from, where a wrong password at six in the morning
  should never lock somebody out of their own VPN. Anything already banned in
  a country added here is let back in at the same moment, and every row that
  is spared says which country spared it rather than an unexplained *never
  kept out*. It is a blunt instrument in both directions and the page says
  so.

* **"The firewalls handed down"**, on the Logins page: every downloadable ACL
  the logins were given, how many logins each, how many rules, when it was
  last downloaded — and, for the ones whose rules cannot be shown, that this
  is the device not needing to fetch what it already holds rather than
  anything missing here. A device downloads an ACL only when it does not
  already hold it, and the name carries ISE's own hash of the contents, so
  the ACL your busiest group uses all day may have been fetched once, long
  before these logs, and never since. It appears the next time the device has
  to fetch it — after a reload, after its cache drops it, or as soon as the
  ACL is edited on ISE.

1.5.3

Measured against a day of real logs and a real database, and then against the
same data grown to what three months of it will be.

* **A record with no address is no longer an address.** ISE writes down its
  own packet handling as well as people's attempts - a RADIUS packet arriving
  twice while the first is still being weighed, a device that never answered
  a change of authorisation - and those carry no address, no name and no
  protocol. Grouped by address they became one enormous row belonging to
  nobody, which sat at the top of *Busiest addresses* with more tries than
  the busiest scanner and was counted among the addresses that had tried. It
  is a record, it is on the Failed attempts page under *Everything else*, and
  it is not an address.

* ...and it is not drawn as an attempt on the VPN either. The chart counts
  what somebody knocked with; the rest are counted and named in the hover, so
  nothing is hidden and nothing is a permanent red floor under the picture
  standing for nobody.

* **The whole ISE record is kept deflated**, against a dictionary made out of
  the records themselves on the machine they arrive at. It is what a database
  mostly weighs: three and a half kilobytes of repetitive JSON per refusal,
  which on a VPN taking eleven thousand a day is forty megabytes a day and
  fourteen gigabytes a year. On a real day of logs the whole database came
  down **5.7 times**, the refusals table alone **eleven times**. Nothing else
  changes: rows written by an older version are read exactly as they were,
  every dictionary there has ever been is kept in the database beside the
  rows, and a copy of the database is still one file.

* **Four things that were slow on a database with a few months in it**, all
  measured on a million rows of the real data:

  | | before | after |
  |---|---|---|
  | the Banned page | 3.9 s | 0.20 s |
  | the front page, a month | 2.4 s, on every poll | 3 ms |
  | <kbd>Ctrl</kbd>+<kbd>K</kbd> on a name | 1.8 s | 0.21 s |
  | the first page after a restart | 3.7 s | at once |

  Which names an address tried, and which addresses tried a name, are counts
  over everything ever recorded - and both were being answered by fetching
  every one of those rows to read the name off it. The name is in the index
  now and the count never leaves it. The front page is kept for a few seconds
  and worked out again behind whoever asked, because with a ban every few
  seconds it was being asked for all of it again every five. The filter lists
  are made before anybody asks, and a page that arrives first waits a quarter
  of a second for them rather than for the whole walk.

* The address popup no longer carries the whole ISE record of every row under
  it: twenty of those were sixty-six kilobytes of JSON for a popup that draws
  two lines of each. It asks for the record when somebody opens one.

* `hours=0` meant *all of it* to the page and *the last nought hours* to the
  daemon, which matched nothing. It means all of it.

* A replay of a log that has more in it than one pass will read now goes round
  until the file is used up, rather than quietly reporting the first eight
  megabytes of it.

* The front page offers **last month** as well, now that asking for it costs
  nothing the second time.

1.5.2

* **Failed attempts is three lists, not one**, with the same buttons along the
  top as the successful logins next door: attempts at the **VPN** over RADIUS,
  attempts at a switch or router over **TACACS+**, and **everything else** —
  the handful of records that carry neither protocol, which used to be
  invisible in a page of RADIUS. Each says how many there are. A burst on the
  network kit no longer disappears into the VPN's traffic.

* **The long explanations have moved off the page and into the hover.** Every
  card keeps one line saying what it is; the paragraph behind it — why it
  works that way, what is counted and what is not, what to do about it — is on
  the heading, where it is there when it is wanted and out of the way when it
  is not.

* **LogHost and *elsewhere* are only said of a TACACS sign-in.** Both come
  from one setting, *Where TACACS sign-ins come from*, which is about signing
  in to a switch and nothing else: a name out of it beside a VPN login is a
  name for somebody's jump box put on a stranger's address, and *elsewhere*
  beside one is an alarm about a rule that was never meant to apply —
  everybody on the VPN comes from elsewhere.

* The counting no longer says **0 of 1**. With the bar for names that were
  never accounts set to one — the usual setting — every address alive is one
  away from it, so the row was showing a fraction counting something that had
  not happened and hiding the two attempts that had. A rule nothing has been
  done towards is not what the row is about; it is still said in the line
  above the list.

1.5.1

* The firewall is **in sync** or **out of sync** rather than *in step*: the
  word everybody who runs one of these already uses. It is the card on the
  front page, the state of each list on the Firewall page, the setting that
  keeps it filled by itself and `isemon --mikrotik`. What that card and the
  words around it talk about is the firewall throughout, rather than the
  router it used to be called.

1.5.0

* **Every filter can be narrowed to one country**, by name rather than by two
  letters: the failed attempts, the logins, each group of bans, the counting,
  the ban history, the whitelist, what the firewall is carrying. The picker
  says the flag, the country's name and how many rows are behind it, and it is
  searched by typing *Germany* as readily as *DE* - which a search box never
  could, because `CZ` also matches every name ending `.cz`. The ban history
  carries the country of the address it was made about, written down with the
  ban, so it keeps saying what it said after the country database is fetched
  again; a history from before this is filled in once, on the first start.

* **The chart tells the VPN from the switches.** Each bar is split in two -
  the VPN over RADIUS underneath, a switch or router over TACACS+ on top - so
  the height goes on meaning everything in that hour while the colours say
  which system it happened to. A burst of refusals on the network kit no
  longer reads as a burst on the VPN. Downloadable ACLs and the commands run
  on a switch are left out of the count: they are not logins, and counting
  them made one person look like two.

* **What an address does while it is banned now counts.** It used to be
  written down and weighed by nothing: the moment an address was out, the
  burst rule and the invalid-name rule could not fire for anything it did
  afterwards, so a scanner served fifteen minutes for a hundred attempts and
  walked back in. Now going on through a ban takes the next rung of the
  ladder, and a burst or a run of names that were never accounts puts it out
  for good - from behind the closed door, which is exactly what those rules
  are for. The same attempts are never charged twice.

* ...and what it was banned for is not charged to it again. An address that
  has served its ban comes back at nought, so one more attempt does not
  instantly ban it for longer, and letting somebody back in by hand is not
  undone a minute later. This is what was behind **6 of 3** sitting on the
  Banned page beside an address that was not banned: the attempts that had
  already earned a ban were still being counted after it ran out. Anything
  that does end up at or over the bar unacted on - a bar lowered under
  addresses already counting, a pass that fell over - is now fetched by a
  sweep within the minute.

* An account the **directory** owns is no longer offered *Change my password*
  at all, and the daemon refuses it if asked: that password lives in the
  domain, and setting one here would make a second way in that nobody looking
  at the domain would ever see.

* The **firewall a VPN session was handed** is proved to be history rather
  than today's answer, with tests: a login shows the rules it was given on the
  day, and one that signed in after the ACL was edited shows the new ones. ISE
  writes the version into the ACL's own name, so the two can never be
  confused; where a session's own download has been thrown away, the copy
  shown is the newest one recorded *at or before* that login and never a later
  edit of it, and the page says which of the two it is looking at.

1.4.0

* A **second firewall**, for a pair in high availability. Switched on, every
  address list is written to both in the same pass, so whichever of the two
  is carrying the traffic already holds every address the other does. They
  share the list names and every rule — one blacklist on two machines — and
  nothing else: each has its own address, account, port and ssh key.

  One of them refusing does not stop the other; the one that answered is
  written, the one that did not is reported against itself, and the next pass
  catches it up. The Firewall page has a line per machine — what each carries,
  how far behind it is, when it was last written to — and says whether the two
  agree. An address counts as banned only when both are carrying it, because
  one of them holding it and the other not is one of them letting the traffic
  through.

* "The router" is called **the firewall** throughout: it is what the thing
  does, and it was never only a router.

1.3.3

* One box that finds anything, top right, and <kbd>Ctrl</kbd>+<kbd>K</kbd>
  from anywhere. It is built around the question this dashboard is asked more
  than any other: type a whole address and it says whether that address is
  banned and for how long, what it has been trying, how many times it has
  been banned before and which public lists name it — with the buttons to ban
  it for good, let it back in, or put it beyond banning, right there. Part of
  an address lists the ones that start with it; a user name lists the names
  being tried; anything else finds the page, the card or the setting of that
  name and leaves it glowing so the eye lands on it.

1.3.2

* Which names an address was trying, wherever the address is. A summary in
  the address popup — every name with how many times each, counted over
  everything recorded and not over the last twenty rows — and the worst four
  on each row of the Banned page and of the counting. One name tried a
  hundred times is a password being guessed; a hundred names tried once each
  is somebody working through a list of accounts, and the two want different
  answers. A name that never existed is marked. Nothing is hidden behind
  "+8 more": pointing at it lists every remaining name with its count.
* The lists inside the address popup are the whole history rather than the
  last twenty, paged and searched by the server, with the same filters the
  Failed attempts page has.
* Active Directory decides what a domain account may do, and goes on
  deciding it. The role is worked out from the groups at every sign-in, and
  now also while somebody is already signed in: at an interval set in
  Settings each signed-in domain account is looked up again, and if their
  groups now earn the other role the account is changed and their sign-ins
  end, so the next one comes back as what they are. Out of both groups, or
  gone from the directory, or switched off there: their sign-ins end and they
  cannot get back in. A directory that cannot be reached changes nothing.
* The two things the domain decides can no longer be set on the accounts
  page. A password set here for a domain account would be a second way in
  that the domain knows nothing about; a role set here would be overwritten
  at the next sign-in. Both are refused, and say where they are decided
  instead. Switching an account off is local, beats the directory, and now
  survives the next sign-in — which it did not, because the sign-in reset it.
* The Banned page opens with its groups closed, and **Clear all** sits under
  the list it acts on.

1.3.1

* Carrying the configuration to another machine now carries the whole of it.
  The export held the accounts and never put them back, and it never held the
  whitelist, the domain's certificate or the router's key at all — so a
  machine rebuilt from one came up with nobody able to sign in, nothing
  protected from banning, and no way to reach the router.

  There are now two shapes of the file. The plain one carries the settings,
  the accounts and what they may do, the never-banned list and who is banned,
  and no password, key or certificate — it can be mailed or committed. The
  complete one carries those too, and is enough to stand a machine up with
  nothing typed in by hand. An import says which of them it was and names
  exactly what it could not bring, because a machine that cannot reach its
  router should say so rather than be discovered.

  `isemon --export FILE [--secrets]` and `isemon --import FILE` do the same
  from the shell. See "Moving to another machine, and rebuilding one" in
  INSTALL.md.
* Second delivery of 1.3.0 was a mistake: it carried the column alignment,
  the row bar, the rebuilt database card and Clear all, and should have been
  its own version. Everything in it is here.

1.3.0

* Active Directory. The dashboard can be signed in to with a domain account,
  over LDAP or LDAPS, with the domain's own root certificate imported in the
  settings rather than dropped on the machine by hand. A name is enough — no
  domain is typed. Two groups decide what somebody may do, and a button goes
  and finds the groups so nobody has to type a distinguished name. A group
  inside a group counts. Somebody who is in the directory is answered by the
  directory and never by a local password of the same name; somebody who is
  not falls back to the local accounts; and a domain controller that cannot
  be reached is not an answer about anybody, so the local accounts still work.
* What the database is costing on disk, and how fast it is growing.
* Everything drawn on the screen says what it is for when pointed at.
* A first attempt with a name like INVALID is now enough on its own for a
  permanent ban, which is what this was built for.
* A copy of the database can be downloaded from the dashboard, and one can be
  put back — from the page or with `isemon --restore`. The file is read and
  checked before anything is replaced, and a copy of what it replaces is made
  first.
* It is quick on a year of records rather than only on a week of them. Asking
  whether an address is on one of the public lists was a walk over every range
  that starts before it — half a table of a hundred thousand — and is now one
  seek; the Banned page went from five and a half seconds to a tenth of one.
  The same for the country of an address. At two million recorded attempts the
  front page went from six seconds to two tenths, and the counts above each
  list stop at twenty thousand and say "more than" rather than reading every
  row there has ever been to print a number.
* The red bar down the left of a row means the address is being kept out right
  now. It used to appear on some banned rows and not others, for no reason
  anybody could see — the mark was drawn before the row it marks existed — and
  it now says what it means when pointed at. The addresses that are only being
  watched carry the state and nothing to press; banning is done from the
  address itself, where the buttons have their words on.
* An address, the name given to it and its flag sit together again. They are
  still three columns so they line up down the page, but the address no longer
  stretches to fill the table and push the other two off to the right.
* The word above a column sits over the column everywhere, measured rather
  than eyeballed — every table on every tab, in every settings pane and in
  every popup. A column of pills was indented from its own heading by the
  pills' own padding, and a size in a right-aligned column had its heading
  flush left.
* The bar that marks a row no longer sits on the first letter of it. It is
  drawn inside the cell, so the only thing keeping it off the text was the
  cell's left padding, and most tables had none.
* Counting up to a ban has a **Clear all**: every address counting up goes
  back to nought. Nothing is deleted, nobody banned is let in, and the ladder
  still remembers who has been banned before — the moment the counting looks
  back to is what moves, and the page says when that was.
* Putting a copy back is where the copies are: in the database card, with a
  Restore beside the Download and Delete of each copy kept, and one place to
  drop a file from somewhere else. Restoring a copy the machine already holds
  sends nothing anywhere.
* Reloading the page opens the page you were on. The address bar was written
  by whichever half of it ran last, which on every load was the settings rail —
  so it said `#settings/logs` whatever was on the screen.

1.2.4

* Nothing is lost over a restart. Where each log was read up to was already
  kept in the database; the count of what has been read out of it is kept
  with it now, so a restart no longer puts every file back to nought — which
  read as "the records are gone" when every one of them was still there. The
  half-arrived record is kept too, so the rest of it has somewhere to go.
* A log rotated while the daemon was stopped is no longer a hole. The file
  that was moved aside is found by its inode, read from where the last read
  stopped, and only then is the new one read from the beginning. It says so
  in the events, because that is the one way records go missing without
  anything looking wrong afterwards. A rotated copy that has since been
  compressed is read too.
* Going back over every log reads the rotated copies beside each file as
  well, so the days before this was installed are read, and it says both
  numbers when it finishes — how many records it read and how many were new.
  Nothing is ever stored twice: every record is kept under the session id ISE
  gave it.
* A burst far past the bar can go out for good at once. The ladder counts how
  many times an address has come back, not how hard it knocked, so a hundred
  failures inside one window and three inside one window were both the first
  step. **A burst this big goes out for good** is the other question, asked
  once; 0 is off.
* Every card on the front page opens. A count, a name, a country, a log file
  or a bar of the chart opens what it is counting — searchable, paged, with a
  way on to the page that holds all of it — and everything that can be
  pressed says so before it is pressed.
* **Signing in with Active Directory**, over LDAP or LDAPS. People use the
  name and password they already have, with no domain in front of it. A name
  that is *in* the directory is answered by the directory and by nothing
  else — the local account of the same name is not consulted, so an old
  local password cannot be a way in past a disabled domain account. A name
  that is *not* in it falls back to the local accounts, and so does every
  name when the directory cannot be reached at all, because a domain
  controller rebooting must not lock everybody out of this.
  - groups decide the role, and a group inside a group counts;
  - **Find the groups** lists what the directory holds and puts one in a
    role by pressing it, so nobody types a distinguished name by hand;
  - **Check it all** says which step failed — reached, signed in, read the
    base, read the groups, are those groups really there;
  - **Try a sign-in** asks the directory one real question and shows the
    whole answer, including the groups it gave back, before anybody signs
    out and finds out the hard way;
  - a certificate authority can be pasted or read from a file, and what it
    is — who it is for, who signed it, when it expires — is read back rather
    than a tick saying the text was stored;
  - the LDAP client is written out in the daemon: this still installs with
    nothing but Python, and an authentication path that stops working when a
    package is missing is worse than one that was never there.
* The database page says what the disk under it has left, how fast the file
  is actually growing — measured daily, not guessed — and how long one will
  hold the other. It also measures the write-ahead log and the copies beside
  it, so "17 MB" here and "260 MB" in `du` is no longer a puzzle.
* Stopping and starting loses nothing and needs nothing: it reads what piled
  up while it was down, judges it, catches the router up once, and carries
  on. There is a test for exactly that.
* Every field in every settings pane lines up. A switch used to be drawn as
  a name with the control beside it while every other setting is a name with
  its field underneath, so a row of four read as ragged because it was.
* **A name that was never an account is kept out for good on the first
  knock.** This is what the daemon is mostly for, and it was not doing it:
  the rule sat below the ordinary bar, so an address had to earn a ban the
  slow way before the fast way was even looked at. It is now the first thing
  asked, and the default is one. On the supplied logs that is 229 addresses
  out for good instead of 4 — and not one of them is an address anybody ever
  got in from.
* The router is written to far less, and far faster:
  - a burst of bans is **one** sync, not one per address. A pass over a busy
    log banned two hundred addresses in under a second and started two
    hundred syncs, each reading the whole list off the router first;
  - the addresses go in **batches** rather than one ssh call each, and what
    actually landed is counted afterwards rather than assumed;
  - a key-authenticated router now gets **one ssh connection** for a whole
    sync instead of one per command, which on a router across a site is most
    of the time a sync was taking.
* The save bar is a card that floats above the page rather than a flat strip
  with a hard line across it and square corners flush to the window.
* `test/rotation.py`: every way logrotate moves an ISE log — rename, copy and
  truncate, a rotation while the daemon was stopped, a copy since compressed,
  several generations in a row, and the same file read down two paths — each
  one checked for a record lost and a record stored twice.
* The Banned page has a second list, folded away: **Counting up to a ban** —
  every address the counting can see inside the window, under the bar, with
  a bar each showing how close it is and which rule it will reach first. An
  empty ban list used to say nothing about whether nothing was happening or
  whether everything was happening one attempt below the line.
* Banning or letting an address back in redraws every row showing it, in
  every list and popup that is open, rather than leaving a row that still
  offers **Ban** after the toast has said it is banned.
* An account that has been switched off is told so when it signs in, instead
  of "that name and password do not go together" — and a right password
  against a switched-off account no longer counts as a wrong one, which five
  of could lock that address out of the dashboard for everybody.
* New on the command line: `--fold` (fold the bans into subnets, or say what
  that would do), `--passed --kind commands|acl|tacacs|vpn|all`, and
  `--mikrotik`, which now opens with whether each list on the router is in
  step and by how much.
* **A name that was never an account** is treated as what it is. ISE writes
  an attempt with no such user as `INVALID`; nobody who works here ever
  produces one. Three of those from one address inside the window and it is
  kept out for good, without climbing any ladder. The names and the number
  are both settings.
* The Router page opens with both lists' state side by side: in sync, out of
  step, or — honestly — cannot be told, with the numbers behind it and the
  addresses on the router that nothing here bans any more.
* **Where TACACS sign-ins come from** is a row per place, with a **+** to add
  another, rather than one line of `address=name` separated by commas.
* A searched, paged list keeps its search box and its pager where they were
  put; only the rows scroll, and the table's own headings stay with them. The
  popups are wider, and no longer hide their pager below the bottom edge.
* The country-list progress counted lines against a total of ranges and so
  finished at "14 000 of 10 306". It counts lines against lines now, and a
  job can no longer report past its own total anywhere.
* Text meant to be read as text is: `<code>` and `<b>` in the help under a
  setting, and a line break in a tooltip, no longer show as markup.
* Every list says which of its addresses are already being kept out, and
  offers the buttons that make sense for one that is: a permanent ban is
  marked as one, a temporary ban shows the clock counting down, and the row
  carries **For good** and **Let in** rather than a second **Ban**.
* Every moment in the whole application is written the same way:
  `dd-mm-yyyy HH:MM:SS`, in the dashboard, in the log and on the command
  line. It used to be left to the browser, which meant `09/23` here,
  `23/09` there and an afternoon written as `05:49 PM`.
* **Where TACACS sign-ins come from**: the addresses people normally reach
  the switches from, each with a name if it deserves one
  (`192.168.251.10=LogHost`). The name is shown wherever that address
  appears, and a sign-in from anywhere else is marked — not blocked, not
  counted against anybody, just the row to read first.
* The marks and the buttons are in columns of their own, so a column of them
  can be read down rather than following the end of an address that is a
  different length on every row. The cards on the front page are the same
  height and start on the same line, which a stray margin had been quietly
  breaking.
* "Put the lists on it" puts everything on the router in one press: the
  banned addresses first, then the country list when one is switched on.

1.2.3

* The Logins page is two lists — AnyConnect and TACACS — and the downloadable
  ACL is no longer a row of its own: it is joined to the login it was handed
  down for and drawn as firewall rules inside it.
* Settings are saved in the database rather than written to `config.json`.
  The file is still read and still wins over the built-in defaults; what is
  saved wins over the file, and every setting says on the page which of the
  three it is standing on. `isemon --set` writes straight to the database
  when the daemon is not answering, and a running daemon takes up a change
  made underneath it — or an edited `config.json` — without a restart.
* The ladder is built rather than typed: ready-made shapes, or a step at a
  time with each length picked from a list.
* A button, and `isemon --rescan`, to go back over every log once and apply
  the bans the records earn — for the day a machine is installed beside a log
  that already holds the last month.
* `--help` and every other command-line output rewritten: two columns, the
  width of your terminal, colour that means something, and the dozen lines
  people actually type at the end of the help. colorama when it is installed,
  the same codes written by hand when it is not.
* The commands somebody runs on a switch are shown inside the sign-in they
  were typed in, the way a VPN session's firewall is: in order, allowed in
  green and refused in red, with the command set that decided beside each.
  ISE writes one record per command and they are no longer forty more rows
  of the same name. They are tied to their session by who, which device,
  which line of it and where from — TACACS+ offers nothing better, because
  ISE writes a different session id on every record.
* Every list in the page is searched and paged: the ban groups, the router's
  entries, the events, the whitelist, the accounts. Nothing is poured onto
  the page whole any more.
* Folding can run by itself, every so many hours, with a floor on how many
  addresses a subnet has to be swallowing before it is worth making. Off by
  default.
* **The interval decides when things are fetched.** "Every hour" means every
  hour. The hour of the day is a separate choice now, off unless asked for,
  and even then it only lines up what is fetched daily or less often — which
  is the one thing it was ever for.
* A setting another setting has taken out of play is dimmed and says so,
  instead of looking exactly like one that is in play.
* The country list on the router has a card of its own on the Router page,
  counted on the router rather than read back. What it is carrying is
  compared with what the last fill actually sent, entries against entries; a
  router that will not say how many is reported as that, not as nought.
* After filling the country list, what is really on the router is counted.
  The adds go in batches wrapped in `on-error={}` so one bad address cannot
  throw away the other hundred and ninety-nine — which also means a batch
  that failed entirely used to look exactly like one that worked.
* The groups on the Banned page fold and unfold with an arrow you can see,
  and each one has its own search box, page size and pager.
* The ban history says how each ban ended with a mark in a column of its own,
  rather than a word beside the address in a different place on every row.
* A button, and `isemon --erase`, to empty the collected data — the records
  read from the logs, the fetched blacklists, the country database, the bans —
  choosing what goes. Accounts, settings and the whitelist are not options
  that could be ticked by mistake: they are not in the list at all.
* Accounts can be switched off and on again, from the page and with
  `isemon --disable-user` / `--enable-user`, instead of only being removed.
* The time of day for automatic fetching now governs only what is fetched
  daily or less often. Set the lists to every hour and they go hourly; the
  hour is there for the country database, which is a hundred megabytes.
  Before this, the hour held everything back and an hourly setting did
  nothing at all.
* What a router says back is cleaned of the terminal's own escape sequences,
  carriage returns and control characters before it is shown, and is drawn in
  a box that scrolls rather than one that wraps — it could be rendered one
  character per line.
* **Fixed:** login records written by an earlier version were all counted as
  AnyConnect logins, because the column that says which kind they are was
  added empty. Every one of them is sorted out on the first start after the
  upgrade, from the ISE record each row already holds — so the TACACS logins
  move to their own list and the downloadable ACLs stop being listed as
  logins.
* **Fixed:** an upgrade from an earlier version could not open its own
  database (`no such column: cpm`). An index named in the schema stood on a
  column that is added to an existing database later, so it was made before
  the column existed. Columns are added first now and the indexes after, and
  a database left half-mended is something `isemon --check` reports.
