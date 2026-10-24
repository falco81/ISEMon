# The tests

Nothing here needs a network, a router, an ISE node, a database server or a
running daemon. Each one makes its own database in a temporary folder and
leaves nothing behind.

Everything except `engines.py` is written for the database this program keeps
by default: one file, made fresh for each run. `engines.py` is the one that
is about the other two engines, and it still needs nothing installed — what
can be checked without a server is checked without one, and the rest happens
only if a server is named.

```bash
./test/checks.py               # the engine
./test/endpoints.py            # the API
./test/router.py               # the whole router half
./test/rotation.py             # log rotation: nothing lost, nothing doubled
./test/directory.py            # Active Directory, against a mock one
./test/ranges.py               # is this address on one of the lists
./test/carry.py                # export here, import onto a bare machine
./test/doors.py                # one ISE, several doors, and only one of them judged
./test/eduroam.py              # the visitors' network: a different RADIUS, a different log
./test/clocks.py               # a log line with no zone in it, read on a machine in the wrong one
./test/names.py                # turning an address back into the machine it is
./test/engines.py              # the file, MariaDB and PostgreSQL: the same installation in each
./test/tacplus.py              # a TACACS+ daemon of the site's own, on real lines of its log
./test/pour.py                 # big batches poured into PostgreSQL: nothing different for it
./test/stopping.py             # a search somebody stopped is stopped on the database too
./test/split.py                # PostgreSQL's biggest tables split by day: nothing different for it
./test/replay.py /var/log/remote   # real logs through the real reader
```

## carry.py

Two machines: one set up the way a real one is, one that has never been run.
The configuration goes from the first to the second and everything on the
second is held against the first — settings, accounts and what they may do,
which account was switched off, the never-banned list with its notes, who is
banned. Both shapes of the file, because the dangerous mistake is thinking the
safe one is the complete one: what is tested for the plain export is that it
carries no password, no key and no certificate **and says so**, so that a
machine built from it does not quietly fail to reach the router.

## ranges.py

The one question a public blocklist exists to answer, asked the fast way and
held against the slow way. Every prefix length from /1 to /32 and /1 to /128,
both families, both sides of every boundary, a thousand addresses against
twelve thousand ranges answered identically by a seek and by reading every
range there is — and the country database beside it, where the same seek has
to work without merging two countries into one.

## checks.py

The things that are easy to get wrong and hard to notice. Every check in it is
one that broke something once, or would have:

* three syslog lines making one record, out of order, half-arrived, with a
  field cut across the join and an escaped comma inside a value
* the ladder climbing one step per **ban**, not per attempt, and forgetting
  after a month
* failures split across the two nodes counted together — the whole reason
  both log paths are read
* the same record read twice not counted twice
* a device outside `watch_devices` earning nothing while still being recorded
* an address on the whitelist earning nothing at all
* folding refusing to swallow anything whitelisted, and undoing putting every
  address back as it was
* an IPv6 address written two ways not reading as two
* the last full administrator being impossible to demote or remove
* every setting that should be refused, being refused
* a log file rotated, emptied, appended to, and caught mid-line

## names.py

Turning an address back into the machine it is, against `mockdns.py` rather
than against a name server. Two servers with two different zones - the
offices in one, the DMZ in the other - because that is the shape this was
written for: the servers are asked in the order they are written and the
first one with a NAME wins, so a server saying it has never heard of an
address has to be passed over rather than believed.

The failures are most of it, and none of them can be arranged with a real
server: one that never answers, one that refuses, one that has never heard
of the address, and a reply cut short so it has to be asked again over TCP.
And the rule the whole feature lives under, checked rather than promised:
reading a log never sends a packet, and switched off nothing is sent at all.

## directory.py

Active Directory, against `mockldap.py` rather than against a domain. Signing
in, the roles that come from group membership, nested groups, a directory
that has gone away in the middle of the day, and the paging that a domain of
thousands of groups needs.

The suffixes a directory answers for are in here too - the mock publishes
them the way a domain controller does - because which directory is asked
about a name is decided by them, and a program that had a site's domains
written into it would be a program that works at one site.

There are two directories in here as well: the one people sign in against and
a second one, asked only who somebody is when the first does not have that
name. What is proved about the second is mostly what it may *not* do —
nobody signs in against it, no account is made from it, it is not asked for
groups, and switched off it is not asked at all.

It also covers what this program asks a directory about a person - locked
out, switched off, password expired, who they are, which groups - and the
thing worth proving twice: that **nothing here writes to a directory**. The
whole client is open, bind, search and close, and the test asserts that list
so that a fifth method could not be added without somebody noticing.

## endpoints.py

Starts a real daemon on a spare port and asks it things — as a full
administrator and as a readonly account, because "the page works" and "a
readonly account cannot ban somebody" are two different questions and only one
of them is obvious. Every endpoint the dashboard depends on is in here.

## router.py

The part nobody can test on a live firewall without either trusting it or
breaking it. `mockrouter.py` is installed as `ssh` for the length of the run
and answers the way RouterOS does, including saying *already have such entry*
when it should.

It proves that a sync sends what it should and nothing more, that an entry
somebody put on the same list by hand survives every operation, that another
address list entirely is never even named, that a country list of thousands
of prefixes goes out in batches rather than one ssh call each, and that taking
ours off takes only ours.

## doors.py

One ISE answers for the VPN, for the switches over TACACS+, for 802.1X on the
LAN and on the wireless, and for MAB — and writes all of it into the same two
files. The records in here are the shapes two real installations write.

What it proves is mostly one thing: **only the VPN is ever judged**. A MAC
failing MAB over and over earns nothing, a supplicant that cannot agree on a
protocol earns nothing, a wrong password on a switch earns nothing, and three
attempts at the VPN earn exactly what they always did. The address on a MAB
refusal is as often as not the switch's own, and banning it would take a floor
of the building off the network.

Beside that: that each record is sorted to the door it knocked on (including a
VPN record from an older ISE that carries no flow type at all), that a machine
keeps its MAC, its socket or its network name, its VLAN and what profiled it
while a VPN record is given none of those, that each tab and each band of the
chart holds its own and nothing else, and that a database written by an older
version — every row with no door on it — is sorted out again on the way up
from the records kept beside them.

Also in here: the token log, when a site has one. That it is read into the
same two tables and tagged as its own door, that a name written
`jnovak@example.int` is stored as the same `jnovak` the ISE logs use, that
the loopback in those records is not written down as an address, that none of
it can ever earn anybody a ban, that the same line read twice is one attempt
- and that switched off, not one of those files is even opened.

## eduroam.py

The visitors' network is not ISE at all: it is a FreeRADIUS of this site's
own, writing two files rather than one. Four things are at stake and each of
them is somebody's afternoon.

**A refusal is one refusal.** FreeRADIUS writes two lines about each one — the
reason (`Invalid user`, or `Login incorrect (Home Server says so)`) and then
the bare `Login incorrect` — both carrying the same request number. Taking
both would double every number on the page. **A login is one login** as well:
the `Login OK` written when the identity inside the EAP tunnel checks out is
not a second person signing in, and the tests hold both of those, including
when the pair is split across two reads of a file being followed.

**A password is never kept.** FreeRADIUS writes what was offered on a refusal
— `[somebody/hunter2]` — and the tests look for that password in the row, in
the record kept beside it and in everything the page is handed.

**Nothing here is ever judged.** The only address on one of these lines is the
wireless controller the request came through, and banning it would take the
whole of eduroam off the air.

Beside that: that the accounting file is found by the day it is named after
and followed across midnight, that what it says about a session — the access
point, the network, the VLAN, the address, the name the machine calls itself
— is joined to the sign-in by the MAC and is missing rather than invented
where the controller has not sent it yet, that an older accounting record
arriving after a newer one does not undo it, that `Unknown` is not the name of
a machine and `NULL` is not the name of an institution, that the accounts on
the ignore list are in no table anywhere, and that a re-sorting does not turn
any of it into "something else".

And the access list for a Cisco router: that a range comes out with the
wildcard mask IOS wants, a single address as a host, an address on a clock
not at all, and that the two lines which must end the list are always the
last two.

## engines.py

Everything this program keeps can be kept in one file on this machine, in
MariaDB or in PostgreSQL, and this is what holds the three to the same
answer.

Most of it runs on a machine with nothing installed, because the part that
goes wrong when this program meets a database server is almost never the
server — it is what this program says to it. A `?` where `%s` was wanted, a
column called `key`, `INSERT OR IGNORE`, `PRAGMA`, a `%` inside somebody's
password read as a placeholder: all of that is decided before anything is
sent, so all of it can be held against a known answer with no server
anywhere. So can the rule that matters most on the page: that the settings
which say *where* the database is come out of `config.json` and are written
back to `config.json`, never into the database they describe.

Then, if there is a server to hand, the same installation is carried into it
and back out again and held against what went in — every record, the bans,
the settings, the accounts, and the compressed detail beside a refusal,
which is the one thing in here that is neither text nor a number:

```bash
ISEMON_TEST_MARIADB='127.0.0.1:3306:isemon:isemon:the password' \
ISEMON_TEST_POSTGRES='127.0.0.1:5432:isemon:isemon:the password' \
    ./test/engines.py
```

Without those it says the server part was skipped, which is not a failure.

Give it an administrator on the same server as well and it also does what
*Set it up* does, for real, in both of that button's two positions: from
nothing — an account and a database made, with a password this program
generates rather than asks for — and then again over a database that is
already there, where no administrator is wanted at all. For the second one a
table, a column and an index are deliberately taken away first, the way a
version three releases older would have left them, and the check is that
opening it puts all three back:

```bash
ISEMON_TEST_MARIADB='127.0.0.1:3306:isemon:isemon:the password' \
ISEMON_TEST_MARIADB_ADMIN='root:the root password' \
ISEMON_TEST_POSTGRES='127.0.0.1:5432:isemon:isemon:the password' \
ISEMON_TEST_POSTGRES_ADMIN='postgres:the postgres password' \
    ./test/engines.py
```

Those two make and then unmake a database and an account called
`isemonset`, so nothing they do touches the one named above. An
administrator's password is a value in the environment of that one command
and goes nowhere else — which is the same promise the button itself makes.

Two of the checks in there are the ones a file never made anybody think
about. A database server keeps a connection that has read something inside a
transaction looking at the same rows for ever until it is told otherwise —
and this daemon has threads that live for months, so a reader that went on
reading would have gone on seeing the same authentications all week. And a
write that fails half way through still has to leave nothing behind, which is
why there is a transaction at all.

## tacplus.py

A TACACS+ daemon of the site's own, on real lines of its log. The shapes are
the ones a site sent: 251,533 lines, five years of three accounts on eighteen
switches, and every single one of them a command — which is the whole of
the difficulty. tac_plus writes nothing about sessions on most installations,
so the sitting a command was typed in has to be read out of the commands, and
it has to come out the same way twice or one session is drawn as two. Held to
that here, with the same lines read twice over and a daemon restarted in the
middle of a sitting.

Also what a stamp with no year in it means in a file holding five years
(nothing may land in the future), that the daemon's own housekeeping is not
read as somebody being turned away, that a command on a switch is not a login,
that nothing here can ever be judged — and that the whole of it can be
counted and erased on its own.

## replay.py

Points the real reader at real ISE logs and prints what it made of them: how
many records, how many addresses banned, for how long and why. Then it throws
the read offsets away and reads every file from the beginning again, and
proves that nothing was counted twice.

```
./test/replay.py /var/log/remote
```

## rotation.py

...and, since 1.9.6, the rotated copy that has been compressed. The pass back
over every log reads those too, and it used to unpack the first 256 MB of one
into memory and work from that copy — which stopped there, silently. The test
makes a compressed copy that unpacks to several read-blocks (the block size is
made small for the test, so a small file crosses as many of them as a real one
crosses of the real size) and holds that every record in it is read, that
asking again once it is finished gives nothing rather than starting the file
over, that the handle is let go, and that a second pass adds nothing.

Since 1.9.7 it also holds the folder a machine really ends up with: the live
file, `.1`, `.2.gz`, `.3.bz2`, `.4.xz`, nineteen `-2026MMDD.gz` and a plain
`-20260920` — two naming series side by side, because the day somebody adds or
removes `dateext` the old one stops being added to and stays there. A full
import has to take the lot; it used to take twelve of them and no more.

## clocks.py

ISE writes the offset that was in force on every record — `+02:00` — so an
ISE record says exactly which second it happened in and nothing on the
machine reading it can move it by a second. The token log and the eduroam log
write `Sep 25 10:21:25` and nothing else, and a time like that is not a
moment until somebody says where it was written. The reader has one thing to
go on: the zone of the machine doing the reading.

Where the two agree that is right and costs nothing, which is why it went
unnoticed. Where they do not — a machine left on `America/New_York` while its
syslog carried Prague time — every one of those records is six hours from
where it belongs and **nothing looks wrong**: the lines parse, the rows
arrive, the counts count, the page draws. The only thing the matter is which
second they are filed under, and the only way to see it is to hold the screen
up beside the log.

So this suite is that machine, reproduced: the same line, read on a machine
set to New York, landing at 15:32 UTC when it happened at 09:32. Then the
setting that says where those logs are written — a zone name, which knows
when summer time starts, or a fixed offset for a machine with no zone
database — and the same line landing on the right second. Then the proof that
none of it touches ISE, whatever it is set to.

Then the part that matters more than either: **a line dated after the moment
it was read is impossible**, and that is what the daemon watches for. It is
only asked of the two logs that carry no zone, it is not asked of a clock a
minute out or of a log being read for the first time, it is said out loud
once rather than every five seconds, and where the difference is one a zone
could actually be it names the offset those lines are really written at —
rather than `+01:45`, which would send somebody to change the one thing that
is right.

And afterwards: erasing the token records or the eduroam records takes those
rows and nothing else — not the ISE records, not each other's — and forgets
where those files were read up to, so the next pass reads what is still in
them again, with the clock as it now is.

## pour.py

From 1.10.136 a big batch of one insert goes to PostgreSQL with `COPY` and
then one `INSERT ... SELECT`, instead of one long statement. This suite
writes the same nine thousand firewall lines both ways and compares every
row and every count. It then tries the awkward cases one at a time:

- text that `COPY` reads in its own way;
- rows that are already there;
- counts added on top of counts;
- a value `COPY` refuses, which must go the old way inside the same
  transaction;
- statement shapes it must leave alone.

On the file engine and MariaDB nothing is poured, and the suite checks that
their writing is unchanged. Run it on PostgreSQL through the engine runner to
exercise `COPY` itself.

## stopping.py

From 1.10.139 the page gives each of its long searches a name. Stop, Clear,
or a newer search in the same list stop it on the database as well as in the
browser.

This suite starts a search that would take half a minute on whichever engine
it runs against, stops it a moment later, and checks four things:

- it is over within seconds;
- it is answered as stopped, not as a fault;
- nothing after the stopped statement ran;
- the connection is fine afterwards.

It also checks that only the session that asked can stop a search. Run it
through the engine runner to exercise PostgreSQL's cancel and MariaDB's
`KILL QUERY` as well as SQLite's interrupt.

## split.py

From 1.10.141, on PostgreSQL, `fw_events`, `fw_roll` and `win_events` are
split by day. An existing table is split in place.

This suite fills two PostgreSQL databases with the same lines, one split and
one not, and checks:

- splitting a table that already holds rows loses nothing and changes
  nothing;
- every later row lands somewhere, whatever its time: an existing day, a day
  not made yet, a day long gone, or the part from before the split;
- the lists, searches and counts read the same on both;
- letting old rows go over six days leaves exactly the same rows on both,
  while the split one drops whole days and whole kinds of row in one step;
- a marked domain event survives;
- the domain's counted answers still agree with the rows;
- the days ahead are made, and a row that arrived early is moved into its
  day;
- deleting part of a table takes only what was asked;
- a split table is one table to everything that lists, copies or counts
  tables.

On SQLite and MariaDB it checks the new columns, the new index and the
searches.

Run it through the engine runner on PostgreSQL. A server superuser is needed
to make the second database.

## i18n.py

From 1.10.153 the page can be shown in another language, from the files in
`web/lang/`. This suite checks:

- each language file is valid JSON, with its `_meta` first and flat, the
  same IDs as `en.json`, and every translation keeping the `{0}` slots, the
  inline tags, the text inside `<code>` and its leading and trailing spaces;
- Czech is translated through;
- the page hands out a language as a script, only what differs from the
  English, and nothing for a code that is not a file;
- with the folder gone, or a file broken, the page is English and loads
  nothing;
- the daemon keeps each person's choice, checks it, carries it in the
  settings file and drops it with the account;
- what the page's code reads back off the page it reads in English.

It needs `php` for the middle part and skips it without.

## trafficready.py

From 1.10.154 the Traffic page's overview is worked out behind the daemon
and kept (`fw_ready`). This suite checks:

- what is handed out is the same as an overview worked out while waiting;
- the first look waits a little; one that takes longer is reported as being
  worked out, never drawn as zeros;
- a window asked for is kept ready from then on, one nobody asks for in
  three days is let go, and the last 24 hours of every firewall is always
  kept;
- an old one is handed out at once and worked out again behind the page,
  and a slow one less often;
- a window chosen by its dates, a window not in the drop-down, and the
  setting off all go the old way;
- erasing the firewall's lines erases these too;
- `--rollup`, `--rollup --json` and `--rollup-build traffic` from a
  terminal.

## banning.py

From 1.10.155. The faults found in the banning, each made to happen:

- a burst read from a backlog is out for good, judged one record at a time;
- a range put in `never_block` outside the page lets its bans go, and a
  spared address is never held longer;
- a ladder of `forever` alone bans for good, and nothing may follow
  `forever`;
- short bans are not folded into a street for good, and whitelisting one
  address in a folded street puts the attackers back one by one;
- erasing the ban history does not ban anybody again for what they served;
- the expiry sweep does not delete a ban lengthened while it looked.
