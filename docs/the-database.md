# Where everything is kept: the file, MariaDB, or PostgreSQL

Everything this program knows lives in one database: the authentications it
has read, who is banned, the story of every ban, the public lists, the
country ranges, the settings and the accounts. Out of the box that database
is **one file on this machine** and nothing else is installed. It can be
moved into **MariaDB** or **PostgreSQL** instead, and moved back, without
losing a row and without editing anything by hand.

This document is the whole of it: which to choose, how to move, what it
costs, and what to do when something goes wrong.

---

## 1. Which one to choose

The honest answer is that the file is faster and a server is easier to look
after, and that most installations should stay on the file.

Measured on this program's own data, everything on one machine:

| | writes a second | reads |
|---|---|---|
| the file (SQLite) | **4,889** | fastest |
| MariaDB | 2,325 | comparable |
| PostgreSQL | 1,847 | comparable |

A busy ISE pair writes a few hundred records a minute. All three are far
past that, so the choice is not about keeping up. It is about where the data
should be:

**Stay on the file** if this machine is the only one that matters, if
backups of this machine are backups of everything, and if nobody has asked
for the data to live anywhere else. Nothing to install, nothing to keep
running, nothing else to patch, and one file to copy away.

**Move to a server** when somebody else's rules say so: the data has to be
on the database server with everything else, the backups have to be the
database team's backups, the machine has to be replaceable without carrying
a file off it. That is what a server buys — not speed.

A server is not high availability, either. The daemon is one process reading
logs on one machine; putting its database somewhere else does not make a
second daemon possible, and two daemons pointed at one database would be two
installations writing to it, which every road in this program refuses.

## 2. What is kept where

Two things live outside the database, on purpose:

* **Which database to use, and how to reach it** — `db_engine`, `db_host`,
  `db_port`, `db_name`, `db_user`, `db_password`, `db_timeout_s`. These are
  in `/etc/isemon/config.json` and nowhere else. A database cannot hold the
  address of itself, and a machine whose database will not open has to be
  able to be put right from the page.
* **Everything else** — every other setting is in the database, and is
  carried with it when it moves.

`/etc/isemon/config.json` holds a password, so it is `0640` and owned by the
account the daemon runs as. `isemon --database` prints which settings those
are on any version.

**A configuration export never carries the database address**, in either
shape, including the one with the passwords in it. It is this machine's own
answer; carried to another machine it would point the new one at the old
one's database.

Standing a server up on AlmaLinux 9 from nothing, and then doing all of
this with every command written out, is in
[mariadb-on-almalinux9.md](mariadb-on-almalinux9.md) and
[postgresql-on-almalinux9.md](postgresql-on-almalinux9.md). What follows is
the same thing said once, for any distribution.

## 3. Moving to MariaDB or PostgreSQL

Four steps, in order, and each one refuses to be the one after it. Until the
last step this installation carries on exactly as it is, on the database it
is on now, and nothing that is in it is touched by any of this.

### 3.1 Put the driver in place

```bash
dnf install python3-PyMySQL          # MariaDB
dnf install python3-psycopg2         # PostgreSQL
```

or, at install time, `./install.sh --with-db mariadb`, `--with-db postgres`
or `--with-db both`. Without the driver the engine is still offered on the
page and says what is missing.

`isemon --database` says which drivers are here.

### 3.2 Say where the server is

Settings → The database → *Where everything is kept*. Choose the engine and
fill in the host, the port, the name of the database and the name of the
account this program will use. **Leave the password empty** — the next step
makes one. **Nothing has to exist on the server yet** either.

Or from the command line:

```bash
isemon --set db_host=10.1.1.9 --set db_port=3306 \
       --set db_name=isemon --set db_user=isemon
```

Note what is *not* set here: `db_engine`. That is the last step, not the
first.

### 3.3 Make the database and the account

```bash
isemon --database setup --to mariadb
```

It asks for an administrator on the server — `root` on MariaDB, `postgres`
on PostgreSQL, or anyone who may create a database — and uses it for that
one connection. **It is written nowhere**: not into the settings, not into
the database, not into any log. What is kept is the account named above,
which is given rights on that one database and on no other — with a password
this program **generates itself**, writes into `config.json`, and prints once
so that a copy can be kept. The only password anybody has to have is the
administrator's, which they have already, because they set the server up.

It then builds every table, column and index inside it.

The page does the same thing, and asks for the administrator in the same way.

**It is also the upgrade check.** Run it a second time, with the password
already saved, and it wants no administrator at all: it signs in as this
program's own account, finds the database and the account already there, and
goes over the tables — adding whatever this version wants that an older one
never made, and naming anything it could not add. A table dropped by hand
comes back; a column an older version never made is added; the indexes are
put back to the full count. Worth doing after every upgrade, and the reason
the button says *Set it up* rather than *Make it*.

Then:

```bash
isemon --database test --to mariadb
```

which opens it, asks what it is, counts what is in it and closes again.

### 3.4 Carry everything across

```bash
isemon --database move --to mariadb
```

A copy of what is here is written to the backups folder first, always, and
then every record, every ban, every setting and every account goes into the
far side. Nothing here is touched and nothing here changes. On a hundred
megabytes it takes about half a minute.

It refuses to move into a database that has anything in it, because that
would mix two installations. If a first attempt left something behind:

```bash
isemon --database empty --to mariadb      # never the one in use
```

### 3.5 Start using it

```bash
isemon --set db_engine=mariadb
systemctl restart isemon
isemon --database
```

The restart is not optional: every thread that is reading a log right now is
holding the database that is open.

On the page this is one button — *Start using it* — which writes the same
setting and restarts the daemon for you.

Afterwards the file on this machine is a spare copy of an installation that
has moved. Delete it when you are happy:

```bash
rm /var/lib/isemon/isemon.db*
```

### 3.6 The server's own settings

A database server is installed with settings for a small machine. *Settings
-> The database -> Tune it for this machine* reads what the machine the
server runs on has - memory, processors, whether the disk is an SSD (and, in
a virtual machine where every disk says it spins, how long a small write
takes) - and shows the settings worked out for it beside what is there now.
They are put in only when somebody presses *Put it in*, by an account that
may: this program's own where it has the right, otherwise an administrator
typed into the popup for that one request. The administrator is not kept -
not in config.json, not in the database, not in the log. What was there
before is kept, and *Put back as it was* goes back to it.

* **PostgreSQL**: `ALTER SYSTEM`, then a reload. `shared_buffers` and the
  other settings that take only at a start wait for a restart, which the
  page does where PostgreSQL is on this machine and install.sh allowed it.
* **MariaDB**: `SET GLOBAL`, at once; the file to keep it over a restart is
  shown to copy. The card says when a restart has since undone it.
* A server on another machine: PostgreSQL's administrator may read its
  memory and processors off the server itself; otherwise they are typed in.

The numbers are the ones in [postgresql-tuning.md](postgresql-tuning.md).

## 4. Coming back to the file

The same four steps with `--to sqlite`, and then the server can be
uninstalled:

```bash
isemon --database move --to sqlite
isemon --set db_engine=sqlite
systemctl restart isemon
```

If the file is still sitting there from before, it holds an old copy of this
installation and the move refuses it. Move it aside first:

```bash
mv /var/lib/isemon/isemon.db /var/lib/isemon/isemon.db.old
```

This is the reason it is safe to try a server at all: going back is the same
short list of steps, and at no point is there only one copy of anything.

## 5. What stays the same

Everything. It is the same program with the same pages on all three:

* **Copies** — a copy is written as a **portable SQLite file** whatever the
  installation runs on, so a copy made on MariaDB restores onto PostgreSQL
  or onto the file. That is also how moving works, which is why all three
  are as tested as each other. It is also why the copies are `.db` files on
  a server installation: each one says inside itself which database it was
  taken off, and the list shows that in the *Taken off* column.
* **The nightly dump** — not the same thing; see §5.1 below.
* **Restoring** — a copy goes back into whichever engine is live. A dump
  goes back into the engine it came off, and is refused anywhere else.
* **Checking** — *Check it* asks the engine to read the whole database
  through: `PRAGMA integrity_check`, `CHECK TABLE`, or a read of every table.
* **Tidying up** — *Tidy it up* is `VACUUM` on the file, `OPTIMIZE TABLE` on
  MariaDB and `VACUUM (ANALYZE)` on PostgreSQL.
* **Erasing, folding, the nightly dump, retention** — the same.
* **How big it is** — the file's size on disk, or what the server says it is
  holding. A server counts space it has allocated and not yet used, so the
  same data reads larger there. That is the server's accounting, not growth.

### 5.1 Two kinds of backup, and which is which

There are two, kept in two folders, and they are for two different things.

| | the copy | the dump |
|---|---|---|
| where | `/var/lib/isemon/backups` | `/var/lib/isemon/dumps` |
| made by | this program, reading the rows | the engine's own program |
| what it is | a SQLite file, always | `.pgc`, `.sql.gz`, or on the file a `.db` |
| goes back into | **any of the three engines** | **the engine it came off** |
| size, on 238 MB of PostgreSQL | 100 MB | 10 MB |
| made when | *Make a copy now*, before every restore, before every move | every night, and *Make one now* |
| read by | this program, and any SQLite tool | `pg_restore`, the `mariadb` client — **without this program** |

The **nightly one is the dump**, because that is the one that is made
fourteen times over: a tenth of the disk, and in a format the database team
already knows. It is `pg_dump --format=custom` on PostgreSQL,
`mariadb-dump --single-transaction` on MariaDB, and on the file SQLite's own
online backup — which is that engine's dump format, and needs nothing
installed. All three are consistent while the daemon carries on writing.

The **copy is what carries an installation anywhere**: to the other engine,
to a machine with no server on it, to a laptop with a SQLite browser. It is
what is made before a restore, so that a restore can itself be undone. *Make
a copy now* is one press away and always has been.

Both lists sit on the same page, under *The database*, each with **Download**,
**Restore** and **Delete** against every file, and a box to drop one into
that was saved somewhere else. Whatever is dropped is **read before anything
happens**: a dump of the wrong engine is named and refused, and so is a file
with no full administrator in it, because putting that back would lock
everybody out.

The client program has to be on the machine with isemon, not only on the
server: `dnf install postgresql` or `dnf install mariadb` — the client
packages, not the servers. `./install.sh --with-db postgres` puts it there
along with the driver. Without it the nightly one falls back to a **portable
copy**, which needs nothing at all, and the page and the log both say that
is what is happening.

```bash
isemon --dump                 # one now, in the engine's own format
isemon --restore FILE         # a copy or a dump; it reads which
isemon --database             # says which the nightly one will be
```

### 5.2 A full backup: the copy with its keys (1.10.222)

A copy holds everything this program knows except three files that are on
purpose kept beside the database rather than in it:

| File | What it is | Without it, after a restore on a new machine |
|---|---|---|
| `/var/lib/isemon/settings.key` | seals every password and private key in the database: the routers', the directory's, the ban feed's, the dashboard certificate's | every one of them has to be typed in again |
| `/var/lib/isemon/banfeed.key` | the key in the published ban list's URL | every firewall fetching it needs a new URL |
| `/var/lib/isemon/known_hosts` | the routers' ssh host keys | each router is met as a stranger once |

A **full backup** is the same copy with those three files inside it (a table
of their own, `isemon_carried`), and this machine's `config.json` beside them
to read - with the database password taken out of it, and never used when it
is put back. Put back on a freshly installed machine, that machine is this one
again: the certificate and its key, the firewall and who may reach which
page, the routers' passwords and keys, all of it, with nothing to type in.

- **Settings → The database → Download a full backup**, or
  `sudo isemon --backup --full` (into `/var/lib/isemon/backups`, mode 0600) -
  for example from cron, then off the machine.
- **Putting one back** is the ordinary restore - the page or
  `isemon --restore FILE`. It says before anything happens that the file is a
  full backup and what it carries. The keys go in place after the database;
  the ones there before are kept beside them as
  `settings.key.before-restore-YYYYMMDD-HHMMSS` (and so on), so the copy of
  what was replaced can still be opened. The table never stays in the live
  database: an ordinary copy made afterwards carries none of it.
- **It is as secret as the key itself.** The nightly dumps and the ordinary
  copies carry none of it, as before.

After a restore the daemon asks root at once to put in what the database
carries - the certificate, the lists, the firewall
([firewall-and-access.md](firewall-and-access.md)).

## 6. When the database is not there

A machine set to a server whose server is down does not refuse to start.
An empty database is opened in its place, off to one side, and:

* **the daemon starts, and the dashboard opens**, with the sign-in page
  saying in as many words which database would not open, what it said, and
  the two commands that put it right;
* **nothing is read out of the logs, and nobody is banned** — reading a day
  of authentications into something nobody will keep, and banning people out
  of it, is not a service;
* **no nightly dump is made either**, and the ones already in the dumps
  folder are left exactly where they are. A copy of the empty stand-in would
  be worse than none: the copy is followed by throwing the oldest ones away,
  so a week of an unnoticed outage would replace every real copy with a copy
  of nothing. It is said in the daemon's log once a day;
* `isemon --status` and `isemon --check` say the same thing, and
  `isemon --database` prints it first.

**Nobody can sign in while it is down**, and that is deliberate rather than
an oversight: the accounts are in the database that is missing. The stand-in
is empty and no administrator is made on it — a machine that invented one
during an outage would be a machine where an outage makes a new way in, and
the note saying what the real first password was would have been written
over. So the fix is from the command line, on the machine, as root:

```bash
isemon --database test --to mariadb     # what is actually wrong
```

and then either put the address right —

```bash
isemon --set db_host=10.1.1.9
systemctl restart isemon
```

— or go back to the file, which needs nothing and is always there:

```bash
isemon --set db_engine=sqlite
systemctl restart isemon
```

The file will be whatever was in it when the installation moved off it,
which is why it is worth keeping for a few days after a move rather than
deleting it the same afternoon.

## 7. When something is wrong and nothing says what

Settings → About → **Write down everything it does**, or:

```bash
isemon --set debug=1
tail -f /var/log/isemon/isemon.log
isemon --set debug=0          # afterwards: it is loud
```

With it on, the daemon writes down every decision, every command sent to the
router, every read of the logs, every request the dashboard makes, and
**every statement put to the database with how long it took**. Thousands of
lines a minute on a busy machine, which is why it is for finding one thing
and then switching off again.

Two kinds of line are written down whatever that switch says:

```
[warn] sql refused by postgres after 0 ms: INSERT INTO ... | 'ise1', 1790363072.5 | invalid input syntax for type bytea
[warn] sql took 2.2 s on postgres: INSERT INTO geo_ranges ("lo", "hi", ...) | '2000 row(s)'
```

A statement that failed, with the values it was given — the same statement
with different values is most of what goes wrong — and a statement that took
more than two seconds. On a database server one slow statement is the whole
difference between a page that draws and a page that hangs, and from the
outside those two look the same.

## 8. What each engine needed teaching

Kept here because it is what somebody will want to check when something
looks wrong on a server and right on the file.

* **Values** arrive as `?` in this program and as `%s` in the other two,
  and a `%` in a statement means something to them. Translated on the way
  out, once, and never inside quoted text.
* **Words they have taken**: `key`, `by`, `before`, `after`, `groups` are
  columns here and reserved words there. Quoted where they are names and
  left alone inside strings — a ban recorded as *"banned by key"* is a
  sentence, not three keywords.
* **Which index to use.** SQLite's `INDEXED BY` is an instruction; MariaDB's
  `USE INDEX` is only a suggestion, so it is given `FORCE INDEX`. This is
  not cosmetic: on 700,000 country ranges the engine's own guess walked half
  of them for every address the Banned page draws — 166 seconds for one
  page, against 1.9 seconds once it was told.
* **Transactions.** A database server keeps a connection that has read
  something inside a transaction looking at the same rows for ever until it
  is told otherwise. This daemon has threads that live for months, so every
  connection commits as it goes, and the places that need several statements
  to be all-or-nothing say so.
* **Counters.** Rows carried in bring their own numbers; PostgreSQL's
  sequences do not notice, so they are set to where the rows are afterwards.
* **Bytes.** PostgreSQL hands back what it stored as bytes in a
  `memoryview`; every packed address and every packed detail in this program
  is compared and written as `bytes`, so that is what comes out.
* **Words and bytes in one column.** SQLite is typeless and this program
  leans on it: the ISE record beside an authentication is stored as words
  when it is short and as packed bytes when it is long, in the same column,
  so a real database holds both. The other two have a type there and take
  one and refuse the other, so which columns hold bytes is read out of the
  schema and every value is carried into the type the far side has.
* **Whole batches.** psycopg2 sends a statement once per row; on three
  quarters of a million country ranges that is three quarters of a million
  round trips. They go as one statement per batch instead, which is the
  difference between six minutes and seventeen seconds. MariaDB's driver
  does this for itself.

Every one of these is checked by `test/engines.py`, which runs on a machine
with no database server at all — and, when one is there, carries a whole
installation into it and back out again and holds it against what went in.

## 9. The commands

| | |
|---|---|
| `isemon --database` | which one it is, what is in it, which drivers are here |
| `isemon --database test --to X` | reach it, say what answered. Changes nothing |
| `isemon --database setup --to X` | make the database, the account and its rights |
| `isemon --database move --to X` | carry everything into it. Changes nothing here |
| `isemon --database empty --to X` | throw away what is in the other one |
| `isemon --set db_engine=X` | which one to open next time |
| `isemon --backup` | a portable copy, now |
| `isemon --dump` | a dump in the engine's own format, now |
| `isemon --restore FILE` | put either one back; it reads which it is |

`--to` never changes which database is in use. That is `--set db_engine`,
and a restart.
