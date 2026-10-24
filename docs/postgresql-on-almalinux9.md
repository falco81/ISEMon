# PostgreSQL on AlmaLinux 9, and moving isemon into it

From a machine that has never had a database server on it to an isemon
running entirely on PostgreSQL, with nothing typed twice and nothing lost.
Every command is meant to be pasted as it stands **except where a word is in
CAPITALS** — those are yours to replace: `SERVER` is the database server's
address (`127.0.0.1` when it is this same machine), and the passwords are
whatever you choose.

Once it is running and the domain events start to run to millions, see
[postgresql-tuning.md](postgresql-tuning.md) — the packaged defaults are set
up to start on anything, not to answer this.

Read [the-database.md](the-database.md) first if you have not decided
*whether* to do this. The short of it: the file on this machine is faster
(4,889 writes a second against PostgreSQL's 1,847), and a server is for when
the data has to live with everything else and be backed up by whoever backs
that up. Neither is more correct.

Two shapes of this are common and the difference matters in exactly two
steps:

* **the server on the isemon machine itself** — nothing crosses a network,
  there is no firewall to open, and `pg_hba.conf` needs one line rather than
  two;
* **the server somewhere else** — the database team's machine, say. Then
  §2.4 and §2.5 are not optional.

---

## 1. Before you start

On the isemon machine:

```bash
isemon --database                    # what it is on now, and what drivers are here
isemon --status                      # it should be reading, and calm
isemon --backup                      # a copy of what you have, before anything
du -h /var/lib/isemon/isemon.db      # roughly how much is about to move
```

For scale, a real installation with a year of ISE records, the country
database and the public lists comes to about **210 MB on PostgreSQL**:

| | on PostgreSQL |
|---|---|
| `geo_ranges` (the country database, 716,496 rows) | 138 MB |
| `failed` (refused authentications) | 30 MB |
| `passed` (successful logins) | 19 MB |
| `feed_ranges` (the public lists) | 12 MB |
| everything else | ~1 MB |

The same data is about 105 MB as a file. PostgreSQL stores each row with a
visibility header and keeps its indexes apart, so the same installation reads
larger there — that is how it works, not growth.

## 2. The server

### 2.1 Install and initialise it

AlmaLinux 9 carries PostgreSQL in AppStream, and **the default is
PostgreSQL 13** — not the newest one. `dnf module list postgresql` shows
what this machine is offered; 15 and 16 are usually there as streams:

```bash
dnf module list postgresql            # 13 is the default; 15 and 16 are offered
dnf install -y postgresql-server postgresql-contrib
```

For a newer one instead, before installing anything:

```bash
dnf module enable -y postgresql:16
dnf install -y postgresql-server postgresql-contrib
```

Either is fine. isemon asks nothing of PostgreSQL that 13 does not have.
Which one you get does change one thing below, and it is the thing that
wastes an afternoon — see §2.2.

```bash
postgresql-setup --initdb
systemctl enable --now postgresql
systemctl status postgresql --no-pager
psql --version                        # what you actually got
```

`postgresql-setup --initdb` is the step people miss: unlike MariaDB, a
freshly installed PostgreSQL has no data directory until it is told to make
one, and the service will not start without it.

The data lives in `/var/lib/pgsql/data`, and the configuration is in there
too — not in `/etc`.

### 2.2 How passwords are stored, and then a password

**Do these two in this order.** On PostgreSQL 13 — the one AlmaLinux 9 gives
you by default — passwords are stored as **md5** unless the server is told
otherwise; upstream only changed that default in 14. If you set a password
first and turn on `scram-sha-256` afterwards, the password stays md5 and
every attempt to sign in against a `scram-sha-256` line in `pg_hba.conf`
fails with

```
FATAL:  password authentication failed for user "postgres"
```

— which reads exactly like a wrong password and is not one. **Changing the
setting does not rewrite what is already stored.** Every password made
before the change has to be set again.

So, the setting first:

```bash
sudo -u postgres psql -c "ALTER SYSTEM SET password_encryption = 'scram-sha-256'"
sudo -u postgres psql -c "SELECT pg_reload_conf()"
sudo -u postgres psql -At -c "SHOW password_encryption"      # must say scram-sha-256
```

and only then the password. PostgreSQL's `postgres` account has none to
begin with; it is reached by being the `postgres` unix user. Give it one,
because `isemon --database setup` signs in over TCP like any other client:

```bash
sudo -u postgres psql -c "ALTER ROLE postgres PASSWORD 'A LONG ADMIN PASSWORD'"
sudo -u postgres psql -At -c \
  "SELECT substr(rolpassword,1,14) FROM pg_authid WHERE rolname='postgres'"
```

That last line must print `SCRAM-SHA-256$`. If it prints `md5...`, the
setting did not take before the password did — do the two again in order.

Write the password down where you will find it in a year. isemon uses it
once, for one connection, and stores it nowhere.

> `sudo -u postgres psql` prints `could not change directory to "/root/..."`
> when run from a directory the `postgres` user may not enter. It is noise —
> psql carries on — and it goes away if you `cd /` first.

**Or skip the superuser password altogether.** It is only ever wanted so
that `isemon --database setup` can sign in over TCP and make the role and
the database. On a server that is on this same machine you can do that
through the unix socket instead, where being root is the credential — two
statements, and then isemon never needs an administrator at all:

```bash
cd /                     # or psql complains it cannot enter root's directory
sudo -u postgres psql <<'SQL'
CREATE ROLE isemon LOGIN PASSWORD 'A GOOD LONG PASSWORD';
CREATE DATABASE isemon OWNER isemon ENCODING 'UTF8';
SQL
```

The `password_encryption` step in §2.2 still has to come **first** — this
role's password is stored the same way every other one is.

Going this way you have invented that password yourself, so §4.1 has one
more setting than it says there — `--set db_password='A GOOD LONG PASSWORD'`,
the same one — and §4.2 makes nothing, because everything is already made.
Run it anyway: with the password saved it wants no administrator and goes
over the tables, which is the half of it worth having after every upgrade.
Or go straight to `isemon --database test --to postgres`, and the move
follows. Owning the database is the part that matters: on PostgreSQL 15 and
later the `public` schema is not writable by everyone, and the owner is what
makes it the role's own. This route was checked end to end — a role made by
those two lines takes `test`, `move` and everything after it with nothing
else done to the server.

### 2.3 Let it be signed in to

`/var/lib/pgsql/data/pg_hba.conf` decides who may connect, from where, and
how. `scram-sha-256` is the method to use, which is what §2.2 made the
server store. (`md5` in these lines works too and is what a PostgreSQL 13
left alone would want — but then every account here is md5, and a machine
that is later moved to a newer PostgreSQL carries that with it. Do it once,
properly.)

**Server on the isemon machine itself** — add this line above the existing
`host ... 127.0.0.1/32 ... ident` line, or change that line's method:

```
# TYPE  DATABASE  USER  ADDRESS        METHOD
host    all       all   127.0.0.1/32   scram-sha-256
host    all       all   ::1/128        scram-sha-256
```

**Server on another machine** — name the isemon machine, and nothing wider:

```
host    isemon    isemon   ISEMON.IP.ADDRESS/32   scram-sha-256
host    postgres  postgres ISEMON.IP.ADDRESS/32   scram-sha-256
```

The second line is only needed while you run `isemon --database setup`,
which signs in as the administrator to make the database. Take it out
afterwards if you would rather.

Order matters in that file: the first line that matches wins, so a new rule
goes **above** a broader one, not below it.

```bash
systemctl reload postgresql
```

### 2.4 If the server is on another machine

By default PostgreSQL listens only on loopback. In
`/var/lib/pgsql/data/postgresql.conf`:

```
listen_addresses = 'THIS.SERVERS.IP'        # or '*' if you must
```

```bash
systemctl restart postgresql                # listen_addresses needs a restart, not a reload
firewall-cmd --permanent --add-service=postgresql
firewall-cmd --reload
```

Narrower, if you can:

```bash
firewall-cmd --permanent --add-rich-rule=\
'rule family="ipv4" source address="ISEMON.IP.ADDRESS/32" service name="postgresql" accept'
firewall-cmd --permanent --remove-service=postgresql
firewall-cmd --reload
```

**SELinux**: nothing to do for PostgreSQL on its usual port. Only if you
move it off 5432:

```bash
dnf install -y policycoreutils-python-utils
semanage port -a -t postgresql_port_t -p tcp 5433
```

The isemon machine needs nothing from SELinux for this: the daemon makes an
outgoing connection, and only the daemon talks to the database — the
dashboard never does.

### 2.5 Settings worth having

`/var/lib/pgsql/data/postgresql.conf`. The defaults are conservative for a
machine that is a database server:

```
# About a quarter of the machine's memory. The default of 128MB means the
# server reads the country ranges off disk for every address the Banned
# page draws.
shared_buffers = 1GB

# What the planner assumes the machine can cache in all. About half to
# three quarters of its memory.
effective_cache_size = 3GB

# One connection per thread that reads, plus room. Twenty is generous.
max_connections = 50
```

```bash
systemctl restart postgresql
sudo -u postgres psql -c "SHOW shared_buffers"
```

### 2.6 Prove the isemon machine can reach it

From the isemon machine, before isemon is told anything:

```bash
dnf install -y postgresql                  # the client, for this one check
PGPASSWORD='A LONG ADMIN PASSWORD' \
    psql -h SERVER -p 5432 -U postgres -c "SELECT version()"
```

`SERVER` is the database server's address — **`127.0.0.1` if it is this same
machine**, which is the common case. `PGPASSWORD` rather than the prompt,
so that a password with awkward characters in it is not the variable.

If that does not answer, nothing below will either, and the thing to fix is
`pg_hba.conf`, `listen_addresses` or the firewall — not isemon.

## 3. The driver on the isemon machine

```bash
isemon --database                          # says whether it is already here
```

If it is not:

```bash
./install.sh --with-db postgres            # from the isemon package: does the rest of this
```

or by hand:

```bash
dnf install -y python3-psycopg2
# or, if that is not offered:
dnf install -y python3-pip && pip3 install psycopg2-binary
```

Check:

```bash
python3 -c 'import psycopg2; print(psycopg2.__version__)'
isemon --database                          # "postgres  the driver is installed"
```

Nothing restarts and nothing changes: the driver is a library sitting there
until somebody asks for PostgreSQL.

### 3.1 Prove it on **your** server before you move anything

The package carries the checks this program is built with, and one of them
is about the three databases it can be kept in. Pointed at a server, it
carries a whole small installation into it and back out again and holds it
against what went in — every record, the bans, the settings, the accounts,
and the compressed detail beside a refusal. Twenty minutes of certainty
about your own PostgreSQL, whichever version AlmaLinux gave you:

```bash
cd /                                     # psql and postgres are fussy about this
sudo -u postgres psql -c "CREATE DATABASE isemon_test OWNER isemon"
cd /usr/local/lib/isemon                 # where install.sh puts the tests
ISEMON_TEST_POSTGRES='127.0.0.1:5432:isemon_test:isemon:A GOOD LONG PASSWORD' \
    ./test/engines.py
```

It must end `0 failed`. **Point it at a database made for this and nothing
else** — it empties what it is given, which is the only way to test a move
into an empty one. Afterwards:

```bash
cd / && sudo -u postgres psql -c "DROP DATABASE isemon_test"
```

Without the variable it still runs and says the server part was skipped;
that part checks what this program says to a server before anything is sent,
and needs nothing installed.

## 4. Moving isemon into it

Four steps, in order. **Until the last one this installation carries on
exactly as it is**, on the file, and nothing in it is touched by any of this.

### 4.1 Say where the server is

On the dashboard: Settings → The database → *Where everything is kept*.
Choose PostgreSQL and fill in the host, the port, the name of the database
and the name of the account isemon will use. **Leave the password empty** —
the next step makes one. Or:

```bash
isemon --set db_host=SERVER \
       --set db_port=5432 \
       --set db_name=isemon \
       --set db_user=isemon
```

Note what is **not** set here: `db_engine`. That is the last step.

Nothing needs to exist on the server yet — the next step makes it. These
seven settings are the only ones isemon keeps in `/etc/isemon/config.json`
rather than in the database, because a database cannot hold the address of
itself. That file comes to hold a password, so it is `0640 root:isemon`.

### 4.2 Make the database and the account

```bash
isemon --database setup --to postgres
```

It asks for an administrator on the server — `postgres`, or any role that
may create a database — and uses it **for that one connection**. It is
written nowhere: not into the settings, not into the database, not into any
log. It then makes:

* the role, `LOGIN`, **with a password it generates itself**;
* the database, `OWNER` that role, `ENCODING UTF8`;
* and every table, column and index isemon wants inside it.

Owning the database is how PostgreSQL says "these are yours": isemon's role
may do as it likes inside its own database and has nothing at all in any
other. The same thing is a button on the page — *Set it up* — which asks for
the administrator the same way.

The password is the part worth reading twice. You do not invent it and you do
not type it: the only password you need to have is the administrator's, which
you already have because you set this server up. isemon makes one for its own
account, writes it into `/etc/isemon/config.json`, and prints it **once**:

```
The password made for isemon
  xSlEPfBoJGKlm38bHk1rNxKx
  It is in /etc/isemon/config.json and nowhere else. Keep a copy if you want
  one; this is the only time it is printed.
```

Keep a copy if you want to reach the database with `psql` one day. If it is
lost it is no disaster — `ALTER ROLE isemon PASSWORD '...'` as the
administrator and `isemon --set db_password=...` sets a new one.

**Run this again whenever you like.** With the password already saved it does
the other half of its job and wants no administrator at all: it signs in as
isemon's own account, finds everything already there, and then goes over the
tables — adding any table, column or index this version wants that an older
one never made, and naming anything it could not add. That is worth doing
after every upgrade, and it is why the button says *Set it up* rather than
*Make it*:

```
[ ok ]   the database and the account are already there
  tables there            15, with 42 index(es)
[ ok ]   every table this version wants is there, with its columns and indexes
```

Then look:

```bash
isemon --database test --to postgres
```

It opens it, asks what it is, counts what is in it and closes again:

```
  it says it is           PostgreSQL 16.13
  tables there            0, 0 of them ours
  records                 0
  may this account write  yes
```

*May this account write* is the half of "it connects" that a password alone
does not answer — it makes a table and drops it again.

### 4.3 Carry everything across

```bash
isemon --database move --to postgres
```

A copy of what is here is written to `/var/lib/isemon/backups/` first,
always. Then every record, every ban, the whole story of every ban, the
public lists, the country ranges, the settings and the accounts go into
PostgreSQL. **Nothing here is touched.** About forty seconds for 100 MB on a
local server.

While it runs it says the table it is on and how far through it is —
`geo_ranges: 482,000 of 717,170` — because the country ranges alone are
three quarters of a million rows. Measured on a real installation of
104 MB: **about 17 seconds** into a server on the same machine, most of it
those ranges. You can close the window and it carries on; what it did is in
Events either way.

It refuses to move into a database that has anything in it — that would mix
two installations. If a first attempt left something behind:

```bash
isemon --database empty --to postgres      # never the one in use
```

### 4.4 Start using it

```bash
isemon --set db_engine=postgres
systemctl restart isemon
isemon --database
isemon --status
```

The restart is not optional: every thread that is reading a log at that
moment is holding the database that is open.

On the page this is one button — *Start using it* — which writes the same
setting and restarts the daemon for you.

### 4.5 Check, then let the file go

Give it a few minutes of real traffic and look at the things that would
show a move that only half worked:

```bash
isemon --status                  # records read climbing, TROUBLE empty
isemon --check                   # ends with "everything is as it should be"
isemon --database                # engine, where, and how much it is holding
```

and on the dashboard: the front page draws, the chart has its usual shape,
**Banned** lists who is banned with their countries and their reasons, and
Events has a line saying everything was carried into PostgreSQL.

Then the file is a spare copy of an installation that has moved. Keep it for
a few days — it is also the way back — and then:

```bash
rm /var/lib/isemon/isemon.db /var/lib/isemon/isemon.db-wal /var/lib/isemon/isemon.db-shm
```

## 5. Backups, now that there are two of them

**The nightly one is a `pg_dump`.** Settings → The database → *Dump the
database daily*, at `backup_at`, keeping `backup_keep` of them in
`/var/lib/isemon/dumps/`. It is the same command the database team would
run — `pg_dump --format=custom --compress=6 --no-owner --no-privileges` — so
what it leaves is a `.pgc` that `pg_restore` takes back with or without this
program. On this program's own data it is about **a tenth of the size of the
database**: 238 MB on the server, 10 MB on the disk.

For that, the **client** has to be on the isemon machine, not only on the
server:

```bash
dnf install postgresql          # the client. NOT postgresql-server
```

`./install.sh --with-db postgres` installs it alongside the driver. Without
it the nightly one is made as a **portable copy** instead — which needs
nothing installed, is several times the size, and goes back into any engine.
The page says which of the two tonight's will be, and the daemon's log says
it once a day.

**The portable copy has not gone anywhere.** It is the other card on the same
page, and it is still what carries an installation between engines, what is
made before every restore and every move, and what opens in any SQLite tool.
The two are kept apart:

| | the copy | the dump |
|---|---|---|
| where | `/var/lib/isemon/backups` | `/var/lib/isemon/dumps` |
| what it is | a SQLite file, always | `.pgc`, PostgreSQL's own |
| goes back into | any of the three engines | PostgreSQL, and nothing else |
| read by | this program, any SQLite tool | `pg_restore`, without this program |
| made when | *Make a copy now*, before every restore and move | every night, *Make one now* |

Both lists are on the page with **Download**, **Restore** and **Delete**
against each file and a box to drop one into. Whatever is dropped is read
before anything happens: a MariaDB dump offered to this installation is named
and refused, and so is any file with no full administrator in it.

That still leaves the question of whether the database team runs their own
job against that server. If they do, you have two, and two is fine. If they
would rather be the only ones holding it, turn isemon's off (*Dump the
database daily*, off) — but make sure somebody has actually pointed a job at
that database first. A machine with neither is a machine nobody notices until
the day it matters.

For one of your own, by hand, from anywhere:

```bash
PGPASSWORD='THE PASSWORD SET UP MADE' \
  pg_dump -h SERVER -U isemon -Fc isemon > isemon-$(date +%F).dump
```

...which is what `isemon --dump` does for you, into the dumps folder, with
the password it already has.

## 6. Going back to the file

The same four steps the other way, and then PostgreSQL can be uninstalled:

```bash
isemon --database move --to sqlite         # if the old file is still there, move it aside first
isemon --set db_engine=sqlite
systemctl restart isemon
isemon --database
```

If `/var/lib/isemon/isemon.db` is still sitting there from before, it holds
an old copy of this installation and the move refuses it:

```bash
mv /var/lib/isemon/isemon.db /var/lib/isemon/isemon.db.old
```

This is what makes trying a server safe: going back is a short list of
commands, and at no point is there only one copy of anything.

## 7. When it goes wrong

**The daemon starts, the dashboard opens, nobody can sign in.** That is
PostgreSQL being unreachable. The sign-in page says which database would not
open and what it said; `isemon --database` says it too. Nothing is being read
out of the logs and nobody is being banned — deliberately, because reading a
day of authentications into a database nobody will keep is not a service. No
nightly dump is made while this lasts either, and the ones already made are
left alone: a week of copying the empty stand-in would have thrown every real
one away.
The accounts are in the database that is missing, which is why nobody can
sign in, and why the fix is from the command line:

```bash
isemon --database test --to postgres       # what is actually wrong
systemctl status postgresql                # on the server
```

and then either put the address right, or go back to the file, which needs
nothing and is always there:

```bash
isemon --set db_engine=sqlite && systemctl restart isemon
```

**connection to server ... failed: Connection refused** — the server is
stopped, or `listen_addresses` is still loopback-only. On the server:
`systemctl status postgresql`, then `ss -ltnp | grep 5432`.

**no pg_hba.conf entry for host ...** — the server is there and is refusing
this client on purpose. That is §2.3: a line naming the address isemon
connects *from*, above any broader line. `sudo -u postgres psql -c "SELECT
pg_reload_conf()"` after editing.

**password authentication failed for user "isemon"** (or for `postgres`) —
the server is there, `pg_hba.conf` is letting this client through and asking
for a password, and the password it holds is not the one being typed. Note
what this error is *not*: a missing `pg_hba.conf` line says *no pg_hba.conf
entry for host*, and a line still set to `ident` says *Ident authentication
failed*. So the file is right and the password is the question.

One command says which of the three it is:

```bash
sudo -u postgres psql -At -c \
  "SELECT rolname, coalesce(substr(rolpassword,1,14),'(none)') FROM pg_authid \
   WHERE rolname IN ('postgres','isemon')"
```

| what comes back | what it means |
|---|---|
| `postgres\|(none)` | that role has no password at all. The `ALTER ROLE` never reached this cluster — a second PostgreSQL on another port, or it was run before the one you are connecting to was started |
| `postgres\|md5...` | the password was stored as md5 while `pg_hba.conf` asks for `scram-sha-256`. **This is the usual one on AlmaLinux 9**, whose PostgreSQL 13 stores md5 unless told otherwise. §2.2, both steps, in order — the setting alone changes nothing about a password that is already stored |
| `postgres\|SCRAM-SHA-256$` | it is stored the right way, so it is what is being typed. Take the prompt out of it: `PGPASSWORD='...' psql -h 127.0.0.1 -U postgres -c "SELECT 1"` |

Set it again with:

```bash
sudo -u postgres psql -c "ALTER ROLE isemon PASSWORD 'A GOOD LONG PASSWORD'"
```

and make sure `db_password` says exactly the same thing — `isemon --settings`
shows it masked, `isemon --database test --to postgres` proves it.

**permission denied for schema public** — on PostgreSQL 15 and later (so not
on the 13 AlmaLinux 9 gives you by default, but yes if you took the 15 or 16
stream), a database's `public` schema is no longer writable by everyone. `isemon
--database setup` avoids this by making the role the **owner** of the
database. If the database was made by hand instead:

```bash
sudo -u postgres psql -c "ALTER DATABASE isemon OWNER TO isemon"
sudo -u postgres psql -d isemon -c "ALTER SCHEMA public OWNER TO isemon"
```

**relation does not exist**, on a database that was set up but never moved
into. `setup` makes the database and the role; `move` makes the tables and
fills them. Run the move.

**Everything works but the page is slow.** Look at `shared_buffers` (§2.5).
With the country database in it this installation reads about 140 MB of
ranges, and a 128 MB buffer means the server goes to disk for every address
the Banned page draws.

## 8. The whole thing, as a list

On the database server:

```bash
cd /
dnf install -y postgresql-server postgresql-contrib
postgresql-setup --initdb
systemctl enable --now postgresql

# how passwords are stored FIRST, then the password - see §2.2
sudo -u postgres psql -c "ALTER SYSTEM SET password_encryption = 'scram-sha-256'"
sudo -u postgres psql -c "SELECT pg_reload_conf()"
sudo -u postgres psql -c "ALTER ROLE postgres PASSWORD 'A LONG ADMIN PASSWORD'"
sudo -u postgres psql -At -c \
  "SELECT substr(rolpassword,1,14) FROM pg_authid WHERE rolname='postgres'"   # SCRAM-SHA-256$

# pg_hba.conf as in §2.3, postgresql.conf as in §2.4 and §2.5
systemctl restart postgresql
PGPASSWORD='A LONG ADMIN PASSWORD' psql -h 127.0.0.1 -U postgres -c "SELECT version()"
```

On the isemon machine:

```bash
isemon --backup
./install.sh --with-db postgres
isemon --set db_host=SERVER --set db_port=5432 --set db_name=isemon \
       --set db_user=isemon             # no password: setup makes one
isemon --database setup --to postgres       # asks for an administrator, keeps it nowhere,
                                            # and prints isemon's own password once
isemon --database test  --to postgres
isemon --database move  --to postgres       # nothing here is touched
isemon --set db_engine=postgres
systemctl restart isemon
isemon --check && isemon --database
```
