# MariaDB on AlmaLinux 9, and moving isemon into it

From a machine that has never had a database server on it to an isemon
running entirely on MariaDB, with nothing typed twice and nothing lost.
Every command is meant to be pasted as it stands **except where a word is in
CAPITALS** — those are yours to replace: `SERVER` is the database server's
address (`127.0.0.1` when it is this same machine), and the passwords are
whatever you choose.

Read [the-database.md](the-database.md) first if you have not decided
*whether* to do this. The short of it: the file on this machine is faster
(4,889 writes a second against MariaDB's 2,325), and a server is for when
the data has to live with everything else and be backed up by whoever backs
that up. Neither is more correct.

Two shapes of this are common and the difference matters in exactly one
step:

* **the server on the isemon machine itself** — nothing crosses a network,
  there is no firewall to open, and the account may be `localhost`-only;
* **the server somewhere else** — the database team's machine, say. Then §2.4
  and §2.5 are not optional.

---

## 1. Before you start

On the isemon machine:

```bash
isemon --database                    # what it is on now, and what drivers are here
isemon --status                      # it should be reading, and calm
isemon --backup                      # a copy of what you have, before anything
```

The copy is not ceremony. Everything below leaves the existing database
untouched, but a copy taken before a change is the difference between a bad
afternoon and a bad week.

Know roughly how big this will be. Ask the machine:

```bash
du -h /var/lib/isemon/isemon.db
```

For scale, a real installation with a year of ISE records, the country
database and the public lists comes to about **200 MB on the server**:

| | rows | on MariaDB |
|---|---|---|
| `geo_ranges` (the country database) | 716,496 | 93.8 MB |
| `failed` (refused authentications) | 38,904 | 51.7 MB |
| `passed` (successful logins) | 20,815 | 31.7 MB |
| `feed_ranges` (the public lists) | 77,140 | 14.4 MB |
| everything else | | ~2 MB |

The same data is about 105 MB as a file. A server keeps its indexes apart
from its rows and allocates space in extents, so the same installation reads
larger there — that is accounting, not growth.

## 2. The server

### 2.1 Install it

AlmaLinux 9 carries MariaDB in AppStream. The default is **10.5**, and a
**10.11** stream is available as a module:

```bash
dnf module list mariadb              # what this machine is offered
dnf install -y mariadb-server        # 10.5, the default
```

For 10.11 instead, before installing anything:

```bash
dnf module enable -y mariadb:10.11
dnf install -y mariadb-server
```

Either is fine. isemon asks nothing of MariaDB that 10.5 does not have — no
window functions, no common table expressions, no JSON columns. Take
whichever your site already standardises on.

```bash
systemctl enable --now mariadb
systemctl status mariadb --no-pager
```

### 2.2 Make it safe to have

```bash
mariadb-secure-installation
```

Answer it: set a root password (write it down somewhere you will find it in
a year), remove the anonymous accounts, disallow remote root, remove the test
database, reload. On a fresh AlmaLinux the first question is about the unix
socket account — leaving that alone is fine.

**Or skip the root password altogether.** It is only ever wanted so that
`isemon --database setup` can sign in and make the database and the account.
On a server that is on this same machine you can do that through the unix
socket instead, where being root is the credential:

```bash
mariadb <<'SQL'
CREATE DATABASE isemon CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'isemon'@'localhost' IDENTIFIED BY 'A GOOD LONG PASSWORD';
CREATE USER 'isemon'@'%'         IDENTIFIED BY 'A GOOD LONG PASSWORD';
GRANT ALL PRIVILEGES ON isemon.* TO 'isemon'@'localhost';
GRANT ALL PRIVILEGES ON isemon.* TO 'isemon'@'%';
FLUSH PRIVILEGES;
SQL
```

Then §4.2 is just `isemon --database test --to mariadb`, and the move
follows. Those are the same statements `--database setup` runs; doing them
here means isemon is never given an administrator at all.

### 2.3 Settings worth having

`/etc/my.cnf.d/isemon.cnf`, new file:

```ini
[mysqld]
# utf8mb4 everywhere. ISE writes user names and device names that are not
# ASCII, and a server defaulting to latin1 stores them as something else.
character-set-server = utf8mb4
collation-server     = utf8mb4_unicode_ci

# isemon's own tables are InnoDB and it does not ask for anything exotic.
# This is the one number worth setting on a machine that is a database
# server: about 60-70% of its memory, or 1G on a 2G VM shared with other
# things. The default of 128M is small for 700,000 country ranges.
innodb_buffer_pool_size = 1G

# One connection per thread that reads, plus the page. Twenty is generous.
max_connections = 50
```

Then:

```bash
systemctl restart mariadb
mariadb -u root -p -e "SELECT @@character_set_server, @@innodb_buffer_pool_size\G"
```

Once isemon uses the server, *Settings -> The database -> Tune it for this
machine* works the InnoDB settings out for the machine's memory, processors
and disk and puts in what MariaDB takes while it runs (`SET GLOBAL`, as an
administrator typed into the popup and stored nowhere). What MariaDB keeps
only until its next start - and `innodb_buffer_pool_size` past the
`innodb_buffer_pool_size_max` a newer 10.11 was started with - comes as a
file to put in `/etc/my.cnf.d/zz-isemon-tuning.cnf`. It is named to be read
after this one, so its `innodb_buffer_pool_size` is the one that counts.

### 2.4 If the server is on another machine

Let it listen, and let the isemon machine in:

```ini
# in the same /etc/my.cnf.d/isemon.cnf
bind-address = 0.0.0.0
```

```bash
systemctl restart mariadb
firewall-cmd --permanent --add-service=mysql
firewall-cmd --reload
```

Better than `0.0.0.0` if you can: bind to the one address the isemon machine
reaches, and narrow the firewall to that source —

```bash
firewall-cmd --permanent --add-rich-rule=\
'rule family="ipv4" source address="ISEMON.IP.ADDRESS/32" service name="mysql" accept'
firewall-cmd --permanent --remove-service=mysql
firewall-cmd --reload
```

**SELinux**: nothing to do for MariaDB on its usual port. Only if you move it
off 3306:

```bash
dnf install -y policycoreutils-python-utils
semanage port -a -t mysqld_port_t -p tcp 3307
```

The isemon machine needs nothing from SELinux for this: the daemon makes an
outgoing connection, and only the daemon talks to the database — the
dashboard never does.

### 2.5 Prove the isemon machine can reach it

From the isemon machine, before isemon is told anything:

```bash
dnf install -y mariadb                     # the client, for this one check
mariadb -h SERVER -P 3306 -u root -p -e "SELECT VERSION()"
```

`SERVER` is the database server's address — **`127.0.0.1` if it is this same
machine**, which is the common case.

If that does not answer, nothing below will either, and the thing to fix is
the firewall or `bind-address` — not isemon.

## 3. The driver on the isemon machine

```bash
isemon --database                          # says whether it is already here
```

If it is not:

```bash
./install.sh --with-db mariadb             # from the isemon package: does the rest of this
```

or by hand, whichever works on your machine:

```bash
dnf install -y python3-PyMySQL             # may need EPEL on a plain AlmaLinux 9
# or
dnf install -y python3-pip && pip3 install PyMySQL
```

Check:

```bash
python3 -c 'import pymysql; print(pymysql.__version__)'
isemon --database                          # "mariadb   the driver is installed"
```

Nothing restarts and nothing changes: the driver is a library sitting there
until somebody asks for MariaDB.

### 3.1 Prove it on **your** server before you move anything

The package carries the checks this program is built with, and one of them
is about the three databases it can be kept in. Pointed at a server, it
carries a whole small installation into it and back out again and holds it
against what went in — every record, the bans, the settings, the accounts,
and the compressed detail beside a refusal. Twenty minutes of certainty
about your own MariaDB, whichever version AlmaLinux gave you:

```bash
mariadb -u root -p -e "CREATE DATABASE isemon_test CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; \
                       GRANT ALL PRIVILEGES ON isemon_test.* TO 'isemon'@'localhost', 'isemon'@'%'"
cd /usr/local/lib/isemon                 # where install.sh puts the tests
ISEMON_TEST_MARIADB='127.0.0.1:3306:isemon_test:isemon:A GOOD LONG PASSWORD' \
    ./test/engines.py
```

It must end `0 failed`. **Point it at a database made for this and nothing
else** — it empties what it is given, which is the only way to test a move
into an empty one. Afterwards:

```bash
mariadb -u root -p -e "DROP DATABASE isemon_test"
```

Without the variable it still runs and says the server part was skipped;
that part checks what this program says to a server before anything is sent,
and needs nothing installed.

## 4. Moving isemon into it

Four steps, in order. **Until the last one this installation carries on
exactly as it is**, on the file, and nothing in it is touched by any of this.

### 4.1 Say where the server is

On the dashboard: Settings → The database → *Where everything is kept*.
Choose MariaDB and fill in the host, the port, the name of the database and
the name of the account isemon will use. **Leave the password empty** — the
next step makes one. Or:

```bash
isemon --set db_host=SERVER \
       --set db_port=3306 \
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
isemon --database setup --to mariadb
```

It asks for an administrator on the server — `root`, or anyone who may
create a database — and uses it **for that one connection**. It is written
nowhere: not into the settings, not into the database, not into any log. It
then makes:

* the database, `CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`;
* the account, **with a password it generates itself**, and `ALL PRIVILEGES`
  **on that one database and no other**, for `'isemon'@'%'` and
  `'isemon'@'localhost'`;
* and every table, column and index isemon wants inside it.

The same thing is a button on the page — *Set it up* — which asks for the
administrator the same way.

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

Keep a copy if you want to reach the database with the `mariadb` client one
day. If it is lost it is no disaster — `SET PASSWORD FOR 'isemon'@'%' =
PASSWORD('...')` as the administrator and `isemon --set db_password=...` sets
a new one.

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
isemon --database test --to mariadb
```

It opens it, asks what it is, counts what is in it and closes again:

```
  it says it is           10.11.14-MariaDB
  tables there            0, 0 of them ours
  records                 0
  may this account write  yes
```

*May this account write* is the half of "it connects" that a password alone
does not answer — it makes a table and drops it again.

### 4.3 Carry everything across

```bash
isemon --database move --to mariadb
```

A copy of what is here is written to `/var/lib/isemon/backups/` first,
always. Then every record, every ban, the whole story of every ban, the
public lists, the country ranges, the settings and the accounts go into
MariaDB. **Nothing here is touched.** About half a minute for 100 MB on a
local server.

While it runs it says the table it is on and how far through it is —
`geo_ranges: 482,000 of 717,170` — because the country ranges alone are
three quarters of a million rows. Measured on a real installation of
104 MB: **about 18 seconds** into a server on the same machine, most of it
those ranges. You can close the window and it carries on; what it did is in
Events either way.

It refuses to move into a database that has anything in it — that would mix
two installations. If a first attempt left something behind:

```bash
isemon --database empty --to mariadb       # never the one in use
```

### 4.4 Start using it

```bash
isemon --set db_engine=mariadb
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
Events has a line saying everything was carried into MariaDB.

Then the file is a spare copy of an installation that has moved. Keep it for
a few days — it is also the way back — and then:

```bash
rm /var/lib/isemon/isemon.db /var/lib/isemon/isemon.db-wal /var/lib/isemon/isemon.db-shm
```

## 5. Backups, now that there are two of them

**The nightly one is a `mariadb-dump`.** Settings → The database → *Dump the
database daily*, at `backup_at`, keeping `backup_keep` of them in
`/var/lib/isemon/dumps/`. It is the same command the database team would
run — `mariadb-dump --single-transaction --quick`, compressed on the way out
— so what it leaves is a `.sql.gz` the `mariadb` client takes back with or
without this program. `--single-transaction` is the flag that matters:
without it a dump locks the tables while isemon is writing to them.

For that, the **client** has to be on the isemon machine, not only on the
server:

```bash
dnf install mariadb             # the client. NOT mariadb-server
```

`./install.sh --with-db mariadb` installs it alongside the driver. Without it
the nightly one is made as a **portable copy** instead — which needs nothing
installed, is several times the size, and goes back into any engine. The page
says which of the two tonight's will be, and the daemon's log says it once a
day.

**The portable copy has not gone anywhere.** It is the other card on the same
page, and it is still what carries an installation between engines, what is
made before every restore and every move, and what opens in any SQLite tool.
The two are kept apart:

| | the copy | the dump |
|---|---|---|
| where | `/var/lib/isemon/backups` | `/var/lib/isemon/dumps` |
| what it is | a SQLite file, always | `.sql.gz`, MariaDB's own |
| goes back into | any of the three engines | MariaDB, and nothing else |
| read by | this program, any SQLite tool | the `mariadb` client, without this program |
| made when | *Make a copy now*, before every restore and move | every night, *Make one now* |

Both lists are on the page with **Download**, **Restore** and **Delete**
against each file and a box to drop one into. Whatever is dropped is read
before anything happens: a PostgreSQL dump offered to this installation is
named and refused, and so is any file with no full administrator in it.

That still leaves the question of whether the database team runs their own
job against that server. If they do, you have two, and two is fine. If they
would rather be the only ones holding it, turn isemon's off (*Dump the
database daily*, off) — but make sure somebody has actually pointed a job at
that database first. A machine with neither is a machine nobody notices until
the day it matters.

For one of your own, by hand, from anywhere:

```bash
mariadb-dump -h SERVER -u isemon -p --single-transaction --quick isemon \
    | gzip -9 > isemon-$(date +%F).sql.gz
```

...which is what `isemon --dump` does for you, into the dumps folder, with
the password it already has.

## 6. Going back to the file

The same four steps the other way, and then MariaDB can be uninstalled:

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
MariaDB being unreachable. The sign-in page says which database would not
open and what it said; `isemon --database` says it too. Nothing is being read
out of the logs and nobody is being banned — deliberately, because reading a
day of authentications into a database nobody will keep is not a service. No
nightly dump is made while this lasts either, and the ones already made are
left alone: a week of copying the empty stand-in would have thrown every real
one away.
The accounts are in the database that is missing, which is why nobody can
sign in, and why the fix is from the command line:

```bash
isemon --database test --to mariadb        # what is actually wrong
systemctl status mariadb                   # on the server
```

and then either put the address right, or go back to the file, which needs
nothing and is always there:

```bash
isemon --set db_engine=sqlite && systemctl restart isemon
```

**Can't connect to MySQL server ... Connection refused** — the server is
stopped, or it is not listening where you think. On the server:
`systemctl status mariadb`, then `ss -ltnp | grep 3306`.

**Access denied for user 'isemon'@'...'** — the account exists for a
different host than the one the connection is arriving from. Check what was
actually made:

```bash
mariadb -u root -p -e "SELECT user, host FROM mysql.user WHERE user='isemon'"
```

`isemon --database setup` makes both `@'%'` and `@'localhost'`; if somebody
has since tidied one away, that is the one to put back.

**Table doesn't exist**, on a database that was set up but never moved into.
`setup` makes the database and the account; `move` makes the tables and
fills them. Run the move.

**Everything works but the page is slow.** Look at
`innodb_buffer_pool_size` (§2.3). With the country database in it this
installation reads about 100 MB of ranges, and a 128 MB pool means the
server goes to disk for every address on the Banned page.

## 8. The whole thing, as a list

On the database server:

```bash
dnf install -y mariadb-server
systemctl enable --now mariadb
mariadb-secure-installation
# /etc/my.cnf.d/isemon.cnf as in §2.3 (and §2.4 if it is a separate machine)
systemctl restart mariadb
```

On the isemon machine:

```bash
isemon --backup
./install.sh --with-db mariadb
isemon --set db_host=SERVER --set db_port=3306 --set db_name=isemon \
       --set db_user=isemon             # no password: setup makes one
isemon --database setup --to mariadb        # asks for an administrator, keeps it nowhere,
                                            # and prints isemon's own password once
isemon --database test  --to mariadb
isemon --database move  --to mariadb        # nothing here is touched
isemon --set db_engine=mariadb
systemctl restart isemon
isemon --check && isemon --database
```
