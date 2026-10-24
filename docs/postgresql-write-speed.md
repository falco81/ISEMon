# Keeping up with a busy firewall: how fast PostgreSQL writes

A firewall that logs every session writes more than everything else isemon
reads put together. An FTD pair in front of a few thousand people can write
fifteen million lines a day. When `isemon --status` says **NOT keeping up**,
this page shows how to find what is slowing it down and what to change.

Most of what is below needs no new version of isemon. Each change can be put
back with one command.

[postgresql-tuning.md](postgresql-tuning.md) is about how fast the pages
*read*. This page is about how fast the daemon *writes*.

---

## 1. Read the status first

```bash
isemon --status | head -15
```

```
  events a second         4,298 now · 3,886 over 1 min · 3,774 over 5 min
  the database            92.6 statement(s) a second, 6.8 ms each, 63% of the minute waiting on it
                           30%  INSERT fw_events (upsert)          0.7/s, 436 ms each
                           13%  INSERT fw_roll (upsert)            0.7/s, 185 ms each
                           10%  SELECT fw_events                   7.6/s, 13.0 ms each
                            4%  SELECT ptr                         12.1/s, 3.7 ms each
                            4%  UPDATE ptr                         11.6/s, 3.0 ms each
                            1%  SELECT geo_ranges                  55.1/s, 0.2 ms each
  keeping up              NOT keeping up — 2.3 GB still to read
```

What each line means:

- **events a second**: how many log lines are read and dealt with each
  second. It is the same number the header shows as *EPS*.
- **the database**: how many statements are sent each second, how long each
  takes on average, and how much of the last minute the daemon spent waiting
  for them. A high share means the daemon is limited by the database, not by
  its own work.
- **The lines under it**: the kinds of statement that minute went on, the
  biggest first. Each line gives its share of the minute, how many run each
  second, and how long each takes.
  - `INSERT fw_events`: the firewall's lines written as rows.
  - `INSERT fw_roll`: the counts behind the Traffic cards and chart.
  - `SELECT fw_events (already here?)`: checking that a line is not already
    there before it is counted. Shown under this name from 1.10.138; before
    that it was counted with the pages' own reads, as `SELECT fw_events`.
  - `SELECT fw_events`: the pages reading the rows (the Sessions list,
    *Connected now*).
  - `SELECT/UPDATE ptr`: names of addresses being written down.
  - `SELECT geo_ranges`: which country an address is in.
- **keeping up**: how much of the logs is still unread.

### Is it a backlog, or is it too slow?

Compare **events a second** with how much the firewall actually writes. The
log folder shows that: add up the size of a day's files, then divide by the
seconds in a day and by about 200 bytes a line.

- **A firewall writing ~170 lines a second, with isemon dealing with 4,000 a
  second:** that is about 25 times as fast as needed. *NOT keeping up* then
  only means a **backlog** is being caught up on, for example after a
  restart, an erase or a first start on a full folder. It goes away by
  itself. The size still to read falls every few minutes, and nothing needs
  changing.
- **Events a second close to (or under) what the firewall writes:** the
  backlog never shrinks. Read on.

---

## 2. Do not wait for every commit to reach the disk

With `synchronous_commit = on` (the default), every commit waits until its
WAL is written and flushed to disk. That takes about 2–3 ms on most disks,
and the daemon does nothing else while it waits. At a few hundred statements
a second that wait is most of the minute.

The change applies to isemon's own role only. Nothing else on the same
server is affected:

```bash
sudo -u postgres psql -c "ALTER ROLE isemon SET synchronous_commit = off;"
systemctl restart isemon
```

Going back:

```bash
sudo -u postgres psql -c "ALTER ROLE isemon RESET synchronous_commit;"
systemctl restart isemon
```

### Why it is safe for isemon

- **The database stays consistent.** `fsync` stays on, so a crash never
  leaves a broken database. If the whole server goes down uncleanly, only
  the commits of the last fraction of a second are lost. A stopped
  PostgreSQL, a stopped isemon or a crashed isemon loses nothing at all.
- **Nothing read is lost.** How far each log file has been read is kept in
  the same database. It is written *after* the lines it covers. The WAL is
  replayed in order, so a crash can lose the newest commits but never an
  older commit while keeping a newer one. The saved position is therefore
  never ahead of the lines that were saved. After the restart the daemon
  reads those lines again, and anything already stored is recognised and
  not counted twice.
- **No ban is lost.** A refusal is judged from the ISE log. If a refusal is
  lost from the database, it is read again from the log and judged again.

There is one exception. With `fwlog_keep_allowed` off (§4), the sessions let
through are only counted, not stored, so isemon cannot recognise them when
they are read again. After an unclean stop of the whole server, the last
fraction of a second of them can be counted twice on the Traffic cards.

### What to expect

Within ten minutes, **ms each** on the database line should fall to a
fraction of what it was. The share of the minute spent waiting on the
database should drop clearly, and events a second should rise.

---

## 3. Make checkpoints less frequent

At each checkpoint PostgreSQL writes every changed page to disk. After a
checkpoint, the first change to a page writes the **whole page** into the
WAL again. With the default `checkpoint_timeout` of 5 minutes and a table
with nine indexes, most index pages are written whole many times an hour.

```bash
sudo -u postgres psql -c "ALTER SYSTEM SET checkpoint_timeout = '15min'" -c "SELECT pg_reload_conf()"
```

No restart is needed. Check that `max_wal_size` is big enough to cover
fifteen minutes of writing:

```bash
sudo -u postgres psql -c "SELECT name, setting, unit FROM pg_settings
  WHERE name IN ('max_wal_size','checkpoint_timeout','wal_compression','shared_buffers')"
sudo -u postgres psql -xc "SELECT checkpoints_timed, checkpoints_req FROM pg_stat_bgwriter"
```

On PostgreSQL 17 and later the second query is
`SELECT num_timed, num_requested FROM pg_stat_checkpointer`.

How to read the result:

- `max_wal_size` of 4–8 GB is right for this.
- `wal_compression` should be on (`pglz`, or `lz4` where it is built in).
- If `checkpoints_req` keeps growing faster than `checkpoints_timed`, the
  checkpoints are forced by the WAL filling up, and `max_wal_size` is too
  small.

Going back: `ALTER SYSTEM RESET checkpoint_timeout;` and a reload.

---

## 4. Do not keep every session it let through as a row

This is the biggest change of all. On a busy firewall it is worth more than
everything above.

First see what the rows of the last hour are made of:

```bash
sudo -u postgres psql isemon -c "SELECT type, sub, verdict, count(*) FROM fw_events
  WHERE ts > extract(epoch FROM now()) - 3600 GROUP BY 1,2,3 ORDER BY 4 DESC LIMIT 15"
```

On a measured site, 9 rows in 10 were:

- `traffic/forward/allow`: sessions let through;
- `traffic/stray/info`: FTD's *Deny TCP (no connection)*, the leftovers of
  sessions already closed.

Nobody opens those line by line. What matters about them (how much went
where, to whom, by which service) is on the cards and the chart, and those
are counted separately.

```bash
isemon --set fwlog_keep_allowed=0
```

The same switch is in *Settings → The firewall log → Keep what it let through
as rows at all*. No restart is needed.

- **What stays:**
  - every card and the chart, still counting every session;
  - the refusals, the blocks, IPS, AMP, Security Intelligence, the VPN, the
    tunnels and *Connected now*, still as rows.
- **What goes:** opening one allowed session as a row of its own.
- **Rows already stored** go by themselves, once *Keep what it let through
  for (days)* runs out.
- **What isemon does about it:**
  - From 1.10.137 the daemon no longer checks the table for lines it is not
    going to keep. On a firewall that was nine checks in ten.
  - `isemon --rescan --logs fwlog` refuses to run while this is off, because the
    sessions it reads again would be counted again. Erase the firewall's log
    first: that reads it all again by itself.

On the measured site, writing to `fw_events` went from 436 ms to 310 ms a
batch within minutes, and events a second from about 3,800 to 5,400. It kept
improving as the table and its indexes shrank.

---

## 5. The indexes on `fw_events`

How often each index has been used since the statistics were last reset, and
how big each one is:

```bash
sudo -u postgres psql isemon -c "SELECT indexrelname, idx_scan,
  pg_size_pretty(pg_relation_size(indexrelid)) FROM pg_stat_user_indexes
  WHERE relname='fw_events' ORDER BY 1"
sudo -u postgres psql isemon -c "SELECT pg_size_pretty(pg_total_relation_size('fw_events')) total,
  pg_size_pretty(pg_relation_size('fw_events')) rows, reltuples::bigint FROM pg_class
  WHERE relname='fw_events'"
```

Every row written is written into every index as well. When the table and
its indexes no longer fit in `shared_buffers`, each new row means random
writes into all of them. That is the half a second a batch seen in the
status. A large `buffers_backend` in `pg_stat_bgwriter` points the same way:
PostgreSQL is evicting pages itself whenever it writes.

**Do not drop the indexes by hand.**

- isemon makes them again when it starts.
- An index that shows `idx_scan = 0` is the one a search by destination, or
  by firewall, needs the first time somebody makes it. Without it, that
  search would have to read the whole table.

Use §4 to make the table smaller instead. Ten times fewer rows means ten
times smaller indexes, and that solves this too. If it is still not enough,
send the output of both queries.

From 1.10.141 two of them are gone by themselves:

- `fw_verdict_ts` (the verdict): 2 uses against 67 million writes on the
  site that measured it, and 900 MB.
- `fw_fw_ts` (which firewall): 5 uses and 825 MB.

In their place is `fw_usr_ts`, over the person a line names. It is built
only over the lines that name somebody. A search with `user:` over a day was
three seconds of walking the time index without it.

---

## 5a. The biggest tables split by day (1.10.141)

On PostgreSQL, three tables are kept in a part a day:

- `fw_events`: the firewall's lines;
- `fw_roll`: their counts;
- `win_events`: the domain's events.

Each day is split again by how long its rows are kept:

| Table | Kept for a shorter time | Kept for the longer time |
|---|---|---|
| `fw_events` | sessions let through and *no connection* lines (`brief` = 1) | everything else (`brief` = 0) |
| `fw_roll` | counted hours (`span` = 3600) | counted days (`span` = 86400) |
| `win_events` | sign-ins (`keepc` = 1), directory reads (`keepc` = 2) | the rest (`keepc` = 0) |

What this changes:

- **Letting old rows go.** A day that has aged out goes with one `DROP`,
  and a day's sessions with one `TRUNCATE`. Before, it was twenty million
  `DELETE`s a day, each a write to every index, a page of WAL and a dead row
  for the vacuum.
- **Writing.** The day being written, and its indexes, are small enough to
  stay in memory.
- **Searching.** A search over a time window reads only the days in it.
- **Marked events.** A domain event this program marked is moved to the
  longer-kept part before its kind's day goes, so it stays exactly as long
  as it did before.

**An existing table is split in place, behind the running daemon, without
copying it:**

1. If the table needs a key that includes the day and the kind, that key is
   built beside the table without stopping writes. On a few tens of
   millions of rows this takes minutes.
2. Every row is checked to be before an edge: a midnight at least six hours
   ahead. This also does not stop writes.
3. One short transaction renames the table, makes the split table and
   attaches the old one whole as its first part, `<table>_legacy`.
4. From the edge on, every day is a part of its own.
5. The legacy part goes, whole, when its last day ages out. Until then its
   old rows are let go one by one, as before.

Every step says when it starts and how long it took, in the log and on the
Database page. If anything stops it, the table is left exactly as it was
and it is tried again six hours later.

**Not waiting the six hours.** Each table that could not be split has a
mark in `meta`, `split_failed_<table>`, holding when it was tried. Take
the mark away and the daemon tries that table again at its next pass,
within about ten minutes, with no restart:

```bash
# PostgreSQL: one table (here win_events)
sudo -u postgres psql isemon -c "DELETE FROM meta WHERE key='split_failed_win_events'"

# ...or every table that is waiting
sudo -u postgres psql isemon -c "DELETE FROM meta WHERE key LIKE 'split\_failed\_%'"
```

Use your own database name in place of `isemon` if it is different. The
log then says `splitting <table> by day: starting` and, when it is done,
`... - done in N s`. Removing the mark is always safe: it is only a note
of when to try again, and the table itself is not touched by deleting it.
Before 1.10.152, a split could fail with *deadlock detected* when an
upgrade ran at the same moment (the command line was building an index on
the same table). That was fixed in 1.10.152; on an older version, clearing
the mark after the upgrade has finished is enough.

**Disk space:** step 1 needs room for one more index the size of the
table's key (on the measured site about 2.5 GB). The old key goes once the
switch is done.

**Rows outside the days:** the days ahead are made three days in advance.
A line stamped further ahead (a clock that is wrong), or for a day already
gone, is kept in `<table>_default` and let go by age like any other.

Switch it off with *Settings → The database → Split the biggest tables by
day*, or `isemon --set db_split=0`. A table already split stays split.

Nothing changes on SQLite or MariaDB.

**Do not open a split database with a version older than 1.10.141.** It
would read it, but it would let old rows go in a way that no longer suits a
split table.

To see what is there:

```bash
sudo -u postgres psql isemon -c "SELECT c.relname, pg_size_pretty(pg_total_relation_size(c.oid)),
  pg_get_expr(c.relpartbound, c.oid) FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
  WHERE i.inhparent = 'fw_events'::regclass ORDER BY 1"
```

---

## 6. What the daemon itself does about it

- **1.10.134:** the firewall's files share a budget of 6 MB a pass, so a
  backlog on the firewall never holds up the ISE refusals, which are what
  bans are made from.
- **1.10.135:** `isemon --status` shows where the database's time goes, by
  kind of statement. The numbers in §1 come from there.
- **1.10.136:**
  - Big batches go to PostgreSQL with `COPY` instead of one long statement:
    three to four times quicker for the database to take in. What lands is
    byte for byte the same as before.
  - Countries are held in memory for 100,000 addresses.
  - Addresses already asked about for their name are not asked again while
    the queue is full.
- **1.10.137:** lines that are only counted (§4) are not checked against the
  table first.
- **1.10.141:** the biggest tables split by day (§5a), and the indexes on
  `fw_events` changed to what the measured site actually used (§5).

---

## 7. What to send if it is still not keeping up

```bash
isemon --status | head -15
sudo -u postgres psql -c "SELECT name, setting, unit FROM pg_settings WHERE name IN
  ('server_version','shared_buffers','max_wal_size','checkpoint_timeout','wal_compression',
   'synchronous_commit','random_page_cost','effective_io_concurrency')"
sudo -u postgres psql -c "SELECT rolname, rolconfig FROM pg_roles WHERE rolname='isemon'"
sudo -u postgres psql -xc "SELECT * FROM pg_stat_bgwriter"
```

Add the two queries from §5. Together they show:

- whether it is a backlog or a limit;
- whether the time goes to the commits (§2), the checkpoints (§3) or the
  size of the table (§4, §5);
- which statement kind to work on next.
