# Making PostgreSQL quick enough for a busy domain

A PostgreSQL that comes out of a package is set up to start on anything —
`shared_buffers` of 128 MB, `work_mem` of 4 MB, and a planner that still
believes the disk is a spinning one. On a database holding a few hundred
thousand ISE records nobody ever notices. On one holding **seven and a half
million domain events a day** every one of those defaults is felt, and the
Domain page is the first place it shows.

Everything below is read-only until you paste it, reversible afterwards, and
none of it needs isemon to be stopped except the one restart in §4.

Worked through for a **32 GB, 8 core** server on SSD, which is the machine
this was measured on. §3 gives the arithmetic so any other size follows.

> **Or let the dashboard do §3 and §4.** Since 1.10.173 *Settings -> The
> database -> Tune it for this machine* reads the server's memory, processors
> and disk, works out the settings in §3 for them, shows them beside what is
> there now, and puts them in with `ALTER SYSTEM` when you say so - as an
> administrator typed into the popup, used for that one request and stored
> nowhere. `shared_buffers` then waits for a restart: on a server on the same
> machine the page does that too (install.sh lets the `isemon` account restart
> PostgreSQL and nothing else, through a polkit rule; `--no-db-restart` takes
> that away), otherwise it shows the command. *Put back as it was* goes back
> to what was there before. It does not touch `max_connections`; `work_mem`
> is kept small enough for whatever that is.

> **First, make sure this is the problem you have.** Since 1.10.74 the two
> things that made that page slow are fixed in the daemon itself, and they
> were worth far more than any setting here — see §7. Tune the server after
> upgrading, not instead of it.

---

## 1. Find out what is actually slow

isemon writes every query that takes more than a moment into its own log, so
the first question is already answered:

```bash
grep "sql took" /var/log/isemon/isemon.log | sed 's/.*sql took //' \
  | sort -rn | head -20
```

Read the *shapes*, not the individual lines: five entries of the same query
against `win_events` is one problem, not five.

For the fuller picture, PostgreSQL will keep the tally itself:

```bash
sudo -u postgres psql -c "ALTER SYSTEM SET shared_preload_libraries = 'pg_stat_statements';"
systemctl restart postgresql-16 || systemctl restart postgresql
sudo -u postgres psql -d isemon -c "CREATE EXTENSION IF NOT EXISTS pg_stat_statements;"
```

and then, after it has watched for a while:

```bash
sudo -u postgres psql -d isemon -c "
  SELECT round(total_exec_time)::bigint AS ms_total, calls,
         round(mean_exec_time)::bigint AS ms_each, left(query, 90) AS query
    FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 20;"
```

The column that matters is **`ms_total`**, not `ms_each`: a two-second query
asked once an hour costs nothing, and a forty-millisecond one asked on every
poll of every open page costs everything.

---

## 2. The largest lever: autovacuum on the big table

This is worth more than all of §3 put together, and it is the one thing
nobody thinks of.

PostgreSQL's defaults say "collect a table once a fifth of it has changed".
On `win_events` with seven and a half million rows that is **one and a half
million dead rows before anything happens**, and three things follow:

* a mass update — which is what happens when isemon works out the marks
  behind a new alarm — leaves the table twice its size until then;
* `autovacuum_vacuum_insert_scale_factor`, which governs an *insert-only*
  table, is on the same fifth, so the visibility map stays stale and every
  `COUNT(*)` has to go to the heap instead of answering from the index;
* the planner's statistics are a fifth of a table out of date, so it chooses
  the wrong plan for exactly the columns that changed most.

Set it per table. It needs nothing but ownership of the table, so the
database user isemon already uses can do it:

```bash
sudo -u postgres psql -d isemon <<'SQL'
ALTER TABLE win_events SET (
  autovacuum_vacuum_scale_factor        = 0.02,
  autovacuum_analyze_scale_factor       = 0.02,
  autovacuum_vacuum_insert_scale_factor = 0.02);

ALTER TABLE failed SET (autovacuum_vacuum_scale_factor  = 0.05,
                        autovacuum_analyze_scale_factor = 0.05);
ALTER TABLE passed SET (autovacuum_vacuum_scale_factor  = 0.05,
                        autovacuum_analyze_scale_factor = 0.05);
SQL
```

Two percent of seven and a half million is 150,000 — often enough that the
table never gets far from the truth, rarely enough that the collecting is not
itself the load.

**And more statistics on the columns the cards group by.** The default is 100
buckets per column, which on an account column holding tens of thousands of
distinct names is a planner guessing:

```bash
sudo -u postgres psql -d isemon <<'SQL'
ALTER TABLE win_events ALTER COLUMN account SET STATISTICS 500;
ALTER TABLE win_events ALTER COLUMN said    SET STATISTICS 500;
ALTER TABLE win_events ALTER COLUMN kind    SET STATISTICS 500;
SQL
sudo -u postgres psql -d isemon -c "ANALYZE win_events;"
```

Check it took:

```bash
sudo -u postgres psql -d isemon -c "
  SELECT relname, reloptions FROM pg_class
   WHERE relname IN ('win_events','failed','passed');"
sudo -u postgres psql -d isemon -c "
  SELECT relname, n_live_tup, n_dead_tup, last_autovacuum, last_autoanalyze
    FROM pg_stat_user_tables ORDER BY n_live_tup DESC LIMIT 6;"
```

`n_dead_tup` should stay a small fraction of `n_live_tup`, and both
timestamps should be recent. If `last_autovacuum` is empty on a table that
has been written to all day, autovacuum is not reaching it and nothing else
here will help.

---

## 3. The server itself

### 3.1 The arithmetic

| setting | what to use | why |
|---|---|---|
| `shared_buffers` | a quarter of RAM | PostgreSQL's own cache; past a quarter it fights the kernel's |
| `effective_cache_size` | three quarters of RAM | not an allocation — it is what the planner *believes* is cached |
| `work_mem` | see below | per sort or hash **per node per worker**, so it multiplies |
| `maintenance_work_mem` | 1–2 GB | only ever one or two at once; makes VACUUM and index builds several times quicker |
| `random_page_cost` | `1.1` on SSD | the default `4` is "a seek costs four times a sequential read", which was true of a disk that spins |
| `effective_io_concurrency` | `200` on SSD | how many reads it will have in flight at once |
| `max_parallel_workers_per_gather` | half the cores | how many helpers one query may use |
| `max_wal_size` | 4–8 GB | bigger means fewer checkpoints, which is what a log-ingesting daemon wants |
| `jit` | `off` | compiling helps a query that runs for minutes; this workload is thousands of short ones, and the compiling is pure latency |

`work_mem` is the one to be careful with. The worst case is
`max_connections × work_mem × the nodes in a plan`, so **lower
`max_connections` when you raise `work_mem`**. isemon opens a handful of
connections; 50 is generous and turns 96 MB into a 4.8 GB worst case rather
than a 9.6 GB one.

### 3.2 For 32 GB and 8 cores

```bash
sudo -u postgres psql <<'SQL'
ALTER SYSTEM SET shared_buffers                  = '8GB';
ALTER SYSTEM SET effective_cache_size            = '24GB';
ALTER SYSTEM SET work_mem                        = '96MB';
ALTER SYSTEM SET maintenance_work_mem            = '2GB';
ALTER SYSTEM SET max_connections                 = 50;

ALTER SYSTEM SET random_page_cost                = 1.1;
ALTER SYSTEM SET effective_io_concurrency        = 200;

ALTER SYSTEM SET max_worker_processes            = 8;
ALTER SYSTEM SET max_parallel_workers            = 8;
ALTER SYSTEM SET max_parallel_workers_per_gather = 4;
ALTER SYSTEM SET max_parallel_maintenance_workers = 4;

ALTER SYSTEM SET max_wal_size                    = '8GB';
ALTER SYSTEM SET min_wal_size                    = '2GB';
ALTER SYSTEM SET wal_compression                 = on;

ALTER SYSTEM SET autovacuum_max_workers          = 4;
ALTER SYSTEM SET autovacuum_naptime              = '15s';
ALTER SYSTEM SET autovacuum_vacuum_cost_limit    = 2000;

ALTER SYSTEM SET jit                             = off;
SQL
```

`ALTER SYSTEM` writes `postgresql.auto.conf` beside the main file and never
touches `postgresql.conf`, so nothing you have edited by hand is at risk.

### 3.3 Other sizes

| RAM | `shared_buffers` | `effective_cache_size` | `work_mem` | `maintenance_work_mem` |
|---|---|---|---|---|
| 8 GB | 2GB | 6GB | 32MB | 512MB |
| 16 GB | 4GB | 12GB | 64MB | 1GB |
| 32 GB | 8GB | 24GB | 96MB | 2GB |
| 64 GB | 16GB | 48GB | 128MB | 2GB |

`max_parallel_workers_per_gather` is half the cores, `max_worker_processes`
and `max_parallel_workers` are the cores.

---

## 4. Putting it in

The quick way is Settings -> The database -> *Tune it for this machine*: the
same arithmetic, put in by the dashboard. On a PostgreSQL on the same
machine, `sudo ./install.sh --db-rights` (done by a fresh install too, since
1.10.201; never by a plain upgrade) lets the program's own account change exactly those
settings, reload the server and restart it, so no administrator's password is
asked for. By hand, as postgres, that is:

```sql
GRANT ALTER SYSTEM ON PARAMETER shared_buffers, effective_cache_size, work_mem,
  maintenance_work_mem, max_worker_processes, max_parallel_workers,
  max_parallel_workers_per_gather, max_parallel_maintenance_workers, max_wal_size,
  min_wal_size, wal_compression, checkpoint_completion_target, random_page_cost,
  effective_io_concurrency, autovacuum_max_workers, autovacuum_naptime,
  autovacuum_vacuum_cost_limit, jit, checkpoint_timeout, autovacuum_work_mem TO isemon;
GRANT pg_read_all_settings TO isemon;
\c isemon
GRANT EXECUTE ON FUNCTION pg_reload_conf() TO isemon;
```

The rest of this section is doing it all by hand.

Take a copy of what you have first, so going back is a file rather than a
memory:

```bash
sudo -u postgres psql -Atc \
  "SELECT name || ' = ' || setting FROM pg_settings WHERE source <> 'default'" \
  > /root/pg-settings-before-$(date +%F).txt
cp -a /var/lib/pgsql/16/data/postgresql.auto.conf /root/postgresql.auto.conf.bak \
  2>/dev/null || cp -a /var/lib/pgsql/data/postgresql.auto.conf /root/postgresql.auto.conf.bak
```

Most of §3 takes effect on a reload. **`shared_buffers`, `max_connections`,
`max_worker_processes` and `max_wal_size` need a restart** — and while
PostgreSQL is down isemon cannot write, so restart it after:

```bash
systemctl restart postgresql-16 || systemctl restart postgresql
systemctl restart isemon
```

Then, once, so the planner starts from the truth:

```bash
sudo -u postgres psql -d isemon -c "VACUUM (ANALYZE) win_events;"
```

---

## 5. Checking it took

```bash
sudo -u postgres psql -c "
  SELECT name, setting, unit FROM pg_settings
   WHERE name IN ('shared_buffers','work_mem','effective_cache_size',
                  'maintenance_work_mem','random_page_cost','max_wal_size',
                  'jit','max_parallel_workers_per_gather')
   ORDER BY name;"
```

`shared_buffers` reads as `1048576` — the unit is 8 kB blocks, and 1,048,576
of them is 8 GB. `work_mem` reads as `98304`, in kB. `jit` reads `off`.

Then watch the thing you were trying to fix:

```bash
tail -F /var/log/isemon/isemon.log | grep "sql took"
```

On the measured machine the queries that had been 2–4 seconds each came back
under a second, and the ones that had been 12–19 seconds cold came back in
two.

### If PostgreSQL will not start

Almost always `shared_buffers` against a kernel limit. Put the old file back
and start again:

```bash
cp /root/postgresql.auto.conf.bak /var/lib/pgsql/16/data/postgresql.auto.conf
systemctl start postgresql-16
```

A single setting goes back with `ALTER SYSTEM RESET shared_buffers;` and a
reload; all of them with `ALTER SYSTEM RESET ALL;`.

---

## 6. What not to do

**`synchronous_commit = off` for the whole server.** It makes writing
quicker by not waiting for the disk, and an unclean stop of the machine costs
the last fraction of a second of commits. That is for each application on the
server to decide. For isemon's own role it is safe, because what was lost is
read again from the logs. When a busy firewall is what the daemon cannot keep
up with, see [postgresql-write-speed.md](postgresql-write-speed.md) §2.

**`fsync = off`** is not a tuning setting. It is for building a database you
are willing to throw away, and an unclean stop with it on leaves one that
will not start.

**Adding indexes to `win_events`.** It has fourteen. Each new one is disk and
a slice off every insert, on the table taking millions of rows a day. If a
query looks like it wants one, send the `EXPLAIN (ANALYZE, BUFFERS)` rather
than adding it — since 1.10.74 the queries that looked like they needed one
are answered by the index on time instead.

**Tuning before upgrading.** See below.

---

## 7. What the daemon already does

None of this replaces the two things the program does about size itself, and
both are worth more than any setting here:

**It does not store what nobody looks at.** *Settings → Windows security
logs* has two switches: whether a successful sign-in is kept at all, and
whether an object being read out of the directory is kept at all. On a
measured domain, of 756,000 events in a day, 500,000 were sign-ins and
241,000 were directory reads; everything the page exists for — the refusals,
the lockouts, the accounts and groups being changed — was 2,083 of them.
Three tenths of one percent. Anything the program has marked is kept whatever
those switches say, so the alarms do not depend on them. *Settings → The
database → Apply what is kept, now* throws away what is already stored.

**It asks the table as few times as it can.** The Domain page's answers are
worked out once however many pages ask at the same moment, kept in proportion
to what they cost to make, and the page comes back with what is ready rather
than waiting for all twenty parts. Since 1.10.74 the "newest row of each"
lookups behind every card are one seek of the index on time rather than
twelve walks of the window — measured on the real database at 39 pages
touched and 0.07 ms, against 3.4 to 3.8 seconds each before.

So the order is: **upgrade, then switch off what the site does not want kept,
then press *Apply what is kept, now*, and only then tune the server.** A
tuned PostgreSQL over a table three times larger than it needs to be is the
slower of the two.

---

## 8. A month later

Two things are worth a glance now and then.

**Is the table bloated?** Dead rows the collecting has not reached:

```bash
sudo -u postgres psql -d isemon -c "
  SELECT relname, n_live_tup, n_dead_tup,
         round(100.0 * n_dead_tup / NULLIF(n_live_tup, 0), 1) AS dead_pct,
         last_autovacuum
    FROM pg_stat_user_tables WHERE n_live_tup > 10000
   ORDER BY n_dead_tup DESC;"
```

Over about 20% on a table being written to all day means autovacuum is losing
the race: lower its scale factor further, or raise
`autovacuum_vacuum_cost_limit`.

**Is anything being read off the disk that should be in memory?**

```bash
sudo -u postgres psql -d isemon -c "
  SELECT round(100.0 * sum(heap_blks_hit)
               / NULLIF(sum(heap_blks_hit) + sum(heap_blks_read), 0), 2) AS cache_pct
    FROM pg_statio_user_tables;"
```

Under 95% on a database this size means `shared_buffers` is too small for
what is being asked of it — or that the table is bigger than it needs to be,
which §7 is about.
