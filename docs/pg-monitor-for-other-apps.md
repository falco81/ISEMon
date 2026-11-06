# PostgreSQL statistics functions, refused: `pg_ls_waldir()` and `pg_monitor`

A write-up for the sister applications (upsmon, plexmon, acme, otp, …) that
keep their data in PostgreSQL under an account of their own. isemon met this
in 1.10.309–1.10.315; the same shape fits anything that reads the server's
own statistics.

## The symptom

The application's log, every time a page is looked at and every time a
background check runs:

```
[warn] sql refused by postgres after 1 ms: SELECT COALESCE(SUM(size), 0) AS n, COUNT(*) AS f FROM pg_ls_waldir()
       | permission denied for function pg_ls_waldir
```

Nothing is broken - the number simply is not shown - but the log fills with a
warning nobody can act on from the log, and a real warning drowns in it.

## The cause

`pg_ls_waldir()` (the size of the write-ahead log, `pg_wal/`) is one of the
functions PostgreSQL gives only to:

- a **superuser**, or
- a member of the predefined role **`pg_monitor`** (PostgreSQL 10 and newer;
  `pg_ls_waldir` itself is there from 10).

The application's own account is neither: it owns its database and nothing
more, as it should. The code caught the exception and went on - but the
database layer logs every refused statement *before* it raises, so catching
it was not enough.

Other functions and views with the same rule, for whoever reads them:
`pg_ls_logdir()`, `pg_ls_tmpdir()`, `pg_ls_archive_statusdir()`,
`pg_stat_file()` and `pg_read_file()` outside the data folder,
`pg_stat_activity` rows of other users (`query` shows `<insufficient
privilege>` there rather than refusing), `pg_stat_replication`. The views
`pg_stat_user_tables`, `pg_stat_user_indexes`, `pg_replication_slots`,
`pg_database_size()`, `pg_relation_size()` and friends need nothing.

## How to tell, without being refused

Ask whether the account may - this one any account may run:

```sql
SELECT r.rolsuper OR pg_has_role(current_user, 'pg_monitor', 'MEMBER') AS may
FROM pg_roles r WHERE r.rolname = current_user;
```

For another account (an administrator looking at the application's):

```sql
SELECT r.rolsuper OR pg_has_role(r.rolname, 'pg_monitor', 'MEMBER')
FROM pg_roles r WHERE r.rolname = 'theapp';
```

On the command line, as root on the database server:

```bash
sudo -u postgres psql -Atc "SELECT pg_has_role('theapp', 'pg_monitor', 'MEMBER')"
```

## The fix, in two halves

### 1. Never ask what the account may not be told

Before the call, ask whether it may; remember the answer (per connection or
per store - it changes only when somebody grants it); when it may not, skip
the call and say *why* in the answer instead of a number.

```python
may = getattr(store, '_may_waldir', None)
if may is None:
    try:
        row = db.execute(
            "SELECT (r.rolsuper OR pg_has_role(current_user, 'pg_monitor', 'MEMBER')) "
            "AS may FROM pg_roles r WHERE r.rolname = current_user").fetchone()
        may = bool(row and row['may'])
    except Exception:
        may = False
    store._may_waldir = may
out['wal'] = None
out['wal_why'] = '' if may else 'pg_monitor'
if may:
    try:
        row = db.execute('SELECT COALESCE(SUM(size), 0) AS n, COUNT(*) AS f '
                         'FROM pg_ls_waldir()').fetchone()
        out['wal'] = {'bytes': int(row['n'] or 0), 'files': int(row['f'] or 0)}
    except Exception:
        store._may_waldir = False      # refused after all: not asked again
```

Points that matter:

- The check must be one **any** account may run (`pg_roles` and
  `pg_has_role` are readable by everybody), else it is the same refusal one
  step earlier.
- Remember it. Asking every few seconds is a round trip for nothing.
- A refusal after a "may" (a role taken away since) turns the remembered
  answer off, so it is not refused again on the next look.
- Forget the remembered answer whenever the application itself grants the
  right (below), so the next look measures at once.

On the page, where the number would be, say what it takes rather than
nothing:

> Write-ahead log – the server tells it to pg_monitor only:
> `GRANT pg_monitor TO` the application's account

### 2. Let the right be given where an administrator already is

Three places in isemon give `pg_monitor` to the application's own account,
each only where an administrator is already acting - the application never
asks for, keeps or logs an administrator's password for this alone:

1. **Settings → The database → Tune it for this machine** (the one that
   already takes an administrator, in the popup, used for that one request
   and stored nowhere). The plan now lists, beside the settings, *what this
   program's account may do* - `pg_monitor: it has it / it has not; Put it in
   gives it`; **Put it in** offers itself when only a right is missing, and
   grants it as that administrator:

   ```python
   from psycopg2 import sql as pgsql
   cur.execute(pgsql.SQL('GRANT {} TO {}').format(
       pgsql.Identifier('pg_monitor'), pgsql.Identifier(app_user)))
   ```

   Only roles from a fixed list in the code (`RIGHTS_PG`), only to the
   application's own account (from its own configuration, never from the
   request), written to Events as who gave what, and the remembered "may"
   forgotten.

2. **The installer's rights step** (`sudo ./install.sh --db-rights` in
   isemon, run once as root on the database server, through `runuser -u
   postgres -- psql`): one more line beside the rights it already gives:

   ```bash
   sql+="GRANT pg_monitor TO \"$user\";"$'\n'
   ```

3. **The move to PostgreSQL** (the wizard that creates the account and the
   database as an administrator): the same `GRANT pg_monitor` after the
   account is made.

Everywhere: `GRANT` of a role the account already has is harmless - a notice,
not an error (PostgreSQL 16: `role "theapp" has already been granted
membership in role "pg_monitor" by role "postgres"`) - so none of these need
to look first; the plan does, to say it.

### What `pg_monitor` gives, so nobody is surprised

It is read-only: membership of `pg_read_all_settings`, `pg_read_all_stats`
and `pg_stat_scan_tables`, and `pg_ls_waldir()` / `pg_ls_logdir()` and
friends. It cannot change a setting, read a table that is not the account's,
or write anything. It does show other sessions' queries in
`pg_stat_activity` - on a server shared with other applications, say so in
the plan.

## Tests

- Against a real PostgreSQL, an account **without** the role: the look
  returns `wal: None, wal_why: 'pg_monitor'`, and **no statement naming
  `pg_ls_waldir` is sent at all** (wrap the connection and record what goes
  through it) - that is what keeps the log clean.
- The same account after Tune's Put it in as `postgres`: `granted:
  ['pg_monitor']`, the plan then says it has it, the look measures the WAL;
  nothing refused in the application's log, the administrator's password in
  no row, event, answer or log line.
- Source checks: the may-check comes before the call; the right is granted
  from a fixed list only; the installer and the migration grant it too.

## Checklist for another application

1. `grep -n "pg_ls_\|pg_stat_file\|pg_read_file\|pg_stat_replication" -r .` -
   every call is behind a may-check like the one above.
2. Look at the application's log on a real install for `permission denied
   for function` / `must be superuser` - each one is a call to put behind a
   check.
3. Where the application has a step with an administrator already (tuning,
   installer, migration), grant `pg_monitor` there; nowhere else ask for an
   administrator for this.
4. The page says what it would take where a number is missing, rather than
   showing nothing or a zero.
5. A test that records the statements sent as an unprivileged account.
