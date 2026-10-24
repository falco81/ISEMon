#!/usr/bin/env python3
"""A database server that drops a connection: every thread gets a new one.

Only means anything on PostgreSQL and MariaDB, which is where it is run
(`runengine64.py <engine> reconnect`); on a file there is no connection to
lose, and the suite says so and passes.

Until 1.10.97 a thread that used the database every few seconds - the main
loop does - was never asked whether its connection was still there, because
the check waited for a minute of quiet. After the database server was
restarted every write on that thread failed for good.
"""
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import isemon  # noqa: E402

PASS = FAIL = 0


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


print('A connection the server dropped is replaced')
if not getattr(isemon.Storage, 'ENGINE', None):
    ok('on a file there is no connection to lose', True)
    print('\n%d ok, %d failed' % (PASS, FAIL))
    sys.exit(0)

store = isemon.Storage()
engine = store.dialect.name
store.set_meta('reconnect-check', 'before')
if engine == 'postgres':
    mine = store.db.execute('SELECT pg_backend_pid() AS n').fetchone()['n']
else:
    mine = store.db.execute('SELECT CONNECTION_ID() AS n').fetchone()['n']
ok('this thread has a connection', bool(mine))

# The server drops it - from another connection, as a restart or an idle
# timeout would - while this thread is busy (used a moment ago, so the idle
# check alone would never look).
killer = {}


def kill():
    other = isemon.Db(store.dialect.connect(), store.dialect)
    if engine == 'postgres':
        other.execute('SELECT pg_terminate_backend(%d)' % int(mine))
    else:
        other.execute('KILL %d' % int(mine))
    other.close()
    killer['done'] = True


t = threading.Thread(target=kill)
t.start()
t.join()
ok('the server was told to drop it', killer.get('done'), True)
time.sleep(0.5)

# The first statement after the drop is the one that finds out; it may fail.
try:
    store.set_meta('reconnect-check', 'during')
except Exception:
    pass
# ...and from then on the thread works again, without a restart.
store.set_meta('reconnect-check', 'after')
ok('the next write on the same thread lands', store.get_meta('reconnect-check'), 'after')
if engine == 'postgres':
    now = store.db.execute('SELECT pg_backend_pid() AS n').fetchone()['n']
else:
    now = store.db.execute('SELECT CONNECTION_ID() AS n').fetchone()['n']
ok('...on a new connection', now != mine, True)

# A refused statement that is only a bad statement does not cost the
# connection.
try:
    store.db.execute('SELECT no_such_column FROM meta')
except Exception:
    pass
same = store.db
ok('a statement the server refused leaves a working connection in place',
   same.execute('SELECT 1 AS n').fetchone()['n'], 1)

# A driver error out of begin/commit is a DbError, which every
# `except sqlite3.Error` in the program catches.
ok('the driver’s own errors are the program’s', issubclass(isemon.DbError,
                                                                  isemon.sqlite3.Error), True)

# A half-built index (only PostgreSQL has them) is taken away at the next
# start and built again.
if engine == 'postgres':
    with store.db_write() as db:
        db.execute('DROP INDEX IF EXISTS events_kind')
    # Made INVALID by hand, the way a CREATE INDEX CONCURRENTLY that was
    # stopped leaves it.
    store.db.execute('CREATE INDEX events_kind ON events (kind)')
    # Only a superuser may; the test harness's server trusts `postgres` locally.
    import psycopg2
    su = psycopg2.connect(host='127.0.0.1', port=5432, user='postgres',
                          dbname=isemon.Storage.ENGINE.get('name') or 'isemontest')
    su.autocommit = True
    su.cursor().execute("UPDATE pg_index SET indisvalid = false WHERE indexrelid = "
                        "'events_kind'::regclass")
    su.close()
    ok('the index is there but not usable', store.dialect.invalid_indexes(store.db),
       ['events_kind'])
    store.mend()
    ok('the next start takes it away and builds it again',
       ('events_kind' in store.dialect.index_names(store.db),
        store.dialect.invalid_indexes(store.db)), (True, []))

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
