#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
engines.py - the three databases this can be kept in, and moving between them.

Everything here runs without a database server anywhere. That is the point:
the part that goes wrong when this program meets MariaDB or PostgreSQL is
almost never the server, it is what this program says to it - a `?` where
`%s` was wanted, a column called `key`, `INSERT OR IGNORE`, `PRAGMA`. All of
that is decided here, by the dialect, before anything is sent, so all of it
can be held against a known answer on a machine with nothing installed.

What is checked:

  * every statement this program makes is translated, and translated once
  * the words the servers keep for themselves are quoted, in the places where
    they are names and nowhere else
  * the schema comes out in each engine's own types, with the columns that
    are indexed narrow enough for that engine to index them
  * the settings that say where the database is come out of config.json and
    are written back to config.json, never to the database they describe
  * a database that will not open leaves the program running and says so,
    rather than stopping it

And then, if there is a server on this machine after all, the same
installation is carried into it and back out again and held against what
went in - `ISEMON_TEST_MARIADB` / `ISEMON_TEST_POSTGRES`, as
`host:port:name:user:password`. Without them that part says it was skipped,
which is not a failure.

    ./test/engines.py
"""
import json
import os
import re
import gzip
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import isemon                                        # noqa: E402

PASS = FAIL = 0


def _index_on(sql):
    """Which table one of this program's index statements is on.

    MariaDB needs the table named when an index is dropped; PostgreSQL and
    the file engine do not. The statement itself says it, in both of the
    shapes the program writes them in - a plain string, and a pair for an
    engine that has partial indexes and one that has not.
    """
    if not isinstance(sql, str):
        sql = list(sql.values())[0]
    found = re.search(r'\bON\s+(\w+)', sql, flags=re.I)
    return found.group(1) if found else ''

LEFT = []


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


def title(text):
    print('\n%s' % text)


def folder():
    made = Path(tempfile.mkdtemp(prefix='isemon-engines-'))
    LEFT.append(made)
    return made


def drop(which, want, boss, code, name):
    """Take away a database and an account made by a check above.

    Written by hand rather than asked of the program, because the program
    has nothing that does this: making one is a step somebody takes once,
    and unmaking it is not a button anybody should be given.
    """
    if which == 'mariadb':
        import pymysql
        conn = pymysql.connect(host=want['host'], port=want['port'], user=boss,
                               password=code, autocommit=True, connect_timeout=10)
        try:
            cur = conn.cursor()
            cur.execute('DROP DATABASE IF EXISTS `%s`' % name)
            for host in ('%', 'localhost'):
                cur.execute("DROP USER IF EXISTS %s@%s", (name, host))
        finally:
            conn.close()
    else:
        import psycopg2
        conn = psycopg2.connect(host=want['host'], port=want['port'], user=boss,
                                password=code, dbname='postgres', connect_timeout=10)
        conn.autocommit = True
        try:
            cur = conn.cursor()
            cur.execute('DROP DATABASE IF EXISTS "%s"' % name)
            cur.execute('DROP ROLE IF EXISTS "%s"' % name)
        finally:
            conn.close()


MARIA = isemon.MariaDialect({'engine': 'mariadb', 'host': 'db', 'port': 3306,
                             'name': 'isemon', 'user': 'isemon', 'password': 'x'})
PG = isemon.PostgresDialect({'engine': 'postgres', 'host': 'db', 'port': 5432,
                             'name': 'isemon', 'user': 'isemon', 'password': 'x'})
FILE = isemon.SqliteDialect({'engine': 'sqlite', 'path': '/var/lib/isemon/isemon.db'})

try:
    # ----------------------------------------------------------------- values
    title('Where the values go')
    ok('the file engine is left exactly as it was written',
       FILE.say('SELECT * FROM failed WHERE ip = ? AND ts > ?'),
       'SELECT * FROM failed WHERE ip = ? AND ts > ?')
    for dia, word in ((MARIA, 'MariaDB'), (PG, 'PostgreSQL')):
        ok('%s is given its own placeholder' % word,
           dia.say('SELECT * FROM failed WHERE ip = ? AND ts > ?'),
           'SELECT * FROM failed WHERE ip = %s AND ts > %s')
        ok('...and a LIKE pattern is not read as one' % (),
           dia.say("SELECT 1 FROM failed WHERE session LIKE ?"),
           "SELECT 1 FROM failed WHERE session LIKE %s")
        ok('...and a percent that is part of the statement is kept',
           dia.say("SELECT 1 WHERE session LIKE 'ise1/%'"),
           "SELECT 1 WHERE session LIKE 'ise1/%%'")
        ok('...and a question mark inside a string is not a value',
           dia.say("SELECT 1 WHERE why = 'who?' AND ip = ?"),
           "SELECT 1 WHERE why = 'who?' AND ip = %s")

    title("SQLite's empty double quotes, which mean two different things")
    ok('MariaDB is given the empty string this program meant',
       MARIA.say('SELECT 1 FROM passed WHERE ip <> ""'),
       'SELECT 1 FROM passed WHERE ip <> \'\'')
    ok('...and PostgreSQL too', PG.say('SELECT 1 FROM passed WHERE ip <> ""'),
       'SELECT 1 FROM passed WHERE ip <> \'\'')
    ok('...but a name in double quotes stays a name, which is what PostgreSQL '
       'reads it as', PG.say('SELECT "session" FROM failed'),
       'SELECT "session" FROM failed')

    title('The words a server keeps for itself')
    said = MARIA.say("CREATE INDEX IF NOT EXISTS passed_sorted ON passed(ts DESC)")
    ok('an index may be called what this program calls it', 'passed_sorted' in said, True)
    ok('a column called `key` is quoted for MariaDB',
       '`key`' in MARIA.say('SELECT key FROM meta WHERE key = ?'), True)
    ok('...and one called `by` as well',
       '`by`' in MARIA.say('SELECT by FROM events'), True)
    ok('...but the same letters inside a string are left alone',
       MARIA.say("SELECT 1 WHERE why = 'banned by key'"),
       "SELECT 1 WHERE why = 'banned by key'")

    title('The things only SQLite says')
    ok('MariaDB is made to use the index this program named, not merely offered it',
       'FORCE INDEX (failed_sorted)' in
       MARIA.say('SELECT * FROM failed INDEXED BY failed_sorted WHERE ts > ?'), True)
    ok('...and PostgreSQL, which has no such thing, is not told at all',
       'INDEXED BY' in PG.say('SELECT * FROM failed INDEXED BY failed_sorted WHERE ts > ?'),
       False)
    ok('an hour is rounded down rather than cast, for MariaDB',
       'FLOOR(ts/%s)' in MARIA.say('SELECT CAST(ts/? AS INTEGER) FROM failed'), True)
    ok('...and for PostgreSQL',
       'FLOOR(ts/%s)' in PG.say('SELECT CAST(ts/? AS INTEGER) FROM failed'), True)
    ok('...and the file engine keeps its own spelling',
       'CAST(ts/? AS INTEGER)' in FILE.say('SELECT CAST(ts/? AS INTEGER) FROM failed'), True)

    title('Adding a row that may already be there')
    ok('MariaDB is given the spelling it knows',
       'INSERT IGNORE' in MARIA.say('INSERT OR IGNORE INTO blocked(ip) VALUES(?)'), True)
    ok('...and PostgreSQL the one it knows',
       'ON CONFLICT DO NOTHING' in PG.say('INSERT OR IGNORE INTO blocked(ip) VALUES(?)'),
       True)
    upsert = ('INSERT INTO meta(key, value) VALUES(?, ?) '
              'ON CONFLICT(key) DO UPDATE SET value=excluded.value')
    ok('an upsert becomes MariaDB\'s own',
       'ON DUPLICATE KEY UPDATE' in MARIA.say(upsert), True)
    ok('...and what it takes the new value from is named the way MariaDB names it',
       'VALUES(`value`)' in MARIA.say(upsert), True)
    ok('...while PostgreSQL keeps the spelling this program already uses',
       'ON CONFLICT' in PG.say(upsert) and 'excluded.value' in PG.say(upsert), True)

    # ----------------------------------------------------------------- schema
    title('The schema, in each engine\'s own types')
    tables = isemon.Dialect.schema_tables(isemon.SCHEMA)
    ok('every table in the schema is found, and only whole ones',
       all(t.isidentifier() for t in tables) and len(tables) > 8, True)
    ok('...and the one everything hangs off is among them', 'failed' in tables, True)
    for dia, word in ((MARIA, 'MariaDB'), (PG, 'PostgreSQL')):
        made = dia.ddl(isemon.SCHEMA)
        ok('%s is given one statement at a time' % word,
           all(one.count('CREATE TABLE') <= 1 for one in made), True)
        ok('...and none of them is empty', all(one.strip() for one in made), True)
        ok('...and nothing SQLite-only is left in them',
           any('AUTOINCREMENT' in one.upper() for one in made), False)
    keys = MARIA.indexed_columns(isemon.SCHEMA)
    ok('the session id is known to be indexed', 'session' in keys.get('failed', set()), True)
    body = [one for one in MARIA.ddl(isemon.SCHEMA) if 'CREATE TABLE' in one
            and ' failed ' in one][0]
    ok('...so MariaDB is told how much of it to index',
       bool(re.search(r'`session`\s+VARCHAR\(191\)', body)), True)
    ok('...while a column that is never a key is left as long as it likes',
       'LONGTEXT' in body, True)
    ok('...and the packed detail is kept as bytes rather than text',
       bool(re.search(r'`detail`\s+LONGBLOB', body)), True)
    pgbody = [one for one in PG.ddl(isemon.SCHEMA) if 'CREATE TABLE' in one
              and ' failed ' in one][0]
    ok('PostgreSQL, which needs no width, is given none',
       'VARCHAR(191)' in pgbody, False)
    ok('...and takes the detail as bytes too', 'BYTEA' in pgbody, True)
    ok('a column added later is added in the right type for MariaDB',
       MARIA.add_column('failed', 'session', 'TEXT'),
       'ALTER TABLE `failed` ADD COLUMN `session` VARCHAR(191) COLLATE utf8mb4_bin')
    ok('...and one that is not indexed is not narrowed',
       MARIA.add_column('failed', 'note', 'TEXT'),
       'ALTER TABLE `failed` ADD COLUMN `note` LONGTEXT COLLATE utf8mb4_bin')

    title('Which columns hold bytes, and what is carried into them')
    ok('the schema is what says so, not a list kept by hand',
       sorted(isemon.Dialect.BYTES_COLUMNS),
       ['failed', 'feed_ranges', 'fw_events', 'geo_ranges', 'passed', 'win_events'])
    ok('...including the domain events, whose record is packed the same way',
       isemon.Dialect.BYTES_COLUMNS['win_events'], ('detail',))
    ok('...the packed addresses of a range are bytes',
       isemon.Dialect.BYTES_COLUMNS['geo_ranges'], ('hi', 'lo'))
    ok('...and so is the record kept beside an authentication',
       isemon.Dialect.BYTES_COLUMNS['failed'], ('detail',))


    class _Far(object):
        def __init__(self, dialect):
            self.dialect = dialect

    into_server = _Far(MARIA)
    into_file = _Far(FILE)
    ok('words going into a column that holds bytes are the bytes they spell',
       isemon.Dialect.carry(['{"a":1}'], into_server, [True]), [b'{"a":1}'])
    ok('...and bytes going into a column that holds words are the words they spell',
       isemon.Dialect.carry([b'ise1'], into_server, [False]), ['ise1'])
    ok('...and each column is judged on its own',
       isemon.Dialect.carry(['x', '{"a":1}'], into_server, [False, True]),
       ['x', b'{"a":1}'])
    ok('the file engine is handed whatever it was given, both kinds',
       isemon.Dialect.carry(['words', b'bytes'], into_file, [True, False]),
       ['words', b'bytes'])
    ok('...and a memoryview is never handed on as one',
       isemon.Dialect.carry([memoryview(b'abc')], into_file, [True]), [b'abc'])
    ok('a NUL cannot be in text on a server, so it does not go',
       isemon.Dialect.carry(['a\x00b'], into_server, [False]), ['ab'])

    title('The indexes that are not in the schema')
    # They are added to a database that already exists, and on an engine that
    # counts an index key in bytes they decide how wide a column has to be
    # declared. A dialect that did not know about them declared those columns
    # unlimited, MariaDB refused to index them - "key was too long" - and
    # nine indexes were quietly missing, with every count that stands on one
    # of them answering nought.
    # An index that is one shape on one engine and another on another is
    # carried as both, because this list is only read to find out which
    # columns are ever indexed - and a column indexed by one shape is
    # indexed by the other.
    both = sum(1 if isinstance(sql, str) else len([one for one in sql.values() if one])
               for _name, sql in isemon.Storage.LATER_INDEXES)
    ok('a dialect knows about them from the moment it exists',
       len(isemon.ServerDialect.also), both)
    ok('...including the ones an engine without partial indexes gets whole',
       any(not isinstance(sql, str) for _n, sql in isemon.Storage.LATER_INDEXES), True)
    ok('...and each engine is given the shape it can make',
       [isemon.MariaDialect.PARTIAL_INDEX,
        getattr(isemon.PostgresDialect, 'PARTIAL_INDEX', True),
        getattr(isemon.SqliteDialect, 'PARTIAL_INDEX', True)],
       [False, True, True])
    fresh_maria = isemon.MariaDialect({'engine': 'mariadb'})
    narrowed = fresh_maria.indexed_columns(isemon.SCHEMA)
    for column in ('kind', 'country', 'mac', 'protocol'):
        ok('...so %s is narrow enough for MariaDB to index' % column,
           column in narrowed.get('failed', set()), True)
    made = [one for one in fresh_maria.ddl(isemon.SCHEMA)
            if 'CREATE TABLE' in one and ' failed ' in one][0]
    ok('...and it comes out of the schema builder that way',
       bool(re.search(r'`kind`\s+VARCHAR\(191\)', made)), True)

    title('A comment is not a statement')
    cut = isemon.Dialect.statements(
        "-- ISE's own AcsSessionID\nCREATE TABLE a(x TEXT);\n"
        "CREATE TABLE b(y TEXT);  -- what's here\n")
    ok('an apostrophe in a comment does not swallow the next statement',
       len(cut), 2)
    ok('...and the comment itself is gone',
       any('ISE' in one for one in cut), False)
    ok('a semicolon inside a string is not the end of anything',
       len(isemon.Dialect.statements("INSERT INTO a VALUES('x;y');")), 1)

    # ------------------------------------------------------------ the address
    title('Where the address of the database is kept')
    home = folder()
    conf = home / 'config.json'
    conf.write_text(json.dumps({'block_tries': 7, 'db_engine': 'mariadb',
                                'db_host': '10.1.1.9', 'db_port': 3307,
                                'db_name': 'isemon', 'db_user': 'isemon',
                                'db_password': 'a good one'}))
    was_file, was_config = isemon.CONFIG_FILE, dict(isemon.CONFIG)
    try:
        isemon.CONFIG_FILE = conf
        isemon.load_config(conf)
        want = isemon.db_config()
        ok('the engine is read out of the file', want['engine'], 'mariadb')
        ok('...with the host', want['host'], '10.1.1.9')
        ok('...and the port', want['port'], 3307)
        ok('...and the password, which is needed to open it at all',
           want['password'], 'a good one')
        ok('the file engine needs no address at all',
           set(isemon.db_config({'db_engine': 'sqlite'})), {'engine', 'path'})
        ok('a setting that means nothing falls back to the file engine',
           isemon.db_config({'db_engine': 'oracle'})['engine'], 'sqlite')

        title('Changing it writes the file, and only what changed')
        isemon.write_file_settings({'db_host': '10.1.1.10'}, conf)
        again = json.loads(conf.read_text())
        ok('the host is changed', again['db_host'], '10.1.1.10')
        ok('...and everything else in the file is left alone',
           again['block_tries'], 7)
        ok('...and so is the password', again['db_password'], 'a good one')
        ok('the file is not readable by everybody: it holds a password',
           conf.stat().st_mode & 0o7, 0)
        # ...and one somebody has deliberately made stricter stays that way.
        os.chmod(conf, 0o600)
        isemon.write_file_settings({'db_host': '10.1.1.11'}, conf)
        ok('...and a stricter one is not loosened by being written',
           conf.stat().st_mode & 0o777, 0o600)
        ok('these are the settings that may only come from the file',
           set(isemon.FILE_ONLY),
           {'db_engine', 'db_host', 'db_port', 'db_name', 'db_user',
            'db_password', 'db_timeout_s'})
        ok('...and the address of the database is all of them',
           all(one.startswith('db_') for one in isemon.FILE_ONLY), True)

        title('A config.json this daemon cannot write')
        # The daemon does not run as root and config.json is in /etc, which
        # its own unit closes. Saying "[Errno 30] Read-only file system" at
        # somebody is telling them what happened and not what to do.
        shut = folder()
        closed = shut / 'config.json'
        closed.write_text('{"site_name": "x"}\n')
        # Closed to whoever is running this, whoever that is - these checks
        # are run as root as often as not, and root walks through a mode.
        # A path that cannot be a path is refused for everybody.
        blocked = shut / 'not-a-folder'
        blocked.write_text('this is a file\n')
        impossible = blocked / 'config.json'
        if True:
            said = ''
            try:
                isemon.write_file_settings({'db_host': '10.1.1.9'}, impossible)
                said = '(it wrote it)'
            except isemon.StorageError as e:
                said = str(e)
            except OSError as e:
                said = 'a bare OSError: %s' % e
            ok('it is refused rather than half-written',
               said.startswith('the settings that say which database'), True)
            ok('...and what to run is in the words', 'chmod 2770' in said, True)
            ok('...including the one the daemon itself is stopped by',
               'ReadWritePaths' in said, True)
            ok('...and the way round it from a root shell',
               'isemon --set' in said, True)
            ok('...and no other config.json is touched',
               closed.read_text(), '{"site_name": "x"}\n')
            ok('...with nothing half-written left lying about',
               sorted(one.name for one in shut.iterdir()),
               ['config.json', 'not-a-folder'])
    finally:
        isemon.CONFIG_FILE = was_file
        isemon.CONFIG.clear()
        isemon.CONFIG.update(was_config)

    title('The nightly copy, when the database is not there')
    # The copy is followed by throwing the oldest ones away. A machine whose
    # server has gone and is standing in with an empty database would
    # otherwise spend a quiet week replacing every real copy with a copy of
    # nothing, and the first anybody would know of it is the day they need
    # one.
    yard = folder()
    was_db, was_backup, was_dumps = isemon.DB_FILE, isemon.BACKUP_DIR, isemon.DUMP_DIR
    try:
        isemon.DB_FILE = yard / 'live.db'
        isemon.BACKUP_DIR = yard / 'copies'
        # The nightly one is a dump now, and a dump is kept in its own
        # folder - on the file engine it is SQLite's own backup, which is
        # the same file a copy is, which is why this reads the same.
        isemon.DUMP_DIR = yard / 'nightly'
        isemon.CONFIG['backup_daily'] = 1
        isemon.CONFIG['backup_at'] = time.strftime('%H:%M')  # now, not a fixed
        # minute: pinned to '00:01' this passed all day and failed for one
        # minute a night, when the nightly copy is not due yet.
        isemon.CONFIG['backup_keep'] = 3
        live = isemon.Storage()
        for i in range(20):
            live.add_failed({'session': 'n/%d' % i, 'ts': time.time() - i, 'server': 'ise1',
                             'ip': '203.0.113.1', 'username': 'u', 'kind': 'vpn',
                             'device': 'FTD-VPN'})
        keeper = isemon.Daemon(live)
        for _ in range(3):
            live.set_meta('backup_day', '')
            keeper.backup_due(wait=True)
            time.sleep(1.05)
        real = sorted(one.name for one in isemon.DUMP_DIR.glob('*.db'))
        ok('three nights running leave three copies', len(real), 3)
        live.close()

        spare = isemon.Storage(path=yard / 'no-database.db',
                               engine={'engine': 'sqlite', 'path': str(yard / 'no-database.db')})
        spare.trouble = "Can't connect to MySQL server on '10.1.1.9'"
        spare.wanted = {'engine': 'mariadb', 'host': '10.1.1.9', 'port': 3306,
                        'name': 'isemon', 'user': 'isemon', 'password': 'x'}
        standing_in = isemon.Daemon(spare)
        for _ in range(5):
            spare.set_meta('backup_day', '')
            standing_in.backup_due(wait=True)
        after = sorted(one.name for one in isemon.DUMP_DIR.glob('*.db'))
        ok('...and five nights with no database add none', len(after), 3)
        ok('...and take none away either: they are the same three', after, real)
        newest = sqlite3.connect(str(isemon.DUMP_DIR / after[-1]))
        try:
            held = newest.execute('SELECT COUNT(*) FROM failed').fetchone()[0]
        finally:
            newest.close()
        ok('...so the newest copy still holds what was in the database', held, 20)
        spare.close()
    finally:
        isemon.DB_FILE, isemon.BACKUP_DIR = was_db, was_backup
        isemon.DUMP_DIR = was_dumps

    # ---------------------------------------------------------------- dumps
    # The nightly one is what the engine in use makes of itself, which means
    # three different programs and three different files - and one promise
    # over all of them: a dump goes back into the engine it came off, is
    # refused anywhere else, and says which of the two it is before anything
    # is replaced.
    title('The dump each engine makes of itself')
    ok('the file engine writes one as a database file',
       isemon.SqliteDialect({'path': 'x'}).dump_suffix, '.db')
    ok('...MariaDB as compressed SQL', MARIA.dump_suffix, '.sql.gz')
    ok('...and PostgreSQL in its own format', PG.dump_suffix, '.pgc')
    ok('the file engine needs nothing installed to make one',
       isemon.SqliteDialect({'path': 'x'}).dump_ready(), (True, ''))
    ok('...and the ending of a file is what says which it is',
       [isemon.Storage.dump_kind(n) for n in
        ('isemon-1.pgc', 'isemon-1.sql.gz', 'isemon-1.db', 'holiday.jpg')],
       ['postgres', 'mariadb', 'sqlite', ''])

    yard3 = folder()
    was_db3, was_dumps3 = isemon.DB_FILE, isemon.DUMP_DIR
    try:
        isemon.DB_FILE = yard3 / 'live.db'
        isemon.DUMP_DIR = yard3 / 'nightly'
        live = isemon.Storage()
        for i in range(30):
            live.add_failed({'session': 'd/%d' % i, 'ts': time.time() - i, 'server': 'ise1',
                             'ip': '203.0.113.7', 'username': 'u', 'kind': 'vpn',
                             'device': 'FTD-VPN'})
        live.put_user('keeper', 'a-long-enough-password', 'fulladmin', by='test')
        made = live.dump(label='daily')
        ok('a dump of the file engine is a file of its own', made.exists(), True)
        ok('...listed as one, and as this engine\'s own',
           [(one['kind'], one['mine']) for one in live.dumps()], [('sqlite', True)])
        said, why = live.dump_peek(made)
        ok('...read back without anything being put anywhere', said is not None, True)
        ok('...and what is in it is counted', said['counts']['failed'], 30)
        ok('...including whether anybody could sign in afterwards',
           said['admins'] >= 1, True)

        # Rubbish, and somebody else's dump: refused for two different
        # reasons, and the reason is the useful part.
        junk = yard3 / 'junk.bin'
        junk.write_bytes(b'this is not a dump of anything' * 40)
        said, why = live.dump_peek(junk)
        ok('something that is not a dump at all is refused', said, None)
        ok('...and named as none of the three', 'not a dump this program made' in why, True)

        # A PostgreSQL dump handed to an installation on the file: refused
        # on sight, by the first five bytes, with the two ways out named.
        far = yard3 / 'isemon-elsewhere.pgc'
        far.write_bytes(b'PGDMP' + b'\x00' * 200)
        said, why = live.dump_peek(far)
        ok('a dump of another engine is refused', said, None)
        ok('...saying which engine it is and which this is',
           'PostgreSQL dump' in why and 'the file on this machine' in why, True)
        ok('...and that a copy is what goes into any of them', 'copy' in why, True)

        # ...and the nightly job, which is the only thing that makes one on
        # its own. Three nights, then a fourth with two kept.
        isemon.CONFIG['backup_daily'] = 1
        isemon.CONFIG['backup_at'] = time.strftime('%H:%M')
        isemon.CONFIG['backup_keep'] = 2
        keeper = isemon.Daemon(live)
        for _ in range(3):
            live.set_meta('backup_day', '')
            keeper.backup_due(wait=True)
            time.sleep(1.05)
        ok('the nightly job makes one, and keeps as many as it is told to',
           len(live.dumps()), 2)
        ok('...and it is done for the day once it has', live.get_meta('backup_day'),
           time.strftime('%Y-%m-%d'))
        newest = live.dumps()[0]
        keeper.backup_due(wait=True)
        ok('...and the same day again makes no second one',
           live.dumps()[0]['name'], newest['name'])
        live.close()
    finally:
        isemon.DB_FILE, isemon.DUMP_DIR = was_db3, was_dumps3

    title('The switch that says everything')
    # It is the one thing somebody reaches for when a database is doing
    # something they cannot see, so what it writes down is worth holding.
    yard2 = folder()
    was_log = isemon._LOG_PATH
    isemon.close_log()
    isemon.open_log(yard2 / 'isemon.log')
    was_debug = isemon.CONFIG.get('debug')
    was_db2, was_backup2 = isemon.DB_FILE, isemon.BACKUP_DIR
    try:
        isemon.DB_FILE = yard2 / 'live.db'
        isemon.BACKUP_DIR = yard2 / 'copies'
        isemon.CONFIG['debug'] = False
        quiet = isemon.Storage()
        quiet.get_meta('nothing in particular')
        lines = ((yard2 / 'isemon.log').read_text().splitlines()
                 if (yard2 / 'isemon.log').exists() else [])
        was = len(lines)
        # Opening a database says what it did to the schema (1.10.94); what
        # the switch governs is the statements.
        sql_off = [one for one in lines if '] sql ' in one]
        isemon.CONFIG['debug'] = True
        quiet.get_meta('nothing in particular')
        quiet.set_meta('something', 'else')
        quiet.db.execute('SELECT ts FROM events WHERE kind = ?',
                         ('nothing in particular',)).fetchall()
        now = (yard2 / 'isemon.log').read_text().splitlines()
        said = [one for one in now[was:] if '[debug] sql ' in one]
        ok('with the switch off, a read writes nothing to the log', sql_off, [])
        ok('...and with it on, every statement is written down', len(said) >= 3, True)
        ok('...with the statement itself in the line',
           any('SELECT value FROM meta' in one for one in said), True)
        ok('...and the values it was given',
           any("'nothing in particular'" in one and 'FROM events' in one for one in said),
           True)
        ok('...and how long it took',
           all(re.search(r'sql \d+ ms', one) for one in said), True)
        # ...but never the values of a statement that touches the tables
        # where the secrets are. `meta` holds the router's own private key,
        # `settings` holds the passwords this machine signs in to things
        # with, `users` holds what people sign in here with and `sessions`
        # holds the tokens their browsers carry. The switch is for finding
        # out why a query is slow, and nobody turning it on has asked for
        # any of that in a file on disk.
        for table, line in (('meta', 'SELECT value FROM meta'),
                            ('meta', 'INSERT INTO meta')):
            hit = [one for one in said if line in one]
            ok('nothing a statement over %s was given is written down' % table,
               bool(hit) and all('not written down' in one for one in hit), True)
        ok('...and neither is the key the statement asked for',
           any('nothing in particular' in one and 'FROM meta' in one for one in said),
           False)

        # A statement that fails is written down whatever the switch says,
        # because that is the line somebody is looking for.
        isemon.CONFIG['debug'] = False
        before_fail = len((yard2 / 'isemon.log').read_text().splitlines())
        try:
            quiet.db.execute('SELECT * FROM a_table_that_is_not_there')
        except Exception:
            pass
        after = (yard2 / 'isemon.log').read_text().splitlines()[before_fail:]
        ok('a statement that failed is written down even with the switch off',
           any('sql refused' in one for one in after), True)
        ok('...saying which engine refused it',
           any('refused by sqlite' in one for one in after), True)
        quiet.close()
    finally:
        isemon.CONFIG['debug'] = was_debug
        isemon.DB_FILE, isemon.BACKUP_DIR = was_db2, was_backup2
        isemon.close_log()
        if was_log:
            isemon.open_log(was_log)

    title('A server that is not there')
    got = isemon.db_try({'engine': 'mariadb', 'host': '127.0.0.1', 'port': 1,
                         'name': 'isemon', 'user': 'isemon', 'password': 'x',
                         'timeout': 2})
    ok('it is said not to have worked', got['ok'], False)
    ok('...and said why, in words', bool(str(got['trouble']).strip()), True)
    ok('...without the password appearing in the saying',
       'x' == got['trouble'] or 'password=' in str(got['trouble']).lower(), False)

    # --------------------------------------------------- carrying it across
    title('Carrying an installation from one engine to another')

    def pages_ask(store):
        """Every question the cards on the page ask, asked of this engine.

        Each of these reads both lists, and the two lists have not got the
        same columns: `reason` is on the refusals, `tkey` and `subtype` are
        on the sign-ins. Asking a table for a column it has not got is not a
        query that comes back empty - it is a query that does not run, and
        what the person sees is an error where the answer should be. On the
        file engine some of it very nearly works, which is how one of these
        shipped and was found by somebody clicking it on PostgreSQL.

        Every answer here is held against the rows that were just put in,
        because an empty answer is exactly what a refused query looks like
        from the outside: all of these catch the refusal and return nothing.
        """
        now = time.time()
        store.add_passed({'session': 'card/lan-ok', 'ts': now - 20, 'server': 'isea',
                          'username': 'NB0003W11', 'kind': 'dot1x-lan',
                          'device': 'SW-4NP-01', 'port': 'GigabitEthernet1/0/14',
                          'mac': 'BC-FC-E7-D7-86-70', 'client': '172.29.14.88',
                          'subtype': 'let on', 'tkey': '607/VLAN607'})
        store.add_failed({'session': 'card/lan-no', 'ts': now - 80, 'server': 'isea',
                          'ip': '', 'username': 'NB0003W11', 'kind': 'dot1x-lan',
                          'device': 'SW-4NP-01', 'port': 'GigabitEthernet1/0/14',
                          'mac': 'BC-FC-E7-D7-86-70',
                          'reason': '22056 Subject not found in the applicable ID store'})
        store.add_failed({'session': 'card/vpn-no', 'ts': now - 30, 'server': 'ise1',
                          'ip': '203.0.113.77', 'username': 'pkolar', 'kind': 'vpn',
                          'device': 'FTD-VPN', 'reason': 'wrong password'})
        store.add_passed({'session': 'card/vpn-ok', 'ts': now - 10, 'server': 'ise1',
                          'ip': '203.0.113.77', 'username': 'pkolar', 'kind': 'vpn',
                          'device': 'FTD-VPN', 'machine': 'NB-PKOLAR'})
        store.note_otp_asked({'ts': now - 5, 'at': now - 5, 'server': 'radius1',
                              'username': 'pkolar@example.cz', 'ip': '203.0.113.77',
                              'port': '41001', 'half': 'answer', 'verdict': 'accept',
                              'said': 'Access-Accept', 'rid': '203.0.113.77:41001'})
        seen = store.address_seen('203.0.113.77')
        who = store.name_seen('pkolar')
        net = store.network_seen('NB0003W11')
        broke = []
        for door in ('vpn', 'otp', 'eduroam', 'dot1x-lan', 'dot1x-wifi', 'mab-lan',
                     'mab-wifi', 'tacacs', 'other', ''):
            for which, ask in (('failed', store.failed_rows), ('passed', store.passed_rows)):
                try:
                    ask(kind=door, text='kolar', ip='203.0.113.77', limit=5)
                except Exception as e:
                    broke.append('%s/%s: %s' % (which, door or 'every door', e))
        return {
            'doors at that address': sorted(d['kind'] for d in seen['doors']),
            'and who was there last': (seen['last'] or {}).get('kind', ''),
            'doors that name has been at': sorted(d['kind'] for d in who['doors']),
            'addresses that name came from': [a['ip'] for a in who['addresses']],
            'token packets from there': len(store.otp_asked_from('203.0.113.77')),
            'how often that name is refused and gets in': store.name_counts('pkolar'),
            'what the machine did on the network':
                [(r['ok'], r['switch'], r['port'], r['vlan'], r['said'][:5]) for r in net],
            'a search at every door': broke,
        }

    PAGES_WANT = {
        'doors at that address': ['otp', 'vpn'],
        'and who was there last': 'otp',
        'doors that name has been at': ['vpn'],
        'addresses that name came from': ['203.0.113.77'],
        'token packets from there': 1,
        'how often that name is refused and gets in': {'failed': 1, 'passed': 1},
        'what the machine did on the network': [
            (True, 'SW-4NP-01', 'GigabitEthernet1/0/14', '607/VLAN607', 'let o'),
            (False, 'SW-4NP-01', 'GigabitEthernet1/0/14', '', '22056')],
        'a search at every door': [],
    }

    def fill(store, tag):
        now = time.time()
        for i in range(60):
            # Half of them with a record too short to be worth packing and
            # half with one long enough to be packed. That is what a real
            # database holds, and it is the thing a fixture made all of one
            # kind will never show: SQLite keeps words and bytes in the same
            # column happily, and every other engine has a type there and
            # takes one and refuses the other. A move that only ever carried
            # the packed ones passed every test and stopped half way through
            # somebody's own data.
            short = i % 2 == 0
            store.add_failed({'session': '%s/%d' % (tag, i), 'ts': now - i,
                              'server': 'ise1', 'ip': '203.0.113.%d' % (i % 50),
                              'username': 'jnovak', 'kind': 'vpn', 'device': 'FTD-VPN',
                              'detail': '{"RadiusFlowType":"RemoteAccessVPN","pad":"%s"}'
                                        % ('x' * (10 if short else 600))})
        store.add_passed({'session': '%s/p' % tag, 'ts': now, 'server': 'ise1',
                          'ip': '10.0.0.1', 'username': 'novak', 'kind': 'vpn',
                          'groups': 'VPN-Users'})
        store.block('203.0.113.7', until=now + 900, why='carried across')
        store.settings_write({'block_tries': 9}, by='test')
        store.add_event('logs', 'made on %s' % tag, 'info')
        # Somebody who could sign in afterwards. Putting a copy or a dump
        # back is refused when there is nobody, so a fixture with no account
        # in it could never be restored - and the check for that is one of
        # the things being checked.
        store.put_user('keeper', 'a-long-enough-password', 'fulladmin', by='test')

    def sums(store):
        n = lambda q: store.db.execute(q).fetchone()['n']
        # One of each: the short record that was never packed and went in as
        # words, and the long one that was packed and went in as bytes. Both
        # have to come back out as the words they were, on every engine.
        one = store.db.execute(
            "SELECT detail FROM failed WHERE session LIKE '%/1'").fetchone()
        two = store.db.execute(
            "SELECT detail FROM failed WHERE session LIKE '%/2'").fetchone()
        return {'failed': n('SELECT COUNT(*) AS n FROM failed'),
                'passed': n('SELECT COUNT(*) AS n FROM passed'),
                'blocked': n('SELECT COUNT(*) AS n FROM blocked'),
                'events': n('SELECT COUNT(*) AS n FROM events'),
                'block_tries': store.settings_saved().get('block_tries'),
                'packed detail': (store.unpack_detail(one['detail']) or '')[:34] if one else '',
                'plain detail': (store.unpack_detail(two['detail']) or '')[:34] if two else ''}

    home = folder()
    was_db, was_backup, was_engine = isemon.DB_FILE, isemon.BACKUP_DIR, isemon.Storage.ENGINE
    try:
        isemon.DB_FILE = home / 'live.db'
        isemon.BACKUP_DIR = home / 'copies'
        isemon.Storage.ENGINE = None
        src = isemon.Storage()
        fill(src, 'sq')
        before = sums(src)
        ok('an installation is made on the file engine', before['failed'], 60)
        ok('...and what it holds can be read back',
           before['packed detail'].startswith('{"RadiusFlowType"'), True)
        ok('...the short records as well as the packed ones',
           before['plain detail'].startswith('{"RadiusFlowType"'), True)
        kinds = sorted({r['t'] for r in src.db.execute(
            'SELECT typeof(detail) AS t FROM failed')})
        ok('...and the file really is holding both shapes in the one column',
           kinds, ['blob', 'text'])
        copy = src.backup(label='to-carry')
        ok('a copy of it is a file', copy.exists() and copy.stat().st_size > 0, True)
        ok('...and it says it was taken off the file engine',
           src.copy_came_off(copy), 'sqlite')
        ok('...and it is recognised as one of ours',
           src.looks_like_ours(copy)[0] is not None, True)
        src.close()
        isemon.DB_FILE = home / 'again.db'
        again = isemon.Storage()
        again.restore(copy)
        ok('read into another file engine, it is the same installation',
           sums(again), before)
        ok('every question the cards ask is answered on the file engine',
           pages_ask(again), PAGES_WANT)
        again.close()

        servers = []
        for which, env, port in (('mariadb', 'ISEMON_TEST_MARIADB', 3306),
                                 ('postgres', 'ISEMON_TEST_POSTGRES', 5432)):
            said = os.environ.get(env, '')
            if not said:
                print('  --    %s: no %s, so nothing was tried' % (which, env))
                continue
            host, _, rest = said.partition(':')
            sport, _, rest = rest.partition(':')
            name, _, rest = rest.partition(':')
            user, _, word = rest.partition(':')
            servers.append((which, {'engine': which, 'host': host or '127.0.0.1',
                                    'port': int(sport or port), 'name': name or 'isemon',
                                    'user': user or 'isemon', 'password': word,
                                    'timeout': 10}))
        for which, want in servers:
            ready, why = isemon.DIALECTS[which].driver_ready()
            if not ready:
                print('  --    %s: %s' % (which, why))
                continue
            isemon.Storage.ENGINE = want
            far = isemon.Storage()
            for table in isemon.Dialect.schema_tables(isemon.SCHEMA):
                try:
                    far.db.execute('DROP TABLE IF EXISTS %s' % far.dialect.ident(table))
                except Exception:
                    pass
            far.close()
            far = isemon.Storage()
            # Minutes of copying with nothing on the screen is
            # indistinguishable from a move that has hung, and somebody
            # watching one is right to think so. So it says where it is,
            # table by table and batch by batch. (A file into a file is
            # SQLite's own backup, one operation and no tables, which is
            # why this is asked of a server.)
            seen = []
            far.restore(copy, say=lambda i, of, table, done, whole: seen.append(
                (i, of, table, done, whole)))
            ok('carried into %s, it is the same installation' % which, sums(far), before)
            ok('...and it said how far it had got while it did it', bool(seen), True)
            ok('...naming the table, and how many there are in all',
               all(one[2] and one[1] == len(isemon.Dialect.schema_tables(isemon.SCHEMA))
                   for one in seen), True)
            ok('...never claiming more rows than the table has',
               [one for one in seen if one[3] > one[4]], [])
            ok('...and ending on the last of them', seen[-1][0], seen[-1][1] - 1)

            # ...and the dump this engine makes of itself, which is the
            # nightly one: made by that engine's own program, read back
            # without a server anywhere near it, and put back over a
            # database that has had a table taken out from under it.
            ready, why = far.dump_ready()
            if not ready:
                print('  --    %s: %s, so the dump was not tried' % (which, why))
            else:
                was_dumps = isemon.DUMP_DIR
                isemon.DUMP_DIR = home / ('dumps-%s' % which)
                try:
                    began = time.time()
                    one_dump = far.dump(label='daily')
                    ok('%s dumps itself with its own program' % which,
                       one_dump.exists() and one_dump.stat().st_size > 0, True)
                    ok('...into the file that engine writes',
                       one_dump.name.endswith(far.dialect.dump_suffix), True)
                    ok('...and it is smaller than the database it came off',
                       one_dump.stat().st_size < max(1, far.dialect.size(far.db)), True)
                    said, why = far.dump_peek(one_dump)
                    ok('...what is in it can be read without a server',
                       said is not None, True)
                    ok('...every table of ours is in it',
                       said and said.get('tables', 0)
                       >= len(isemon.Dialect.schema_tables(isemon.SCHEMA)), True)
                    ok('...and it knows whether anybody could sign in afterwards',
                       said and said.get('admins', 0) >= 1, True)
                    # Take a table away and empty another, the way a bad day
                    # does it, and put the dump back over the wreckage.
                    with far.db_write() as db:
                        db.execute('DELETE FROM failed')
                        db.execute('DROP TABLE %s' % far.dialect.ident('eduroam_seen'))
                    done = far.restore_dump(one_dump)
                    ok('...putting it back gives the whole installation back',
                       sums(far), before)
                    ok('...including the table that was dropped',
                       'eduroam_seen' in set(far.dialect.tables(far.db)), True)
                    ok('...and a portable copy of what it replaced was made first',
                       (isemon.BACKUP_DIR / done['safety']).exists(), True)
                    # The other engine's dump, offered to this one.
                    other_kind = 'postgres' if which == 'mariadb' else 'mariadb'
                    wrong = home / ('isemon-elsewhere'
                                    + isemon.DIALECTS[other_kind].dump_suffix)
                    wrong.write_bytes(b'PGDMP' + b'\x00' * 300 if other_kind == 'postgres'
                                      else gzip.compress(b'-- nothing of ours\n' * 40))
                    said, why = far.dump_peek(wrong)
                    ok('...a dump of the other engine is refused here', said, None)
                    # ...while the portable copy is taken by the same door,
                    # because a copy goes into any of the three.
                    said, why = far.dump_peek(copy)
                    ok('...and a portable copy is still taken by that same door',
                       said is not None and said.get('kind'), 'sqlite')
                finally:
                    isemon.DUMP_DIR = was_dumps

            back = far.backup(label='from-%s' % which)

            # Everything that follows writes, so it happens after the copy
            # that is held against what went in.
            #
            # A database server keeps a connection that has read inside a
            # transaction looking at the same rows for ever unless it is
            # told otherwise, and this daemon has threads that live for
            # months.
            other = isemon.Storage()
            was = far.db.execute('SELECT COUNT(*) AS n FROM events').fetchone()['n']
            other.add_event('logs', 'written while the other one was idle', 'info')
            now = far.db.execute('SELECT COUNT(*) AS n FROM events').fetchone()['n']
            ok('...and a connection that read a moment ago sees what was written since',
               now, was + 1)
            ok('...and what was written got a number of its own, rather than one that '
               'was already taken',
               far.db.execute('SELECT COUNT(*) AS n FROM events').fetchone()['n'] > 0, True)
            other.close()

            # The nightly copy, on this engine. It is the same button and the
            # same scheduled work as on the file, and what it writes is a
            # file either way - a copy made on a server has to be openable
            # on a machine that has no server.
            nights = folder()                 # its own, so nothing else is pruned
            kept_dir, isemon.DUMP_DIR = isemon.DUMP_DIR, nights
            try:
                isemon.CONFIG['backup_daily'] = 1
                isemon.CONFIG['backup_at'] = time.strftime('%H:%M')
                far.set_meta('backup_day', '')
                isemon.Daemon(far).backup_due(wait=True)
                nightly = sorted(nights.glob('isemon-*daily*'))
                ok('the nightly one is made on %s too' % which, bool(nightly), True)
                if nightly:
                    ok('...as this engine\'s own dump, not as a copy',
                       far.dump_kind(nightly[-1].name), which)
                    said, why = far.dump_peek(nightly[-1])
                    ok('...holding every table of ours',
                       said and said.get('tables', 0)
                       >= len(isemon.Dialect.schema_tables(isemon.SCHEMA)), True)
                    ok('...and the day is written down, so it happens once a day',
                       far.get_meta('backup_day'), time.strftime('%Y-%m-%d'))
                    isemon.Daemon(far).backup_due(wait=True)
                    ok('...and asking again the same day makes no second one',
                       len(sorted(nights.glob('isemon-*daily*'))), 1)
            finally:
                isemon.DUMP_DIR = kept_dir

            # Checking and tidying, which are two buttons on the page and
            # are the two that look the same on every engine and are not.
            ok('%s says whether it is sound' % which, far.check(), 'ok')
            spare = far.db.execute('SELECT COUNT(*) AS n FROM failed').fetchone()['n']
            # Enough rows that there is real room to give back. A handful
            # deleted out of an empty database leaves nothing to reclaim,
            # and the room the tidy itself takes - the maps a plain VACUUM
            # writes for a table it has never had to think about - is bigger
            # than what came back. What the button promises is the disk back
            # after somebody erases a year of records, so that is what is
            # asked of it.
            stamp = time.time()
            with far.db_write() as db:
                db.executemany(
                    'INSERT INTO failed (session, ts, server, ip, username, kind) '
                    'VALUES (?,?,?,?,?,?)',
                    [('t/%d' % i, stamp - i, 'ise1', '10.0.0.%d' % (i % 250),
                      'somebody%d' % i, 'vpn') for i in range(60000)])
            far.optimize()                       # ...so the growing is already done
            with far.db_write() as db:
                db.execute('DELETE FROM failed')
            was, now = far.optimize()
            ok('...and tidying it up really gives the room back (%s -> %s)'
               % (isemon.human_size(was), isemon.human_size(now)), now < was, True)
            ok('...and what it holds is what is left, not what was deleted',
               far.db.execute('SELECT COUNT(*) AS n FROM failed').fetchone()['n'], 0)
            far.restore(copy)          # put it back for the checks below
            ok('...and it comes back whole afterwards',
               far.db.execute('SELECT COUNT(*) AS n FROM failed').fetchone()['n'], spare)

            # ...while a write that goes wrong half way through still leaves
            # nothing behind, which is the reason a transaction is opened at
            # all.
            kept = far.db.execute('SELECT COUNT(*) AS n FROM whitelist').fetchone()['n']
            try:
                with far.db_write() as db:
                    db.execute('INSERT INTO whitelist(ip, note, by, at) VALUES(?,?,?,?)',
                               ('203.0.113.201', 'half', 'test', time.time()))
                    db.execute('INSERT INTO no_such_table_here(x) VALUES(1)')
            except Exception:
                pass
            ok('...and a write that fails half way leaves nothing behind',
               far.db.execute('SELECT COUNT(*) AS n FROM whitelist').fetchone()['n'], kept)

            # The cards on the page, on this engine. This is the one thing
            # in here that a file engine cannot stand in for: the queries
            # behind them name columns that are on one list and not the
            # other, and a server refuses that outright where SQLite is
            # often forgiving.
            ok('every question the cards ask is answered on %s' % which,
               pages_ask(far), PAGES_WANT)
            far.close()
            isemon.Storage.ENGINE = None
            isemon.DB_FILE = home / ('back-%s.db' % which)
            home_again = isemon.Storage()
            home_again.restore(back)
            ok('...and carried back out of it, still the same',
               sums(home_again), before)
            home_again.close()
    finally:
        isemon.DB_FILE, isemon.BACKUP_DIR = was_db, was_backup
        isemon.Storage.ENGINE = was_engine

    # ------------------------------------------------------------ setting up
    # "Set it up" does two different jobs behind the one button, and which
    # one depends on whether the account already gets in: make what is not
    # there, or check over and mend what is. The password for the account is
    # made here rather than asked for, which is the part that has to be
    # right - it is written into config.json and shown once, and if it were
    # ever lost or printed twice that would be a real fault.
    title('Setting a server up, and checking one over')
    made = {isemon.db_password_made() for _ in range(200)}
    ok('every password it makes is a different one', len(made), 200)
    ok('...long enough to be worth having', min(len(w) for w in made) >= 24, True)
    ok('...and nothing in it that a shell, a URL or a psql line reads as punctuation',
       sorted({c for w in made for c in w if not c.isalnum()}), [])
    ok('...made of letters and digits, which is what those two rules leave',
       all(w.isalnum() and w.isascii() for w in made), True)

    for which, want in servers:
        said = os.environ.get('ISEMON_TEST_%s_ADMIN' % which.upper(), '')
        if not said:
            print('  --    %s: no ISEMON_TEST_%s_ADMIN, so setting up was not tried'
                  % (which, which.upper()))
            continue
        boss, _, code = said.partition(':')
        # A name of its own, so that nothing here touches the database the
        # checks above have been using.
        fresh = dict(want)
        fresh['name'] = fresh['user'] = 'isemonset'
        fresh['password'] = ''
        was_engine = isemon.Storage.ENGINE
        try:
            drop(which, want, boss, code, 'isemonset')
            gone = isemon.db_try(dict(fresh, password='whatever-it-is-not'))
            ok('%s: before any of this, that account does not get in' % which,
               bool(gone.get('ok')), False)

            # From nothing: it makes the password itself.
            fresh['password'] = isemon.db_password_made()
            done = isemon.db_make(fresh, boss, code)
            ok('...an administrator makes the database and the account',
               len(done) >= 2, True)
            got = isemon.db_try(fresh)
            ok('...and afterwards that account gets in with the password made for it',
               bool(got.get('ok') and got.get('writable')), True)
            ok('...to a database with nothing of ours in it yet', got.get('ours'), 0)

            isemon.Storage.ENGINE = dict(fresh)
            store = isemon.Storage()
            whole = sorted(isemon.Dialect.schema_tables(isemon.SCHEMA))
            ok('...and opening it builds every table this version wants',
               sorted(t for t in store.dialect.tables(store.db) if t in set(whole)), whole)
            ok('...with no column short', store.missing_columns(), [])
            indexes = sum(len(store.dialect.indexes(store.db, t)) for t in whole)
            ok('...and its indexes on them', indexes > 0, True)
            store.close()

            # Pressed a second time, with no administrator anywhere near it:
            # this is the upgrade check. Take away an index, a column and a
            # whole table, the way an older version would have left them.
            isemon.Storage.ENGINE = dict(fresh)
            store = isemon.Storage()
            # EVERY column and EVERY index this version adds after the fact,
            # not a sample of them. An upgrade has to work from any version
            # to any version - nobody goes version by version - and a test
            # that takes away two columns proves only that those two come
            # back. Written from the program's own lists, so a column added
            # next year is in this test the day it is added.
            gone_columns = []
            for table, columns in isemon.Storage.LATER_COLUMNS.items():
                if table not in set(store.dialect.tables(store.db)):
                    continue
                have = {c.lower() for c in store.dialect.columns(store.db, table)}
                for name, _kind in columns:
                    if name.lower() in have:
                        gone_columns.append((table, name))
            gone_index = []
            with store.db_write() as db:
                for table, name in gone_columns:
                    db.execute('ALTER TABLE %s DROP COLUMN %s'
                               % (store.dialect.ident(table), store.dialect.ident(name)))
                db.execute('DROP TABLE %s' % store.dialect.ident('eduroam_seen'))
            # One index, one transaction - the lesson the program itself
            # learned about PostgreSQL: a statement that fails inside a
            # transaction poisons every statement after it, so a `try` around
            # each one inside a single transaction does nothing at all.
            there = set(store.dialect.index_names(store.db))
            for name, _sql in isemon.Storage.LATER_INDEXES:
                if name not in there:
                    continue
                try:
                    with store.db_write() as db:
                        db.execute('DROP INDEX %s' % (
                            name if which == 'postgres' else
                            '%s ON %s' % (name, _index_on(_sql))))
                    gone_index.append(name)
                except Exception:
                    pass
            ok('...every column this version adds after the fact can be gone',
               len(gone_columns) >= 15, True)
            ok('...and every index it adds after the fact',
               len(gone_index) >= 10, True)
            # Looked at through the connection that did the damage, because
            # opening a Storage is itself the mending: there is no moment
            # when this program has a broken database open.
            ok('...a table, the columns and the indexes are then really gone',
               ['eduroam_seen' in set(store.dialect.tables(store.db)),
                'client' in {c.lower() for c in store.dialect.columns(store.db, 'failed')},
                'machine' in {c.lower() for c in store.dialect.columns(store.db, 'passed')},
                'by_logon' in {c.lower()
                               for c in store.dialect.columns(store.db, 'win_events')},
                bool(set(gone_index) & set(store.dialect.index_names(store.db)))],
               [False, False, False, False, False])
            store.close()

            again = isemon.db_try(fresh)
            ok('...and the account still gets in, so no administrator is wanted',
               bool(again.get('ok') and again.get('writable')), True)
            isemon.Storage.ENGINE = dict(fresh)
            mended = isemon.Storage()
            ok('...opening it puts the missing table back',
               sorted(t for t in mended.dialect.tables(mended.db) if t in set(whole)), whole)
            ok('...and every missing column, on every table that lost one',
               [mended.missing_columns(),
                sorted(set((t, n) for t, n in gone_columns
                           if n.lower() not in {c.lower() for c
                                                in mended.dialect.columns(mended.db, t)}))],
               [[], []])
            ok('...and every missing index',
               sorted(set(gone_index) - set(mended.dialect.index_names(mended.db))), [])
            ok('...and the missing index, back to as many as it had',
               sum(len(mended.dialect.indexes(mended.db, t)) for t in whole), indexes)
            # Every list, at every door, with words in the search box. The
            # box adds a column or two for the door being looked at, and a
            # column belongs to one table and not always to the other - ask
            # the wrong one for it and the query does not come back wrong,
            # it does not run at all. SQLite says so and so does a server,
            # but only a server is what this site is actually on, so it is
            # asked here too.
            # ---------------------------------------------------------
            # A copy does not stop everything else.
            #
            # It used to hold the write lock for the whole of itself, and a
            # gigabyte off PostgreSQL is minutes of reading: pressing "make
            # a copy now" stopped the entire installation - the reader, the
            # page, a person signing in - for five minutes, which from
            # outside is indistinguishable from a daemon that has died.
            title('...and a copy of it does not stop everything else')
            isemon.Storage.ENGINE = dict(fresh)
            busy = isemon.Storage()
            now = time.time()
            with busy.db_write() as db:
                db.executemany(
                    'INSERT INTO failed (session, ts, server, ip, username, kind) '
                    'VALUES (?,?,?,?,?,?)',
                    [('c/%d' % i, now - i, 'ise1', '10.0.0.%d' % (i % 250),
                      'somebody%d' % (i % 90), 'vpn') for i in range(40000)])
            waits, stop = [], threading.Event()

            def keep_writing():
                i = 0
                while not stop.is_set():
                    at = time.time()
                    try:
                        with busy.db_write() as db:
                            db.execute('DELETE FROM meta WHERE key = ?', ('beat',))
                            db.execute('INSERT INTO meta (key, value) VALUES (?,?)',
                                       ('beat', str(i)))
                    except Exception:
                        break
                    waits.append(time.time() - at)
                    i += 1
                    time.sleep(0.02)

            beat = threading.Thread(target=keep_writing)
            beat.start()
            began = time.time()
            copy = busy.backup(label='while-writing')
            took = time.time() - began
            stop.set()
            beat.join()
            worst = max(waits) if waits else 0.0
            ok('the copy was made', copy.exists() and copy.stat().st_size > 0, True)
            ok('...and the rest of the program kept writing throughout',
               len(waits) > 5, True)
            # The whole point: the worst wait is a moment, not the length of
            # the copy. Generously judged, because a test machine is a test
            # machine - what is being caught is a wait as long as the job.
            ok('...and none of them waited anything like the length of the copy '
               '(worst %.2f s of %.1f s)' % (worst, took),
               worst < max(1.0, took * 0.5), True)
            # ...and what came out is a copy of everything, not of a moment
            # in the middle of one.
            spare = isemon.sqlite3.connect(str(copy))
            spare.row_factory = isemon.sqlite3.Row
            ok('...and it holds every row that was there when it started',
               spare.execute('SELECT COUNT(*) AS n FROM failed').fetchone()['n'] >= 40000,
               True)
            spare.close()
            copy.unlink()
            busy.close()

            isemon.Storage.ENGINE = dict(fresh)
            mended = isemon.Storage()
            broke = []
            for door in ('vpn', 'tacacs', 'otp', 'eduroam', 'dot1x-lan', 'dot1x-wifi',
                         'mab-lan', 'mab-wifi', 'other', ''):
                for name, ask in (('failed', mended.failed_rows),
                                  ('passed', mended.passed_rows)):
                    try:
                        ask(kind=door, text='somebody', limit=5)
                    except Exception as e:
                        broke.append('%s/%s: %s' % (name, door or 'every door', str(e)[:80]))
            ok('...and every list can be searched at every door on this engine', broke, [])
            mended.close()
        finally:
            isemon.Storage.ENGINE = was_engine
            drop(which, want, boss, code, 'isemonset')

finally:
    for one in LEFT:
        shutil.rmtree(one, ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
