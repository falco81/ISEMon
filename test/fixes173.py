#!/usr/bin/env python3
"""1.10.173: the database server's own settings, for its machine.

What the machine has, read through whatever reads its files; the settings
worked out for PostgreSQL and MariaDB the way docs/postgresql-tuning.md
works them out; what is there already left alone where it is within reason;
what a server takes only at a start said so; the page, the relay and the
installer's polkit rule. On a database server, with ISEMON_TUNE_ADMIN set
to `name:password` of an administrator there, the settings are also put
in and put back - and the administrator is looked for, and not found, in
everything this program keeps.

    ./test/fixes173.py
    ISEMON_TUNE_ADMIN=postgres:secret ./test/fixes173.py   (on a server)
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import isemon                                        # noqa: E402

PASS = FAIL = 0
GB = 1024 ** 3
MB = 1024 ** 2


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


source = (HERE.parent / 'isemon.py').read_text(encoding='utf-8')
page = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')
setup = (HERE.parent / 'install.sh').read_text(encoding='utf-8')
rule = (HERE.parent / 'deploy' / '49-isemon-database.rules').read_text(encoding='utf-8')


def plan_of(items):
    return {it['name']: it['want'] for it in items}


def pg_server(**now):
    """A PostgreSQL as installed, with what is given in place of that."""
    base = {'shared_buffers': 128 * MB, 'effective_cache_size': 4 * GB, 'work_mem': 4 * MB,
            'maintenance_work_mem': 64 * MB, 'max_worker_processes': 8,
            'max_parallel_workers': 8, 'max_parallel_workers_per_gather': 2,
            'max_parallel_maintenance_workers': 2, 'max_wal_size': GB,
            'min_wal_size': 80 * MB, 'wal_compression': 'off',
            'checkpoint_completion_target': 0.9, 'random_page_cost': 4.0,
            'effective_io_concurrency': 1, 'autovacuum_max_workers': 3,
            'autovacuum_naptime': 60, 'autovacuum_vacuum_cost_limit': -1, 'jit': True,
            'max_connections': 100}
    base.update(now)
    restart = {'shared_buffers', 'max_worker_processes', 'autovacuum_max_workers',
               'max_connections'}
    return {k: {'value': v, 'min': None, 'max': None, 'restart': k in restart,
                'pending': False} for k, v in base.items()}


print('\nPostgreSQL, worked out for 32 GB and 8 processors on an SSD (the doc’s machine)')
m = {'ram': 32 * GB, 'cpus': 8, 'disk': 'ssd', 'avail': None}
want = plan_of(isemon.tune_plan_pg(m, pg_server(max_connections=50), local=False,
                                   free=200 * GB))
ok('the numbers of docs/postgresql-tuning.md §3.2', {k: want[k] for k in (
    'shared_buffers', 'effective_cache_size', 'work_mem', 'maintenance_work_mem',
    'max_worker_processes', 'max_parallel_workers', 'max_parallel_workers_per_gather',
    'max_parallel_maintenance_workers', 'max_wal_size', 'min_wal_size',
    'random_page_cost', 'effective_io_concurrency', 'autovacuum_max_workers',
    'autovacuum_naptime', 'autovacuum_vacuum_cost_limit', 'jit')},
   {'shared_buffers': 8 * GB, 'effective_cache_size': 24 * GB, 'work_mem': 96 * MB,
    'maintenance_work_mem': 2 * GB, 'max_worker_processes': 8, 'max_parallel_workers': 8,
    'max_parallel_workers_per_gather': 4, 'max_parallel_maintenance_workers': 4,
    'max_wal_size': 8 * GB, 'min_wal_size': 2 * GB, 'random_page_cost': 1.1,
    'effective_io_concurrency': 200, 'autovacuum_max_workers': 4,
    'autovacuum_naptime': 15, 'autovacuum_vacuum_cost_limit': 2000, 'jit': False})
same = plan_of(isemon.tune_plan_pg(m, pg_server(max_connections=50), local=True))
ok('...the same with this program beside it on the machine', same['shared_buffers'], 8 * GB)
wide = plan_of(isemon.tune_plan_pg(m, pg_server(max_connections=100), local=False))
ok('work_mem kept small enough for a hundred connections', wide['work_mem'] < 96 * MB
   and wide['work_mem'] * 100 * 2 <= (32 - 8) * GB * 0.5 + MB)
ok('max_connections itself is never planned', 'max_connections' in want, False)
far = plan_of(isemon.tune_plan_pg(m, pg_server(), local=False))
ok('a server elsewhere, whose free disk is not known: WAL kept to 4 GB',
   far['max_wal_size'], 4 * GB)

print('\nOther machines')
small = plan_of(isemon.tune_plan_pg({'ram': 8 * GB, 'cpus': 2, 'disk': 'ssd'},
                                    pg_server(max_connections=50), local=False))
ok('8 GB: the doc’s row', (small['shared_buffers'], small['effective_cache_size'],
                                small['maintenance_work_mem']), (2 * GB, 6 * GB, 512 * MB))
ok('...and never fewer worker processes than PostgreSQL’s own eight',
   small['max_worker_processes'], 8)
hdd = plan_of(isemon.tune_plan_pg({'ram': 32 * GB, 'cpus': 8, 'disk': 'hdd'}, pg_server(),
                                  local=False))
ok('a disk that spins: reads from anywhere cost what PostgreSQL thinks they cost',
   (hdd['random_page_cost'], hdd['effective_io_concurrency']), (4.0, 2))
roomy = isemon.tune_plan_pg(m, pg_server(), local=False, free=40 * GB)
ok('WAL kept to a tenth of the free disk', plan_of(roomy)['max_wal_size'], 4 * GB)
tight = isemon.tune_plan_pg({'ram': 32 * GB, 'cpus': 8, 'disk': 'ssd', 'avail': 3 * GB},
                            pg_server(), local=False)
ok('shared_buffers grows only as far as the memory free now allows: 128 MB + 2.5 GB',
   plan_of(tight)['shared_buffers'], 128 * MB + 3 * GB - 512 * MB)
ok('...and says why', 'free now' in tight[0]['why'])

print('\nWhat is there already')
judged = {it['name']: it for it in isemon.tune_judge(
    isemon.tune_plan_pg(m, pg_server(shared_buffers=12 * GB, effective_io_concurrency=300),
                        local=False), pg_server(shared_buffers=12 * GB,
                                                effective_io_concurrency=300))}
ok('more than the plan, within what is safe, is left alone',
   (judged['shared_buffers']['change'], judged['effective_io_concurrency']['change']),
   (False, False))
too = {it['name']: it for it in isemon.tune_judge(
    isemon.tune_plan_pg(m, pg_server(shared_buffers=20 * GB), local=False),
    pg_server(shared_buffers=20 * GB))}
ok('...past it is brought back', (too['shared_buffers']['change'],
                                   too['shared_buffers']['want']), (True, 8 * GB))
ok('the settings that take only at a start are said so',
   (too['shared_buffers']['restart'], too['work_mem']['restart']), (True, False))
older = pg_server()
del older['jit']
older['effective_io_concurrency']['max'] = 100
oj = {it['name']: it for it in isemon.tune_judge(isemon.tune_plan_pg(m, older, local=False),
                                                 older)}
ok('a setting a server does not have is left out', 'jit' in oj, False)
ok('...and a value past what it takes is brought within it',
   oj['effective_io_concurrency']['want'], 100)
again = isemon.tune_judge([dict(it) for it in judged.values()], pg_server(
    shared_buffers=12 * GB, effective_io_concurrency=300))
ok('judging what was judged gives the same answer',
   sorted(it['name'] for it in again if it['change']),
   sorted(n for n, it in judged.items() if it['change']))

print('\nMariaDB')
ms = {k: {'value': v, 'min': None, 'max': None, 'restart': False, 'pending': False}
      for k, v in {'innodb_buffer_pool_size': 128 * MB, 'innodb_log_file_size': 96 * MB,
                   'innodb_io_capacity_max': 2000, 'innodb_io_capacity': 200,
                   'innodb_flush_neighbors': 1, 'innodb_read_io_threads': 4,
                   'innodb_write_io_threads': 4, 'tmp_table_size': 16 * MB,
                   'max_heap_table_size': 16 * MB}.items()}
mp = isemon.tune_plan_maria(m, ms, local=True)
ok('half the memory for the buffer pool, beside this program',
   plan_of(mp)['innodb_buffer_pool_size'], 16 * GB)
ok('...more of it on a machine of its own',
   plan_of(isemon.tune_plan_maria(m, ms, local=False))['innodb_buffer_pool_size'] > 16 * GB)
ok('an SSD: nothing written beside a page for nothing, and more written a second',
   (plan_of(mp)['innodb_flush_neighbors'], plan_of(mp)['innodb_io_capacity']), (0, 2000))
capped = dict(ms)
capped['innodb_buffer_pool_size_max'] = {'value': 128 * MB, 'min': None, 'max': None,
                                         'restart': True, 'pending': False}
mj = {it['name']: it for it in isemon.tune_judge(mp, capped)}
ok('a pool past the most the server was started with waits for its start',
   mj['innodb_buffer_pool_size']['restart'], True)
ok('...and the file says that most too',
   'innodb_buffer_pool_size_max = 16G' in isemon.DbTune.cnf(
       type('T', (), {})(), list(mj.values())))
nj = isemon.tune_judge(mp, ms)
ok('...which a server without it is not given', 'innodb_buffer_pool_size_max' in
   isemon.DbTune.cnf(type('T', (), {})(), nj), False)
ok('the file is named to be read last', 'zz-isemon-tuning.cnf' in
   isemon.DbTune.cnf(type('T', (), {})(), nj)
   and "/etc/my.cnf.d/zz-isemon-tuning.cnf" in page)

print('\nWhat the server says, as numbers')


class Cursor(object):
    def __init__(self, rows):
        self.rows = rows

    def execute(self, sql, args=None):
        self.sql = sql

    def fetchall(self):
        return self.rows


class Conn(object):
    def __init__(self, rows):
        self.rows = rows

    def cursor(self):
        return Cursor(self.rows)


pg_rows = [('shared_buffers', '16384', '8kB', 'integer', 'postmaster', '16', '1073741823',
            '/var/lib/pgsql/16/data/postgresql.auto.conf', False, 'configuration file'),
           ('work_mem', '4096', 'kB', 'integer', 'user', '64', '2147483647', None, False,
            'configuration file'),
           ('max_wal_size', '1024', 'MB', 'integer', 'sighup', '2', '2147483647',
            '/x/postgresql.conf', True, 'configuration file'),
           ('autovacuum_naptime', '60', 's', 'integer', 'sighup', '1', '2147483', None, False,
            'default'),
           ('random_page_cost', '4', None, 'real', 'user', '0', '1.79769e+308', None, False,
            'default'),
           ('jit', 'on', None, 'bool', 'user', None, None, None, False, 'default'),
           ('wal_compression', 'off', None, 'enum', 'superuser', None, None, None, False,
            'default')]
got = isemon.tune_settings(Conn(pg_rows), 'postgres', ['x'])
ok('PostgreSQL: sizes in bytes, whatever the unit', (got['shared_buffers']['value'],
   got['work_mem']['value'], got['max_wal_size']['value']), (128 * MB, 4 * MB, GB))
ok('...the limits in the same', (got['shared_buffers']['min'], got['work_mem']['min']),
   (16 * 8192, 64 * 1024))
ok('...times in seconds, and the rest as they are', (got['autovacuum_naptime']['value'],
   got['random_page_cost']['value'], got['jit']['value'], got['wal_compression']['value']),
   (60, 4.0, True, 'off'))
ok('...what takes a start, what waits for one, and where it came from',
   (got['shared_buffers']['restart'], got['max_wal_size']['pending'],
    got['shared_buffers']['in_auto'], got['max_wal_size']['in_auto'],
    got['work_mem']['in_auto'], got['jit']['in_auto']), (True, True, True, False, None, False))
ok('PostgreSQL 16 says pglz for wal_compression = on, and that is the same',
   (isemon.tune_same('enum', 'pglz', 'on'), isemon.tune_same('enum', 'off', 'on')),
   (True, False))
mrows = [('INNODB_BUFFER_POOL_SIZE', '134217728', 'NO', '2097152', '9223372036854775807'),
         ('INNODB_READ_IO_THREADS', '4', 'YES', '1', '64')]
mgot = isemon.tune_settings(Conn(mrows), 'mariadb', ['x'])
ok('MariaDB: by its name in small letters, read-only as taking a start',
   (mgot['innodb_buffer_pool_size']['value'], mgot['innodb_read_io_threads']['restart']),
   (128 * MB, True))
t = isemon.DbTune.__new__(isemon.DbTune)
up = [n['name'] for n in t.order_maria([{'name': 'innodb_io_capacity', 'want': 2000},
                                        {'name': 'innodb_io_capacity_max', 'want': 4000}],
                                       {'innodb_io_capacity': 200})]
down = [n['name'] for n in t.order_maria([{'name': 'innodb_io_capacity', 'want': 200},
                                          {'name': 'innodb_io_capacity_max', 'want': 400}],
                                         {'innodb_io_capacity': 2000})]
ok('the most a capacity may be goes first when it rises, last when it falls',
   (up, down), (['innodb_io_capacity_max', 'innodb_io_capacity'],
                ['innodb_io_capacity', 'innodb_io_capacity_max']))
clamped = isemon.tune_judge([{'name': 'effective_io_concurrency', 'kind': 'int', 'want': 200,
                              'lo': 100, 'hi': 1000, 'why': ''}],
                            {'effective_io_concurrency': {'value': 0, 'min': 0, 'max': 0,
                                                          'restart': False, 'pending': False}})
ok('a value the server cannot go past is not asked for again and again',
   (clamped[0]['want'], clamped[0]['change']), (0, False))

print('\nThe machine, read')
files = {
    '/proc/meminfo': 'MemTotal:       32847108 kB\nMemFree:  100 kB\nMemAvailable:   30000000 kB\n',
    '/proc/cpuinfo': ''.join('processor\t: %d\nflags\t\t: fpu sse2 hypervisor\n\n' % i
                             for i in range(8)),
    '/proc/self/mountinfo': (
        '22 1 253:0 / / rw - xfs /dev/mapper/root rw\n'
        '40 22 8:17 / /var/lib/pgsql rw - xfs /dev/sdb1 rw\n'),
    '/sys/dev/block/8:17/../queue/rotational': '0\n',
}
got = isemon.tune_machine(files.get, '/var/lib/pgsql/16/data')
ok('memory, free memory, processors', (got['ram'], got['avail'], got['cpus']),
   (32847108 * 1024, 30000000 * 1024, 8))
ok('a virtual machine, from its processors', got['virtual'], True)
ok('the disk under the data, through its partition', (got['device'], got['rotational']),
   ('8:17', False))
files['/sys/fs/cgroup/memory.max'] = '%d\n' % (4 * GB)
files['/sys/fs/cgroup/cpu.max'] = '200000 100000\n'
boxed = isemon.tune_machine(files.get, '/var/lib/pgsql/16/data')
ok('a container’s limits count', (boxed['ram'], boxed['avail'], boxed['cpus']),
   (4 * GB, 4 * GB, 2))
files['/sys/fs/cgroup/memory.max'] = 'max\n'
ok('...and "max" is no limit', isemon.tune_machine(files.get, '')['ram'], 32847108 * 1024)
ok('a mount on top of another: the last one', isemon.tune_device_of(
    '1 0 8:1 / / rw - x\n2 1 8:2 / /data rw - x\n3 1 8:3 / /data rw - x\n', '/data/pg'), '8:3')
ok('...and a path beside a mount is not under it', isemon.tune_device_of(
    '1 0 8:1 / / rw - x\n2 1 8:2 / /data rw - x\n', '/database/pg'), '8:1')
ok('nothing to read, nothing said', isemon.tune_machine(lambda p: None, '/x'),
   {'ram': None, 'avail': None, 'cpus': None, 'rotational': None, 'virtual': None,
    'device': ''})

print('\nWhat is typed, against what was read')


class Dialect(object):
    name = 'mariadb'
    config = {}


class Box(object):
    def __init__(self, local):
        self.local = local
        self.dialect = Dialect()

    def server_local(self):
        return self.local

    def server_files(self):
        return None


def tuner(local, read=None):
    t = isemon.DbTune.__new__(isemon.DbTune)
    t.store = Box(local)
    t.engine = 'mariadb'
    t.here = lambda conn: (local, None)
    return t


real_machine = isemon.tune_machine
isemon.tune_machine = lambda read, data_dir='': {'ram': 8 * GB, 'avail': 6 * GB, 'cpus': 2,
                                                 'rotational': None, 'virtual': True,
                                                 'device': ''}
try:
    far = tuner(False).facts(None, False, {'ram_gb': '16', 'cpus': '4'})
    ok('a server elsewhere, nothing read: what is typed, said to be typed',
       (far['ram'], far['avail'], far['cpus'], far['source']), (16 * GB, None, 4, 'typed'))
    here = tuner(True)
    try:
        here.facts(None, False, {'ram_gb': '16'})
        ok('more memory than this machine has cannot be typed for a server on it', False)
    except isemon.StorageError as e:
        ok('more memory than this machine has cannot be typed for a server on it',
           'more than that cannot be typed' in str(e))
    less = here.facts(None, False, {'ram_gb': '4,0', 'cpus': '2'})
    ok('...less can, and what is free is no more than that',
       (less['ram'], less['avail'], less['source']), (4 * GB, 4 * GB, 'this machine'))
    same = here.facts(None, False, {'ram_gb': '8.0'})
    ok('...and the number read, typed back as it was shown, changes nothing',
       (same['ram'], same['avail']), (8 * GB, 6 * GB))
    for bad in ({'ram_gb': 'lots'}, {'ram_gb': '0'}, {'cpus': '2.5'}):
        try:
            here.facts(None, False, bad)
            ok('%r is refused' % bad, False)
        except isemon.StorageError as e:
            ok('%r is refused, saying what is wanted' % bad, 'a number of GB' in str(e))
finally:
    isemon.tune_machine = real_machine

print('\nTwo presses, and going back')
kept_meta = {}


class Kept(object):
    dialect = type('D', (), {'name': 'postgres', 'where': lambda self: 'pg@here/db'})()

    def meta_json(self, key, fallback=None):
        return json.loads(kept_meta[key]) if key in kept_meta else fallback

    def set_meta(self, key, value):
        kept_meta[key] = value


class OneConn(object):
    def close(self):
        pass

    def cursor(self):
        return type('C', (), {'execute': lambda self, *a: None})()


def press(plan_items, before, after):
    t = isemon.DbTune.__new__(isemon.DbTune)
    t.store = Kept()
    t.engine = 'postgres'
    t.plan = lambda *a, **k: {'items': plan_items, 'may': True, 'facts': {}, 'restart': {}}
    real = (isemon.tune_connect, isemon.tune_settings)
    calls = iter([before, after])
    isemon.tune_connect = lambda *a, **k: OneConn()
    isemon.tune_settings = lambda conn, engine, names: next(calls)
    try:
        return t.apply('admin', 'pw', by='tester')
    finally:
        isemon.tune_connect, isemon.tune_settings = real


def setting(v, raw, in_auto=False):
    return {'value': v, 'raw': raw, 'in_auto': in_auto, 'pending': False}


one = {'name': 'max_wal_size', 'kind': 'mem', 'want': 4 * GB, 'change': True, 'restart': False,
       'lo': 4 * GB, 'hi': None}
two = {'name': 'jit', 'kind': 'bool', 'want': False, 'change': True, 'restart': False,
       'lo': None, 'hi': None}
press([dict(one)], {'max_wal_size': setting(GB, '1024')},
      {'max_wal_size': setting(4 * GB, '4096')})
press([dict(two), dict(one, want=3 * GB, change=False)], {'jit': setting(True, 'on')},
      {'jit': setting(False, 'off'), 'max_wal_size': setting(4 * GB, '4096')})
rec = json.loads(kept_meta['db_tune'])
ok('a second press keeps what the first put in, and what it was before',
   (rec['want'].get('max_wal_size'), rec['before']['max_wal_size']['raw'],
    sorted(rec['set'])), (4 * GB, '1024', ['jit', 'max_wal_size']))
ok('...and what it was before the first, for each', rec['before']['jit']['raw'], 'on')

ok('what it says, on a machine of its own',
   (isemon.tune_disk_guess({'rotational': True, 'virtual': False}, 0.2)['disk'],
    isemon.tune_disk_guess({'rotational': False, 'virtual': True}, 9)['disk']), ('hdd', 'ssd'))
ok('in a virtual machine, every disk "spins": a write is timed instead',
   (isemon.tune_disk_guess({'rotational': True, 'virtual': True}, 0.4)['disk'],
    isemon.tune_disk_guess({'rotational': True, 'virtual': True}, 9.0)['disk']),
   ('ssd', 'hdd'))
ok('...and an SSD where nothing says', isemon.tune_disk_guess({}, None)['disk'], 'ssd')

print('\nWhat the page sends, and what reaches the server')
at = source.index('    def db_tune_do(')
ok('only the machine is taken from the page: memory, processors, disk',
   "for k in ('ram_gb', 'cpus', 'disk', 'confirmed')" in source[at:at + 2000])
at = source.index('    def apply(self, admin_user=')
ok('the plan is worked out again by the daemon before anything is put in',
   "plan = self.plan(admin_user, admin_password, hardware, probe=False)"
   in source[at:at + 800])
ok('a name reaches ALTER SYSTEM or SET GLOBAL only from the list',
   source.count("if name not in self.names():") == 1
   and source.count("if name not in self.names() or name not in now:") == 1)
ok('full admins only: the POST goes through need_admin',
   re.search(r"if path.startswith\('/api/db/'\) and method == 'POST':\n\s+me = self.need_admin\(\)",
             source) is not None and "if what == 'tune':" in source)
ok('the relay knows it, both ways', page.count("'db-tune'") >= 2
   and "=> '/api/db/tune'" in page)
ok('the administrator goes with the popup, out of its boxes too',
   page.count("MODAL_CLOSE = tuneForget;") == 2 and "function (i) { i.value = ''; }" in page)
ok('a file database has nothing to tune', 'the file on this machine has no server to tune'
   in source)
at = source.index('    def restart(self, by')
ok('the restart is within what the web server waits for: asked for, then waited for',
   "'--no-block', 'restart'" in source[at:at + 4000]
   and 'deadline = began + 62' in source[at:at + 5000]
   and source[at:at + 7000].count('min(5, max(1, deadline - time.time()))') == 2)
ok('...and not when the server may not come back',
   "if huge == 'on':" in source[at:at + 4000] and 'too little for shared_buffers'
   in source[at:at + 4000])
ok('numbers only typed are put in once somebody says they are that server\u2019s',
   "if plan.get('typed') and not (hardware or {}).get('confirmed'):" in source)
ok('a server at 127.0.0.1 is this machine\u2019s only if its postmaster is',
   'def tune_postmaster(conn):' in source and "local, pid = self.here(conn)" in source)

print('\nThe polkit rule')
ok('restart, of PostgreSQL, by the service account, and nothing else',
   'verb === "restart"' in rule and 'subject.user === "isemon"' in rule
   and '/^postgresql(-[0-9]+)?(@[A-Za-z0-9_.-]+)?\\.service$/' in rule)
ok('...on a fresh install after the account and its folder are made',
   setup.index('\ndb_restart_rule\n') > setup.index('run useradd')
   and setup.index('\ndb_restart_rule\n') > setup.rindex('\nconfig_dir_writable\n'))
ok('install.sh puts it in on both paths, and --no-db-restart leaves it out',
   setup.count("\n    db_restart_rule\n") + setup.count("\ndb_restart_rule\n") == 3
   and '--no-db-restart)   DB_RESTART=""' in setup)
ok('...and --uninstall takes it away', '"/etc/polkit-1/rules.d/49-isemon-database.rules"'
   in setup)
if shutil.which('node'):
    harness = r"""
const fs = require('fs'); let r;
global.polkit = {Result: {YES: 'yes'}, addRule: f => { r = f; }};
eval(fs.readFileSync(process.argv[1], 'utf8'));
const ask = (u, unit, verb) => r({id: 'org.freedesktop.systemd1.manage-units',
  lookup: k => ({unit, verb})[k]}, {user: u}) || 'no';
console.log(JSON.stringify([ask('isemon', 'postgresql-16.service', 'restart'),
  ask('isemon', 'postgresql@16-main.service', 'restart'),
  ask('isemon', 'postgresql-16.service', 'stop'), ask('isemon', 'sshd.service', 'restart'),
  ask('nginx', 'postgresql-16.service', 'restart')]));
"""
    said = subprocess.run(['node', '-e', harness, str(HERE.parent / 'deploy' /
                                                       '49-isemon-database.rules')],
                          capture_output=True, text=True)
    ok('...as polkit would run it', json.loads(said.stdout or '[]'),
       ['yes', 'yes', 'no', 'no', 'no'])

# ---- on a database server --------------------------------------------------
folder = tempfile.mkdtemp(prefix='isemon-173-')
isemon.STATE_DIR = Path(folder)
isemon.LOG_DIR = Path(folder)
isemon._LOG_PATH = Path(folder) / 'd.log'
store = isemon.Storage(Path(folder) / 't.db')
tune = isemon.DbTune(store)
if store.dialect.name == 'sqlite':
    print('\nThe file')
    try:
        tune.plan()
        ok('a plan for the file is refused', False)
    except isemon.StorageError as e:
        ok('a plan for the file is refused, saying why', 'no server to tune' in str(e))
else:
    word = store.dialect.name
    print('\nOn %s' % word)
    plan = tune.plan()
    ok('it reads the server’s settings and the machine', bool(plan['items'])
       and bool(plan['facts'].get('ram')) or bool(plan.get('need_facts')))
    ok('a write is timed', plan['facts'].get('commit_ms') is not None)
    ok('the account the tests use may not change them', plan['may_own'], False)
    try:
        tune.apply()
        ok('putting it in as that account is refused', False)
    except isemon.StorageError as e:
        ok('putting it in as that account is refused, saying who may',
           'an administrator on that server is needed' in str(e))
    admin = os.environ.get('ISEMON_TUNE_ADMIN', '')
    if ':' in admin:
        who, code = admin.split(':', 1)
        done = tune.apply(who, code, {'disk': 'ssd'}, by='tester')
        ok('as an administrator, it is put in', bool(done['done']) and not done['failed'])
        look = tune.plan(probe=False)
        ok('...and nothing is left to change but what waits for a start',
           [it['name'] for it in look['items'] if it['change'] and not it['restart']], [])
        ok('a server at 127.0.0.1 here is this machine\u2019s own', look['facts']['local'],
           True)
        # Through the API's own handler, as the page asks.
        said = []

        class Answer(object):
            def fail(self, words, *a, **k):
                said.append(('fail', words))

            def send_json(self, data, *a, **k):
                said.append(('ok', data))

        class Daemon(object):
            def forget_held(self, prefix):
                pass
        isemon.ApiHandler.db_tune_do(Answer(), {'act': 'plan', 'admin_user': who,
                                                'admin_password': code},
                                     {'name': 'tester'}, store, Daemon())
        kept = store.get_meta('db_tune') or ''
        logged = (Path(folder) / 'd.log').read_text(errors='replace') \
            if (Path(folder) / 'd.log').exists() else ''
        events = json.dumps([dict(r) for r in store.db.execute('SELECT * FROM events')])
        ok('the administrator\u2019s password is in no row, no event, no answer, no line of '
           'the log', (code in kept, code in events, code in json.dumps(said, default=str),
                       code in logged), (False, False, False, False))
        # Somebody changes one by hand: going back leaves it be.
        hand = isemon.tune_connect(store, who, code)
        cur = hand.cursor()
        if word == 'postgres':
            cur.execute("ALTER SYSTEM SET random_page_cost = '2.5'")
            cur.execute('SELECT pg_reload_conf()')
        else:
            cur.execute('SET GLOBAL tmp_table_size = %s', (32 * MB,))
        hand.close()
        import time as _t
        _t.sleep(0.6)
        back = tune.undo(who, code, by='tester')
        mine = 'random_page_cost' if word == 'postgres' else 'tmp_table_size'
        ok('...and it is put back as it was', bool(back['done']) and not back['failed'])
        ok('...but what somebody changed since is left as it is', (mine in back['left'],
                                                                  mine in back['done']),
           (True, False))
        ok('...once', 'undone' in json.loads(store.get_meta('db_tune')))
        hand = isemon.tune_connect(store, who, code)
        cur = hand.cursor()
        if word == 'postgres':
            cur.execute('ALTER SYSTEM RESET random_page_cost')
            cur.execute('SELECT pg_reload_conf()')
        else:
            cur.execute('SET GLOBAL tmp_table_size = %s', (16 * MB,))
        hand.close()
        try:
            tune.restart()
            ok('a restart with no service to restart is refused', False)
        except isemon.StorageError as e:
            ok('a restart with nothing waiting, or no service here, is refused, saying why',
               'nothing waits' in str(e) or 'no database server' in str(e))
    else:
        print('  (ISEMON_TUNE_ADMIN not set: nothing is put in)')

shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
