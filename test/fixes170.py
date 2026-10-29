#!/usr/bin/env python3
"""1.10.170: what held the loop up on a big database - the nightly dump and
the firewall's old lines - done behind it; the part from before the split
not walked every day for nothing; the token given back to the page at the
reload; and the database page saying where a server on this machine keeps
its files.

    ./test/fixes170.py
"""
import json
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import isemon                                        # noqa: E402

PASS = FAIL = 0


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


folder = tempfile.mkdtemp(prefix='isemon-170-')
isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = Path(folder) / 'c.db'
isemon.BACKUP_DIR = Path(folder) / 'backups'
isemon.DUMP_DIR = Path(folder) / 'dumps'
isemon.RUN_DIR = Path(folder)
isemon.LOG_DIR = Path(folder)
isemon._LOG_PATH = Path(folder) / 'c.log'
isemon.TOKEN_FILE = Path(folder) / 'api-token'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0})
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
source = (HERE.parent / 'isemon.py').read_text(encoding='utf-8')

print('\nThe nightly copy, behind the loop')
isemon.CONFIG.update({'backup_daily': 1, 'backup_at': '00:00', 'backup_keep': 3})
store.set_meta('backup_day', '')
real_dump = store.dump
gate = threading.Event()
seen = {}


def slow_dump(label='daily', folder=None):
    seen['thread'] = threading.current_thread().name
    gate.wait(10)
    return real_dump(label=label, folder=folder)


store.dump = slow_dump
began = time.time()
daemon.backup_due()
ok('the loop is not held while the copy is made', time.time() - began < 1.0)
ok('...which is made on a thread of its own', daemon._backup_thread.is_alive())
daemon.backup_due()
ok('...and asked again meanwhile, no second one is started',
   sum(1 for t in threading.enumerate() if t.name == 'db-backup'), 1)
ok('...nor is the day noted before it is done', store.get_meta('backup_day') or '', '')
gate.set()
daemon._backup_thread.join(30)
ok('...and when it is done, the day is', store.get_meta('backup_day'),
   time.strftime('%Y-%m-%d'))
ok('...by the thread named for it', seen.get('thread'), 'db-backup')
store.dump = real_dump
store.set_meta('backup_day', '')
daemon.backup_due(wait=True)
ok('backup_due(wait=True) is done when it returns', store.get_meta('backup_day'),
   time.strftime('%Y-%m-%d'))

print('\nThe firewall’s old lines, behind the loop')
isemon.CONFIG.update({'fwlog_sources': [{'name': 'f', 'kind': 'fortigate', 'path': folder}]})
gate2 = threading.Event()
real_tidy = store.tidy_fw
tidied = {}


def slow_tidy():
    tidied['thread'] = threading.current_thread().name
    gate2.wait(10)
    return 0


store.tidy_fw = slow_tidy
daemon.fwlog_on = lambda: True
began = time.time()
daemon.housekeeping()
ok('housekeeping does not wait for it', time.time() - began < 5.0)
daemon.housekeeping()
ok('...one at a time', sum(1 for t in threading.enumerate() if t.name == 'fw-tidy'), 1)
gate2.set()
daemon._fw_tidy.join(10)
ok('...on its own thread', tidied.get('thread'), 'fw-tidy')
store.tidy_fw = real_tidy

print('\nWhether a walk got to the cut is each thread’s own')
got = {}


def walk(name, cut):
    store.tidy_older('events', cut)
    time.sleep(0.2)
    got[name] = getattr(store._local, 'tidy_whole', None)


one = threading.Thread(target=walk, args=('a', time.time()))
one.start()
store._local.tidy_whole = 'mine'
one.join()
ok('another thread’s walk leaves this thread’s answer alone',
   (got.get('a'), store._local.tidy_whole), (True, 'mine'))

print('\nThe part from before the split, walked only when something went into it')
walks = []
state = {'edge': 1000.0, 'ins': 5, 'whole': True}


def fake_tidy(table, cut, only='', mark='', **kw):
    walks.append((table, mark))
    store._local.tidy_whole = state['whole']
    return 0


real_tidy_older = store.tidy_older
store.tidy_older = fake_tidy
store.legacy_state = lambda table: (state['edge'], state['ins'])
try:
    store.tidy_legacy_allowed(900.0)
    ok('the cut still inside it: walked from where the last walk got to', walks[-1],
       ('fw_events_legacy', 'fw_allowed'))
    walks[:] = []
    store.tidy_legacy_allowed(5000.0)
    ok('past its edge, never walked whole: walked from the beginning', walks,
       [('fw_events_legacy', '')])
    walks[:] = []
    store.tidy_legacy_allowed(5000.0)
    store.tidy_legacy_allowed(5100.0)
    ok('...and after that, nothing went into it: not walked again', walks, [])
    state['ins'] = 6
    store.tidy_legacy_allowed(5200.0)
    ok('a line read late went into it: walked again from the beginning', walks,
       [('fw_events_legacy', '')])
    walks[:] = []
    store.tidy_legacy_allowed(5300.0)
    ok('...and then left again', walks, [])
    state['ins'] = 7
    state['whole'] = False
    store.tidy_legacy_allowed(5400.0)
    store.tidy_legacy_allowed(5500.0)
    ok('a walk that stopped half way is walked again', len(walks), 2)
    state['whole'] = True
    store.tidy_legacy_allowed(5600.0)
    walks[:] = []
    store.set_meta('legacy_settled_fw_events', '7 %r' % (time.time() - 8 * 86400))
    store.tidy_legacy_allowed(5700.0)
    ok('...and once a week it is walked anyway', len(walks), 1)
    state['edge'] = None
    walks[:] = []
    store.tidy_legacy_allowed(5800.0)
    ok('where the engine will not say: walked as before', walks,
       [('fw_events_legacy', 'fw_allowed')])
finally:
    store.tidy_older = real_tidy_older
    del store.legacy_state
ok('the count is taken before the walk',
   source.index("edge, ins = self.legacy_state('fw_events')")
   < source.index("gone = self.tidy_older('fw_events_legacy', cut, only=only)"))
ok('the threads behind the loop give their connection back',
   source.count('self.store.release()', source.index('    def _backup_today('),
                source.index('    def _backup_today_now(')) == 1
   and 'finally:\n            self.store.release()' in
   source[source.index('    def _tidy_fw_behind('):source.index('    def seen_due(')])
ok('a stop waits for them a while', "('the nightly copy', '_backup_thread', 60)" in source)

print('\nThe token at the reload')
at = source.index("if self.reopen_asked.is_set():")
ok('given back to the page as the HUP is taken, not a minute later',
   'token_to_web_group()' in source[at:at + 2500])
ok('a rotated file read to its end is said as information, with its folder',
   "log(said, 'info')" in source and 'os.path.basename(os.path.dirname(path))' in source)

print('\nWhere a database server on this machine keeps its files')
link = Path(folder) / 'linked'
link.symlink_to('/proc')
ok('a folder linked to another disk is on that disk', isemon.mount_of(str(link)), '/proc')
ok('the mount table: /proc is a disk of its own', isemon.mount_of('/proc/self'), '/proc')
ok('...and a folder nobody may enter is found by its name alone',
   isemon.mount_of('/no/such/folder/at/all'), '/')
d = store.disk()
if store.dialect.name == 'sqlite':
    ok('on the file: the database and the copies', (d['holds_key'], 'db_disk' in d),
       ('file', False))
else:
    ok('on %s: said as one of the server\u2019s cases' % store.dialect.name,
       d['holds_key'] in ('server', 'same', 'other', 'unknown'))


class Fake(object):
    def __init__(self, host):
        self.name = 'postgres'
        self.config = {'host': host}

    def where(self):
        return 'isemon@%s:5432/isemon' % self.config['host']


real_dialect = store.dialect
try:
    for host, want in (('127.0.0.1', True), ('localhost', True), ('', True),
                       ('/var/run/postgresql', True), ('::1', True), ('10.9.9.9', False),
                       ('db.example.org', False)):
        store.dialect = Fake(host)
        store._server_files = store._server_local = None
        ok('a server at %r is on this machine: %s' % (host, want), store.server_local(), want)
    store.dialect = Fake('127.0.0.1')
    store._server_files = None
    store._server_local = None
    store.growth = lambda: {'a_day': 1024.0 ** 3}
    here = isemon.mount_of(str(store.path.parent))
    store._server_files = (time.time(), {'engine': 'PostgreSQL', 'dir': '/x/pg', 'mount': here})
    d = store.disk()
    ok('its files on the same disk: the disk holds the database, and the days are counted',
       (d['holds_key'], d['days_left'] is not None), ('same', True))
    other = next((m for m in ('/dev/shm', '/dev', '/run', '/tmp')
                  if isemon.mount_of(m) == m and m != here
                  and shutil.disk_usage(m).total), None)
    store._server_files = (time.time(), {'engine': 'PostgreSQL', 'dir': '/x/pg',
                                         'mount': other})
    d = store.disk()
    ok('on another disk: said, and that disk measured on its own',
       (d['holds_key'], 'db_disk' in d), ('other', True))
    store._server_files = (time.time(), None)
    d = store.disk()
    ok('it will not say where: said so, rather than "the database is elsewhere"',
       (d['holds_key'], d['days_left']), ('unknown', None))
    store.dialect = Fake('10.9.9.9')
    store._server_files = store._server_local = None
    d = store.disk()
    ok('a server elsewhere: as before', d['holds_key'], 'server')
finally:
    store.dialect = real_dialect
    del store.growth

print('\nThe page says it')
page = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')
node = shutil.which('node')
if not node:
    print('  (no node here)')
else:
    at = page.index('\nfunction diskHolds(') + 1
    fn = page[at:page.index('\n}\n', at) + 3]
    script = r'''
function el(tag, cls, text) { return {tag: tag, text: text || '', kids: [],
  appendChild: function (c) { this.kids.push(c); return c; }}; }
var document = {createTextNode: function (t) { return {text: t, kids: []}; }};
function said(p) { return p.kids.map(function (k) { return k.text; }).join(''); }
''' + fn + r'''
var srv = {engine: 'PostgreSQL', dir: '/var/lib/pgsql/data'};
console.log(JSON.stringify({
  file: said(diskHolds({holds_key: 'file'})),
  server: said(diskHolds({holds_key: 'server', server_where: 'u@10.1.1.1:5432/x'})),
  same: said(diskHolds({holds_key: 'same', server: srv})),
  other: said(diskHolds({holds_key: 'other', server: srv})),
  unknown: said(diskHolds({holds_key: 'unknown', server_where: 'u@127.0.0.1:5432/x'})),
  old: said(diskHolds({holds: 'something'})),
  guess: said(diskHolds({holds_key: 'same', server: {engine: 'MariaDB', dir: '/var/lib/mysql',
                                                  guessed: true}}))}));
'''
    got = json.loads(subprocess.run([node, '-e', script], capture_output=True, text=True,
                                    check=True).stdout)
    ok('the file', got['file'], 'That disk holds the database and the copies kept beside it.')
    ok('a server elsewhere', got['server'], 'That disk holds the copies kept on this machine; '
       'the database itself is on u@10.1.1.1:5432/x.')
    ok('a server here, on the same disk', got['same'],
       'That disk holds the database and the copies kept beside it. PostgreSQL keeps its '
       'files in /var/lib/pgsql/data.')
    ok('a server here, on a disk of its own', 'on a disk of its own: PostgreSQL keeps its files '
       'in /var/lib/pgsql/data.' in got['other'])
    ok('a server here that will not say', 'is on this machine too (u@127.0.0.1:5432/x)'
       in got['unknown'])
    ok('an older daemon’s answer still reads', got['old'], 'That disk holds something.')
    ok('the database’s own disk is drawn with how long it lasts',
       'var dd = disk.db_disk;' in page and 'dd.days_left' in page)

shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
