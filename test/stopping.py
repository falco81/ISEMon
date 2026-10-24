#!/usr/bin/env python3
"""A search somebody stopped is stopped on the database too.

From 1.10.139 the page names each of its long searches (`job=`). Stop,
Clear, or a newer search in the same list send `POST /api/stop` with that
name, and the daemon interrupts the statement that search is running:
SQLite's own interrupt, PostgreSQL's cancel request, MariaDB's KILL QUERY.
Nothing goes on working on the database for an answer nobody will read.

Here a search that would take half a minute is started, stopped a moment
later, and must be over within a few seconds - on whichever engine this is
run against. Then: only the session that asked may stop it, a search
nobody stops is answered as before, and the page has what it needs.

    ./test/stopping.py
"""
import json
import shutil
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import isemon                                        # noqa: E402

PAGE_SRC = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')
PASS = FAIL = 0
PORT = 19873


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


def call(path, method='GET', payload=None, session=None):
    req = urllib.request.Request('http://127.0.0.1:%d%s' % (PORT, path),
                                 data=json.dumps(payload).encode() if payload is not None
                                 else None, method=method)
    req.add_header('X-Isemon-Token', isemon.API_TOKEN)
    if session:
        req.add_header('X-Isemon-Session', session)
    if payload is not None:
        req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req, timeout=90) as answer:
            return answer.status, json.loads(answer.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or '{}')


folder = tempfile.mkdtemp(prefix='isemon-stopping-')
isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = Path(folder) / 's.db'
isemon.BACKUP_DIR = Path(folder) / 'backups'
isemon.DUMP_DIR = Path(folder) / 'dumps'
isemon.RUN_DIR = Path(folder)
isemon.LOG_DIR = Path(folder)
isemon.CONFIG_FILE = Path(folder) / 'config.json'
isemon._LOG_PATH = Path(folder) / 's.log'
isemon.TOKEN_FILE = Path(folder) / 'api-token'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'api_port': PORT, 'geo': 0, 'ise_paths': [folder]})

store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
daemon.add_user('boss', 'a-long-enough-password', 'fulladmin', by='test')
daemon.add_user('watcher', 'another-long-password', 'readonly', by='test')
api = isemon.ApiServer(daemon, PORT)
api.start()
time.sleep(0.4)
engine = store.dialect.name
print('  (engine: %s)' % engine)

# Half a minute of work for the database, in each engine's own words.
SLOW = {
    'sqlite': 'WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c '
              'WHERE x < 400000000) SELECT COUNT(*) AS n FROM c',
    'postgres': 'SELECT pg_sleep(30) AS n',
    'mariadb': 'SELECT BENCHMARK(4000000000, MD5(\'isemon\')) AS n',
}[engine]
real_rows = store.fw_rows
RAN = []


def slow_rows(*args, **kw):
    RAN.append(time.time())
    store.db.execute(SLOW).fetchall()
    # ...and what a real search does next - its count - which must not start.
    store.db.execute('SELECT 1 AS one').fetchall()
    RAN.append('finished')
    return [], 0


try:
    status, data = call('/api/auth/login', 'POST', {'name': 'boss',
                                                    'password': 'a-long-enough-password'})
    admin = data['token']
    status, data = call('/api/auth/login', 'POST', {'name': 'watcher',
                                                    'password': 'another-long-password'})
    looker = data['token']

    print('\nA search stopped while the database is working on it')
    store.fw_rows = slow_rows
    got = {}

    def ask(name, session, into):
        began = time.time()
        into['answer'] = call('/api/fw/rows?q=x&job=' + name, session=session)
        into['took'] = time.time() - began

    worker = threading.Thread(target=ask, args=('abcdef0123456789', admin, got))
    worker.start()
    time.sleep(1.2)
    ok('while it runs, the daemon knows it by its name',
       'abcdef0123456789' in daemon.asking, True)
    status, said = call('/api/stop', 'POST', {'job': 'abcdef0123456789'}, session=looker)
    ok('another session cannot stop it', (status, said.get('stopped')), (200, False))
    status, said = call('/api/stop', 'POST', {'job': 'abcdef0123456789'}, session=admin)
    ok('the session that asked stops it, while its statement is running',
       (status, said.get('stopped'), said.get('was_running')), (200, True, True))
    worker.join(30)
    ok('...and the search is over within seconds, not half a minute',
       (not worker.is_alive(), got.get('took', 99) < 8), (True, True))
    ok('...answered as stopped, not as a fault', (got.get('answer') or (0, {}))[1].get('stopped'),
       True)
    ok('...and nothing after the stopped statement was run', 'finished' in RAN, False)
    # Forgotten as the request ends, which is a moment after its answer has
    # gone out: given that moment.
    for _ in range(20):
        if 'abcdef0123456789' not in daemon.asking:
            break
        time.sleep(0.05)
    ok('...and it is forgotten once answered', 'abcdef0123456789' in daemon.asking, False)
    status, said = call('/api/stop', 'POST', {'job': 'abcdef0123456789'}, session=admin)
    ok('stopping one already over is harmless', (status, said.get('stopped')), (200, False))
    status, said = call('/api/stop', 'POST', {'job': '../../etc'}, session=admin)
    ok('a name that is not a name is nothing', (status, said.get('stopped')), (200, False))
    status, said = call('/api/stop', 'POST', {'job': 'abcdef0123456789'})
    ok('nobody signed in may stop anything', status, 401)

    print('\nThe connection is still good afterwards')
    store.fw_rows = real_rows
    status, said = call('/api/fw/rows?job=0123456789abcdef', session=admin)
    ok('the next search on it is answered as usual', (status, said.get('ok')), (200, True))
    status, said = call('/api/fw/rows', session=admin)
    ok('...and so is one the page did not name', (status, said.get('ok')), (200, True))
    for _ in range(20):
        if not daemon.asking:
            break
        time.sleep(0.05)
    ok('...and nothing is left registered', daemon.asking, {})

    print('\nThe page')
    ok('every long list is a lane that can be stopped: Traffic, Failed attempts, Logins, '
       'Events, the domain, the history, the server lists and Ctrl+K',
       all(("{lane: '%s'" % lane) in PAGE_SRC for lane in
           ('t-rows', 'failed', 'passed', 'events', 'win-events', 'past', 'find'))
       and "{lane: 'list-' + opts.key}" in PAGE_SRC, True)
    ok('...a bar along the top and a pill with the time and Stop',
       'id="asking-bar"' in PAGE_SRC and 'id="asking-stop"' in PAGE_SRC
       and "$('asking-stop').onclick = stopAllLanes" in PAGE_SRC, True)
    ok('...Stop tells the daemon as well as the browser',
       "fetch('?api=stop'" in PAGE_SRC and "'stop'         => '/api/stop'" in PAGE_SRC, True)
    ok('...the refresh never starts a search over one still going, and a slow one waits '
       'a minute', 'QUIET_TICK = true;' in PAGE_SRC
       and 'Math.max(60000, 20 * lane.took)' in PAGE_SRC, True)
    ok('...Clear stops the Traffic search', "stopLane('t-rows');\n  $('t-q').value = '';"
       in PAGE_SRC, True)
    ok('...a refresh arriving while a search is still going is handed that search\u2019s '
       'answer, so the list is never left waiting behind "Searching..." (1.10.140)',
       'if (quiet && lane.ctrl && lane.promise) return lane.promise;' in PAGE_SRC
       and 'return new Promise(function () {});    // nothing in this list to wait for'
       in PAGE_SRC, True)
    ok('the columns are laid out by the browser again, as before 1.10.141 (1.10.143)',
       ('function fitColumns(' in PAGE_SRC, 'function holdWidths(' in PAGE_SRC,
        'WIDTH_EPOCH' in PAGE_SRC), (False, False, False))
    ok('...and on the Traffic lists the addresses are never broken across lines',
       '#t-table .t-ip, #t-table div.t-host, #t-table td.t-host{white-space:nowrap;'
       in PAGE_SRC, True)
    ok('...and their columns are fixed by which column and which list it is, never by '
       'the rows, so a refresh or a closed popup moves nothing (1.10.144)',
       '#t-table{table-layout:fixed;' in PAGE_SRC
       and "$('t-table').setAttribute('data-shape', shape);" in PAGE_SRC
       and "' tc-' + (h[3] || h[1])" in PAGE_SRC, True)
    ok('...and a name found for an address goes above it without dimming it or the '
       'line under it (1.10.144)',
       "if (!box.classList.contains('inline')) box.classList.add('inline');" in PAGE_SRC,
       False)
    ok('the bar along the top for anything the page waits on, the Stop only for the searches '
       '(1.10.150)', 'var waiting = waitStart();' in PAGE_SRC
       and 'line.hidden = !(bar || any);' in PAGE_SRC and 'pill.hidden = !any;' in PAGE_SRC
       and PAGE_SRC.count('waitDone(waiting);') >= 3, True)
    ok('...and a stopped search is not an error on the page',
       'if (e && e.stopped) return;' in PAGE_SRC, True)
finally:
    store.fw_rows = real_rows
    api.stop()
    shutil.rmtree(folder, ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
