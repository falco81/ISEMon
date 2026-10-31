#!/usr/bin/env python3
"""1.10.266: Settings → Upgrades and maintenance, as otp's pane - and this
server in maintenance, as otp has a node in it, without a cluster.

In maintenance the health check (healthz.php) says 503 - a load balancer or
the monitoring leaves the server alone - while the daemon goes on reading
the logs and banning and the pages go on working. It is kept in a file of
this machine's own, with who, when and why, and survives a restart. An
upgrade from the pages puts the server into maintenance first and takes it
out once the new version answers; one that fails while the old version still
runs comes back into service, one whose new version runs and did not pass is
left in maintenance with why (otp's rule). A backup being put back counts as
maintenance for as long as it takes.

    ./test/fixes266_maintenance.py
"""
import argparse
import contextlib
import io
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
os.environ['ISEMON_WEB_HELPER'] = '1'
os.environ['ISEMON_UPGRADE_HELPER'] = '1'
import isemon                                        # noqa: E402

PASS = FAIL = 0
PORT = 20600 + random.randint(0, 89)
WEB_PORT = PORT + 1
RUNS = isemon.__version__


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


work = Path(tempfile.mkdtemp(prefix='isemon-266-'))
state = work / 'state'
(state / 'upgrade').mkdir(parents=True)
isemon.STATE_DIR = state
isemon.DB_FILE = state / 'd.db'
isemon.BACKUP_DIR = state / 'backups'
isemon.DUMP_DIR = state / 'dumps'
isemon.RUN_DIR = state
isemon.LOG_DIR = state
isemon.CONFIG_FILE = state / 'config.json'
isemon._LOG_PATH = state / 'd.log'
isemon.TOKEN_FILE = state / 'api-token'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'api_port': PORT, 'geo': 0, 'mikrotik1': 0, 'upgrade_check': 0})
(state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
up = daemon.upgrades
HOST = isemon.maintenance_host()
php = None


def events(n=6):
    return [r['detail'] for r in store.db.execute(
        'SELECT detail FROM events ORDER BY id DESC LIMIT ?', (n,)).fetchall()]


def fresh():
    """As a restart reads it: nothing remembered in memory."""
    isemon.MAINT_CACHE.update(at=0.0, row=None)
    return isemon.maintenance_now()


def health():
    with urllib.request.urlopen('http://127.0.0.1:%d/api/health' % PORT, timeout=10) as a:
        return json.loads(a.read().decode())


def healthz(q=''):
    try:
        with urllib.request.urlopen('http://127.0.0.1:%d/healthz.php%s' % (WEB_PORT, q),
                                    timeout=10) as a:
            return a.status, a.read().decode().strip()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode().strip()


try:
    print('Nothing changes where maintenance is never used')
    ok('no file until somebody asks for it', (state / 'maintenance.json').exists(), False)
    ok('...in service', isemon.maintenance_now().get('on'), False)
    ok('the status says so, as a record', daemon.status()['maintenance']['on'], False)

    print('\nThe API: who may')
    daemon.add_user('boss', 'a-long-enough-password', 'fulladmin', by='test')
    daemon.add_user('watcher', 'a-third-long-password', 'readonly', by='test')
    daemon.add_user('banner', 'a-fourth-long-password', 'banadmin', by='test')
    api = isemon.ApiServer(daemon, PORT)
    api.start()
    time.sleep(0.4)

    def call(path, payload=None, session=None):
        req = urllib.request.Request('http://127.0.0.1:%d%s' % (PORT, path),
                                     data=json.dumps(payload).encode() if payload is not None
                                     else None, method='POST' if payload is not None else 'GET')
        req.add_header('X-Isemon-Token', isemon.API_TOKEN)
        req.add_header('Content-Type', 'application/json')
        if session:
            req.add_header('X-Isemon-Session', session)
        try:
            with urllib.request.urlopen(req, timeout=60) as answer:
                return answer.status, json.loads(answer.read().decode() or '{}')
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or '{}')
    tok = {n: call('/api/auth/login', {'name': n, 'password': p})[1]['token']
           for n, p in (('boss', 'a-long-enough-password'), ('watcher', 'a-third-long-password'),
                        ('banner', 'a-fourth-long-password'))}
    for who in ('watcher', 'banner'):
        ok('%s may not put it into maintenance' % who,
           call('/api/upgrade', {'action': 'maintenance', 'on': True}, tok[who])[0], 403)
    ok('...and nothing was written', (state / 'maintenance.json').exists(), False)
    st, v = call('/api/upgrade', session=tok['watcher'])
    ok('read only sees the nodes: one, this server, in service',
       (st, [(n['name'], n['me'], n['alive'], n['version'], n['maintenance']['on'])
             for n in v['nodes']]), (200, [(HOST, True, True, RUNS, False)]))

    # healthz.php through PHP's own server, pointed at this daemon.
    web = work / 'web'
    shutil.copytree(str(ROOT / 'web'), str(web))
    api_php = (web / 'isemon-api.php').read_text()
    lines = []
    for line in api_php.split('\n'):
        if line.startswith('const ISEMON_PORT '):
            line = 'const ISEMON_PORT    = %d;' % PORT
        elif line.startswith('const ISEMON_TOKEN '):
            line = "const ISEMON_TOKEN   = '%s';" % isemon.TOKEN_FILE
        lines.append(line)
    (web / 'isemon-api.php').write_text('\n'.join(lines))
    isemon.TOKEN_FILE.write_text(isemon.API_TOKEN + '\n')
    have_php = bool(shutil.which('php'))
    if have_php:
        php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % WEB_PORT, '-t', str(web)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.0)
        ok('healthz.php in service: 200 ok', healthz(), (200, 'ok'))

    print('\nBy hand: into maintenance and back')
    st, v = call('/api/upgrade', {'action': 'maintenance', 'on': True,
                                  'why': 'the disk is being replaced'}, tok['boss'])
    ok('a full administrator may', (st, v.get('message')), (200, '%s: maintenance on' % HOST))
    m = v['nodes'][0]['maintenance']
    ok('...the node says in maintenance, with why and who',
       (m['on'], m['why'], m['by']), (True, 'the disk is being replaced', 'boss'))
    row = json.loads((state / 'maintenance.json').read_text())
    ok('written down in a file of this machine\'s own', (row['on'], row['why'], row['by'],
                                                         abs(row['at'] - time.time()) < 60),
       (True, 'the disk is being replaced', 'boss', True))
    ok('...and survives a restart', fresh().get('on'), True)
    ok('the health the daemon gives says it - only whether, never why',
       (health().get('maintenance'), 'why' in json.dumps(health())), (True, False))
    if have_php:
        ok('healthz.php says 503 maintenance', healthz(), (503, 'maintenance'))
        st_, body = healthz('?json=1')
        ok('...and as JSON', (st_, json.loads(body)), (503, {'ok': False, 'database': True,
                                                            'maintenance': True,
                                                            'said': 'maintenance'}))
    ok('the header has it', (daemon.status()['maintenance']['on'],
                             daemon.status()['maintenance']['why']),
       (True, 'the disk is being replaced'))
    ok('an event: in maintenance, with why, by whom',
       tuple(store.db.execute("SELECT level, who FROM events WHERE detail = ?",
                              ('%s: in maintenance - healthz.php says 503 - the disk is being '
                               'replaced' % HOST,)).fetchone()[k] for k in ('level', 'who')),
       ('warn', 'boss'))
    st, v = call('/api/upgrade', {'action': 'maintenance', 'on': False}, tok['boss'])
    ok('back in service', (st, v['nodes'][0]['maintenance']['on'], fresh().get('on')),
       (200, False, False))
    ok('...an event says so', events(1), ['%s: back in service' % HOST])
    if have_php:
        ok('healthz.php 200 again', healthz(), (200, 'ok'))
    n = len(events(100))
    isemon.maintenance_by_hand(store, False, '', 'boss')
    ok('back in service when it is: nothing written, no event', len(events(100)), n)

    print('\nThe header and the console say it only when it is so')
    page = (ROOT / 'web' / 'index.php').read_text(encoding='utf-8')
    ok('the page draws the band only for on: true',
       "s.maintenance && s.maintenance.on === true ? s.maintenance : null" in page and
       'function drawMaintBand(m)' in page)
    words = [v_ for v_ in vars(isemon).values()
             if isinstance(v_, type) and 'status_lines' in vars(v_)][0].status_lines
    ok('the console\'s bar: nothing for {on: false}', [
        w for w, _t in words({'maintenance': {'on': False, 'why': 'x'}, '_answered': True})
        if 'MAINTENANCE' in w], [])
    ok('...THIS SERVER IS IN MAINTENANCE, with why, for on', [
        w for w, _t in words({'maintenance': {'on': True, 'why': 'disk'}, '_answered': True})
        if 'MAINTENANCE' in w], ['THIS SERVER IS IN MAINTENANCE - healthz.php says 503 (disk)'])

    print('\nThe pane, as otp\'s')
    ok('the title, the cards, in otp\'s order', [page.index(x) for x in (
        '<h2 class="ctl-title">Upgrades and maintenance</h2>', '<h2>The nodes</h2>',
        '<h2>From the web</h2>', '<h2>A new version</h2>',
        '<h2>Going back to an older version</h2>', '<h2>The upgrade</h2>',
        '<h2>What root said last', '<h2>On the command line</h2>')] == sorted(
        page.index(x) for x in ('<h2 class="ctl-title">Upgrades and maintenance</h2>',
                                '<h2>The nodes</h2>', '<h2>From the web</h2>',
                                '<h2>A new version</h2>',
                                '<h2>Going back to an older version</h2>',
                                '<h2>The upgrade</h2>', '<h2>What root said last',
                                '<h2>On the command line</h2>')))
    ok('the table and its button',
       "listTable(['Node', 'Version', 'Heard from', 'State', '']" in page and
       "cmdButton(m.on ? 'Back in service' : 'Maintenance', m.on ? 'play' : 'power', 'small')"
       in page)
    ok('the menu entry: Upgrades, under Monitoring and updates, the arrow up',
       '<div class="ctl-group">Monitoring and updates</div>\n    <button type="button" '
       'data-pane="upgrade" data-icon="up"' in page)
    ok('the buttons are otp\'s', ('>Upgrade this server</button>' in page,
                                  'data-icon="trash" hidden>Forget the package</button>' in page),
       (True, True))
    ok('the setting is worded as otp\'s',
       "'upgrade_check': 'Look for a new version every day'" in (ROOT / 'isemon.py').read_text())

    print('\nAn upgrade from the pages: out of service first, back once it answers')
    pk_name = 'isemon-%s.tar.gz' % RUNS

    def waiting(version, downgrade=False):
        (state / 'upgrade' / ('isemon-%s.tar.gz' % version)).write_bytes(b'x')
        (state / 'upgrade' / 'package.json').write_text(json.dumps({
            'version': version, 'file': 'isemon-%s.tar.gz' % version, 'sha': '0' * 64,
            'by': 'boss', 'at': time.time(), 'signed_by': 'test', 'downgrade': downgrade}))
        for f in ('request.json', 'request.taken', 'status.json'):
            try:
                (state / 'upgrade' / f).unlink()
            except OSError:
                pass

    def root_says(state_, **more):
        st_ = json.loads((state / 'upgrade' / 'status.json').read_text())
        st_.update(state=state_, at=time.time(), **more)
        (state / 'upgrade' / 'status.json').write_text(json.dumps(st_))
        try:
            (state / 'upgrade' / 'request.json').unlink()
        except OSError:
            pass

    waiting(RUNS)
    st, v = call('/api/upgrade', {'action': 'start'}, tok['boss'])
    m = fresh()
    ok('started: in maintenance first, why says the upgrade',
       (st, m.get('on'), m.get('why'), (m.get('upgrade') or {}).get('version')),
       (200, True, 'upgrade to %s' % RUNS, RUNS))
    ok('...the health check says 503 meanwhile', health().get('maintenance'), True)
    ok('...and the node says it on the page', v['nodes'][0]['maintenance']['on'], True)
    ok('while root works, it stays', (isemon.maintenance_tick(daemon), fresh().get('on')),
       (None, True))
    root_says('done', rc=0)
    ok('root said done and the version answers: back in service',
       (isemon.maintenance_tick(daemon), fresh().get('on')), ('done', False))
    ok('...an event says so', '%s is upgraded to %s, checked, back in service' % (HOST, RUNS)
       in events(4))

    print('\n...failing while the version that was there runs: back in service')
    newer = '.'.join(RUNS.split('.')[:2] + [str(int(RUNS.split('.')[2]) + 1)])
    waiting(newer)
    up.start('boss')
    ok('in maintenance for it', fresh().get('on'), True)
    root_says('failed', rc=1, said='install.sh ended with 1')
    ok('failed before anything was put in: back in service',
       (isemon.maintenance_tick(daemon), fresh().get('on')), ('failed', False))
    ok('...the failure is an event', any(
        e.startswith('the upgrade of %s to %s failed: install.sh ended with 1' % (HOST, newer))
        for e in events(4)))

    print('\n...failing with the new version running: left in maintenance, with why')
    waiting(newer)
    up.start('boss')
    isemon.__version__ = newer             # the new version answers, and did not pass
    try:
        root_says('failed', rc=3, said='install.sh ended with 3')
        ok('left in maintenance', (isemon.maintenance_tick(daemon), fresh().get('on')),
           ('failed', True))
        ok('...why says so', fresh().get('why').startswith(
            'the upgrade to %s failed: install.sh ended with 3 - left in maintenance' % newer))
        ok('...not touched again by the next look', isemon.maintenance_tick(daemon), None)
        if have_php:
            ok('...healthz.php 503', healthz()[0], 503)
    finally:
        isemon.__version__ = RUNS
    call('/api/upgrade', {'action': 'maintenance', 'on': False}, tok['boss'])

    print('\n...in maintenance before it began: left in it after')
    call('/api/upgrade', {'action': 'maintenance', 'on': True, 'why': 'by me'}, tok['boss'])
    waiting(RUNS)
    up.start('boss')
    ok('the why it had is kept', fresh().get('why'), 'by me')
    root_says('done', rc=0)
    ok('done, still in maintenance as it was', (isemon.maintenance_tick(daemon),
                                               fresh().get('on'), fresh().get('why'),
                                               'upgrade' in fresh()), ('done', True, 'by me', False))
    call('/api/upgrade', {'action': 'maintenance', 'on': False}, tok['boss'])

    print('\n...root never took the request')
    waiting(newer)
    up.start('boss')
    row = json.loads((state / 'maintenance.json').read_text())
    row['upgrade']['at'] = time.time() - 600
    (state / 'maintenance.json').write_text(json.dumps(row))
    for f in ('request.json', 'status.json'):
        (state / 'upgrade' / f).unlink()
    ok('failed, back in service', (isemon.maintenance_tick(daemon), fresh().get('on')),
       ('failed', False))
    ok('...saying why', any('isemon-upgrade.service never took the request' in e
                            for e in events(3)))

    print('\n...going back to a version that knows no maintenance: not put into it')
    waiting('1.10.200', downgrade=True)
    up.back_refused = lambda version: ''
    up.start('boss')
    ok('in service all along', fresh().get('on'), False)

    print('\nA backup being put back: in maintenance for as long as it takes')
    with isemon.maintenance_while('a backup is being put back'):
        ok('in maintenance meanwhile', (isemon.maintenance_now().get('on'),
                                        health().get('maintenance')), (True, True))
        ok('...nothing written down', (state / 'maintenance.json').exists() and
           json.loads((state / 'maintenance.json').read_text()).get('on'), False)
    ok('...and out of it after', (isemon.maintenance_now().get('on'),
                                  health().get('maintenance')), (False, False))
    copy = store.backup(label='265')
    held = []
    real = isemon.Storage._restore_dump

    def spy(self, path, say=None):
        held.append(isemon.maintenance_now().get('on'))
        return real(self, path, say=say)
    isemon.Storage._restore_dump = spy
    try:
        store.restore_dump(copy)
    finally:
        isemon.Storage._restore_dump = real
    ok('a restore runs in maintenance', held, [True])
    ok('...the file written by hand is this machine\'s - not put back with the database',
       json.loads((state / 'maintenance.json').read_text()).get('on'), False)

    print('\nThe command line')
    pal = isemon.Palette(False)

    def cli(*argv):
        ns = argparse.Namespace(maintenance=argv[0], why=(argv[1] if len(argv) > 1 else None),
                                json=False)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = isemon.cmd_maintenance(ns, pal, store)
        return rc, out.getvalue().strip()
    ok('--maintenance status: in service, 0', cli('status'), (0, '%s: in service' % HOST))
    rc, said = cli('on', 'patching')
    ok('--maintenance on --why: through the daemon', (rc, fresh().get('on'), fresh().get('why'),
                                                      fresh().get('by')),
       (0, True, 'patching', 'boss'))
    rc, said = cli('status')
    ok('--maintenance status: in maintenance, with why, 3', (rc, said.endswith('- patching')),
       (3, True))
    st, v = call('/api/status', session=tok['boss'])
    ok('--status says it, from what the daemon answers',
       isemon.maintenance_words(pal, v.get('maintenance')).startswith(
           'IN MAINTENANCE - healthz.php says 503 (patching · boss · since '))
    ok('...and in service when it is not', isemon.maintenance_words(
        pal, {'on': False, 'why': 'x'}), 'in service')
    ok('--off', (cli('off')[0], fresh().get('on')), (0, False))
    isemon.CONFIG['api_port'] = 1                         # the daemon not answering
    try:
        rc, said = cli('on', 'daemon stopped')
        ok('the daemon stopped: written here, read when it starts',
           (rc, fresh().get('on'), fresh().get('by')), (0, True, 'command line'))
        cli('off')
    finally:
        isemon.CONFIG['api_port'] = PORT
    ok('the option is there', '--maintenance' in subprocess.run(
        [sys.executable, str(ROOT / 'isemon.py'), '--help'], capture_output=True,
        text=True).stdout)

    print('\ninstall.sh --upgrade by hand takes it out and back by itself')
    sh = (ROOT / 'install.sh').read_text()
    ok('...only when it was in service, never from the pages',
       '--maintenance on --why "install.sh --upgrade"' in sh and
       '"$BIN_LINK" --maintenance off' in sh and 'ISEMON_UPGRADE_FROM_PAGES' in sh)
finally:
    if php:
        php.terminate()
        php.wait(timeout=10)
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
