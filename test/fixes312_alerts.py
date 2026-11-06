#!/usr/bin/env python3
"""1.10.312: one way to say on every page what wants doing - and the first
two things said: the parts root installs older than the program (./install.sh
--upgrade not run for this version), and trouble on the disks and in the logs.

    ./test/fixes312_alerts.py
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
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


print('The parts root installs, as this version ships them')
want = []
for src, dest, sha in isemon.ROOT_PARTS:
    got = hashlib.sha256((ROOT / src).read_bytes()).hexdigest()
    if got != sha:
        want.append(src)
ok('ROOT_PARTS says what is in deploy/ now - else run python3 tools/root_parts.py', want, [])
ok('...every part install.sh copies as it is', sorted(s for s, d, h in isemon.ROOT_PARTS),
   sorted(['deploy/isemon_web.py', 'deploy/isemon_upgrade.py', 'deploy/isemon_main.py',
           'deploy/isemon-web.service', 'deploy/isemon-web.path', 'deploy/isemon-upgrade.service',
           'deploy/isemon-upgrade.path', 'deploy/isemon.service', 'deploy/isemon.logrotate']))
inst = (ROOT / 'install.sh').read_text()
ok('...and install.sh copies each of them as it is, to where it says',
   [s for s, d, h in isemon.ROOT_PARTS if ('$SOURCE_DIR/%s"' % s) not in inst], [])
got = subprocess.run([sys.executable, str(ROOT / 'tools' / 'root_parts.py')], capture_output=True,
                     text=True)
ok('tools/root_parts.py with nothing changed: changes nothing', got.stdout.strip(),
   'ROOT_PARTS: as it was')

work = Path(tempfile.mkdtemp(prefix='isemon-312-'))
try:
    parts = []
    for src, dest, sha in isemon.ROOT_PARTS:
        d = work / 'root' / dest.lstrip('/')
        d.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(str(ROOT / src), str(d))
        parts.append((src, str(d), sha))
    real_parts, real_inst = isemon.ROOT_PARTS, isemon.ROOT_INSTALLED
    isemon.ROOT_PARTS = parts
    isemon.ROOT_INSTALLED = str(work / 'none')
    ok('a machine isemon is not installed on as a service: nothing said',
       isemon.root_parts_stale(fresh=True), [])
    isemon.ROOT_INSTALLED = parts[-2][1]
    ok('installed as this version ships it: nothing said', isemon.root_parts_stale(fresh=True), [])
    ok('...and no band', isemon.root_parts_alert('1.10.312'), None)
    web_py = next(d for s, d, h in parts if s.endswith('isemon_web.py'))
    Path(web_py).write_text('# an older helper\n')
    os.unlink(next(d for s, d, h in parts if s.endswith('isemon-web.path')))
    stale = isemon.root_parts_stale(fresh=True)
    ok('an older root helper and a path unit not there: both said', sorted((x['part'], x['why'])
                                                                           for x in stale),
       [('isemon-web.path', 'missing'), ('isemon_web.py', 'older')])
    a = isemon.root_parts_alert('1.10.312')
    ok('...as trouble, with ./install.sh --upgrade to copy',
       (a['level'], a['steps'][0]['text'], 'install.sh --upgrade' in a['says'], '1.10.312' in a['title']),
       ('crit', './install.sh --upgrade', True, True))
    shutil.copy(str(ROOT / 'deploy' / 'isemon_web.py'), web_py)
    shutil.copy(str(ROOT / 'deploy' / 'isemon-web.path'), next(d for s, d, h in parts
                                                              if s.endswith('isemon-web.path')))
    Path(next(d for s, d, h in parts if s.endswith('isemon.logrotate'))).write_text('old\n')
    a = isemon.root_parts_alert('1.10.312') if isemon.root_parts_stale(fresh=True) else None
    ok('only the daemon\'s own logrotate file older: worth a look, not trouble',
       (a and a['level'], a and [x['part'] for x in a['parts']]), ('warn', ['isemon.logrotate']))
    print('\nTo be done by hand: looked at again, done, and what was done lately (1.10.314)')
    state0 = work / 'state0'
    state0.mkdir()
    isemon.DB_FILE = state0 / 'd.db'
    (state0 / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    isemon.CONFIG_FILE = state0 / 'config.json'
    st0 = isemon.Storage(isemon.DB_FILE)

    class D0(object):
        version = '1.10.314'
    d0 = D0()
    d0.store = st0
    isemon.TODO_CACHE.update(keys=None, at=0.0)
    got = isemon.alerts_now(d0)
    hand = [x for x in got if x.get('place') == 'upgrade']
    ok('under Upgrades, with when it was first noticed and what can be done to it',
       (len(hand), bool(hand and hand[0].get('at')), hand and hand[0].get('can')), (1, True, ['look', 'done']))
    try:
        isemon.todo_api(d0, {'do': 'done', 'key': 'root-parts'}, 'boss')
        ok('Done while it is not so: refused, with what is still not so', False)
    except ValueError as e:
        ok('Done while it is not so: refused, with what is still not so',
           'isemon.logrotate' in str(e) and 'install.sh --upgrade' in str(e))
    ok('...nothing written down as done', isemon.todo_view(st0)['done'], [])
    shutil.copy(str(ROOT / 'deploy' / 'isemon.logrotate'), next(d for s_, d, h in parts
                                                               if s_.endswith('isemon.logrotate')))
    r = isemon.todo_api(d0, {'do': 'done', 'key': 'root-parts'}, 'boss')
    done = isemon.todo_view(st0)['done']
    ok('once it is so, Done is taken: written down as done, by whom',
       (r['still'], [(x['how'], x['who']) for x in done]), (False, [('done', 'boss')]))
    Path(next(d for s_, d, h in parts if s_.endswith('isemon.logrotate'))).write_text('old\n')
    isemon.ROOT_PARTS_SEEN.update(at=0.0)
    isemon.TODO_CACHE.update(keys=None, at=0.0)
    isemon.alerts_now(d0)
    shutil.copy(str(ROOT / 'deploy' / 'isemon.logrotate'), next(d for s_, d, h in parts
                                                               if s_.endswith('isemon.logrotate')))
    isemon.ROOT_PARTS_SEEN.update(at=0.0)
    isemon.TODO_CACHE.update(keys=None, at=0.0)
    isemon.alerts_now(d0)
    ok('one that is put right without Done: gone by itself, nobody named',
       [(x['how'], x['who']) for x in isemon.todo_view(st0)['done']][:1], [('gone by itself', '')])
    try:
        isemon.todo_api(d0, {'do': 'done', 'key': 'something-else'}, 'boss')
        ok('a key that is no such thing: refused', False)
    except ValueError:
        ok('a key that is no such thing: refused', True)
    isemon.ROOT_PARTS, isemon.ROOT_INSTALLED = real_parts, real_inst
    isemon.ROOT_PARTS_SEEN.update(at=0.0, out=[])

    print('\nTrouble on the disks and in the logs, looked at behind')
    isemon.ROOT_INSTALLED = str(work / 'none')
    isemon.ROOT_PARTS_SEEN.update(at=0.0, out=[])
    for _ in range(100):
        if not isemon.STORE_ALERT['busy']:
            break
        time.sleep(0.05)
    isemon.STORE_ALERT.update(at=0.0, out=[], busy=False)
    state = work / 'state'
    state.mkdir()
    for k, v in dict(STATE_DIR=state, DB_FILE=state / 'd.db', BACKUP_DIR=state / 'b',
                     DUMP_DIR=state / 'dumps', RUN_DIR=state, LOG_DIR=state,
                     CONFIG_FILE=state / 'config.json', _LOG_PATH=state / 'd.log',
                     TOKEN_FILE=state / 'token').items():
        setattr(isemon, k, v)
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0})
    (state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    store = isemon.Storage(isemon.DB_FILE)
    remote = work / 'remote'
    (remote / 'fw9').mkdir(parents=True)
    with open(str(remote / 'fw9' / '%FTD-6-302014.log'), 'wb') as f:
        f.truncate(6 * 1024 ** 3)
    (work / 'lr.d').mkdir()
    (work / 'lr.conf').write_text('include %s\n' % (work / 'lr.d'))
    isemon.STORE_LOG_ROOTS[:] = [str(remote)]
    isemon.STORE_LOGROTATE[:] = [str(work / 'lr.conf'), str(work / 'lr.d')]

    class D(object):
        version = '1.10.312'
    d = D()
    d.store = store
    t0 = time.time()
    first = isemon.alerts_now(d)
    ok('the first status is not kept waiting for the look', (first == [] or True, time.time() - t0 < 1),
       (True, True))
    for _ in range(100):
        if not isemon.STORE_ALERT['busy'] and isemon.STORE_ALERT['at']:
            break
        time.sleep(0.05)
    got = isemon.alerts_now(d)
    ok('...the next one says the folder nothing rotates, with Disk and logs to open',
       [(a['key'], a['level'], a['pane']) for a in got], [('storage:unrotated', 'crit', 'storage')])
finally:
    shutil.rmtree(str(work), ignore_errors=True)

src = (ROOT / 'isemon.py').read_text()
page = (ROOT / 'web' / 'index.php').read_text()
print('\nCarried and drawn')
ok('in the status every page asks for every few seconds', "'alerts': alerts_now(self)," in src)
ok('...for a full admin alone: nobody else is sent them',
   "if isinstance(said, dict) and said.get('alerts') and me.get('role') != 'fulladmin':" in src)
ok('said by isemon --status too', "for a in data.get('alerts') or []:" in src)
ok('under Settings -> Upgrades, for a full admin, its commands with a copy button (1.10.313)',
   ('<div class="card full todo-card" id="up-alerts-card" hidden>' in page,
    "var mine = !!(ME && ME.role === 'fulladmin');" in page,
    "copyText(st.text, 'the command was copied')" in page,
    "drawAlerts(data.alerts || [])" in page), (True, True, True, True))
ok('...the one about upgrading there, with a number on the Settings tab and on Upgrades',
   ("'place': 'upgrade'," in src, "var up = all.filter(function (a) { return a.place === 'upgrade'; });" in page,
    'id="tabn-settings" hidden' in page, "u.id = 'up-alert-n';" in page), (True, True, True, True))
ok('the card always there for a full admin, saying so when there is nothing; Done lately under it',
   ('id="todo-none" hidden>Nothing is to be done by hand.' in page, "card.hidden = !mine;" in page,
    "host.appendChild(el('h4', 'todo-h', 'Done lately'));" in page), (True, True, True))
ok('a number on the Upgrades icon itself, seen with the menu shut', '.ctl-nav button[data-pane] .n.badge{position:absolute' in page)
ok('...the rest across the top of every page as before, each put away for a day by Not now',
   ('<div id="alerts-top" class="alerts" hidden></div>' in page, "if (a.place) return false;" in page,
    "until: Date.now() + 86400000" in page), (True, True, True))
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
