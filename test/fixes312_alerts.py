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
    isemon.ROOT_PARTS, isemon.ROOT_INSTALLED = real_parts, real_inst
    isemon.ROOT_PARTS_SEEN.update(at=0.0, out=[])

    print('\nTrouble on the disks and in the logs, looked at behind')
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
ok('a band each under the header, for a full admin, its commands with a copy button',
   ('<div id="alerts" class="alerts" hidden></div>' in page,
    "if (!ME || ME.role !== 'fulladmin') { host.hidden = true; return; }" in page,
    "copyText(st.text, 'the command was copied')" in page,
    "drawAlerts(data.alerts || [])" in page), (True, True, True, True))
ok('put away on this browser for a day, or until what it says changes',
   ("until: Date.now() + 86400000" in page, "h.sig === alertSig(a)" in page), (True, True))
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
