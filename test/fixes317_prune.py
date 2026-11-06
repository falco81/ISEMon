#!/usr/bin/env python3
"""1.10.317: isemon's own rotation no longer wanted - a folder gone, or one a
file of somebody's own takes now - taken out of what isemon wrote itself
(remote-isemon, isemon-day-logs), and never anything somebody made by hand.

    ./test/fixes317_prune.py
"""
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


def put(p, size=10, age_days=0.0):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(b'x' * int(size))
    t = time.time() - age_days * 86400
    os.utime(str(p), (t, t))


work = Path(tempfile.mkdtemp(prefix='isemon-317-'))
try:
    state = work / 'state'
    (state / 'web').mkdir(parents=True)
    remote = work / 'remote'
    lrd = work / 'logrotate.d'
    lrd.mkdir()
    cron = work / 'cron.daily'
    cron.mkdir()
    conf = work / 'logrotate.conf'
    conf.write_text('weekly\nrotate 4\ninclude %s\n' % lrd)
    fake = work / 'logrotate'
    fake.write_text('#!/bin/sh\nexit 0\n')
    fake.chmod(0o755)
    ENV = dict(os.environ, ISEMON_STATE=str(state), ISEMON_WEB_NO_SERVICES='1',
               ISEMON_REMOTE_LOGS=str(remote), ISEMON_LOGROTATE_D=str(lrd),
               ISEMON_LOGROTATE_CONF=str(conf), ISEMON_LOGROTATE=str(fake), ISEMON_GROUP='root',
               ISEMON_CRON_DAILY=str(cron), ISEMON_NGINX_CONF=str(work / 'none.conf'))
    HELPER = ROOT / 'deploy' / 'isemon_web.py'

    def ask(req):
        req = dict(req, at=time.time())
        (state / 'web' / 'logfix.ask').write_text(json.dumps(req))
        subprocess.run(['python3', '-I', str(HELPER)], env=ENV, capture_output=True, text=True)
        return json.loads((state / 'web' / 'logfix.json').read_text())

    for n in ('p1', 'p2', 'p3'):
        put(remote / n / 'a.log')
    for d in range(1, 5):
        put(remote / 'day1' / ('date=2026-11-0%d.log' % d), 10, 5 - d)
        put(remote / 'day2' / ('date=2026-11-0%d.log' % d), 10, 5 - d)
    (lrd / 'remote-logs').write_text('%s/day1/*.log\n%s/day2/*.log\n%s/keep/*.log\n{\n daily\n'
                                     ' rotate 30\n}\n' % (remote, remote, remote))
    ok('isemon\'s own: p1, p2, p3 put in', ask({'do': 'cover', 'folders': ['p1', 'p2', 'p3'],
                                               'keep': 2})['ok'])
    ok('...and day1, day2 aged by its own cron', ask({'do': 'dayfix', 'folders': ['day1', 'day2'],
                                                     'keep': 30})['ok'])
    mine, dl = lrd / 'remote-isemon', cron / 'isemon-day-logs'

    print('\nWhat is no longer wanted, looked for')
    shutil.rmtree(str(remote / 'p1'))
    hand = lrd / 'remote-hand'
    hand.write_text('# somebody\'s own\n%s/p2/*.log\n{\n daily\n rotate 7\n}\n' % remote)
    hand_was = hand.read_text()
    shutil.rmtree(str(remote / 'day1'))
    (lrd / 'remote-logs').write_text((lrd / 'remote-logs').read_text().replace(
        '%s/keep/*.log' % remote, '%s/day2/*.log' % remote))
    logs_was = (lrd / 'remote-logs').read_text()
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
    isemon.STORE_LOG_ROOTS[:] = [str(remote)]
    isemon.STORE_LOGROTATE[:] = [str(conf), str(lrd)]
    isemon.STORE_DAYLOGS = str(dl)
    look = isemon.storage_health(store, fresh=True)
    own = next((p for p in look['problems'] if p['key'] == 'isemon-own'), None)
    ok('said: isemon\'s own for p1 (gone), p2 (taken by remote-hand), day1 (gone), day2 (taken by '
       'remote-logs)', own and sorted((x['folder'], x['why'].split(' ')[0]) for x in own['apply']['what']),
       [('day1', 'gone'), ('day2', 'taken'), ('p1', 'gone'), ('p2', 'taken')])

    class WR(object):
        def helper_there(self):
            return True

        def folder(self):
            return state / 'web'

        def write(self, name, data):
            (state / 'web' / name).write_text(json.dumps(data))
            subprocess.run(['python3', '-I', str(HELPER)], env=ENV, capture_output=True)

        def read(self, name):
            try:
                return json.loads((state / 'web' / name).read_text())
            except (OSError, ValueError):
                return None
    got = isemon.storage_fix(store, WR(), {'do': 'prune'}, 'boss')
    ok('taken away from isemon\'s own: p1 and p2 out of remote-isemon, p3 left',
       (mine.exists(), 'p1' in mine.read_text(), 'p2' in mine.read_text(), 'p3' in mine.read_text()),
       (True, False, False, True))
    ok('...day1 and day2 out of isemon-day-logs, nothing left in it: the file away',
       dl.exists(), False)
    ok('...somebody\'s own files exactly as they were', (hand.read_text() == hand_was,
                                                        (lrd / 'remote-logs').read_text() == logs_was),
       (True, True))
    ok('...said in Events', 'no longer wanted' in json.dumps(
        [dict(e) for e in store.db.execute('SELECT * FROM events')]))
    look = isemon.storage_health(store, fresh=True)
    ok('looked at again: nothing no longer wanted', [p['key'] for p in look['problems']
                                                     if p['key'] == 'isemon-own'], [])

    print('\nWhat somebody made by hand, never')
    shutil.rmtree(str(remote / 'p3'))
    pasted = '# /etc/logrotate.d/remote-isemon\n#\n# Written by isemon (Settings - Disk and logs) for ' \
             'folders under\n%s/p3/*.log\n{\n daily\n}\n' % remote
    mine.write_text(pasted)
    look = isemon.storage_health(store, fresh=True)
    ok('a remote-isemon pasted from the page\'s text by hand: not taken for isemon\'s own',
       [p['key'] for p in look['problems'] if p['key'] == 'isemon-own'], [])
    r = ask({'do': 'prune'})
    ok('...and root leaves it as it was', (r['ok'], mine.read_text() == pasted), (True, True))
    dl.write_text('#!/bin/sh\n# mine\nFOLDERS=\'\ngone 30\n\'\n')
    r = ask({'do': 'prune'})
    ok('an isemon-day-logs somebody else wrote: passed over, as it was',
       (r['ok'], r['data']['done'], dl.read_text().startswith('#!/bin/sh\n# mine')), (True, [], True))
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
