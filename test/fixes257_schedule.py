#!/usr/bin/env python3
"""1.10.257: updates and restarts on a schedule, as otp 1.0.164-1.0.168 has
them, for one server - and the manual update of the security updates only.

The scheduler is run with the time it is told ("now"), the way the remote
backups' schedule is tested (rb_due). Root's half (isemon_web.py) is run for
real, with the package manager played by a script of the test's own
(ISEMON_OSUP_PM); a thread plays the path unit. A restart asked of root is
written into a file (ISEMON_POWER_CMD); a reboot is a new boot time.
The rule that greys out a setting whose switch is off - and one that hangs
on a greyed-out one (otp 1.0.165) - is run by node on the page's own code.

    ./test/fixes257_schedule.py
"""
import argparse
import builtins
import contextlib
import importlib.util
import io
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import types
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

work = Path(tempfile.mkdtemp(prefix='isemon-257sched-'))
state = work / 'state'
(state / 'web').mkdir(parents=True)
PM_STATE = work / 'pm.json'
PM = work / 'fake-dnf'
LOCK = work / 'osup.lock'
POWER = work / 'power.log'
BTIME = work / 'btime'
BTIME.write_text('1000\n')

os.environ.update(ISEMON_WEB_HELPER='1', ISEMON_BTIME_FILE=str(BTIME))
HELPER_ENV = dict(os.environ, ISEMON_STATE=str(state), ISEMON_WEB_NO_SERVICES='1',
                  ISEMON_OSUP_PM=str(PM), ISEMON_OSUP_LOCK=str(LOCK),
                  ISEMON_POWER_CMD=str(POWER), ISEMON_RSYSLOG=str(work / 'none'),
                  ISEMON_NGINX_CONF=str(work / 'none.conf'))

PY = sys.executable
PM.write_text('''#!%s
import json, sys, time
p = %r
s = json.load(open(p))
a = sys.argv[1]
if a == 'check':
    for x in s['pk']:
        print(x)
elif a == 'upgrade':
    s.setdefault('upgrades', []).append(sys.argv[2:])
    print('Dependencies resolved.')
    n = len(s['pk'])
    for i, x in enumerate(s['pk'], 1):
        time.sleep(s.get('slow', 0))
        print('  Upgrading        : %%s   %%d/%%d' %% (x.split()[0], i, n))
        sys.stdout.flush()
    print('Complete!')
    if s.get('needs_after'):
        s['needs'] = True
    s['pk'] = []
    json.dump(s, open(p, 'w'))
elif a == 'needs-restart':
    sys.exit(1 if s.get('needs') else 0)
else:
    sys.exit(2)
''' % (PY, str(PM_STATE)))
PM.chmod(0o755)
PKGS = ['kernel-core.x86_64 5.14.0-503.el9', 'openssl.x86_64 3.2.2-6.el9 security',
        'nginx.x86_64 1.20.1-20.el9']


def pm(**kw):
    s = json.loads(PM_STATE.read_text()) if PM_STATE.exists() else {}
    s.update(kw)
    PM_STATE.write_text(json.dumps(s))
    return s


pm(pk=PKGS, needs=False)


def run_helper(*args):
    return subprocess.run(['python3', '-I', str(ROOT / 'deploy' / 'isemon_web.py')] + list(args),
                          capture_output=True, text=True, env=HELPER_ENV)


import isemon                                        # noqa: E402

PASS = FAIL = 0
PORT = 20400 + random.randint(0, 90)


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


def wait_for(fn, secs=20):
    end = time.time() + secs
    while time.time() < end:
        try:
            if fn():
                return True
        except Exception:                               # noqa: BLE001
            pass
        time.sleep(0.1)
    return False


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
isemon.CONFIG.update({'api_port': PORT, 'geo': 0, 'mikrotik1': 0})
(state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
os.environ['ISEMON_UPGRADE_HELPER'] = '1'
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
np = daemon.netpower
C = isemon.CONFIG
BY = isemon.OSUP_SCHED_BY
STOP = threading.Event()


def path_unit():
    while not STOP.is_set():
        if (state / 'web' / 'osup.ask').exists() or (state / 'web' / 'net.ask').exists():
            run_helper()
        time.sleep(0.05)


def all_events():
    return [str(r.get('detail') or '') for r in reversed(store.events(limit=1000)[0])]


def tick(now):
    isemon.osup_sched_tick(daemon, now)


def drive(fn, secs=30):
    def go():
        isemon.osup_tick(daemon)
        np.tick() if hasattr(np, 'tick') else None
        return fn()
    return wait_for(go, secs)


def ripen():
    """The few seconds an update waits before it begins, gone by."""
    p = isemon.osup_plan(store)
    if p.get('state') == 'running':
        p['at'] = time.time() - isemon.OSUP_GRACE_S - 1
        store.set_meta('osup:plan', json.dumps(p))


def looked():
    want = json.loads(store.get_meta('osup:checkwant', '') or '{}')
    c = isemon.osup_check(store)
    return c.get('state') == 'done' and want.get('id') in (c.get('asked') or [])


def settle():
    """Whatever was started has ended, and the look after it as well."""
    ripen()
    return drive(lambda: isemon.osup_plan(store).get('state') != 'running' and
                 not isemon.osup_settling(daemon) and (not json.loads(
                     store.get_meta('osup:checkwant', '') or '{}') or looked()), 40)


def reboot():
    BTIME.write_text(str(float(BTIME.read_text()) + 100) + '\n')


def power_reset():
    POWER.write_text('')
    np._put('power:plan', {})


WED = datetime(2026, 10, 28, 4, 45)          # a Wednesday


try:
    # ------------------------------------------------------------------------
    print('\nOff until switched on')
    D = isemon.DEFAULTS
    ok('every switch off, the times and choices as otp has them',
       (D['osup_check'], D['osup_check_at'], D['osup_auto'], D['osup_auto_what'],
        D['osup_auto_every'], D['osup_auto_day'], D['osup_auto_at'], D['osup_auto_reboot'],
        D['power_auto'], D['power_auto_every'], D['power_auto_day'], D['power_auto_at'],
        D['power_auto_needed']),
       (0, '06:15', 0, 'security', 'weekly', '7', '04:45', 'auto', 0, 'weekly', '7', '05:40', 1))
    before = all_events()
    for h in range(0, 24):
        tick(datetime(2026, 11, 1, h, 59))           # a Sunday, the 1st: every window there is
    ok('a whole day of passes: nothing asked of root, nothing kept, nothing said',
       ((state / 'web' / 'osup.ask').exists(), store.get_meta('osup:check:day', ''),
        store.get_meta('osup:auto:day', ''), store.get_meta('power:auto:day', ''),
        store.get_meta('osup:checkwant', ''), store.get_meta('osup:plan', ''),
        all_events() == before), (False, '', '', '', '', '', True))
    src = (ROOT / 'isemon.py').read_text()
    ok('...and the daemon\'s pass asks the scheduler every few seconds, behind the loop',
       'osup_sched_tick(self)' in src.split('def _net_pass')[1].split('\n    def ')[0])

    th = threading.Thread(target=path_unit, daemon=True)
    th.start()

    # ------------------------------------------------------------------------
    print('\nThe windows')
    due = isemon.sched_due
    ok('daily: not before its time, from it to the end of the day, the day its id',
       (due('daily', '', '04:45', datetime(2026, 10, 28, 4, 44)),
        due('daily', '', '04:45', datetime(2026, 10, 28, 4, 45)),
        due('daily', '', '04:45', datetime(2026, 10, 28, 23, 59))),
       ((False, '2026-10-28'), (True, '2026-10-28'), (True, '2026-10-28')))
    ok('weekly: only on its day (3 is Wednesday)',
       (due('weekly', '3', '04:45', datetime(2026, 10, 27, 5, 0)),
        due('weekly', '3', '04:45', datetime(2026, 10, 28, 5, 0)),
        due('weekly', '7', '04:45', datetime(2026, 11, 1, 5, 0))),
       ((False, ''), (True, '2026-10-28'), (True, '2026-11-01')))
    ok('monthly: on the first of the month only',
       (due('monthly', '7', '04:45', datetime(2026, 11, 1, 5, 0)),
        due('monthly', '7', '04:45', datetime(2026, 11, 2, 5, 0))),
       ((True, '2026-11-01'), (False, '')))
    ok('a time that does not read: the time it falls back to',
       due('daily', '', 'x', datetime(2026, 10, 28, 4, 44), '04:45')[0], False)

    # ------------------------------------------------------------------------
    print('\nThe daily look for updates')
    C.update(osup_check=1, osup_check_at='06:15')
    tick(datetime(2026, 10, 28, 6, 14))
    ok('not before its time', store.get_meta('osup:checkwant', ''), '')
    tick(datetime(2026, 10, 28, 6, 15))
    want = json.loads(store.get_meta('osup:checkwant', '') or '{}')
    ok('at its time: asked for, by the schedule, said', (want.get('by'),
       store.get_meta('osup:check:day', ''),
       'the look for updates on a schedule started' in all_events()),
       (BY, '2026-10-28', True))
    ok('...done, what is waiting kept', drive(looked))
    ok('...and said in the events, with how many are security',
       'the look for updates on a schedule: 3 waiting, 1 of them security' in all_events())
    n0 = len(all_events())
    for hm in ((6, 16), (12, 0), (23, 59)):
        tick(datetime(2026, 10, 28, *hm))
    ok('once in its day: not asked again', (json.loads(store.get_meta('osup:checkwant', ''))
                                            ['id'], len(all_events())), (want['id'], n0))
    tick(datetime(2026, 10, 29, 6, 20))
    ok('the next day: asked again', json.loads(store.get_meta('osup:checkwant', ''))['id'] !=
       want['id'])
    ok('...and done', drive(looked))
    ok('nothing put in by a look', json.loads(PM_STATE.read_text()).get('upgrades'), None)
    C.update(osup_check=0)

    # ------------------------------------------------------------------------
    print('\nThe updates on a schedule: daily, only the security ones')
    C.update(osup_auto=1, osup_auto_every='daily', osup_auto_at='04:45', osup_auto_what='security',
             osup_auto_reboot='ask')
    tick(datetime(2026, 10, 30, 4, 44))
    ok('not before its time', isemon.osup_plan(store), {})
    tick(datetime(2026, 10, 30, 4, 45))
    p = isemon.osup_plan(store)
    ok('at its time: started, by the schedule, the security updates only, the restart offered',
       (p.get('state'), p.get('by'), p.get('security'), p.get('reboot')),
       ('running', BY, True, 'ask'))
    ok('...said in the events',
       '%s started the update of the system (security updates only)' % BY in all_events())
    tick(datetime(2026, 10, 30, 5, 30))
    ok('...once in its window: not started again', isemon.osup_plan(store)['id'], p['id'])
    ok('done', settle() and isemon.osup_plan(store).get('state') == 'done')
    ok('...root\'s work put in the security updates only (upgrade security)',
       json.loads(PM_STATE.read_text()).get('upgrades'), [['security']])
    tick(datetime(2026, 10, 30, 23, 0))
    ok('...and not again the same day after it ended', isemon.osup_plan(store)['id'], p['id'])
    pm(pk=PKGS)
    C.update(osup_auto_what='all')
    tick(datetime(2026, 10, 31, 4, 50))
    p2 = isemon.osup_plan(store)
    ok('the next day: started again, every update this time', (p2['id'] != p['id'],
                                                               p2.get('security')), (True, False))
    ok('...done', settle())
    ok('...every update: upgrade with nothing more', json.loads(PM_STATE.read_text())['upgrades'],
       [['security'], []])

    # ------------------------------------------------------------------------
    print('\nWeekly and monthly')
    C.update(osup_auto_every='weekly', osup_auto_day='3')
    pm(pk=PKGS)
    tick(datetime(2026, 11, 3, 5, 0))                # a Tuesday
    ok('weekly on Wednesday: not on the Tuesday', isemon.osup_plan(store)['id'], p2['id'])
    tick(datetime(2026, 11, 4, 4, 44))
    ok('...nor on the Wednesday before its time', isemon.osup_plan(store)['id'], p2['id'])
    tick(datetime(2026, 11, 4, 4, 45))
    p3 = isemon.osup_plan(store)
    ok('...on the Wednesday at its time', (p3['id'] != p2['id'], p3['state']), (True, 'running'))
    ok('...done', settle())
    tick(datetime(2026, 11, 4, 18, 0))
    ok('...once that Wednesday', isemon.osup_plan(store)['id'], p3['id'])
    C.update(osup_auto_every='monthly')
    pm(pk=PKGS)
    tick(datetime(2026, 11, 11, 5, 0))
    ok('monthly: not on another day', isemon.osup_plan(store)['id'], p3['id'])
    tick(datetime(2026, 12, 1, 5, 0))
    p4 = isemon.osup_plan(store)
    ok('...on the first of the month', p4['id'] != p3['id'])
    ok('...done', settle())
    tick(datetime(2026, 12, 1, 6, 0))
    ok('...once on it', isemon.osup_plan(store)['id'], p4['id'])

    # ------------------------------------------------------------------------
    print('\nSomething going on: said, and not tried over and over')
    C.update(osup_auto_every='daily')
    daemon.upgrades.folder().mkdir(parents=True, exist_ok=True)
    (daemon.upgrades.folder() / 'status.json').write_text(json.dumps(
        {'state': 'running', 'at': time.time()}))
    tick(datetime(2026, 12, 2, 4, 50))
    ok('an upgrade of isemon going on: not started', isemon.osup_plan(store)['id'], p4['id'])
    ok('...said in the events, with why',
       'the update of the system on a schedule did not start: an upgrade of isemon is going on '
       '- wait for it to end' in all_events())
    (daemon.upgrades.folder() / 'status.json').unlink()
    n0 = len(all_events())
    tick(datetime(2026, 12, 2, 5, 0))
    tick(datetime(2026, 12, 2, 9, 0))
    ok('...over now: still not tried again until the next window',
       (isemon.osup_plan(store)['id'], len(all_events())), (p4['id'], n0))
    for setup, words, undo in (
            (lambda: np._put('net:job', {'id': 'n', 'state': 'trial', 'at': time.time()}),
             'a new network is on trial - keep it, or put the old one back, first',
             lambda: np._put('net:job', {})),
            (lambda: np._put('power:plan', {'id': 'p', 'how': 'reboot', 'state': 'asked',
                                            'at': time.time()}),
             'a restart or a power-off is going on - wait for it to end', power_reset)):
        setup()
        day = datetime(2026, 12, 3 if 'network' in words else 4, 4, 50)
        tick(day)
        ok('%s: not started, said' % words.split(' - ')[0].split(',')[0],
           (isemon.osup_plan(store)['id'],
            'the update of the system on a schedule did not start: %s' % words in all_events()),
           (p4['id'], True))
        undo()
    pm(pk=PKGS, slow=0.3)
    isemon.osup_start(daemon, 'ask', 'boss')
    pb = isemon.osup_plan(store)
    tick(datetime(2026, 12, 5, 4, 50))
    ok('an update by hand going on: the scheduled one not started, said',
       (isemon.osup_plan(store)['id'], 'the update of the system on a schedule did not start: '
        'an update is going on already' in all_events()), (pb['id'], True))
    ok('...the one by hand goes to its end', settle())
    pm(slow=0)
    C.update(osup_auto=0)

    # ------------------------------------------------------------------------
    print('\nA restart on a schedule')
    power_reset()
    pm(needs=False, pk=[])
    isemon.osup_check_ask(daemon, 'boss')
    drive(looked)
    C.update(power_auto=1, power_auto_every='weekly', power_auto_day='7', power_auto_at='05:40',
             power_auto_needed=1)
    tick(datetime(2026, 12, 6, 5, 39))               # a Sunday
    ok('not before its time', store.get_meta('power:auto:day', ''), '')
    tick(datetime(2026, 12, 6, 5, 40))
    ok('only when needed, and not needed: no restart, said',
       (POWER.read_text(), store.get_meta('power:auto:day', ''),
        'the restart on a schedule: this server does not need one' in all_events()),
       ('', '2026-12-06', True))
    pm(needs=True)
    isemon.osup_check_ask(daemon, 'boss')
    drive(looked)
    ok('a look now says a restart is waiting', isemon.osup_view(daemon)['nodes'][0]['reboot'])
    tick(datetime(2026, 12, 6, 6, 0))
    ok('...not again the same Sunday', POWER.read_text(), '')
    tick(datetime(2026, 12, 7, 5, 45))
    ok('...nor on the Monday', POWER.read_text(), '')
    tick(datetime(2026, 12, 13, 5, 45))
    ok('the next Sunday, needed: restarted, through root as by hand',
       wait_for(lambda: POWER.read_text().split()[:1] == ['reboot']))
    ok('...said in the events: asked by the schedule, and why',
       ('%s asked for a restart of this server' % BY in all_events(),
        'the restart on a schedule: this server restarts' in all_events()), (True, True))
    reboot()
    pm(needs=False)
    np.tick()
    ok('...up again', np.power_plan().get('state'), 'back')
    power_reset()
    C.update(power_auto_needed=0, power_auto_every='monthly')
    ok('up again, the look after the restart', drive(lambda: not isemon.osup_settling(daemon)))
    tick(datetime(2026, 12, 20, 5, 45))
    ok('always, monthly: not on another day', POWER.read_text(), '')
    tick(datetime(2027, 1, 1, 5, 45))
    ok('...on the first, restarted though it does not need one',
       wait_for(lambda: POWER.read_text().split()[:1] == ['reboot']))
    reboot()
    np.tick()
    power_reset()
    drive(lambda: not isemon.osup_settling(daemon))

    # ------------------------------------------------------------------------
    print('\nThe restart waits while an update is going on')
    pm(pk=PKGS, slow=0.5, needs_after=True, needs=False)
    C.update(power_auto_needed=1, power_auto_every='weekly', power_auto_day='7')
    isemon.osup_start(daemon, 'ask', 'boss')
    ripen()
    drive(lambda: isemon.osup_row(store).get('state') == 'updating', 20)
    tick(datetime(2027, 1, 3, 5, 41))                # a Sunday, in the window
    ok('an update going on: no restart, the day not given up',
       (POWER.read_text(), store.get_meta('power:auto:day', '')), ('', '2027-01-01'))
    ok('...the update ends - and the look after it', drive(
        lambda: isemon.osup_plan(store).get('state') == 'done', 30))
    tick(datetime(2027, 1, 3, 5, 50))
    ok('...nor while the look after it is still going on',
       (isemon.osup_settling(daemon) or POWER.read_text() == ''), True)
    ok('...which is over', drive(lambda: not isemon.osup_settling(daemon), 30))
    tick(datetime(2027, 1, 3, 6, 10))
    ok('later in the window: restarted, as the update left it needing',
       wait_for(lambda: POWER.read_text().split()[:1] == ['reboot']))
    reboot()
    pm(needs=False)
    np.tick()
    power_reset()

    print('\nA restart on a schedule with something going on')
    C.update(power_auto_needed=0)
    np._put('net:job', {'id': 'n', 'state': 'trial', 'at': time.time()})
    tick(datetime(2027, 1, 10, 5, 45))
    ok('a network on trial: not restarted, said',
       (POWER.read_text(), 'the restart on a schedule did not start: a new network is on trial '
        '- keep it, or put the old one back, first' in all_events()), ('', True))
    np._put('net:job', {})
    tick(datetime(2027, 1, 10, 7, 0))
    ok('...not tried again that day', POWER.read_text(), '')
    C.update(power_auto=0)

    # ------------------------------------------------------------------------
    print('\nThe security updates only, by hand')
    pm(pk=PKGS, slow=0, needs_after=False, upgrades=[])
    plan = isemon.osup_start(daemon, 'ask', 'boss', security=True)
    ok('the plan says so', plan['security'], True)
    ok('...and the event', 'boss started the update of the system (security updates only)' in
       all_events())
    ok('...done, root asked for the security updates only', settle() and json.loads(
        PM_STATE.read_text())['upgrades'], [['security']])
    v = isemon.osup_view(daemon, True)
    ok('...the page shows it', v['plan'].get('security'), True)
    a = None
    (state / 'web' / 'osup.ask').write_text(json.dumps(
        {'do': 'run', 'kind': 'upgrade', 'id': 'u9', 'at': time.time(), 'security': 'yes'}))
    STOP.set()
    time.sleep(0.2)
    run_helper()
    a = json.loads((state / 'web' / 'osup.ans').read_text())
    ok('root refuses a "security" that is not true or false', (a['ok'], a.get('said')),
       (False, 'security: true or false'))
    (state / 'web' / 'osup.ask').write_text(json.dumps(
        {'do': 'run', 'kind': 'check', 'id': 'c9', 'at': time.time(), 'security': True}))
    run_helper()
    a = json.loads((state / 'web' / 'osup.ans').read_text())
    ok('...a look is a look, whatever it says', (a['ok'], a['data']['security']), (True, False))
    wait_for(lambda: json.loads((state / 'web' / 'osup.json').read_text()).get('id') == 'c9' and
             json.loads((state / 'web' / 'osup.json').read_text()).get('state') == 'done')

    # The job itself as dnf and apt run it: the commands it gives.
    saved_env = dict(os.environ)
    os.environ.update(ISEMON_STATE=str(state), ISEMON_OSUP_LOCK=str(LOCK),
                      ISEMON_WEB_NO_SERVICES='1')
    os.environ.pop('ISEMON_OSUP_PM', None)
    spec = importlib.util.spec_from_file_location('isemon_web_t257', str(ROOT / 'deploy' /
                                                                         'isemon_web.py'))
    W = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(W)
    os.environ.clear()
    os.environ.update(saved_env)
    ran = []

    class FakePopen(object):
        def __init__(self, cmd, **kw):
            ran.append(list(cmd))
            self.stdout = iter(['Complete!\n'])

        def wait(self):
            return 0

    def fake_run(cmd, **kw):
        ran.append(list(cmd))
        return types.SimpleNamespace(returncode=0, stdout='', stderr='')
    W.subprocess = types.SimpleNamespace(Popen=FakePopen, run=fake_run, PIPE=-1, STDOUT=-2,
                                         DEVNULL=-3, SubprocessError=Exception)
    have = {'unattended-upgrade': '/usr/bin/unattended-upgrade'}
    W.shutil = types.SimpleNamespace(which=lambda n: have.get(n))
    for pmname, sec, want in (
            ('dnf', True, [['dnf', '-y', '--refresh', 'upgrade', '--security']]),
            ('dnf', False, [['dnf', '-y', '--refresh', 'upgrade']]),
            ('apt', True, [['apt-get', 'update'], ['unattended-upgrade', '-v']]),
            ('apt', False, [['apt-get', 'update'], ['apt-get', '-y', '-o',
                                                    'Dpkg::Options::=--force-confdef', '-o',
                                                    'Dpkg::Options::=--force-confold',
                                                    'upgrade']])):
        W.osup_pm = lambda p=pmname: p
        del ran[:]
        W.osup_job('j1', 'upgrade', sec)
        got = json.loads((state / 'web' / 'osup.json').read_text())
        ok('%s, %s: %s' % (pmname, 'security only' if sec else 'every update',
                           ' ; '.join(' '.join(c) for c in want)),
           ([c for c in ran if c[:2] != ['dnf', 'needs-restarting']], got['state'],
            got.get('security_only')), (want, 'done', sec))
    have.clear()
    W.osup_pm = lambda: 'apt'
    W.osup_job('j2', 'upgrade', True)
    got = json.loads((state / 'web' / 'osup.json').read_text())
    ok('apt without unattended-upgrade: refused, saying what to put in',
       (got['state'], got.get('said')),
       ('failed', 'only the security updates: unattended-upgrade is not on this machine '
                  '(apt install unattended-upgrades)'))
    ok('the unit started with "security" only for an upgrade',
       ('+ ([\'security\'] if security else [])' in (ROOT / 'deploy' / 'isemon_web.py')
        .read_text(), "argv[3:4] == ['security']" in (ROOT / 'deploy' / 'isemon_web.py')
        .read_text()), (True, True))

    # ------------------------------------------------------------------------
    print('\nThe command line and the console')
    parser = isemon.cli_parser()
    a = parser.parse_args(['--os-update', '--security', '--reboot-after', 'auto', '--yes'])
    ok('isemon --os-update --security parses', (a.os_update, a.security), (True, True))
    sent = []
    real_call, real_view = isemon.api_call, isemon._osup_view_cli

    def fake_call(path, method='GET', body=None, **kw):
        if method == 'POST':
            sent.append(body)
            return 200, {'ok': True, 'plan': {'id': 'zz'}, 'message': 'asked'}
        return 200, {'ok': True, 'helper': True, 'plan': {'id': 'zz', 'state': 'done',
                                                          'security': True},
                     'nodes': [{'row': {'state': 'done', 'said': 'updated'}}]}
    isemon.api_call = fake_call
    isemon._osup_view_cli = lambda s: fake_call('/api/osup')
    try:
        for flag in (True, False):
            args = argparse.Namespace(json=False, yes=True, reboot_after=None, security=flag)
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                isemon.cmd_os_update(args, isemon.Palette(False, buf), store)
        ok('...the daemon asked for the security updates only, or every update',
           [(b['action'], b['security']) for b in sent], [('start', True), ('start', False)])
        args = argparse.Namespace(json=False, yes=False, reboot_after=None, security=True)
        buf = io.StringIO()
        was = builtins.input
        builtins.input = lambda prompt='': 'no'
        try:
            with contextlib.redirect_stdout(buf):
                isemon.cmd_os_update(args, isemon.Palette(False, buf), store)
        finally:
            builtins.input = was
        ok('...asked first, in its words', 'Only the security updates are put in.' in
           buf.getvalue())
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            isemon.osup_print(isemon.Palette(False, buf), fake_call('/api/osup')[1])
        ok('--os-updates says which', 'only the security updates' in buf.getvalue())
    finally:
        isemon.api_call, isemon._osup_view_cli = real_call, real_view
    got = subprocess.run([sys.executable, str(ROOT / 'isemon.py'), '--help'],
                         capture_output=True, text=True)
    ok('--help has it', '--security' in got.stdout)

    class Dry(isemon.Console):
        def __init__(self):
            super(Dry, self).__init__(isemon.Palette(False))
            self.ran, self.picks = [], {}

        def out(self, *args):
            return {'nodes': [{'check': {}}]}

        def choose(self, title_, options, words='', cur=0):
            want = self.picks.get(title_)
            vals = [o[0] for o in options]
            return want if want in vals else (vals[0] if vals and want is None else None)

        def confirm(self, title_, words, yes='Yes', no='No', danger=False):
            self.words = words
            return True

        def show_live(self, *args, env=None):
            self.ran.append(tuple(args))

        def live(self, fn):
            return fn()
    d = Dry()
    d.picks = {'System updates': 'update', 'Which': 'security', 'After the update': 'ask'}
    d.os_updates()
    ok('the console: the security updates only, said and asked for',
       (d.ran, d.words.startswith('Only the security updates')),
       ([('--os-update', '--reboot-after', 'ask', '--security', '--yes')], True))
    d.ran, d.picks = [], {'System updates': 'update', 'Which': 'all', 'After the update': 'auto'}
    d.os_updates()
    ok('...every update, as before', d.ran, [('--os-update', '--reboot-after', 'auto', '--yes')])

    # ------------------------------------------------------------------------
    print('\nThe settings')
    cs = isemon.check_setting
    for key, val, want in (('osup_check_at', '6:05', '6:05'), ('osup_auto_at', '23:59', '23:59'),
                           ('power_auto_at', '00:00', '00:00'), ('osup_auto_day', 3, '3'),
                           ('power_auto_day', '7', '7'), ('osup_auto_every', 'Monthly', 'monthly'),
                           ('osup_auto_what', 'all', 'all'), ('osup_auto_reboot', 'ask', 'ask'),
                           ('power_auto_needed', 0, 0), ('osup_auto', '1', 1)):
        ok('%s = %r taken' % (key, val), cs(key, val), want)
    for key, val in (('osup_check_at', '24:00'), ('osup_auto_at', '4.45'),
                     ('power_auto_at', ''), ('osup_auto_day', '8'), ('power_auto_day', '0'),
                     ('osup_auto_every', 'yearly'), ('power_auto_every', 'daily'),
                     ('osup_auto_what', 'some'), ('osup_auto_reboot', 'never'),
                     ('power_auto', 2)):
        try:
            cs(key, val)
            ok('%s = %r refused' % (key, val), False)
        except ValueError as e:
            ok('%s = %r refused: %s' % (key, val, e), bool(str(e)))
    rows = {r['key']: r for r in daemon.settings_state()}
    ok('the page gets each with its name and words, the days by name',
       (rows['osup_auto']['name'], rows['power_auto']['name'],
        rows['osup_auto_day']['choice_words']['7'], rows['power_auto_every']['choices'],
        rows['osup_auto_what']['choice_words']['security'], bool(rows['osup_check']['says'])),
       ('Updates on a schedule', 'A restart on a schedule', 'Sunday', ['weekly', 'monthly'],
        'only the security updates', True))
    daemon.save_settings({'osup_auto': 1, 'osup_auto_day': '2'}, 'boss')
    ok('saved from the page', (C['osup_auto'], C['osup_auto_day']), (1, '2'))
    try:
        daemon.save_settings({'osup_auto_at': 'soon'}, 'boss')
        ok('...a time that is not HH:MM refuses the save', False)
    except ValueError:
        ok('...a time that is not HH:MM refuses the save', C['osup_auto_at'], '04:45')
    daemon.save_settings({'osup_auto': 0}, 'boss')

    # ------------------------------------------------------------------------
    print('\nThe page: the cards, and what is greyed out')
    page = (ROOT / 'web' / 'index.php').read_text()
    ok('"On a schedule" in System updates and in Restart and power off',
       (page.split('id="pane-osup"')[1].split('ctl-pane')[0].count('id="sect-osup"'),
        page.split('id="pane-power"')[1].split('ctl-pane')[0].count('id="sect-power"')),
       (1, 1))
    ok('...their settings in them', ("osup:    ['osup_check', 'osup_check_at', 'osup_auto'" in page,
                                     "power:   ['power_auto', 'power_auto_every'" in page),
       (True, True))
    ok('the manual update: Every update or Only the security updates, sent with it',
       ("[['all', 'Every update'], ['security', 'Only the security updates']]" in page,
        "{action: 'start', reboot: OU.reboot, security: sec}" in page), (True, True))
    # applyOnlyWhen run by node, on the page's own ONLY_WHEN and code.
    rules = page[page.index('var ONLY_WHEN = {'):page.index('function applyOnlyWhen()')]
    fn = page[page.index('function applyOnlyWhen()'):]
    fn = fn[:fn.index('\n}\n') + 3]
    js = r'''
var items = {}, boxes = {};
function Item(key) {
  this.key = key; this.cls = {}; this.kids = [];
  var me = this;
  this.classList = {toggle: function (c, on) { if (on) me.cls[c] = 1; else delete me.cls[c]; }};
  this.querySelector = function () { return me.kids.filter(function (k) { return !k.gone; })[0] || null; };
  this.appendChild = function (k) { me.kids.push(k); k.remove = function () { k.gone = true; }; };
}
var document = {querySelector: function (sel) { var m = /data-key="([^"]+)"/.exec(sel); return items[m[1]] || null; }};
function $(id) { return boxes[id.replace(/^set-/, '')] || null; }
function el(kind, cls, text) { return {cls: cls, text: text, dataset: {}}; }
var NAMES = %s;
function settingByKey(k) { return {key: k, name: NAMES[k] || k, min: 0, max: NAMES[k + '#b'] ? 1 : 9}; }
function isBool(s) { return s.min === 0 && s.max === 1; }
function applyFwFields() {}
%s
%s
var keys = ['osup_check', 'osup_check_at', 'osup_auto', 'osup_auto_what', 'osup_auto_every',
            'osup_auto_day', 'osup_auto_at', 'osup_auto_reboot', 'power_auto', 'power_auto_every',
            'power_auto_day', 'power_auto_at', 'power_auto_needed'];
keys.forEach(function (k) { items[k] = new Item(k); });
function set(v) { Object.keys(v).forEach(function (k) { boxes[k] = {type: 'select-one', value: String(v[k])}; }); }
function asleep() {
  applyOnlyWhen();
  var out = {};
  keys.forEach(function (k) {
    var w = items[k].querySelector();
    if (items[k].cls.asleep) out[k] = w ? w.text : '';
  });
  return out;
}
var res = [];
set({osup_check: 0, osup_auto: 0, osup_auto_every: 'weekly', power_auto: 0, power_auto_every: 'weekly'});
res.push(asleep());
set({osup_check: 1, osup_auto: 1, osup_auto_every: 'weekly', power_auto: 1, power_auto_every: 'weekly'});
res.push(asleep());
set({osup_check: 1, osup_auto: 1, osup_auto_every: 'daily', power_auto: 1, power_auto_every: 'monthly'});
res.push(asleep());
set({osup_check: 1, osup_auto: 0, osup_auto_every: 'daily', power_auto: 1, power_auto_every: 'monthly'});
res.push(asleep());
console.log(JSON.stringify(res));
''' % (json.dumps({'osup_check': 'Look for updates every day', 'osup_check#b': 1,
                   'osup_auto': 'Updates on a schedule', 'osup_auto#b': 1,
                   'power_auto': 'A restart on a schedule', 'power_auto#b': 1,
                   'osup_auto_every': 'How often', 'power_auto_every': 'How often'}),
       rules, fn)
    (work / 'ow.js').write_text(js)
    got = subprocess.run(['node', str(work / 'ow.js')], capture_output=True, text=True)
    res = json.loads(got.stdout) if got.returncode == 0 else got.stderr
    off = 'Not in use while %s is off.'
    ok('every switch off: all of it greyed out - On the day as well, though weekly is chosen',
       res[0] if isinstance(res, str) else res[0],
       {'osup_check_at': off % 'Look for updates every day',
        'osup_auto_what': off % 'Updates on a schedule',
        'osup_auto_every': off % 'Updates on a schedule',
        'osup_auto_day': off % 'Updates on a schedule',
        'osup_auto_at': off % 'Updates on a schedule',
        'osup_auto_reboot': off % 'Updates on a schedule',
        'power_auto_every': off % 'A restart on a schedule',
        'power_auto_day': off % 'A restart on a schedule',
        'power_auto_at': off % 'A restart on a schedule',
        'power_auto_needed': off % 'A restart on a schedule'})
    if not isinstance(res, str):
        ok('switched on, weekly: nothing greyed out', res[1], {})
        ok('daily and monthly: only On the day greyed out, saying why',
           res[2], {'osup_auto_day': 'Not in use while How often is not “weekly”.',
                    'power_auto_day': 'Not in use while How often is not “weekly”.'})
        ok('the update switched off again: its On the day says the switch, not the choice',
           res[3]['osup_auto_day'], off % 'Updates on a schedule')

    # ------------------------------------------------------------------------
    print('\nThe docs and the version')
    ok('version 1.10.257 or later', tuple(int(x) for x in isemon.__version__.split('.'))
       >= (1, 10, 257))
    readme = (ROOT / 'README.md').read_text()
    entry = readme.split('## Version', 1)[1].split('\n1.10.257\n', 1)[1].strip().split('\n')
    ok('README: the entry of 1.10.257, its first line naming no other version',
       re.findall(r'\d+\.\d+\.\d+', entry[0]), [])
    doc = (ROOT / 'docs' / 'system-updates.md').read_text()
    ok('docs: System updates says the schedule and the security updates only',
       ('On a schedule' in doc, 'osup_auto_what' in doc, '--security' in doc), (True,) * 3)
    doc = (ROOT / 'docs' / 'network-and-power.md').read_text()
    ok('docs: Restart and power off says the schedule', ('On a schedule' in doc,
                                                        'power_auto_needed' in doc), (True,) * 2)
finally:
    STOP.set()
    time.sleep(0.2)
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
