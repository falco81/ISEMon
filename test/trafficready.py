#!/usr/bin/env python3
"""The Traffic page's overview, worked out ahead of time (1.10.154).

Before this, the cards, the chart and the lists of the busiest were added up
from the counted buckets while the page waited - on a big firewall, minutes
for the first look and again whenever nobody had looked for a while. Now a
thread behind the daemon works out each window of the drop-down and keeps it
(`fw_ready`), and the page is handed that at once with how old it is.

Checked here: the answer handed out is the same as the one worked out while
waiting; the very first look waits a little and is otherwise told it is
being worked out; a window asked for is kept ready from then on and one
nobody asks for is let go; an old one is worked out again; a window chosen by
its dates, and the setting off, are the old way; erasing the firewall's lines
erases these too; and `isemon --rollup` / `--rollup-build traffic` say and do
it from a terminal.

    ./test/trafficready.py
"""
import json
import os
import subprocess
import sys
import tempfile
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


folder = tempfile.mkdtemp(prefix='isemon-fwready-')
isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = Path(folder) / 'r.db'
isemon.BACKUP_DIR = Path(folder) / 'backups'
isemon.DUMP_DIR = Path(folder) / 'dumps'
isemon.RUN_DIR = Path(folder)
isemon.LOG_DIR = Path(folder)
isemon._LOG_PATH = Path(folder) / 'r.log'
isemon.CONFIG.update({
    'blacklist': 0, 'geo': 0, 'mikrotik_host': '', 'debug': False,
    'ise': 0, 'ise_paths': [str(Path(folder) / 'nothing')],
    'winsec': 0, 'otp': 0, 'eduroam': 0, 'tacplus': 0, 'nps': 0,
    'fwlog': 1, 'fwlog_sources': [{'name': 'fw-a', 'type': 'fortigate',
                                   'paths': [str(Path(folder) / 'a')], 'files': '*.log'},
                                  {'name': 'fw-b', 'type': 'fortigate',
                                   'paths': [str(Path(folder) / 'b')], 'files': '*.log'}],
    'fwlog_keep_days': 7, 'fwlog_allowed_days': 1, 'fwlog_keep_allowed': 1, 'log_zone': '',
})
store = isemon.Storage(isemon.DB_FILE)
isemon.Storage.SETTLED.set()

NOW = int(time.time()) - 600
HEAD = 'Oct  1 07:56:02 fw.example.cz '


def line(rest, n):
    return (HEAD + 'date=2026-10-01 time=07:56:02 devname="FG-EXAMPLE" '
            'devid="FGT00EXAMPLE0001" eventtime=%d%09d tz="+0200" ' % (NOW, n * 1000) + rest)


lines = []
for i in range(40):
    lines.append(line(
        'logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" '
        'srcip=10.1.2.%d srcport=6%04d srcintf="LAN" dstip=198.51.100.7 dstport=443 '
        'dstintf="wan1" sessionid=%d proto=6 action="close" policyid=6 '
        'service="HTTPS" duration=12 sentbyte=1500 rcvdbyte=64000' % (i % 7, i, 5000 + i),
        i + 1))
for i in range(15):
    lines.append(line(
        'logid="0001000014" type="traffic" subtype="local" level="notice" vd="root" '
        'srcip=192.0.2.%d srcport=4%04d srcintf="wan1" dstip=203.0.113.1 dstport=9793 '
        'dstintf="root" sessionid=%d proto=6 action="deny" policyid=0 service="tcp/9793" '
        'duration=0 sentbyte=0 rcvdbyte=0' % (60 + i % 3, i, 9000 + i), 100 + i))
facts = [e.facts for e in isemon.fw_parse_lines(lines)]
for f in facts:
    f['fw'] = 'fw-a'
store.note_fw_events(facts)

daemon = isemon.Daemon(store)
daemon.FW_READY_WAIT_S = 15

print('\nThe first look')
slow = {'s': 0.0}
real_summary = store.fw_summary


def slowed(*a, **k):
    time.sleep(slow['s'])
    return real_summary(*a, **k)


store.fw_summary = slowed
waited = time.time()
first = daemon.fw_summary(24)
waited = time.time() - waited
ok('nothing kept yet: the page waits for the first one to be worked out',
   (first.get('pending'), 'ready' in first), (None, True))
ok('...and it is the same answer as one worked out while waiting',
   (first['totals'], first['tops']['src']['busiest'][:3]),
   (daemon._fw_now(24)['totals'], daemon._fw_now(24)['tops']['src']['busiest'][:3]))
ok('...with the live parts as they are: the firewalls, the one asked for',
   ([f['name'] for f in first['firewalls']], first['fw']), (['fw-a', 'fw-b'], ''))
ok('...and how old it is, how long it took, how often it is worked out again',
   (first['ready']['age'] < 5, first['ready']['took'] >= 0, first['ready']['every']),
   (True, True, 300))
row = store.fw_ready_get(daemon.fw_ready_name(24, ''))
ok('kept in the database, with what the time went on',
   (row is not None, 'cards and chart' in json.loads(store.fw_ready_list()[0]['parts'])),
   (True, True))
again = time.time()
second = daemon.fw_summary(24)
ok('asked again: handed out at once from what is kept',
   (time.time() - again < 1, second['ready']['at']), (True, first['ready']['at']))

print('\nA window that takes long the first time')
slow['s'] = 4.0
daemon.FW_READY_WAIT_S = 1
said = daemon.fw_summary(6, 'fw-a')
ok('the page is told it is being worked out, not handed zeros',
   (bool(said.get('pending')), said.get('totals'), said.get('fw')), (True, {}, 'fw-a'))
ok('...it says which one is being worked out', said['pending'].get('busy'), True)
time.sleep(5)
said = daemon.fw_summary(6, 'fw-a')
ok('...and a moment later it is there', (said.get('pending'), 'ready' in said), (None, True))
ok('...for that firewall alone', said['totals'].get('deny', {}).get('n'), 15)
slow['s'] = 0.0
names = sorted(r['name'] for r in store.fw_ready_list())
ok('both windows are kept ready from now on', names, ['h24|', 'h6|fw-a'])

print('\nKeeping them up to date')
name = daemon.fw_ready_name(24, '')
with store.db_write() as db:
    db.execute('UPDATE fw_ready SET at = ? WHERE name = ?', (time.time() - 3600, name))
daemon._fwr['mem'].clear()
old = daemon.fw_summary(24)
ok('an old one is still handed out at once, saying how old it is',
   old['ready']['age'] > 3000, True)
deadline = time.time() + 10
while time.time() < deadline and store.fw_ready_get(name)['at'] < time.time() - 60:
    time.sleep(0.2)
ok('...and is worked out again behind the page', store.fw_ready_get(name)['at']
   > time.time() - 60, True)
ok('one that takes long is worked out less often: three times what it took at the least',
   (daemon.fw_ready_every(24, 10), daemon.fw_ready_every(24, 400), daemon.fw_ready_every(1)),
   (300, 1200.0, 60))
with store.db_write() as db:
    db.execute('UPDATE fw_ready SET asked = ? WHERE name = ?',
               (time.time() - 4 * 86400, 'h6|fw-a'))
daemon.fw_ready_wanted()
ok('a window nobody has looked at for three days is let go',
   sorted(r['name'] for r in store.fw_ready_list()), ['h24|'])
with store.db_write() as db:
    db.execute('UPDATE fw_ready SET asked = ? WHERE name = ?',
               (time.time() - 9 * 86400, 'h24|'))
daemon.fw_ready_wanted()
ok('...but the last 24 hours of every firewall is always kept',
   [r['name'] for r in store.fw_ready_list()], ['h24|'])
store.fw_ready_asked({'h6|gone': (6, 'gone', time.time())})
daemon.fw_ready_wanted()
ok('one for a firewall no longer set up is let go',
   [r['name'] for r in store.fw_ready_list()], ['h24|'])

print('\nThe old way, where it still is')
custom = daemon.fw_summary(24, '', since=NOW - 3600, until=NOW + 60)
ok('a window chosen by its dates is worked out when asked', 'ready' in custom, False)
odd = daemon.fw_summary(5)
ok('...and a window that is not in the drop-down', 'ready' in odd, False)
isemon.CONFIG['fwlog_ready'] = 0
off = daemon.fw_summary(24)
ok('switched off: worked out while the page waits, as before 1.10.154',
   ('ready' in off, off['totals'] == first['totals']), (False, True))
isemon.CONFIG['fwlog_ready'] = 1

print('\nWhen things go wrong (1.10.155)')
name = daemon.fw_ready_name(24, '')
kept = store.fw_ready_get(name)
real_top = store.fw_top


def broken_top(*a, **k):
    raise isemon.sqlite3.OperationalError('the server went away')


store.fw_top = lambda *a, **k: {'busiest': [], 'refused': [], 'heaviest': [], 'values': 0,
                                'trouble': 'the server went away'}
daemon.fw_ready_work(24, '')
store.fw_top = real_top
ok('an overview the database refused part of is not kept as zeros',
   store.fw_ready_get(name)['data']['totals'], kept['data']['totals'])
ok('...and it is tried again in a minute, not straight away',
   name in daemon._fwr['failed'], True)
daemon._fwr['failed'].clear()
slow['s'] = 2.0
store.fw_summary = slowed
before_at = store.fw_ready_get(name)['at']
worker = isemon.threading.Thread(target=daemon.fw_ready_work, args=(24, ''))
worker.start()
time.sleep(0.5)
with daemon._fwr['lock']:
    daemon._fwr['gen'] += 1                # as erasing the lines does
worker.join()
slow['s'] = 0.0
ok('one worked out across an erase of the lines is not kept',
   store.fw_ready_get(name)['at'], before_at)
held = {'kind': 'erase', 'done': False}
with daemon._jobs_lock:
    daemon._jobs['x'] = held
ok('nothing is worked out behind the page while the lines are being erased',
   daemon.fw_ready_can_run(), False)
store.fw_ready_drop(['h72|'])
daemon._fwr['mem'].clear()
said = daemon.fw_summary(72)
ok('...and a window with nothing kept is then worked out while the page waits, the old way',
   ('pending' in said, 'ready' in said, said['totals'] == daemon._fw_now(72)['totals']),
   (False, False, True))
held['done'] = True
ok('...and afterwards the thread may go on', daemon.fw_ready_can_run(), True)

print('\nErasing the firewall\'s lines')
group = store.ERASABLE['firewall']['tables']
ok('erasing them erases these too (they are worked out again)', 'fw_ready' in group, True)

print('\nFrom a terminal')
store.fw_summary = real_summary
cfg = Path(folder) / 'config.json'
cfg.write_text(json.dumps({k: isemon.CONFIG[k] for k in (
    'fwlog', 'fwlog_sources', 'ise_paths', 'geo', 'blacklist', 'winsec')}), encoding='utf-8')
env = dict(os.environ, ISEMON_CONFIG=str(cfg), ISEMON_STATE=folder)
run = subprocess.run([sys.executable, str(HERE.parent / 'isemon.py'), '--rollup-build',
                      'traffic'], env=env, capture_output=True, text=True, timeout=300)
ok('--rollup-build traffic works every kept window out now',
   (run.returncode, 'the last 24 hours, every firewall' in run.stdout), (0, True))
run = subprocess.run([sys.executable, str(HERE.parent / 'isemon.py'), '--rollup', '--json'],
                     env=env, capture_output=True, text=True, timeout=120)
said = json.loads(run.stdout)
ok('--rollup says each one, how old and how long it took',
   [(w['name'], w['age'] < 60) for w in said['traffic']['windows']], [('h24|', True)])
run = subprocess.run([sys.executable, str(HERE.parent / 'isemon.py'), '--rollup'],
                     env=env, capture_output=True, text=True, timeout=120)
ok('...and in words, with what the time went on',
   ('worked out ahead of time' in run.stdout and 'the time went on' in run.stdout
    or 'worked out' in run.stdout), True)
run = subprocess.run([sys.executable, str(HERE.parent / 'isemon.py'), '--rollup-build',
                      'nonsense'], env=env, capture_output=True, text=True, timeout=60)
ok('...and anything but domain or traffic is refused', run.returncode != 0, True)

PAGE = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')
print('\nThe page')
ok('says it is being worked out and looks again by itself',
   ('function tPending(' in PAGE, 'if (d.pending) {' in PAGE), (True, True))
ok('a quiet refresh does not throw away an answer still on its way',
   'if (quiet && T_ASKING && Date.now() - T_ASKING < 60000) return;' in PAGE)
ok('another window\'s numbers are greyed while this one is worked out',
   "classList.toggle('t-stale', other)" in PAGE)
ok('says how old what it shows is', "'worked out ' + ago(d.ready.at)" in PAGE)
ok('the setting is on the firewall log pane', "'fwlog_allowed_days', 'fwlog_ready']" in PAGE)
ok('the Domain page shows the same card while its answers are counted ahead of time',
   ('function drawWinCounting(' in PAGE, "bgCard('w-counting', 'w-working'" in PAGE,
    "bgCard('t-pending', 't-cards'" in PAGE), (True, True, True))
DAEMON = (HERE.parent / 'isemon.py').read_text(encoding='utf-8')
ok('...told by the daemon whether that counting is going, here or at a terminal',
   ("'counting': counting})" in DAEMON, "counting['busy'] = store.roll_busy()" in DAEMON),
   (True, True))

daemon.stopping.set()
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
