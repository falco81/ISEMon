#!/usr/bin/env python3
"""1.10.380: bug hunt, round 9 of 10 - the banning, the role checks of the
API, and the alerts and the daemon's own timers.

    ./test/fixes380_hunt.py
"""
import ipaddress
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


folder = Path(tempfile.mkdtemp(prefix='isemon-380-'))
for k, v in dict(STATE_DIR=folder, DB_FILE=folder / 'c.db', BACKUP_DIR=folder / 'b',
                 DUMP_DIR=folder / 'd', RUN_DIR=folder, LOG_DIR=folder,
                 CONFIG_FILE=folder / 'config.json', _LOG_PATH=folder / 'c.log',
                 TOKEN_FILE=folder / 'tok').items():
    setattr(isemon, k, v)
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'mikrotik_sync': 0, 'blacklist': 1,
                      'block_tries': 3, 'block_window_min': 10, 'watch_devices': '',
                      'block_ladder': '10, 60, forever', 'fold_least': 2})
# The documentation ranges count as the internet here.
DOC = [ipaddress.ip_network(x) for x in ('198.51.100.0/24', '203.0.113.0/24')]
was_public = isemon.is_public_address


def public(ip):
    try:
        if any(ipaddress.ip_address(str(ip)) in n for n in DOC):
            return True
    except ValueError:
        pass
    return was_public(ip)


isemon.is_public_address = public
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
n = [0]


class R:
    def __init__(self, ts):
        self.ts = ts


def judge(ip, ts, kind='vpn', device='FTD'):
    n[0] += 1
    store.add_failed({'session': 's%d' % n[0], 'ts': ts, 'ip': ip, 'username': 'u',
                      'kind': kind, 'device': device})
    return daemon.judge_refusal(ip, R(ts), [device],
                                door='nps' if kind == 'nps-vpn' else 'ise')


def minutes(ip):
    b = store.blocked_one(ip)
    return None if b['until'] is None else round((b['until'] - time.time()) / 60)


print('The ladder')
now = time.time()
ip = '198.51.100.20'
for i in range(3):
    judge(ip, now - 100 + i)
ok('the first ban, the first rung', minutes(ip), 10)
for i in range(3):
    judge(ip, now - 90 + i)
ok('on trying through it, the second', minutes(ip), 60)

print('A door only watched changes nothing for the doors that ban')
isemon.CONFIG['ban_from_nps'] = 'watch'
ip = '198.51.100.40'
judge(ip, now - 50)
judge(ip, now - 49)
judge(ip, now - 48, kind='nps-vpn', device='NPS')
ok('two at ISE and one at NPS watched: no ban carried', bool(daemon.carried_covers(ip)), False)
judge(ip, now - 47)
ok('the third at ISE bans, as with NPS off', bool(daemon.carried_covers(ip)), True)
isemon.CONFIG['ban_from_nps'] = 'on'

print('A ban by hand over one run out')
isemon.CONFIG['block_lots'] = 5
ip = '198.51.100.50'
for i in range(3):
    judge(ip, now - 3000 + i)
with store.db_write() as db:
    db.execute('UPDATE blocked SET until=? WHERE ip=?', (now - 2000, ip))
judge(ip, now - 100)
judge(ip, now - 99)
daemon.ban(ip, minutes=60, why='by hand', by='admin')
judge(ip, time.time())
ok('one attempt does not make it for good', minutes(ip), 60)

print('The timers')
src = (ROOT / 'isemon.py').read_text()
ok('the directory recheck with the clock put back',
   'if 0 <= now - self._directory_looked < every * 60:' in src)
ok('the disk alerts and the root parts likewise',
   "if not (0 <= now - STORE_ALERT['at'] <= STORE_ALERT_EVERY_S)" in src
   and "if not fresh and 0 <= now - ROOT_PARTS_SEEN['at'] < ROOT_PARTS_EVERY_S:" in src)
ok('a TLS self-check that could not ask is asked again',
   "had.get('ok') is not None" in src)
ok('the daily clean-up that failed: said, and again in an hour',
   'the daily clean-up failed, tried again in an hour' in src)

ok('a MikroTik API key or certificate changed only with a POST',
   "if method != 'POST' and what != 'commands':" in src)

print('Looking for a new version')
up = daemon.upgrades if hasattr(daemon, 'upgrades') else None
if up is None:
    up = next((v for v in vars(daemon).values() if isinstance(v, isemon.Upgrades)), None)
if up is not None:
    isemon.CONFIG['upgrade_url'] = 'https://updates.example.test/isemon/'
    state = {'fail': False}

    def listing(url):
        if state['fail']:
            raise OSError('network is unreachable')
        return [{'version': '9.9.9', 'name': 'isemon-9.9.9.tar.gz'}]
    up.online_list = listing
    up.online_url = lambda: 'https://updates.example.test/isemon/'
    up.online_look()
    state['fail'] = True
    row = up.online_look()
    ok('a look that failed keeps what the last one found', row.get('newer'), True)
    state['fail'] = False
    up.online_look()
    said = [e for e in store.db.execute("SELECT detail FROM events WHERE detail LIKE "
                                        "'isemon 9.9.9 is out%'")]
    ok('...and "is out" is said once', len(said), 1)
else:
    ok('the Upgrades object is there', False)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
