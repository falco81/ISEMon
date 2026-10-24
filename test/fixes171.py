#!/usr/bin/env python3
"""1.10.171: the page's questions never hold up the reading of the logs.

The VPN as it stands put together without walking every open session for
every line; the page's questions of the records taking turns; the subnets on
the ban list kept while single addresses are lengthened; the index for the
made-up names of an address still trying; and the Traffic list by Bytes out
of the heavy sessions.

    ./test/fixes171.py
"""
import json
import random
import shutil
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


folder = tempfile.mkdtemp(prefix='isemon-171-')
isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = Path(folder) / 'c.db'
isemon.LOG_DIR = Path(folder)
isemon._LOG_PATH = Path(folder) / 'c.log'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0})
store = isemon.Storage(isemon.DB_FILE)
source = (HERE.parent / 'isemon.py').read_text(encoding='utf-8')

print('\nThe VPN as it stands: the same answer, without the walk')
space = dict(vars(isemon))
exec((HERE / 'ref_vpn_fold_170.txt').read_text(encoding='utf-8'), space)
old_fold = space['fw_vpn_fold']
R = random.Random(171)
NOW = 1790000000.0


def lines(n, people, seed):
    r = random.Random(seed)
    out = []
    ts = NOW - 6 * 86400
    for k in range(n):
        ts += r.random() * 30
        who = 'user%02d' % r.randrange(people)
        ip = '198.51.100.%d' % r.randrange(1, 40)
        inner = '10.8.0.%d' % r.randrange(1, 30)
        fw = r.choice(['ftd-a', 'ftd-a', 'ftd-b'])
        roll = r.random()
        if roll < 0.2:
            msgid, f = r.choice(['113039', '722022', '716001']), {}
        elif roll < 0.35:
            msgid, f = r.choice(['113019', '716002']), {'reason': 'User Requested'}
        elif roll < 0.5:
            msgid, f = '737016', {'assigned': inner}
            if r.random() < 0.5:
                who = ''
        elif roll < 0.6:
            msgid, f = r.choice(['109210', '737031']), {'assigned': inner}
            who = ''
        elif roll < 0.75:
            msgid, f = '722051', {'assigned': inner, 'group_policy': 'GP%d' % r.randrange(3)}
            if r.random() < 0.3:
                f['handle'] = 'h%d' % r.randrange(20)
        elif roll < 0.85:
            msgid, f = '737006', {'handle': 'h%d' % r.randrange(20), 'pool': 'P1',
                                  'assigned': inner}
            who = ''
        elif roll < 0.92:
            msgid, f = r.choice(['722037', '722035']), {'reason': 'DPD', 'packet': '1500',
                                                        'threshold': '1400'}
        else:
            # A tunnel id of its own for each person and address: one given
            # to somebody else ends the first session since 1.10.200, which
            # the fold of 1.10.170 compared against here did not do (that is
            # tested on its own in fixes200).
            r.randrange(1, 9)
            tid = 1 + int(who[4:] or 0) * 40 + int(ip.rsplit('.', 1)[1])
            msgid, f = '', {'tunnelid': str(tid), 'assigned': inner}
        f['msgid'] = msgid
        out.append({'ts': ts, 'fw': fw, 'dev': fw, 'area': 'client-vpn', 'type': 'event',
                    'sub': 'vpn', 'action': r.choice(['tunnel-up', 'tunnel-stats', 'tunnel-down',
                                                      '']) if not msgid else '',
                    'verdict': r.choice(['', '', '', 'fail']) if r.random() < 0.1 else '',
                    'srcip': ip, 'dstip': '', 'user': who, 'msg': '', 'sent': r.randrange(9999),
                    'rcvd': r.randrange(9999), 'duration': r.randrange(0, 900),
                    'fields': f})
        if r.random() < 0.05:
            out.append({'ts': ts, 'fw': fw, 'dev': fw, 'area': 's2s-vpn', 'type': 'event',
                        'sub': 'vpn', 'action': r.choice(['tunnel-up', 'tunnel-down',
                                                          'tunnel-stats', 'install_sa']),
                        'verdict': '', 'srcip': '203.0.113.%d' % r.randrange(1, 6),
                        'dstip': '192.0.2.1', 'user': '', 'msg': '', 'sent': 1, 'rcvd': 1,
                        'duration': 60, 'fields': {'spi': str(r.randrange(99))}})
    return out


same = True
for seed, n, people in ((1, 3000, 5), (2, 6000, 40), (3, 9000, 300), (4, 2000, 2)):
    rows = lines(n, people, seed)
    a = old_fold(json.loads(json.dumps(rows)), NOW)
    b = isemon.fw_vpn_fold(json.loads(json.dumps(rows)), NOW)
    same = same and json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    if not same:
        print('  (differs for seed %d)' % seed)
        break
ok('four weeks of made-up lines: the same clients and tunnels, field for field', same)
big = lines(40000, 4000, 9)
t0 = time.time()
isemon.fw_vpn_fold(json.loads(json.dumps(big)), NOW)
quick = time.time() - t0
t0 = time.time()
old_fold(json.loads(json.dumps(big)), NOW)
slow = time.time() - t0
ok('...and on many people at once, quicker by far (%.2f s against %.2f s)' % (quick, slow),
   quick * 3 < slow)
ok('the VPN as it stands is kept a minute', isemon.FW_VPN_HELD_S, 60)

print('\nThe page’s questions of the records take turns')
gate = isemon.ApiGate(most=1)
ok('a question of the records is gated', gate.heavy('GET', '/api/fw/rows'))
ok('...and the domain’s pages', gate.heavy('GET', '/api/windows/events'))
for light in ('/api/status', '/api/health', '/api/auth/login', '/api/banfeed', '/api/stop',
              '/api/settings', '/api/jobs', '/api/log', '/api/export', '/api/ptr',
              '/api/macs', '/api/acls', '/api/geolist', '/api/windows/directory-names'):
    ok('%s never waits' % light, gate.heavy('GET', light), False)
ok('the bans, and "has anything changed", never wait',
   (gate.heavy('GET', '/api/blocked', {'parts': ['bans'], 'if': ['x']}),
    gate.heavy('GET', '/api/blocked', {})), (False, False))
ok('...the history searched does',
   (gate.heavy('GET', '/api/blocked', {'parts': ['history']}),
    gate.heavy('GET', '/api/blocked', {'q': ['10.1.1.1']})), (True, True))
ok('a change is never held back', gate.heavy('POST', '/api/blocked'), False)
ok('the first goes straight in', gate.enter())
began = time.time()
ok('a second waits, and is told "busy" when the wait runs out',
   (gate.enter(wait_s=0.6), time.time() - began >= 0.5), (False, True))
job = {'stop': False}
result = {}


def stopper():
    result['in'] = gate.enter(job, wait_s=30)


waiting = threading.Thread(target=stopper)
waiting.start()
time.sleep(0.3)
ok('...one waiting is counted as waiting', gate.snapshot()['waiting'], 1)
job['stop'] = True
waiting.join(5)
ok('...and leaves the queue as soon as the page stops it', result.get('in'), False)
gate.leave()
ok('with the turn given back, the next goes straight in', gate.enter())
gate.leave()
ok('it says what it is doing', set(gate.snapshot()), {'most', 'inside', 'waiting',
                                                      'turned_away'})
ok('at least two at a time, at most three quarters of the processors',
   2 <= isemon.API_GATE.most <= max(2, ((isemon.os.cpu_count() or 2) * 3) // 4))
at = source.index('        gated = API_GATE.heavy(method, path, query) and bool(self.who())')
ok('the API asks the gate once the token is right and somebody is signed in, and gives '
   'the turn back after',
   source.rindex("if not self.token_ok():", 0, at) > at - 600
   and 'API_GATE.enter(_ASKING.job)' in source[at:at + 400]
   and 'API_GATE.leave()' in source[at:at + 5000])
crowd = isemon.ApiGate(most=1)
crowd.QUEUE_MOST = 1
crowd.enter()
held_up = threading.Thread(target=lambda: crowd.enter(wait_s=1.0))
held_up.start()
time.sleep(0.3)
began = time.time()
ok('with too many waiting already, "busy" straight away',
   (crowd.enter(wait_s=5), time.time() - began < 0.5), (False, True))
held_up.join()
ok('the wait is well inside the page\u2019s minute', isemon.ApiGate.WAIT_S <= 30)

print('\nThe subnets on the list, kept while single addresses are lengthened')
store.block('203.0.113.9', time.time() + 3600, 'test')
store.block('198.51.100.0/24', time.time() + 3600, 'test')
time.sleep(2.1)
store.ban_nets()
held = store._ban_nets
store.lengthen('203.0.113.9', time.time() + 7200)
ok('an address lengthened leaves the subnets as they were read', store._ban_nets is held)
store.lengthen('198.51.100.0/24', time.time() + 7200)
ok('a subnet lengthened has them read again', store._ban_nets is None)
ok('...and the lengthened one is what is read',
   [r['until'] > time.time() + 7000 for r in store.ban_nets()
    if r['ip'] == '198.51.100.0/24'], [True])
store.unblock('198.51.100.0/24')
ok('a subnet taken off is gone at once',
   store.blocked_until('198.51.100.7') is None or store.blocked_until('198.51.100.7') == 0)

print('\nThe made-up names of an address still trying, by index')
ok('the index is one of those made behind the daemon',
   'failed_ip_name_ts' in dict(store.LATER_INDEXES))
made = store.index_sql(dict(store.LATER_INDEXES)['failed_ip_name_ts'])
ok('made on the engines that have an index over an expression, and only there',
   bool(made), store.dialect.name != 'mariadb')
if made:
    store.db.execute(made)
if store.dialect.name == 'sqlite':
    plan = ' '.join(str(r['detail']) for r in store.db.execute(
        'EXPLAIN QUERY PLAN SELECT 1 FROM failed WHERE ip=? AND ts>? AND ts<=? AND '
        + isemon.judged_sql() + ' AND LOWER(TRIM(username)) IN (?,?) LIMIT 1',
        ('203.0.113.9', 0, 1e10, 'invalid', 'x')).fetchall())
    ok('the question asked of it is answered from it', 'failed_ip_name_ts' in plan)
for k in range(30):
    store.add_failed({'session': 'f-%d' % k, 'ts': NOW + k, 'server': 'ise1',
                      'ip': '203.0.113.9', 'username': 'INVALID' if k == 20 else 'bob',
                      'kind': 'vpn', 'device': 'FTD-VPN'})
ok('...and counts as before', (store.failed_tally('203.0.113.9', NOW, NOW + 100,
                                                  names={'invalid'}, most=1),
                               store.failed_tally('203.0.113.9', NOW + 21, NOW + 100,
                                                  names={'invalid'}, most=1)), (1, 0))

print('\nThe Traffic list by Bytes, out of the heavy sessions')
fw_rows = []
for k in range(400):
    big_one = k % 7 == 0
    fw_rows.append({'ident': 'b-%03d' % k, 'ts': NOW - k * 60, 'type': 'traffic',
                    'sub': 'forward', 'action': 'close', 'verdict': 'allow',
                    'srcip': '10.0.0.%d' % (k % 50), 'dstip': '192.0.2.%d' % (k % 9),
                    'dstport': 443, 'proto': 6, 'area': 'session', 'fw': 'f',
                    'sent': (3000000 + k * 1000) if big_one else k * 10,
                    'rcvd': (k % 5) * 1000 if big_one else k, 'detail': '{}'})
store.note_fw_events(fw_rows)
made = store.index_sql(dict(store.LATER_INDEXES)['fw_big_bytes'])
if made:
    store.db.execute(made)
store._fw_big_index = None
ok('the index is one of those made behind the daemon', 'fw_big_bytes' in
   dict(store.LATER_INDEXES))
ok('...and seen to be there, where the engine has partial indexes', store.fw_big_index(),
   store.dialect.name != 'mariadb')
pages = []
for skip, want in ((0, 20), (20, 20), (40, 20), (50, 20)):
    a, _ = store.fw_rows(since=NOW - 86400, sort='bytes', desc=True, limit=want, offset=skip)
    store._fw_big_index = (time.time(), False)
    b, _ = store.fw_rows(since=NOW - 86400, sort='bytes', desc=True, limit=want, offset=skip)
    store._fw_big_index = None
    pages.append(([r['ident'] for r in a] == [r['ident'] for r in b], len(a)))
ok('every page is the one ordering them all gives - with enough heavy ones, and past them',
   pages, [(True, 20), (True, 20), (True, 20), (True, 20)])
a, _ = store.fw_rows(since=NOW - 86400, sort='bytes', desc=False, limit=20)
ok('the other way round asks as before', len(a), 20)
ok('the index and the question say it in the same words',
   "WHERE ' + FW_BIG_SQL" in source and "' AND ' + FW_BIG_SQL" in source)

shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
