#!/usr/bin/env python3
"""1.10.283: Counting up to a ban - one address cleared; and the pass that
looks for anything missed asks of its banned addresses at once.

- Counting up to a ban -> a row's own button: that address back to nought,
  as Clear all does for everybody - nothing deleted, nobody let in, its
  attempts still on the Failed attempts page; its counting starts again
  from that moment (the floor the counting keeps for each address, as after
  a ban it served), written in its ban history with who and when. A full
  administrator's, as Clear all is. Every other address counts on.
- `judge_anything_missed` (every few seconds) asked, for every address over
  the bar that is already banned, whether a carried ban keeps it out - one
  statement each, thousands a pass on a busy site. Now one statement a few
  hundred, with the same answer for every address (subnets, watched and
  switched-off sources included).

    ./test/fixes283_counting.py
"""
import json
import random
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import isemon                                        # noqa: E402

PASS = FAIL = 0
PORT = 19800 + random.randint(0, 90)


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


VPN = ('Protocol=Radius, NetworkDeviceName=FTD-VPN, NAS-IP-Address=172.29.14.81, '
       'Calling-Station-ID=%s, NAS-Port-Type=Virtual, Tunnel-Client-Endpoint=(tag=0) %s, '
       'FailureReason=22056 Subject not found in the applicable identity store')
SEQ = [7000]


def line(ip, user, ts=None):
    SEQ[0] += 1
    ts = ts or time.time()
    stamp = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(ts)) + '.500 +00:00'
    head = ('%s 0075245450 5400 NOTICE Failed-Attempt: Authentication failed, ConfigVersionId=126, '
            'Device IP Address=172.29.2.23, UserName=%s, %s, AcsSessionID=c283/1/%d,'
            % (stamp, user, VPN % (ip, ip), SEQ[0]))
    return '%s c283 CISE_Failed_Attempts %010d 1 0 %s' % (
        time.strftime('%b %d %H:%M:%S', time.gmtime(ts)), SEQ[0], head)


work = Path(tempfile.mkdtemp(prefix='isemon-283-'))
api = None
try:
    state = work / 'state'
    state.mkdir()
    isemon.STATE_DIR = state
    isemon.DB_FILE = state / 'd.db'
    isemon.BACKUP_DIR = state / 'b'
    isemon.DUMP_DIR = state / 'dumps'
    isemon.RUN_DIR = state
    isemon.LOG_DIR = state
    isemon.CONFIG_FILE = state / 'config.json'
    isemon._LOG_PATH = state / 'd.log'
    isemon.TOKEN_FILE = state / 'token'
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    isemon.CONFIG.update({'api_port': PORT, 'geo': 0, 'mikrotik1': 0, 'block_tries': 5,
                          'block_window_min': 60, 'block_bogus_tries': 0, 'judge_max_age_h': 0})
    (state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
    store = isemon.Storage(isemon.DB_FILE)
    daemon = isemon.Daemon(store)
    daemon.add_user('boss', 'a-long-enough-password', 'fulladmin', by='test')
    daemon.add_user('banner', 'a-fourth-long-password', 'banadmin', by='test')

    A, B = '203.0.113.10', '203.0.113.20'
    now = time.time()
    daemon.read_records([line(A, 'u%d' % i, now - 300 + i) for i in range(4)], kind='failed')
    daemon.read_records([line(B, 'v%d' % i, now - 300 + i) for i in range(4)], kind='failed')

    def counting():
        daemon.forget_held('counting/')
        return {r['ip']: int(r['tries']) for r in daemon.counting_up(1000)['rows']}
    print('Two addresses counting up, four of five each')
    ok('both counting', (counting().get(A), counting().get(B)), (4, 4))

    api = isemon.ApiServer(daemon, PORT)
    api.start()
    time.sleep(0.4)

    def call(path, body=None, sess=None):
        req = urllib.request.Request('http://127.0.0.1:%d%s' % (PORT, path),
                                     data=json.dumps(body).encode() if body is not None else None,
                                     method='POST' if body is not None else 'GET')
        req.add_header('X-Isemon-Token', isemon.API_TOKEN)
        req.add_header('Content-Type', 'application/json')
        if sess:
            req.add_header('X-Isemon-Session', sess)
        try:
            with urllib.request.urlopen(req, timeout=60) as a:
                return a.status, json.loads(a.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or '{}')

    def login(n, p):
        return call('/api/auth/login', {'name': n, 'password': p})[1]['token']
    boss, banner = login('boss', 'a-long-enough-password'), login('banner', 'a-fourth-long-password')

    print('\nOne of them cleared')
    ok('a ban admin may not', call('/api/blocked', {'clear_counting_of': A}, banner)[0], 403)
    ok('not an address: refused', call('/api/blocked', {'clear_counting_of': 'nonsense'}, boss)[0],
       400)
    st, d = call('/api/blocked', {'clear_counting_of': A}, boss)
    ok('a full admin: back to nought, said', (st, d['ip'], d['message']),
       (200, A, '%s went back to nought' % A))
    c = counting()
    ok('it is no longer counting; the other counts on', (A in c, c.get(B)), (False, 4))
    ok('...on the page at once (the kept list let go)',
       A not in [r['ip'] for r in call('/api/blocked?parts=bans', sess=boss)[1]['counting']['rows']])
    ok('nothing deleted: its four attempts still kept',
       store.db.execute('SELECT COUNT(*) AS n FROM failed WHERE ip=?', (A,)).fetchone()['n'], 4)
    ok('the global line not moved', store.counting_from(), 0.0)
    hist = store.block_events_of(A)
    ok('its ban history says who and when', (hist[0]['what'], hist[0]['by']),
       ('counting cleared', 'boss'))
    ok('...and the events', any('the counting of %s was started again' % A in (e['detail'] or '')
                                for e in store.events(limit=10)[0]))

    print('\nWhat comes after')
    time.sleep(1.2)
    daemon.read_records([line(A, 'w%d' % i) for i in range(2)], kind='failed')
    ok('new attempts count from nought: two, not six', counting().get(A), 2)
    daemon.judge_anything_missed()
    ok('the pass that looks for anything missed does not ban it for the old ones',
       store.blocked_one(A), None)
    daemon.read_records([line(B, 'x9')], kind='failed')
    ok('the other one reaches its bar as ever, and is banned', store.blocked_one(B) is not None)
    daemon.read_records([line(A, 'w%d' % i) for i in range(2, 5)], kind='failed')
    ok('the cleared one earns its ban on five new attempts', store.blocked_one(A) is not None)
    store.forget_blocked_history()
    ok('forgetting the ban history keeps the line (as it keeps let back in)',
       'counting cleared' in [h['what'] for h in store.block_events_of(A, 50)] or
       store.db.execute("SELECT COUNT(*) AS n FROM block_events WHERE ip=? AND what='counting "
                        "cleared'", (A,)).fetchone()['n'] == 1)

    print('\nWhether a carried ban keeps them out, for many at once')
    with store.db_write() as db:
        pass
    daemon.ban('198.51.100.0/24', None, why='a range', by='boss')
    daemon.ban('192.0.2.50', None, why='by hand', by='boss')
    ips = [A, B, '198.51.100.7', '192.0.2.50', '192.0.2.51', '8.8.8.8']
    one = {ip for ip in ips if daemon.carried_covers(ip)}
    ok('the same answer as one at a time', daemon.carried_covers_many(ips), one)
    isemon.CONFIG['ban_src_manual'] = 'off'
    one = {ip for ip in ips if daemon.carried_covers(ip)}
    ok('...with bans by hand switched off as well', daemon.carried_covers_many(ips), one)
    isemon.CONFIG.pop('ban_src_manual', None)
    asked = []
    real = store.blocked_one
    store.blocked_one = lambda ip: (asked.append(ip), real(ip))[1]
    daemon.carried_covers_many([A, B, '192.0.2.50'])
    store.blocked_one = real
    ok('...their own rows read together, not one by one', asked, [])

    print('\nThe page')
    page = (ROOT / 'web' / 'index.php').read_text()
    ok('a button on every row, for a full admin', (
        "var zero = iconButton('forget', 'Clear its counting: ' + r.ip + ' goes back to nought');"
        in page, "api('blocked', {clear_counting_of: r.ip})" in page,
        ".concat(ADMIN ? [{words: '', cls: 'act'}] : []), page," in page), (True, True, True))
finally:
    if api is not None:
        try:
            api.stop()
        except Exception:
            pass
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
