#!/usr/bin/env python3
"""1.10.168: big data and many events a second - the busiest lists picked by
the database, a ban looked up by its key, the firewall's names asked for a
lot at once, smaller answers to the page; and the page's own fixes.

    ./test/fixes168.py
"""
import heapq
import json
import random
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import isemon                                        # noqa: E402

PASS = FAIL = 0
PORT = 19000 + random.randint(0, 900)


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


folder = tempfile.mkdtemp(prefix='isemon-168-')
isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = Path(folder) / 'c.db'
isemon.BACKUP_DIR = Path(folder) / 'backups'
isemon.DUMP_DIR = Path(folder) / 'dumps'
isemon.RUN_DIR = Path(folder)
isemon.LOG_DIR = Path(folder)
isemon.CONFIG_FILE = Path(folder) / 'config.json'
isemon._LOG_PATH = Path(folder) / 'c.log'
isemon.TOKEN_FILE = Path(folder) / 'api-token'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'api_port': PORT, 'geo': 0, 'ise_paths': [folder], 'mikrotik1': 0})
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
R = random.Random(168)

print('\nThe busiest, the most refused and the heaviest, picked by the database')
HOUR = int(time.time() // 3600) * 3600 - 7200
rows = []
for k in range(600):
    val = R.choice(['10.0.0.%d' % R.randint(1, 60), 'b%02d' % R.randint(0, 30), 'Zz', 'a',
                    'Česko', 'x y'])
    for verdict in ('allow', 'deny', 'block', 'fail', 'info'):
        if R.random() < 0.4:
            # Ties on purpose: small counts collide.
            rows.append((3600, HOUR + 3600 * R.randint(0, 1), 'src', val, verdict,
                         R.randint(1, 4), R.choice([0, 10, 20]), R.choice([0, 5])))
merged = {}
for r in rows:
    key = r[:5]
    one = merged.setdefault(key, [0, 0, 0])
    one[0] += r[5]
    one[1] += r[6]
    one[2] += r[7]
with store.db_write() as db:
    db.executemany(store.FW_ROLL_UPSERT, [k + tuple(v) for k, v in merged.items()])


def the_old_way(low, high, most=12):
    """What 1.10.167 did: every value to Python, and the lists picked here."""
    sums = {}
    for (span, at, dim, val, verdict), (n, sent, rcvd) in merged.items():
        if span != 3600 or dim != 'src' or not low <= at < high:
            continue
        one = sums.setdefault(val, [0, 0, 0, 0])
        one[0] += n
        one[1] += sent
        one[2] += rcvd
        if verdict in ('deny', 'block', 'fail'):
            one[3] += n
    vals = [(v, a[0], a[1], a[2], a[3]) for v, a in sums.items()]
    busiest = heapq.nsmallest(most, vals, key=lambda r: (-r[1], r[0]))
    refused = heapq.nsmallest(most, [r for r in vals if r[4]], key=lambda r: (-r[4], r[0]))
    heaviest = heapq.nsmallest(most, vals, key=lambda r: (-(r[2] + r[3]), r[0]))
    return (len(vals), [r[0] for r in busiest], [r[0] for r in refused],
            [r[0] for r in heaviest])


for most in (12, 3):
    got = store.fw_top('src', 3600, HOUR, HOUR + 7200, most=most)
    ok('the same lists, ties and all, as every value picked in Python (%d)' % most,
       (got['values'], [r['val'] for r in got['busiest']], [r['val'] for r in got['refused']],
        [r['val'] for r in got['heaviest']]), the_old_way(HOUR, HOUR + 7200, most))
ok('...each with how it was decided',
   all(set(r['by']) <= {'allow', 'deny', 'block', 'fail', 'info'} and r['by']
       for r in store.fw_top('src', 3600, HOUR, HOUR + 7200)['busiest']))
ok('nothing in the window: empty lists, no values',
   store.fw_top('src', 3600, 1000, 2000), {'values': 0, 'busiest': [], 'refused': [],
                                             'heaviest': []})

print('\nA ban looked up by its key, the subnets out of a list kept a moment')
now = time.time()
store.block('203.0.113.7', now + 3600, 'by hand', auto=False, by='test')
store.block('198.51.100.0/24', now + 3600, 'folded', auto=False, by='test')
ok('the address itself', store.blocked_until('203.0.113.7') > now)
ok('an address inside a subnet on the list', store.blocked_until('198.51.100.42') > now)
ok('an address on no list', store.blocked_until('192.0.2.1'), None)
store.block('192.0.2.0/28', None, 'folded', auto=False, by='test')
ok('a subnet added is known at once - the list kept is let go when it changes',
   store.blocked_until('192.0.2.1'), 0)
store.unblock('198.51.100.0/24', by='test')
ok('...and one taken off', store.blocked_until('198.51.100.42'), None)
ok('the lookup of many agrees', store.blocked_lookup()('192.0.2.1'),
   store.blocked_until('192.0.2.1'))

print('\nThe firewall\'s refused VPN lines, named out of ISE a lot at a time')
isemon.CONFIG['ise'] = 1
for k in range(6):
    store.add_failed({'session': 'f%d' % k, 'ts': now - 60 + k, 'ip': '45.0.0.%d' % (k % 3),
                      'username': 'person%d' % k, 'kind': 'vpn', 'server': 'ise1'})
lines = [{'type': 'event', 'verdict': 'fail', 'sub': 'vpn', 'srcip': '45.0.0.%d' % (k % 3),
          'ts': now - 30 + k, 'fields': {}} for k in range(5)]
lines.append({'type': 'event', 'verdict': 'fail', 'sub': 'vpn', 'srcip': '45.0.0.9',
              'ts': now, 'fields': {}})
daemon._ise_vpn_at = 0
names = daemon.fw_ise_names(lines)
one_by_one = []
for f in lines:
    g = dict(f, fields={})
    daemon.fw_name_from(g)
    one_by_one.append(g.get('user'))
together = []
for f in lines:
    g = dict(f, fields={})
    daemon.fw_name_from(g, names)
    together.append(g.get('user'))
ok('the same names as one question a line', together, one_by_one)
ok('...and some were found', sum(1 for x in together if x) >= 5)

print('\nWho is on the VPN, a page at a time')
said = {'clients': [{'id': str(k), 'user': 'u%03d' % k, 'srcip': '45.1.%d.%d' % (k // 200, k % 200),
                     'group': 'G%d' % (k % 3), 'lines': [1] * (k % 4)} for k in range(450)],
        'tunnels': [{'id': 't%d' % k, 'peer': '203.0.113.%d' % k, 'sas': [1, 2],
                     'selectors': [1, 2, 3], 'events': [1]} for k in range(5)],
        'ended_clients': 7, 'oldest': 1.0, 'fw': '', 'made': 2.0}
page = isemon.fw_vpn_page(said, '', 200, 400)
ok('the last page of the people, and how many there are',
   (len(page['clients']), page['clients_total'], page['clients_match']), (50, 450, 450))
page = isemon.fw_vpn_page(said, 'g1 u0', 200, 0)
ok('...the words typed, in the fields the page looked in',
   (page['clients_match'], {c['group'] for c in page['clients']}), (33, {'G1'}))
page = isemon.fw_vpn_page(said, '', 200, 0)
ok('...a tunnel without its SAs and networks, but how many',
   ({k for k in page['tunnels'][0]} & {'sas', 'selectors', 'events'},
    page['tunnels'][0]['sas_n'], page['tunnels'][0]['selectors_n']), (set(), 2, 3))

print('\nThe counting, without its rows while its fold is shut')
c = {'rows': [{'ip': str(k)} for k in range(10)], 'total': 10, 'bar': 5}
ok('none of them', (isemon.counting_rows(c, 0)['rows'], isemon.counting_rows(c, 0)['total'],
                    isemon.counting_rows(c, 0)['rows_cut']), ([], 10, True))
ok('all of them, as before', isemon.counting_rows(c, 1000) is c)

print('\nA line from the future, in the zone of the firewall that wrote it')
said = isemon.clock_words('/var/log/fw/x.log', 7200, time.time(), True, False,
                          {'name': 'edge', 'zone': 'UTC'})
ok('it names that firewall\'s setting, not the ISE logs\'', (
    'the zone of the firewall "edge"' in said, 'The ISE logs' in said), (True, False))
ok('...and reads it in that zone', 'being read as +00:00' in said)

print('\nThe answers the page asks for, smaller')
api = isemon.ApiServer(daemon, PORT)
api.start()
time.sleep(0.4)


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
        with urllib.request.urlopen(req, timeout=60) as answer:
            return answer.status, json.loads(answer.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or '{}')


try:
    daemon.add_user('boss', 'a-long-enough-password', 'fulladmin', by='test')
    tok = call('/api/auth/login', 'POST', {'name': 'boss',
                                           'password': 'a-long-enough-password'})[1]['token']
    status, got = call('/api/blocked?parts=history&limit=25', session=tok)
    ok('the ban history alone', (status, sorted(got)), (200, sorted(
        ['ok', 'history', 'history_total', 'q_error', 'history_capped', 'history_countries'])))
    status, got = call('/api/blocked?parts=bans&limit=1&counting=0', session=tok)
    ok('the bans, with the counting\'s numbers and none of its rows',
       (status, 'blocked' in got, got['counting'].get('rows')), (200, True, []))
    status, got = call('/api/status', session=tok)
    status2, got2 = call('/api/status?logs=0', session=tok)
    ok('the status without the files, where they are not drawn',
       ('logs' in got, 'logs' in got2, got2.get('logs_left_out')), (True, False, True))
    status, got = call('/api/fw?hours=24&counts=1', session=tok)
    ok('the firewall\'s counts alone, for a page of lines',
       (status, got.get('counts_only'), set((got.get('tops') or {}).keys()) <= {'area', 'kind', 'natted'},
        'events' in got), (200, True, True, False))
    status, got = call('/api/fw/suggest?field=srcip&typed=1&hours=24', session=tok)
    ok('values offered for a field', (status, isinstance(got.get('values'), list)), (200, True))
    status, got = call('/api/fw/vpn?list=1&climit=5', session=tok)
    ok('the VPN as a page', (status, got.get('paged'), 'clients_total' in got), (200, True, True))
finally:
    api.stop() if hasattr(api, 'stop') else None

print('\nA word searched for, counted no longer than a few seconds')
facts = []
for k in range(4):
    f = isemon.fg_record_from(
        'date=2026-10-01 time=10:01:13 devname="FG-1" devid="FGT0" eventtime=%d000000000 '
        'tz="+0000" logid="0000000013" type="traffic" subtype="forward" level="notice" '
        'vd="root" srcip=10.1.1.%d dstip=8.8.8.8 dstport=443 action="close" service="HTTPS" '
        'msg="findme %d"' % (int(time.time()) - k * 86400 - 60, k, k)).facts
    f['ts'] = time.time() - k * 86400 - 60
    f['fw'] = 'branch'
    f['area'] = isemon.fw_area(f)
    f['ident'] = isemon.fw_ident(f) if hasattr(isemon, 'fw_ident') else 'id%d' % k
    facts.append(f)
store.note_fw_events(facts)
said = {}
rows, total = store.fw_rows(since=time.time() - 5 * 86400, text='findme', limit=1, said=said)
ok('counted a day at a time, the same number', (len(rows), total, said.get('stopped')),
   (1, 4, False))
store.FW_COUNT_SECONDS = -1
said = {}
store.fw_rows(since=time.time() - 5 * 86400, text='findme', limit=1, said=said)
ok('the count stops, and says it stopped', said.get('stopped'), True)

print('\nThe page')
page = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')
node = shutil.which('node')
if node:
    import subprocess

    def js_function(name):
        at = page.index('\nfunction %s(' % name) + 1
        return page[at:page.index('\n}', at) + 2]
    script = ('var I18N = {on: true, code: "cs"};\nvar NUM_FMT = {lang: null, dec: "."};\n'
              + '\n'.join(js_function(n) for n in ('numLang', 'numDecimal', 'shownNumber',
                                                    'bytes', 'num'))
              + '\nvar cs = [num(1234567), bytes(1536 * 1024), shownNumber(num(1234567)), '
                'shownNumber("45,8")];\nI18N.on = false;\n'
                'var en = [num(1234567), bytes(1536 * 1024), shownNumber("1,234,567"), '
                'shownNumber("45.8")];\nconsole.log(JSON.stringify([cs, en]));')
    got = json.loads(subprocess.run([node, '-e', script], capture_output=True, text=True,
                                    check=True).stdout)
    ok('numbers in Czech: spaces between the thousands, a comma before the decimals, '
       'read back as written', [[got[0][0].replace('\u00a0', ' '), got[0][1], got[0][2],
                                got[0][3]], got[1]],
       [['1 234 567', '1,5 MB', 1234567, 45.8], ['1,234,567', '1.5 MB', 1234567, 45.8]])
for what, bits in (
        ('the page starts from the status it was drawn with', ['STATUS.serial : -1']),
        ('nobody looking, or somebody in the middle of something: the list waits',
         ['RELOAD_WHEN_SEEN = true;', 'function userHolds(host)', ":focus-visible"]),
        ('the refresh asks the search that ran, not what is half typed',
         ['function tAsk(quiet)', 'if (quiet && T_Q_RAN !== null) typed = T_Q_RAN;']),
        ('a capped list says so and has no Last', ['function pager(id, page, per, total, go, capped)',
                                                   "page >= pages - 1 || capped"]),
        ('Next, not On', ["button('Next', 'next'"]),
        ('a box\'s placeholder and title are translated',
         ['var I18N_BOXES = {INPUT: 1, TEXTAREA: 1};', 'function i18nAttrsSkip(el)']),
        ('numbers written as the language writes them', ['function shownNumber(text)',
                                                         'function numLang()']),
        ('the VPN a page at a time', ["'fw-vpn&list=1'", "pager('tv-c-pager'"]),
        ('a popup opened by a button is not closed by it',
         ['if (b.close && MODAL_GEN === was) closeModal();']),
        ('Escape and Tab inside the find box', ["$('findback').addEventListener('keydown'"]),
        ('a link to a Traffic page opens it', ["T_PAGES[sub] || sub === 'vpn'"]),
        ('only what was drawn is explained', ['NAMING_ROOTS.push(t);'])):
    ok(what, all(b in page for b in bits))

shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
