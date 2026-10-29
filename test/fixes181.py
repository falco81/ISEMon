#!/usr/bin/env python3
"""1.10.181-183: the VPN of a week read a page at a time rather than held whole,
and the daemon's memory cap no longer a fixed 768 MB.

    ./test/fixes181.py
"""
import shutil
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import isemon                                        # noqa: E402

PASS = FAIL = 0
FOLDERS = []


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


def fresh():
    folder = tempfile.mkdtemp(prefix='isemon-181-')
    FOLDERS.append(folder)
    isemon.STATE_DIR = Path(folder)
    isemon.DB_FILE = Path(folder) / 'f.db'
    isemon.BACKUP_DIR = Path(folder) / 'b'
    isemon.DUMP_DIR = Path(folder) / 'd'
    isemon.RUN_DIR = Path(folder)
    isemon.LOG_DIR = Path(folder)
    isemon._LOG_PATH = Path(folder) / 'l.log'
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    isemon.CONFIG.update({'watch_devices': '', 'feeds_ban': 0, 'geo': 0,
                          'fwlog_keep_days': 14, 'fwlog_allowed_days': 14})
    return isemon.Storage(isemon.DB_FILE)


NOW = time.time()
SEQ = [0]


def line(ts, action, extra, logid='0101039947', subtype='vpn'):
    SEQ[0] += 1
    f = isemon.fg_record_from(
        'date=2026-10-01 time=10:01:13 devname="FG-1" devid="FGT0" eventtime=%d000000000 '
        'tz="+0000" logid="%s" type="event" subtype="%s" level="information" vd="root" '
        'action="%s" %s msg="n%d"' % (int(ts), logid, subtype, action, extra, SEQ[0])).facts
    f['ts'] = float(ts)
    f['fw'] = 'branch'
    return f


facts = []
# One person on for three days, said every ten minutes.
facts.append(line(NOW - 3 * 86400, 'tunnel-up',
                  'tunneltype="ssl-tunnel" tunnelid=42 remip=9.9.9.11 tunnelip=10.212.134.200 '
                  'user="pdvorak" group="VPN"'))
for k in range(1, 3 * 144):
    at = NOW - 3 * 86400 + k * 600
    facts.append(line(at, 'tunnel-stats',
                      'tunneltype="ssl-tunnel" tunnelid=42 remip=9.9.9.11 '
                      'tunnelip=10.212.134.200 user="pdvorak" group="VPN" nextstat=600 '
                      'duration=%d sentbyte=%d rcvdbyte=%d' % (k * 600, k * 1000, k * 2000),
                      logid='0101039949'))
# Another one whose start is older than the week, known only by its statistics.
for k in range(0, 2 * 144):
    at = NOW - 2 * 86400 + k * 600
    facts.append(line(at, 'tunnel-stats',
                      'tunneltype="ssl-tunnel" tunnelid=43 remip=9.9.9.12 '
                      'tunnelip=10.212.134.201 user="mkral" group="VPN" nextstat=600 '
                      'duration=%d sentbyte=5 rcvdbyte=6' % (9 * 86400 + k * 600),
                      logid='0101039949'))
# One who came and went yesterday.
facts.append(line(NOW - 30 * 3600, 'tunnel-up',
                  'tunneltype="ssl-tunnel" tunnelid=44 remip=9.9.9.13 tunnelip=10.212.134.202 '
                  'user="jnovak" group="VPN"'))
facts.append(line(NOW - 29 * 3600, 'tunnel-stats',
                  'tunneltype="ssl-tunnel" tunnelid=44 remip=9.9.9.13 tunnelip=10.212.134.202 '
                  'user="jnovak" group="VPN" nextstat=600 duration=3600 sentbyte=7 rcvdbyte=8',
                  logid='0101039949'))
facts.append(line(NOW - 28 * 3600, 'tunnel-down',
                  'tunneltype="ssl-tunnel" tunnelid=44 remip=9.9.9.13 tunnelip=10.212.134.202 '
                  'user="jnovak" group="VPN" duration=7200 sentbyte=9 rcvdbyte=10'))
# ...and the internet trying, thousands of times.
for k in range(3000):
    facts.append(line(NOW - k * 60, 'ssl-login-fail',
                      'tunneltype="ssl-web" remip=203.0.113.%d user="admin" '
                      'reason="sslvpn_login_permission_denied"' % (k % 200 + 1),
                      logid='0101039426'))
for f in facts:
    f['area'] = isemon.fw_area(f)
    f['ident'] = isemon.fw_ident(f) if hasattr(isemon, 'fw_ident') else '%032x' % id(f)

store = fresh()
store.note_fw_events([dict(f, fields=dict(f['fields'])) for f in facts])
since = NOW - isemon.FW_VPN_LOOK_S


def every_line():
    """The lines as 1.10.161 read them: every remote-access one."""
    out = []
    cols = ('SELECT ts, fw, dev, area, type, sub, action, verdict, srcip, dstip, usr, msg, '
            'sent, rcvd, duration, detail FROM fw_events WHERE ')
    for extra, args in (("area = ? AND ts >= ?", ['client-vpn', since]),
                        (isemon.FW_S2S_KEPT + ' AND ts >= ?', [since])):
        for r in store.db.execute(cols + extra, args):
            one = dict(r)
            import json
            one['fields'] = json.loads(store.unpack_detail(one.pop('detail')) or '{}')
            one['user'] = one.pop('usr', '') or ''
            out.append(one)
    out.sort(key=lambda r: float(r['ts']))
    return out



import json


def read_whole(since, most):
    """The lines as 1.10.180 read them: all at once, the newest `most` of each."""
    out = []
    cols = ("SELECT ident, ts, fw, dev, area, type, sub, action, verdict, srcip, dstip, usr, "
            "msg, sent, rcvd, duration, detail FROM fw_events WHERE ")
    stats_from = time.time() - isemon.FW_VPN_STATS_S
    thin = " AND (COALESCE(action, '') <> 'tunnel-stats' OR ts >= ?)"
    for area, extra in (('client-vpn', "area = ? AND ts >= ? AND COALESCE(verdict, '') <> 'fail'"),
                        ('s2s-vpn', isemon.FW_S2S_KEPT + ' AND ts >= ?')):
        args = ([area, since] if area == 'client-vpn' else [since]) + [stats_from]
        for r in store.db.execute(cols + extra + thin + ' ORDER BY ts DESC LIMIT %d' % most, args):
            one = dict(r)
            one['fields'] = json.loads(store.unpack_detail(one.pop('detail')) or '{}')
            one['user'] = one.pop('usr', '') or ''
            out.append(one)
    out.sort(key=lambda r: float(r['ts']))
    return out


import inspect
source_vpn = inspect.getsource(isemon.Storage.fw_vpn_batches)
print('\nThe week a page at a time')
whole = read_whole(since, 10 ** 9)
store.FW_VPN_PAGE = 37
pages = list(store.fw_vpn_batches(since))
paged = [r for p in pages for r in p]
ok('read in many pages, none bigger than a page',
   (len(pages) > 5, max(len(p) for p in pages) <= 37), (True, True))
ok('the same lines', sorted(r['ident'] for r in paged), sorted(r['ident'] for r in whole))
ok('...oldest first', [r['ts'] for r in paged] == sorted(r['ts'] for r in paged), True)
def picture(rows):
    got = isemon.fw_vpn_fold(rows, NOW)
    return ([(c['user'], c['inner'], c['srcip'], int(c['started']), c['since_known'],
              int(c['last']), c['sent'], c['rcvd'], c['quiet'], c['for_s'] // 60)
             for c in got['clients']], got['ended_clients'], len(got['tunnels']))



ok('the same VPN made of them', picture(paged), picture(whole))
ok('no line is read by counting back from the newest',
   'OFFSET' not in source_vpn, True)
was = isemon.FW_VPN_ROWS
isemon.FW_VPN_ROWS = 50
few_paged = store.fw_vpn_rows(since)
isemon.FW_VPN_ROWS = was
newest = []
for area in ('client-vpn', 's2s-vpn'):
    mine = sorted([r for r in whole if r['area'] == area],
                  key=lambda r: (r['ts'], r['ident']), reverse=True)[:50]
    newest += mine
ok('only the newest of each kind, as ever (here fifty), across pages',
   sorted(r['ident'] for r in few_paged), sorted(r['ident'] for r in newest))
ok('...still oldest first', [r['ts'] for r in few_paged] == sorted(r['ts'] for r in few_paged),
   True)

print('\nThrough the daemon, fed a page at a time')
isemon.CONFIG.update({'fwlog': 1})
daemon = isemon.Daemon(store)
got = daemon._fw_vpn_now('')
want = isemon.fw_vpn_fold(paged, got['made'])
ok('the same people on as the whole week folded at once',
   sorted((c['user'], c['inner']) for c in got['clients']),
   sorted((c['user'], c['inner']) for c in want['clients']))
ok('...and nothing read twice on the next look',
   len(daemon._fw_vpn_now('')['clients']), len(got['clients']))

print('\nA page asking while the VPN is first put together')
daemon2 = isemon.Daemon(store)
gate = __import__('threading').Event()
real_now = daemon2._fw_vpn_now
daemon2._fw_vpn_now = lambda fw='': (gate.wait(5), real_now(fw))[1]
t0 = time.time()
said = daemon2.fw_vpn_now('', wait=False)
ok('is told at once that it is being put together',
   (said.get('building'), time.time() - t0 < 2), (True, True))
gate.set()
page = (HERE.parent / 'web' / 'index.php').read_text()
ok('...and the page says so and asks again', 'if (d.building) {' in page, True)

print('\nThe memory the daemon is allowed')
unit = (HERE.parent / 'deploy' / 'isemon.service').read_text()
ok('half of the machine rather than 768 MB',
   ('MemoryMax=50%' in unit, 'MemoryMax=768M' in unit), (True, False))

for folder in FOLDERS:
    shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
