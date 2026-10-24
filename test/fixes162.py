#!/usr/bin/env python3
"""1.10.162: the VPN as it stands, read from far fewer lines - and the same
answer as when every line was read.

    ./test/fixes162.py
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
    folder = tempfile.mkdtemp(prefix='isemon-162-')
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


print('\nThe VPN as it stands, from fewer lines')
before = every_line()
after = store.fw_vpn_rows(since)
ok('far fewer lines are read', (len(before) > 3000, len(after) < len(before) / 5),
   (True, True))


def picture(rows):
    got = isemon.fw_vpn_fold(rows, NOW)
    return ([(c['user'], c['inner'], c['srcip'], int(c['started']), c['since_known'],
              int(c['last']), c['sent'], c['rcvd'], c['quiet'], c['for_s'] // 60)
             for c in got['clients']], got['ended_clients'], len(got['tunnels']))


ok('the same people, the same start, the same counters, the same quiet',
   picture(after), picture(before))
ok('...and somebody is on at all', len(picture(after)[0]), 2)

print('\nThe size of a table, without waiting on a lock')
ok('a table\'s size is still said', store.rows_in('fw_events') >= 0, True)

for folder in FOLDERS:
    shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
