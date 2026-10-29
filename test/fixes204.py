#!/usr/bin/env python3
"""1.10.204: going back over the logs reads every log switched on, whatever
its kind, and weighs the sources counted on their own over the same span; a
FreeRADIUS's sign-ins learn what its accounting and the router's DHCP said
of each machine - the door, the network, the access point, the address, the
zone of the server's clock.

    ./test/fixes204.py
"""
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


page = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')
src = (HERE.parent / 'isemon.py').read_text(encoding='utf-8')
folder = Path(tempfile.mkdtemp(prefix='isemon-204-'))
isemon.STATE_DIR = folder
isemon.DB_FILE = folder / 'c.db'
isemon.LOG_DIR = folder
isemon._LOG_PATH = folder / 'c.log'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
logs = folder / 'logs'
for name in ('ise1', 'otp', 'edu', 'tac', 'nps', 'dc1', 'fw', 'radius'):
    (logs / name).mkdir(parents=True)
isemon.CONFIG.update({
    'geo': 0, 'mikrotik1': 0, 'mikrotik_sync': 0,
    'ise_paths': [str(logs / 'ise1')], 'otp': 1, 'otp_paths': [str(logs / 'otp')],
    'otp_detail': 1, 'eduroam': 1, 'eduroam_paths': [str(logs / 'edu')],
    'tacplus': 1, 'tacplus_paths': [str(logs / 'tac')], 'nps': 1,
    'nps_paths': [str(logs / 'nps')], 'winsec': 1, 'winsec_paths': [str(logs / 'dc1')],
    'fwlog': 1, 'fwlog_sources': [{'name': 'gw', 'type': 'routeros', 'path': str(logs / 'fw'),
                                   'files': '*.log'}],
    'radius': 1, 'radius_paths': [str(logs / 'radius')]})
(logs / 'edu' / 'detail-20261017').write_text('')
(logs / 'edu' / 'detail-20261018').write_text('')
(logs / 'radius' / 'radius.log').write_text('')
(logs / 'radius' / 'detail-20261018').write_text('')
(logs / 'nps' / 'IN2610.log').write_text('')
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)

print('\nGoing back over every log')
sources = {s for _k, _p, s in daemon.log_files()}
ok('every kind of log followed is one going back over can be asked for by name',
   sorted(sources - set(isemon.LOG_MODULE_NAMES)), [])
listed = [one['log'] for one in daemon.rescan_logs()]
ok('the page is told every log switched on, the accounting under its log',
   sorted(listed), ['eduroam', 'fwlog', 'ise', 'nps', 'otp', 'radius', 'tacplus', 'winsec'])
ok('...and nothing is left out because it has no zone of its own',
   "elif source in ZONELESS_LOGS:\n                    continue" in src, False)
ok('every day of the accounting of eduroam and of FreeRADIUS',
   "if source in ('radius-detail', 'eduroam-detail'):" in src)
ok('the firewall left out where what it let through is not kept (it would count twice)',
   "if source == 'fwlog' and not int(CONFIG.get('fwlog_keep_allowed', 1) or 0):" in src)
ok('the page offers the logs to tick, every one ticked',
   'id="rescan-logs"' in page and 'function rescanPicked()' in page
   and "logs: picked.all ? '' : picked.logs.join(',')" in page)

print('\nThe sources counted on their own, weighed going back')
isemon.CONFIG.update({'ban_from_fw': 'on', 'block_tries': 3, 'block_window_min': 10})
now = time.time()
long_ago = now - 5 * 86400
for i in range(3):
    store.note_fw_events([{'ident': 'ros/x/%d' % i, 'ts': long_ago + i * 30, 'dev': 'gw', 'fw': 'gw',
                           'type': 'event', 'sub': 'system', 'action': 'login', 'verdict': 'fail',
                           'srcip': '185.220.10.77', 'user': 'admin', 'fields': {}}])
for i in range(3):     # three, but an hour apart: never inside one window
    store.note_fw_events([{'ident': 'ros/y/%d' % i, 'ts': long_ago + i * 3600, 'dev': 'gw',
                           'fw': 'gw', 'type': 'event', 'sub': 'system', 'action': 'login',
                           'verdict': 'fail', 'srcip': '185.220.10.78', 'user': 'root',
                           'fields': {}}])
ok('the pass of their own sees only the last hour', daemon.judge_sources(), 0)
ok('going back finds the three inside one window, five days ago',
   daemon.judge_sources_back(now - 7 * 86400), 1)
ok('...banned', store.blocked_until('185.220.10.77') is not None, True)
ok('...and not the three an hour apart', store.blocked_until('185.220.10.78'), None)
ok('...saying where it was found',
   'going back over the logs' in store.db.execute(
       "SELECT why FROM blocked WHERE ip='185.220.10.77'").fetchone()[0])
ok('...and only within the days asked for', daemon.judge_sources_back(now - 86400), 0)

print('\nFreeRADIUS: what the accounting says')
isemon.FRAD_LEARNED.update({'mac': {}, 'user': {}, 'dhcp': {}, 'offset': {}})
root = str(logs / 'radius')
detail = ['Sun Oct 18 16:58:36 2026', '\tAcct-Status-Type = Start', '\tUser-Name = "Watch"',
          '\tNAS-IP-Address = 192.168.40.244', '\tFramed-IP-Address = 192.168.40.100',
          '\tNAS-Identifier = "9a2a6fb2e8da"',
          '\tCalled-Station-Id = "9A-2A-6F-B2-E8-DA:FalconSoftENT"',
          '\tNAS-Port-Type = Wireless-802.11', '\tCalling-Station-Id = "F4-CB-E7-D1-63-75"',
          '\tTimestamp = 1792357116', '']
read = daemon.parser_for('radius-detail', str(logs / 'radius' / 'detail-20261018'))
sessions = read(detail, {})
ok('the zone of the server\'s clock, out of its own accounting',
   (isemon.FRAD_LEARNED['offset'].get(root), sessions[0].facts.get('offset')), (-14400, -14400))
for one in sessions:
    daemon.take_record('radius-detail', one)
ok('...kept over a restart', store.get_meta('radius_offset_%s' % root), '-14400')
line = ('Oct 18 16:58:40 radius radius: Sun Oct 18 16:58:40 2026 : Auth: (24) Login OK: '
        '[Watch/<via Auth-Type = eap>] (from client XYZ port 3 cli F4-CB-E7-D1-63-75)')
recs = daemon.parser_for('radius', str(logs / 'radius' / 'radius.log'))([line], {})
ok('a sign-in is read in that zone, so it falls beside its accounting',
   int(recs[0].ts), 1792357120)
ok('...and carries what the accounting said of the machine',
   [isemon.ise_first(recs[0].fields, k) for k in ('Medium', 'SSID', 'Address it was given')],
   ['wifi', 'FalconSoftENT', '192.168.40.100'])
daemon.take_record('radius', recs[0])
row = dict(store.db.execute("SELECT kind, ssid, port, client, nad FROM passed").fetchone())
ok('...on its door, with its network, access point, address and the box that asked',
   row, {'kind': 'radius-dot1x-wifi', 'ssid': 'FalconSoftENT', 'port': '9A-2A-6F-B2-E8-DA',
         'client': '192.168.40.100', 'nad': '192.168.40.244'})
ok('an access point named AP or AP-something is a radio by default',
   [isemon.frad_door(c, '11-22-33-44-55-66', 'x')[0] for c in ('AP', 'AP-VR', 'sw-core1', 'XYZ')],
   ['radius-dot1x-wifi', 'radius-dot1x-wifi', 'radius-dot1x-lan', 'radius-other'])

print('\nFreeRADIUS: a sign-in before anything was known')
early = ('Oct 18 17:30:00 radius radius: Sun Oct 18 17:30:00 2026 : Auth: (31) Login OK: '
         '[pc/<via Auth-Type = eap>] (from client XYZ port 3 cli 20-E2-A8-7D-9E-4D)')
daemon.take_record('radius', daemon.parser_for('radius', str(logs / 'radius' / 'radius.log'))(
    [early], {})[0])
ok('...is something else at first',
   store.db.execute("SELECT kind FROM passed WHERE username='pc'").fetchone()[0], 'radius-other')
late = [d.replace('Watch', 'pc').replace('F4-CB-E7-D1-63-75', '20-E2-A8-7D-9E-4D')
        .replace('192.168.40.100', '192.168.40.103').replace('1792357116', '1792359000')
        for d in detail]
for one in read(late, {}):
    daemon.take_record('radius-detail', one)
ok('...and put on its door, with its network and address, once the accounting says',
   dict(store.db.execute("SELECT kind, ssid, client FROM passed WHERE username='pc'").fetchone()),
   {'kind': 'radius-dot1x-wifi', 'ssid': 'FalconSoftENT', 'client': '192.168.40.103'})

print('\nFreeRADIUS: the router\'s DHCP')
isemon.ros_parse_lines(['Oct 19 09:58:11 gw.example.net dhcp,info DHCP_GUEST assigned '
                        '172.16.16.172 for F0:2F:4B:E1:3A:AF Jan--iPadPro'], {})
f = isemon.frad_enrich({'Calling-Station-ID': ['F0-2F-4B-E1-3A-AF'], 'Account': ['jan']})
ok('a machine the router gave an address to has that address and its name',
   (isemon.ise_first(f, 'Address it was given'), isemon.ise_first(f, 'The machine calls itself')),
   ('172.16.16.172', 'Jan--iPadPro'))

print('\nFreeRADIUS: the VPN')
isemon.frad_detail_lines(['Mon Oct 19 09:00:00 2026', '\tAcct-Status-Type = Start',
                          '\tUser-Name = "jnovak"', '\tNAS-Port-Type = Virtual',
                          '\tFramed-IP-Address = 10.8.0.6', '\tCalling-Station-Id = "185.1.2.3"',
                          '\tTimestamp = 1792414800', ''], {})
f = isemon.frad_enrich({'Calling-Station-ID': ['185.1.2.3'], 'Account': ['jnovak']})
ok('the address inside the VPN, from its accounting',
   isemon.ise_first(f, 'Address it was given'), '10.8.0.6')

print('\nThe whole pass')
said = []
got = daemon.rescan(lambda d, t, w='': said.append(w), by='test', read_files=True)
ok('it runs over every log switched on and says what it did', bool(got.get('message')), True)
ok('...reading the files of all of them, the FreeRADIUS accounting of every day too',
   any('detail-20261018' in w for w in said) and any('IN2610.log' in w for w in said))

print('\nA zone changed since a log was read')
daemon.zone_noted('otp')
ok('the zone a log was first read in is written down',
   store.get_meta('zone_read_otp', None) is not None, True)
isemon.CONFIG['log_zone'] = 'UTC'
ok('...a zone changed since is seen', daemon.zone_moved('otp'), True)
said = []
daemon.rescan(lambda d, t, w='': said.append(w), by='test', read_files=True)
ok('...and that log is left out of going back, saying why',
   any('left out: the zone it is read in was changed' in w for w in said), True)
ok('ISE has a zone of its own and is never left out for it', daemon.zone_moved('ise'), False)
store.forget_tails('otp')
ok('erasing its records forgets the zone, so it is read again in the new one',
   (store.get_meta('zone_read_otp', None), daemon.zone_moved('otp')), (None, False))
isemon.CONFIG['log_zone'] = ''

print('\nThe settings')
ok('the zone can be set, and is checked as every zone is',
   ('radius_zone' in isemon.DEFAULTS, isemon.check_setting('radius_zone', '-04:00')),
   (True, '-04:00'))
ok('...and the page offers it', "'radius_zone'" in page)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
