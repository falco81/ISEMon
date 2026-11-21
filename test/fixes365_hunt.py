#!/usr/bin/env python3
"""1.10.365: the second bug hunt over the newest parts, each kept fixed.

- SELinux: binding another service's port never a rule; a program called
  "isemon" is not isemon's; root does exactly what was confirmed; a reload
  that failed is not "put right";
- the DNAT analyzer: the router's own rules count for the device's kind of
  ports; a rule of several ranges, or none, drawn whole; a UDP peer
  answering from the port it was sent to is a knock; a netmap's prefix; an
  interface with a space quoted; only the newest answer drawn; the list of
  devices of the firewall chosen;
- the sign-in page during an upgrade: loaded again unless a key was pressed.

All names and addresses made up.

    ./test/fixes365_hunt.py
"""
import importlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime
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


folder = Path(tempfile.mkdtemp(prefix='isemon-365-'))
for k, v in dict(STATE_DIR=folder, DB_FILE=folder / 'c.db', BACKUP_DIR=folder / 'b',
                 DUMP_DIR=folder / 'd', RUN_DIR=folder, LOG_DIR=folder,
                 CONFIG_FILE=folder / 'config.json', _LOG_PATH=folder / 'c.log',
                 TOKEN_FILE=folder / 'tok').items():
    setattr(isemon, k, v)
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'mikrotik_sync': 0, 'api_port': 18965,
                      'fwlog': 1})
NOW = time.time()
DEV = '192.168.88.20'
PUB = '94.100.30.7'


def h(ago):
    d = datetime.fromtimestamp(NOW - ago)
    return d.strftime('%b ') + '%2d' % d.day + d.strftime(' %H:%M:%S') + ' gw.example.net '


print('DNAT')
ok('a netmap\'s prefix takes in the device', isemon.dnat_to_has('192.168.88.0/24', DEV))
ok('...another prefix does not', isemon.dnat_to_has('10.1.0.0/16', DEV), False)

lines = []
ago = 2000
# An Xbox: UDP 3074 out to its peers, the port changed by the NAT.
for i in range(6):
    ago -= 3
    lines.append(h(ago) + 'firewall,info accept forward: in:LAN out:WAN1, '
                 'connection-state:new,snat src-mac 00:11:22:33:44:55, proto UDP, '
                 '%s:3074->81.20.2.%d:3074, NAT (%s:3074->%s:3074)->81.20.2.%d:3074, len 60'
                 % (DEV, i, DEV, PUB, i))
# ...the peers answering from the port it sent to - dropped, nothing forwards it.
for i in range(6):
    ago -= 2
    lines.append(h(ago) + 'firewall,info drop-wan input: in:WAN1 out:(unknown 0), '
                 'connection-state:new src-mac 44:31:92:3E:5E:CA, proto UDP, '
                 '81.20.2.%d:3074->%s:3074, len 60' % (i, PUB))
store = isemon.Storage(isemon.DB_FILE)
hold = {}
store.note_fw_events([dict(r.facts, fw='gw') for r in isemon.ros_parse_lines(lines, hold, NOW)])
d = isemon.Daemon(store)


class Ros:
    def snapshot(self, fw):
        return {'wan': ['ether1 - WAN'],
                'addresses': [{'interface': 'ether1 - WAN', 'address': PUB + '/24'}],
                'rules': [
                    {'table': 'nat', 'chain': 'dstnat', 'action': 'dst-nat', '.id': '*1',
                     'protocol': 'udp', 'dst-port': '3544', 'to-addresses': DEV,
                     'comment': 'teredo'},
                    {'table': 'nat', 'chain': 'dstnat', 'action': 'dst-nat', '.id': '*2',
                     'protocol': 'tcp', 'dst-port': '80,8080-8090', 'to-addresses': DEV,
                     'comment': 'two ranges'},
                    {'table': 'nat', 'chain': 'dstnat', 'action': 'netmap', '.id': '*3',
                     'protocol': 'tcp', 'dst-port': '9000', 'to-addresses': '192.168.88.0/24',
                     'comment': 'netmap'}]}


d.rosapi = Ros()
got = d.fw_dnat(DEV, 24, 'gw')
miss = {(m['proto'], m['port']): m for m in got['missing']}
ok('a UDP peer answering from the port it was sent to is a knock for it', ('udp', 3074) in miss)
ok('...with the peer said', any(w['kind'] == 'peer' for w in miss.get(('udp', 3074), {})
                                .get('why', [])))
rows = sorted((f['proto'], f['public_port'], f.get('public_last')) for f in got['forwards']
              if f.get('rule') == 'two ranges')
ok('a rule of two ranges drawn as both', rows, [('tcp', 80, 80), ('tcp', 8080, 8090)])
ok('a netmap to its prefix is its own rule', '*3' in [r['id'] for r in got['router']['rules']])
xbox = [p for p in got['profiles'] if p['key'] == 'xbox']
ok('seen as an Xbox', bool(xbox))
if xbox:
    st = {(pp['proto'], pp['ports'][0]): pp['state'] for pp in xbox[0]['ports']}
    ok('a port the router forwards to it, unused, is not "missing"', st.get(('udp', 3544)),
       'forwarded')
ok('the profile counts a rule of every port', isemon.Daemon._dnat_profile_port(
    ('tcp', 3074, 3075, 'need', 'x'), {}, {}, lambda *a: [], set(),
    [{'protocol': '', 'ports': []}])['state'], 'forwarded')
ok('...a rule switched off counts for nothing', isemon.Daemon._dnat_profile_port(
    ('tcp', 3074, 3074, 'need', 'x'), {}, {}, lambda *a: [], set(),
    [{'protocol': 'tcp', 'ports': [(3074, 3074)], 'disabled': True}])['state'], 'missing')
ok('the list of devices of the firewall chosen', store.fw_dnat_hosts(NOW - 86400, fw='other'), [])

page = (ROOT / 'web' / 'index.php').read_text()


def js_function(name):
    m = re.search(r'\nfunction %s\(.*?\n}\n' % name, page, re.S)
    return m.group(0) if m else ''


src = js_function('dnSafe') + '\n' + re.search(r'function dnQuote\(.*?\n', page).group(0) + \
    js_function('dnPorts') + js_function('dnatRuleText') + r"""
var $ = function () { return null; };
var d = {ip: '192.168.88.20', out: {public: [{ip: '94.100.30.7'}], wan: ['ether1 - WAN'],
         changed: 0, kept: 1}, router: {dstnat_filter: 'x'}, zone: '', profiles: []};
console.log(JSON.stringify(dnatRuleText(d, [{proto: 'udp', lo: 3074, hi: 3074}], 'routeros')));
"""
r = subprocess.run(['node', '-e', src], capture_output=True, text=True, timeout=60)
text = json.loads(r.stdout or '""')
ok('an interface with a space is quoted for RouterOS', 'in-interface="ether1 - WAN"' in text)
ok('only the newest answer is drawn', 'DN.tok !== tok' in page
   and "if (!$('dn-out') || DN.tok !== tok) return;" in page)
ok('the sign-in page waits only for a key pressed',
   "document.addEventListener('keydown', function () { keyed = true; }, true);" in page)
ok('root is sent what the page showed', "seAsk('fix', {ids: ids, fixes: fixes})" in page)

print('the upgrade')
ok('install.sh says no version in the words of done',
   'upgrade_tell done "$UP_STEPS" "done"' in (ROOT / 'install.sh').read_text())
up = (ROOT / 'deploy' / 'isemon_upgrade.py').read_text()
ok('an upgrade from the console tells the pages', "by='root on the console'" in up
   and "tell('done' if rc == 0 else 'failed'" in up)
ok('stopped before install.sh ran: failed, not running', 'signal.signal(signal.SIGTERM, '
   'stopped_early)' in up)

print('SELinux')
os.environ.update({'ISEMON_STATE': str(folder / 'st'), 'ISEMON_WEB_NO_SERVICES': '1',
                   'ISEMON_ROOT_STATE': str(folder / 'rs')})
sys.path.insert(0, str(ROOT / 'deploy'))
web = importlib.import_module('isemon_web')
g = {'st': 'httpd_t', 'tt': 'postgresql_port_t', 'cls': 'tcp_socket', 'perms': 'name_bind'}
ok('binding another service\'s port is never a rule', bool(web.se_never(g)))
ok('...a free port is left to the port kind', web.se_never(dict(g, tt='unreserved_port_t')), '')
tool = sorted(web.SE_TOOL_DOMAINS)[0]
ok('a program called "isemon" in a tool\'s domain is not isemon\'s', web.se_whose(
    {'st': tool, 'tt': 'mysqld_port_t', 'comm': 'isemon', 'exe': '/tmp/isemon', 'path': '',
     'port': '3306'}, None, set()), False)
helper = (ROOT / 'deploy' / 'isemon_web.py').read_text()
ok('root does only what was confirmed',
   "said.append('%s: changed since it was looked at - look again' % fid)" in helper)
ok('a reload that failed is not put right', 'for fid in reloaded:\n                done.remove(fid)'
   in helper)
ok('the daemon passes what was shown on', "more['fixes'] = " in (ROOT / 'isemon.py').read_text())

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
