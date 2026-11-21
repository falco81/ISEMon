#!/usr/bin/env python3
"""1.10.364: what the bug hunt over the newest parts found, each kept fixed.

- the DNAT analyzer: a reverse name never a command in the rule text, a
  hairpin no public address, an answer come late no knock, a TCP port its
  connections left by no reason, ranges of to-addresses, the router's rules
  to other devices taking their ports, a rule switched off never over one
  that works;
- SELinux: a quoted file name never read as a context, a boolean only of the
  short list, "isemon" in a path no proof;
- the upgrade band: no "done" made up, a click told it waits, the band of
  maintenance not over the upgrade's, the sign-in page not loaded away under
  what is typed;
- the card watch: a check slow for a moment ends no session.

All names and addresses made up.

    ./test/fixes364_hunt.py
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


folder = Path(tempfile.mkdtemp(prefix='isemon-364-'))
for k, v in dict(STATE_DIR=folder, DB_FILE=folder / 'c.db', BACKUP_DIR=folder / 'b',
                 DUMP_DIR=folder / 'd', RUN_DIR=folder, LOG_DIR=folder,
                 CONFIG_FILE=folder / 'config.json', _LOG_PATH=folder / 'c.log',
                 TOKEN_FILE=folder / 'tok').items():
    setattr(isemon, k, v)
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'mikrotik_sync': 0, 'api_port': 18964,
                      'fwlog': 1})
NOW = time.time()
DEV = '192.168.60.20'
PUB = '94.100.20.5'


def h(ago):
    d = datetime.fromtimestamp(NOW - ago)
    return d.strftime('%b ') + '%2d' % d.day + d.strftime(' %H:%M:%S') + ' gw.example.net '


print('DNAT: to-addresses')
ok('a range takes in an address inside it', isemon.dnat_to_has('192.168.60.10-192.168.60.30', DEV))
ok('...not one outside', isemon.dnat_to_has('192.168.60.10-192.168.60.19', DEV), False)
ok('a list of them', isemon.dnat_to_has('10.0.0.1, 192.168.60.20', DEV))
ok('junk is no address', isemon.dnat_to_has('x-y', DEV), False)

lines = []
ago = 2000
# Out to a game server, TCP, the port changed - and UDP to a peer, kept.
for i in range(6):
    ago -= 3
    lines.append(h(ago) + 'firewall,info accept forward: in:LAN out:WAN1, '
                 'connection-state:new,snat src-mac 00:11:22:33:44:55, proto TCP (SYN), '
                 '%s:5100%d->18.20.1.1:443, NAT (%s:5100%d->%s:5100%d)->18.20.1.1:443, len 60'
                 % (DEV, i, DEV, i, PUB, i))
    lines.append(h(ago) + 'firewall,info accept forward: in:LAN out:WAN1, '
                 'connection-state:new,snat src-mac 00:11:22:33:44:55, proto UDP, '
                 '%s:3074->18.20.2.%d:9000, NAT (%s:3074->%s:3074)->18.20.2.%d:9000, len 60'
                 % (DEV, i, DEV, PUB, i))
# Hairpin: to a server inside by the public address, masqueraded to the
# router's inside address - never the way out.
for i in range(5):
    ago -= 3
    lines.append(h(ago) + 'firewall,info accept forward: in:LAN out:LAN, '
                 'connection-state:new,snat src-mac 00:11:22:33:44:55, proto TCP (SYN), '
                 '%s:5200%d->192.168.60.9:443, NAT (%s:5200%d->192.168.60.1:5200%d)->'
                 '192.168.60.9:443, len 60' % (DEV, i, DEV, i, i))
# Late answers from the game server, after the router forgot the connection.
for i in range(6):
    ago -= 2
    lines.append(h(ago) + 'firewall,info drop-wan input: in:WAN1 out:(unknown 0), '
                 'connection-state:invalid src-mac 44:31:92:3E:5E:CA, proto TCP (ACK), '
                 '18.20.1.1:443->%s:5100%d, len 52' % (PUB, i))
# Knocks on the UDP port its connections leave by, from others.
for i in range(4):
    ago -= 2
    lines.append(h(ago) + 'firewall,info drop-wan input: in:WAN1 out:(unknown 0), '
                 'connection-state:new src-mac 44:31:92:3E:5E:CA, proto UDP, '
                 '77.%d.1.1:6000->%s:3074, len 60' % (i, PUB))
# TCP 8080 forwarded to it, and working.
for i in range(3):
    ago -= 2
    lines.append(h(ago) + 'firewall,info accept forward: in:WAN1 out:LAN, connection-state:new,dnat '
                 'src-mac 44:31:92:3E:5E:CA, proto TCP (SYN), 66.%d.1.1:40000->%s:8080, NAT '
                 '66.%d.1.1:40000->(%s:8080->%s:8080), len 60' % (i, DEV, i, PUB, DEV))
# Knocks on 25565, which the router forwards to another device.
for i in range(3):
    ago -= 2
    lines.append(h(ago) + 'firewall,info drop-wan input: in:WAN1 out:(unknown 0), '
                 'connection-state:new src-mac 44:31:92:3E:5E:CA, proto TCP (SYN), '
                 '55.%d.1.1:4000->%s:25565, len 60' % (i, PUB))

store = isemon.Storage(isemon.DB_FILE)
hold = {}
lot = [dict(r.facts, fw='gw') for r in isemon.ros_parse_lines(lines, hold, NOW)]
store.note_fw_events(lot)
d = isemon.Daemon(store)


class Ros:
    def snapshot(self, fw):
        return {'wan': ['WAN1'], 'addresses': [{'interface': 'WAN1', 'address': PUB + '/24'}],
                'rules': [
                    {'table': 'nat', 'chain': 'dstnat', 'action': 'dst-nat', '.id': '*1',
                     'protocol': 'tcp', 'dst-port': '8080', 'to-addresses': DEV,
                     'disabled': 'true', 'comment': 'old one'},
                    {'table': 'nat', 'chain': 'dstnat', 'action': 'dst-nat', '.id': '*2',
                     'protocol': '', 'dst-port': '8080',
                     'to-addresses': '192.168.60.10-192.168.60.30', 'comment': 'the range',
                     'packets': '9'},
                    {'table': 'nat', 'chain': 'dstnat', 'action': 'dst-nat', '.id': '*3',
                     'protocol': 'tcp', 'dst-port': '25560-25570',
                     'to-addresses': '192.168.60.77', 'comment': 'the game server'},
                    {'table': 'nat', 'chain': 'dstnat', 'action': 'dst-nat', '.id': '*4',
                     'protocol': 'udp', 'dst-port': '9999', 'to-addresses': '192.168.60.78',
                     'disabled': 'true'}]}


d.rosapi = Ros()
got = d.fw_dnat(DEV, 24, 'gw')
pubs = [p['ip'] for p in got['out']['public']]
ok('a hairpin is no public address', '192.168.60.1' in pubs, False)
ok('...the real one is', PUB in pubs)
miss = {(m['proto'], m['port']): m for m in got['missing']}
scans = {(m['proto'], m['port']) for m in got['scans']}
ok('late answers to its own connections are no knock',
   any(p in miss or p in scans for p in [('tcp', 51000 + i) for i in range(6)]), False)
ok('the UDP port it leaves by is a reason', ('udp', 3074) in miss
   and any(w['kind'] == 'mapped' for w in miss[('udp', 3074)]['why']))
fwd = {(f['proto'], f['public_port']): f for f in got['forwards']}
ok('a range of to-addresses found as its rule', [r['id'] for r in got['router']['rules']],
   ['*1', '*2'])
ok('a rule switched off is not the state of one that works', fwd[('tcp', 8080)]['state'],
   'working')
ok('...the rule that counts is the one switched on', fwd[('tcp', 8080)]['rule'], 'the range')
ok('...and no "switched off" warning for it',
   any(w['key'] == 'disabled' for w in got['warnings']), False)
ok('a rule with no protocol covers the forward: not listed twice',
   len([f for f in got['forwards'] if f['public_port'] == 8080]), 1)
row = miss.get(('tcp', 25565)) or next((m for m in got['scans'] if m['port'] == 25565), {})
ok('a port the router forwards to another device says so', row.get('elsewhere'),
   ['192.168.60.77'])
ok('...a rule switched off takes nothing', 'elsewhere' in got['router'], False)

page = (ROOT / 'web' / 'index.php').read_text()


def js_function(name):
    m = re.search(r'\nfunction %s\(.*?\n}\n' % name, page, re.S)
    return m.group(0) if m else ''


def node(src):
    r = subprocess.run(['node', '-e', src], capture_output=True, text=True, timeout=60)
    return (r.stdout.strip(), r.stderr.strip()[-400:])


print('DNAT: the rule text')
out, err = node(js_function('dnSafe') + js_function('dnQuote') + js_function('dnPorts') + js_function('dnatRuleText') + r"""
var $ = function (id) { return id === 'dn-name' ? {textContent: 'evil\n/system reset-configuration'} : null; };
var d = {ip: '192.168.60.20', out: {public: [{ip: '94.100.20.5'}], wan: ['ether1"; /x'],
         changed: 0, kept: 1}, router: {dstnat_filter: 'x'}, zone: 'br\nidge', profiles: []};
var all = ['routeros', 'iptables', 'fortigate', 'cisco'].map(function (k) {
  return dnatRuleText(d, [{proto: 'udp;rm', lo: '3074', hi: 3074}], k);
}).join('\n');
console.log(JSON.stringify({reset: /^\/system/m.test(all), quote: all.indexOf('ether1"') >= 0,
  udp: all.indexOf('udp;rm') >= 0, name: all.indexOf('evilsystemreset-configuration') >= 0}));
""")
try:
    said = json.loads(out)
except ValueError:
    said = {'err': err}
ok('a line break in a reverse name is no command of its own', said.get('reset'), False)
ok('...a quote in an interface closes nothing', said.get('quote'), False)
ok('...a protocol is tcp or udp', said.get('udp'), False)
ok('...the name still said, its letters only', said.get('name'), True)
ok('a port forwarded elsewhere is not ticked by itself',
   "m.likely === 'likely' && !(m.elsewhere || []).length" in page)

print('the upgrade band')
sim = r"""
var UPG = {u: null, heard: 0, away: 0, web: false, sawRunning: false, reloading: false,
           timer: null, ended: false, asking: false};
var ended = 0;
function drawUpBand() {} function upgradeTimer() {} function upgradeEnd() { ended++; }
""" + js_function('upgradeHeard') + r"""
var r = {};
upgradeHeard(null, true, '1.10.363');
upgradeHeard({state: 'running', started: 5, id: 'a'}, true, '1.10.363');
upgradeHeard(null, true, '1.10.363');
r.same = [UPG.u, ended];
UPG.u = null; UPG.sawRunning = false;
upgradeHeard({state: 'running', started: 6, id: 'b', version: '1.10.364'}, true, '1.10.363');
upgradeHeard(null, true, '1.10.364');
r.other = [UPG.u && UPG.u.state, ended];
UPG.ended = false; ended = 0; UPG.u = null;
upgradeHeard({state: 'running', started: 7, id: 'c'}, false);
upgradeHeard({state: 'done', started: 7, id: 'c'}, true, '1.10.364');
r.said = ended;
console.log(JSON.stringify(r));
"""
out, err = node(sim)
try:
    r = json.loads(out)
except ValueError:
    r = {'err': err}
ok('no word of the run and the same version: no "done" made up, nothing loaded',
   r.get('same'), [None, 0])
ok('the daemon of another version: done, loaded once', r.get('other'), ['done', 1])
ok('a done said is done', r.get('said'), 1)
ok('the refresh is marked as asked by nobody',
   'if (quietAsk && e && typeof e === \'object\') e.quiet = true;' in page)
ok('a click is told it waits', "if (!(e && e.quiet)) toast('isemon is being upgraded - try "
   "again in a moment.', 'warn');" in page)
ok('the band of maintenance stays hidden while the upgrade runs',
   "band.hidden = !m || !!(typeof UPG === 'object' && UPG.u && UPG.u.state === 'running');"
   in page)
ok('the sign-in page is not loaded away under what is typed',
   'if (away && !typing()) {' in page and 'function typing()' in page)
php = page
ok('a big POST needs a session that is signed in, not only a cookie',
   "$big_who = isemon_whoami();" in php and "!empty($big_who['second'])" in php)

print('SELinux')
os.environ.update({'ISEMON_STATE': str(folder / 'st'), 'ISEMON_WEB_NO_SERVICES': '1',
                   'ISEMON_ROOT_STATE': str(folder / 'rs')})
sys.path.insert(0, str(ROOT / 'deploy'))
web = importlib.import_module('isemon_web')
spoof = ('type=AVC msg=audit(1700000000.100:42): avc:  denied  { write } for  pid=1 '
         'comm="isemon" name="x tcontext=system_u:object_r:etc_t:s0 tclass=dir" dev="dm-0" '
         'scontext=system_u:system_r:unconfined_service_t:s0 '
         'tcontext=system_u:object_r:var_lib_t:s0 tclass=file permissive=0')
g = web.se_parse_avc(spoof)
ok('a quoted file name is never read as the context', (g['tt'], g['cls']), ('var_lib_t', 'file'))
ok('only the short list of booleans', web.SE_GOOD_BOOLEANS,
   ('httpd_can_network_connect', 'httpd_can_network_connect_db'))
ok('"isemon" in a path is no proof the refusal is isemon\'s',
   web.se_whose({'st': 'httpd_t', 'tt': 'tmp_t', 'comm': 'nginx', 'exe': '/usr/sbin/nginx',
                 'path': '/tmp/isemon-x', 'port': ''}, None, set()), False)
ok('a tool of isemon\'s on its port is', web.se_whose(
    {'st': list(web.SE_TOOL_DOMAINS)[0], 'tt': 'x_port_t', 'comm': 'curl', 'exe': '',
     'path': '', 'port': '18964'}, None, {18964}), True)

print('the card watch')
isemon.CONFIG.update({'certlogin': 1, 'certlogin_watch': 'signout', 'directory': 1,
                      'directory_host': 'dc.x', 'directory_base': 'DC=corpnet,DC=loc'})
d.add_user('carda', 'a-long-enough-password-1', 'fulladmin', by='test')
tok = store.new_session('carda', 'fulladmin', '127.0.0.1', 'test', '')
subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
                '-nodes', '-keyout', str(folder / 'c.key'), '-out', str(folder / 'c.pem'),
                '-days', '2', '-subj', '/CN=card'], capture_output=True, check=True)
d.certlogin_watch_mark(tok, (folder / 'c.pem').read_text())
store.session_card(tok, card_ok=time.time())
d.certlogin_alive(tok, (folder / 'c.pem').read_text())
said = d.certlogin_card_gone(tok, 'waiting')
ok('signed out mode: a check slow for a moment ends nothing', (said['watched'], said['gone']),
   (True, False))
ok('...the session is there', bool(d.who(tok)), True)
ok('the page counts grace only in grace', 'CW.out' in page)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
