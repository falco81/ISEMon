#!/usr/bin/env python3
"""1.10.190: an OPNsense or a pfSense as either firewall - through its API
or over ssh with pfctl - beside the Mikrotik as it always was; the published
ban list in the shape those two fetch; and settings of each kind kept while
another kind is in use.

    ./test/fixes190.py
"""
import http.server
import ipaddress
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
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


source = (HERE.parent / 'isemon.py').read_text(encoding='utf-8')
page = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')
folder = tempfile.mkdtemp(prefix='isemon-190-')
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
isemon.CONFIG.update({'geo': 0, 'mikrotik_sync': 0, 'blacklist': 1})

# ---------------------------------------------------------------------------
# A certificate for the two make-believe firewalls' HTTPS
# ---------------------------------------------------------------------------
cert, key = Path(folder) / 'c.pem', Path(folder) / 'k.pem'
subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
                '-subj', '/CN=localhost', '-keyout', str(key), '-out', str(cert)],
               check=True, capture_output=True)


def serve(handler):
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class Quiet(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def answer(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        n = int(self.headers.get('Content-Length') or 0)
        return json.loads(self.rfile.read(n).decode() or '{}') if n else {}


# An OPNsense: aliases of the type External, and alias_util.
OPN = {'tables': {'isemon_ban': set(), 'isemon_geo': set()}, 'adds': 0, 'lists': 0}
OPN_AUTH = 'Basic ' + __import__('base64').b64encode(b'KEY1:SECRET1').decode()
OPN_LOCK = threading.Lock()


class Opnsense(Quiet):
    def go(self, method):
        if self.headers.get('Authorization') != OPN_AUTH:
            return self.answer(401, {'status': 401, 'message': 'Authentication Failed'})
        url = urllib.parse.urlparse(self.path)
        parts = url.path.strip('/').split('/')
        if parts[:4] == ['api', 'firewall', 'alias', 'getAliasUUID']:
            return self.answer(200, {'uuid': 'u-' + parts[4]} if parts[4] in OPN['tables']
                               else [])
        if parts[:3] != ['api', 'firewall', 'alias_util'] or len(parts) != 5:
            return self.answer(404, {'errorMessage': 'Endpoint not found'})
        what, table = parts[3], parts[4]
        with OPN_LOCK:
            if table not in OPN['tables']:
                return self.answer(200, {'status': 'failed'})
            held = OPN['tables'][table]
            if what == 'list' and method == 'GET':
                OPN['lists'] += 1
                ask = urllib.parse.parse_qs(url.query)
                page_n = int(ask.get('current', ['1'])[0])
                rows_n = int(ask.get('rowCount', ['10'])[0])
                every = sorted(held)
                rows = every[(page_n - 1) * rows_n:page_n * rows_n]
                return self.answer(200, {'total': len(every), 'rowCount': len(rows),
                                         'current': page_n, 'rows': [{'ip': r} for r in rows]})
            if method != 'POST':
                return self.answer(405, {})
            said = self.body()
            if what == 'add':
                OPN['adds'] += 1
                held.add(isemon.same_address(said['address']))
            elif what == 'delete':
                held.discard(isemon.same_address(said['address']))
            elif what == 'flush':
                held.clear()
            else:
                return self.answer(404, {})
        return self.answer(200, {'status': 'done'})

    def do_GET(self):
        self.go('GET')

    def do_POST(self):
        self.go('POST')


# A pfSense with the REST API package: aliases of the type Network.
PFR = {'aliases': [{'id': 0, 'name': 'isemon_ban', 'type': 'network', 'address': ['192.0.2.1'],
                    'detail': ['placeholder']},
                   {'id': 1, 'name': 'isemon_geo', 'type': 'network', 'address': [],
                    'detail': []}],
       'applies': 0, 'patches': 0}


class Pfrest(Quiet):
    def ok_key(self):
        if self.headers.get('X-API-Key') != 'PFKEY':
            self.answer(401, {'code': 401, 'status': 'unauthorized', 'message': 'no'})
            return False
        return True

    def do_GET(self):
        if not self.ok_key():
            return
        if self.path.startswith('/api/v2/firewall/aliases'):
            return self.answer(200, {'code': 200, 'status': 'ok', 'data': PFR['aliases']})
        self.answer(404, {'code': 404})

    def do_PATCH(self):
        if not self.ok_key():
            return
        said = self.body()
        for row in PFR['aliases']:
            if row['id'] == said['id']:
                row['address'] = list(said['address'])
                row['detail'] = list(said.get('detail') or [])
                PFR['patches'] += 1
                return self.answer(200, {'code': 200, 'status': 'ok', 'data': row})
        self.answer(404, {'code': 404})

    def do_POST(self):
        if not self.ok_key():
            return
        if self.path == '/api/v2/firewall/apply':
            PFR['applies'] += 1
            return self.answer(200, {'code': 200, 'status': 'ok', 'data': {}})
        self.answer(404, {'code': 404})


opn_server = serve(Opnsense)
pfr_server = serve(Pfrest)

# A firewall over ssh that only runs pfctl.
PFCTL = {}
SSH_SEEN = []


def fake_ssh(cfg, host, command):
    SSH_SEEN.append((host, dict(cfg), command))
    tables = PFCTL.setdefault(host, {'isemon_ban': set(), 'isemon_geo': set()})
    if command.strip() == 'hostname':
        return 'fw-%s\n' % host
    words = command.split()
    if '2>&1' in words:
        return 'not a Bourne shell: 2>&1 was read as an address\n'
    if words[:2] == ['sudo', '-n']:
        words = words[2:]
    if words[0] != '/sbin/pfctl' or words[1] != '-t' or words[3] != '-T':
        return 'sh: %s: not found\n' % words[0]
    table, what, rest = words[2], words[4], words[5:]
    if table not in tables:
        # As ssh_run says it: pfctl exits with a fault and says why on stderr.
        raise RuntimeError('pfctl: Table does not exist.')
    if what == 'show':
        return ''.join('   %s\n' % one for one in sorted(tables[table]))
    if what == 'add':
        tables[table].update(isemon.same_address(x) for x in rest)
        return '%d/%d addresses added.\n' % (len(rest), len(rest))
    if what == 'delete':
        for x in rest:
            tables[table].discard(isemon.same_address(x))
        return '%d/%d addresses deleted.\n' % (len(rest), len(rest))
    if what == 'flush':
        n = len(tables[table])
        tables[table].clear()
        return '%d addresses deleted.\n' % n
    return 'pfctl: unknown command\n'


real_ssh = isemon.ssh_run
isemon.ssh_run = fake_ssh

store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)

try:
    print('\nThe kinds and their settings')
    ok('every kind is a choice for both firewalls',
       (daemon.TUNABLE['mikrotik_kind'], daemon.TUNABLE['mikrotik2_kind']),
       (isemon.FW_KINDS, isemon.FW_KINDS))
    ok('a Mikrotik unless said otherwise', isemon.fw_kind('mikrotik'), 'mikrotik')
    ok('a Mikrotik’s settings keep the names they had',
       [isemon.fw_conf('mikrotik', 'host'), isemon.fw_conf('mikrotik2', 'key')],
       ['mikrotik_host', 'mikrotik2_key'])
    ok('another kind’s are its own',
       [isemon.fw_conf('mikrotik', 'host', 'opnsense-api'),
        isemon.fw_conf('mikrotik2', 'key', 'pfsense-ssh')],
       ['mikrotik_opn_host', 'mikrotik2_pfssh_key'])
    ok('every new setting has a name, words and a range',
       [k for k in isemon.DEFAULTS
        if (k.endswith('_kind') or k.startswith('pf_') or '_opn' in k or '_pf' in k)
        and not (k in daemon.TUNABLE and k in daemon.NAMES and k in daemon.SAYS)], [])
    ok('the secrets of the new kinds are secrets',
       all(k in isemon.SECRET_KEYS for k in ('mikrotik_opn_apikey', 'mikrotik_opn_apisecret',
                                             'mikrotik2_pfa_apikey', 'mikrotik_opnssh_password',
                                             'mikrotik2_pfssh_password')), True)

    def refused(key, value):
        try:
            isemon.check_setting(key, value)
            return False
        except ValueError:
            return True
    ok('an alias name a pf table would not take is refused',
       (refused('pf_list', 'isemon-bans'), refused('pf_list', 'x' * 32),
        refused('pf_list', 'isemon_bans')), (True, True, False))
    ok('an ssh host that would be an option is refused for the new kinds too',
       (refused('mikrotik_opnssh_host', '-oProxyCommand=x'),
        refused('mikrotik2_pfssh_user', '-x'), refused('mikrotik_opn_host', 'fw.example.org')),
       (True, True, False))
    try:
        isemon.check_settings_together({'pf_list': 'same', 'pf_geolist': 'same'})
        ok('the two aliases may not share a name', False)
    except ValueError:
        ok('the two aliases may not share a name', True)

    print('\nSwitching a firewall to another kind and back')
    daemon.save_settings({'mikrotik1': 1, 'mikrotik_host': '10.1.1.1', 'mikrotik_user': 'mt',
                          'mikrotik_auth': 'password', 'mikrotik_password': 'mt-password-1'},
                         by='test')
    store.set_meta('mikrotik_key', 'MIKROTIK-PRIVATE')
    daemon.save_settings({'mikrotik_kind': 'opnsense-api', 'mikrotik_opn_host': '127.0.0.1',
                          'mikrotik_opn_port': opn_server.server_address[1],
                          'mikrotik_opn_apikey': 'KEY1', 'mikrotik_opn_apisecret': 'SECRET1',
                          'mikrotik_opn_verify': 0}, by='test')
    ok('the firewall is an OPNsense now', isemon.fw_kind('mikrotik'), 'opnsense-api')
    ok('...and is ready, with its own list', (daemon.mikrotik_ready('mikrotik'),
                                               daemon.fw_list_name('mikrotik')),
       (True, 'isemon_ban'))
    ok('the Mikrotik’s address, account, password and key are all still there',
       (isemon.CONFIG['mikrotik_host'], isemon.CONFIG['mikrotik_user'],
        isemon.CONFIG['mikrotik_password'], store.get_meta('mikrotik_key')),
       ('10.1.1.1', 'mt', 'mt-password-1', 'MIKROTIK-PRIVATE'))
    ok('...and the change is said', 'is now %s rather than %s' in source, True)

    print('\nAn OPNsense, through its API')
    store.block('45.9.148.9', None, 'for good')
    store.block('81.200.10.0/24', None, 'a street')
    store.block('2a01:430:17::5', time.time() + 3600, 'an hour')
    ok('trying it names its aliases', daemon.mikrotik_identity('mikrotik').startswith(
        'OPNsense at https://127.0.0.1:%d - isemon_ban: 0' % opn_server.server_address[1]),
       True)
    said = daemon.mikrotik_sync('a test', fw='mikrotik')
    ok('three went on', (said['added'], said['removed']), (3, 0))
    ok('...and the alias holds exactly them', sorted(OPN['tables']['isemon_ban']),
       ['2a01:430:17::5', '45.9.148.9', '81.200.10.0/24'])
    said = daemon.mikrotik_sync('again', fw='mikrotik')
    ok('a second sync sends nothing', (said['added'], said['removed']), (0, 0))
    OPN['tables']['isemon_ban'].add('10.66.66.66')
    store.unblock('45.9.148.9')
    said = daemon.mikrotik_sync('after an unban', fw='mikrotik')
    ok('what is let go comes off, and so does anything else in the alias',
       (said['removed'], sorted(OPN['tables']['isemon_ban'])),
       (2, ['2a01:430:17::5', '81.200.10.0/24']))
    OPN['tables']['isemon_ban'].clear()                     # the OPNsense restarted
    said = daemon.mikrotik_sync('after a restart', fw='mikrotik')
    ok('an alias emptied by a restart is filled again', said['added'], 2)
    seen = store.meta_json('mikrotik_seen', {})
    ok('what it carries is written down for the pages', sorted(seen.get('ours') or []),
       ['2a01:430:17::5', '81.200.10.0/24'])
    pic = daemon.router_picture()
    ok('the router page reads it', (pic['list'], len(pic['carrying']), pic['firewalls'][0]['kind']),
       ('isemon_ban', 2, 'opnsense-api'))
    isemon.CONFIG['mikrotik_opn_apisecret'] = 'WRONG'
    try:
        daemon.mikrotik_identity('mikrotik')
        ok('a wrong secret is said, not swallowed', False)
    except Exception as e:
        ok('a wrong secret is said, not swallowed', 'HTTP 401' in str(e), True)
    isemon.CONFIG['mikrotik_opn_apisecret'] = 'SECRET1'
    isemon.CONFIG['mikrotik_opn_verify'] = 1
    try:
        daemon.mikrotik_identity('mikrotik')
        ok('a certificate this machine does not trust is refused while checked', False)
    except Exception as e:
        ok('a certificate this machine does not trust is refused while checked',
           'certificate' in str(e), True)
    isemon.CONFIG['mikrotik_opn_verify'] = 0
    isemon.CONFIG['pf_list'] = 'no_such_alias'
    try:
        daemon.mikrotik_identity('mikrotik')
        ok('a missing alias is named', False)
    except Exception as e:
        ok('a missing alias is named', 'no alias called no_such_alias' in str(e), True)
    isemon.CONFIG['pf_list'] = 'isemon_ban'

    print('\nThe country list on it')
    rows = []
    for i in range(300):
        n = i * 2
        lo = ipaddress.ip_address('81.%d.%d.0' % (n // 256, n % 256)).packed
        hi = ipaddress.ip_address('81.%d.%d.255' % (n // 256, n % 256)).packed
        rows.append((lo, hi, 4, 'CZ'))
    net = ipaddress.ip_network('2a02:100::/32')
    rows.append((net.network_address.packed, net.broadcast_address.packed, 6, 'CZ'))
    store.put_geo(rows)
    daemon._geo_any = True
    isemon.CONFIG.update({'geolist': 1, 'geolist_countries': 'CZ'})
    ok('ready with the alias name of its kind', daemon.geolist_ready(), True)
    said = daemon.geolist_sync('a test', fw='mikrotik')
    ok('every range went on', (said['added'], len(OPN['tables']['isemon_geo'])), (301, 301))
    ok('...counted per family', daemon.geolist_count('mikrotik'), {'v4': 300, 'v6': 1})
    adds = OPN['adds']
    said = daemon.geolist_sync('again', fw='mikrotik')
    ok('filled again, only the difference is sent', OPN['adds'] - adds, 0)
    ok('...and the ban list was not touched', sorted(OPN['tables']['isemon_ban']),
       ['2a01:430:17::5', '81.200.10.0/24'])

    print('\nTaking ours off it')
    got = daemon.mikrotik_purge('both')
    ok('both aliases emptied', (len(OPN['tables']['isemon_ban']),
                                len(OPN['tables']['isemon_geo'])), (0, 0))
    ok('...and said', sorted(v['gone'] for v in got['taken'].values()), [2, 301])
    daemon.mikrotik_sync('back', fw='mikrotik')

    print('\nNo country alias, the country list off')
    isemon.CONFIG['geolist'] = 0
    del OPN['tables']['isemon_geo']
    daemon.mikrotik_sync('back again', fw='mikrotik')
    got = daemon.mikrotik_purge('both')
    ok('taking ours off empties the ban alias and does not fail on the missing one',
       (len(OPN['tables']['isemon_ban']), sorted(v['gone'] for v in got['taken'].values())),
       (0, [2]))
    OPN['tables']['isemon_geo'] = set()
    isemon.CONFIG['geolist'] = 1
    daemon.mikrotik_sync('back', fw='mikrotik')

    print('\nThe blacklist switched off')
    owed = daemon.blacklist_clear_routers(['mikrotik'])
    ok('the alias is emptied, nothing owed', (owed, len(OPN['tables']['isemon_ban'])), ([], 0))

    print('\nThe second firewall: a pfSense over ssh, with sudo')
    daemon.save_settings({'mikrotik2': 1, 'mikrotik2_kind': 'pfsense-ssh',
                          'mikrotik2_pfssh_host': '10.2.2.2', 'mikrotik2_pfssh_user': 'admin',
                          'mikrotik2_pfssh_sudo': 1}, by='test')
    store.set_meta('mikrotik2_pfssh_key', 'PF-PRIVATE')
    ok('both are written to now', daemon.firewalls(), ['mikrotik', 'mikrotik2'])
    got = daemon.mikrotik_sync_all('the pair')
    ok('both carry the same', (sorted(OPN['tables']['isemon_ban']),
                               sorted(PFCTL['10.2.2.2']['isemon_ban'])),
       (['2a01:430:17::5', '81.200.10.0/24'], ['2a01:430:17::5', '81.200.10.0/24']))
    last = SSH_SEEN[-1]
    ok('over ssh with its own account, its own key, through sudo',
       (last[0], last[1]['ssh_user'], last[1]['ssh_key'], last[2].startswith('sudo -n /sbin/pfctl')),
       ('10.2.2.2', 'admin', 'PF-PRIVATE', True))
    ok('the pair agree', daemon.firewall_marks()['agree'], True)
    ok('trying it names it and its table',
       daemon.mikrotik_identity('mikrotik2').startswith('name: fw-10.2.2.2 - isemon_ban: 2'), True)
    PFCTL['10.2.2.2']['isemon_ban'].clear()                    # a filter reload
    got = daemon.mikrotik_sync_all('after a reload')
    ok('what a filter reload took out is put back', got['firewalls']['mikrotik2']['added'], 2)
    del PFCTL['10.2.2.2']['isemon_geo']
    try:
        daemon.geolist_sync('no table', fw='mikrotik2')
        ok('a table that is not there is said', False)
    except Exception as e:
        ok('a table that is not there is said', 'Table does not exist' in str(e), True)
    PFCTL['10.2.2.2']['isemon_geo'] = set()
    said = daemon.geolist_sync_all('both')
    ok('the country list on both', (len(OPN['tables']['isemon_geo']),
                                    len(PFCTL['10.2.2.2']['isemon_geo'])), (301, 301))

    print('\nA pfSense through the REST API package')
    daemon.save_settings({'mikrotik2_kind': 'pfsense-api', 'mikrotik2_pfa_host': '127.0.0.1',
                          'mikrotik2_pfa_port': pfr_server.server_address[1],
                          'mikrotik2_pfa_apikey': 'PFKEY', 'mikrotik2_pfa_verify': 0}, by='test')
    ok('the pfSense over ssh is kept for switching back',
       (isemon.CONFIG['mikrotik2_pfssh_host'], store.get_meta('mikrotik2_pfssh_key')),
       ('10.2.2.2', 'PF-PRIVATE'))
    said = daemon.mikrotik_sync('a test', fw='mikrotik2')
    ban = [a for a in PFR['aliases'] if a['name'] == 'isemon_ban'][0]
    ok('the whole alias is sent at once, the placeholder gone',
       (sorted(ban['address']), said['added'], said['removed']),
       (['2a01:430:17::5', '81.200.10.0/24'], 2, 1))
    ok('...and applied', PFR['applies'] >= 1, True)
    patches = PFR['patches']
    daemon.mikrotik_sync('again', fw='mikrotik2')
    ok('nothing changed is nothing sent', PFR['patches'], patches)
    patches = PFR['patches']
    said = daemon.geolist_sync('a test', fw='mikrotik2')
    ok('a country list is one change, not one per range',
       (PFR['patches'] - patches, len([a for a in PFR['aliases']
                                       if a['name'] == 'isemon_geo'][0]['address'])), (1, 301))
    ok('trying it names the alias and its type',
       daemon.mikrotik_identity('mikrotik2').startswith('pfSense at https://127.0.0.1:%d - '
                                                         'isemon_ban (network): 2'
                                                         % pfr_server.server_address[1]), True)

    print('\nAnd back to the Mikrotik')
    daemon.save_settings({'mikrotik_kind': 'mikrotik', 'mikrotik2': 0}, by='test')
    ok('everything it had is in use again',
       (isemon.fw_kind('mikrotik'), daemon.fw_list_name('mikrotik'),
        daemon.mikrotik_cfg('mikrotik')['ssh_user'], daemon.mikrotik_cfg('mikrotik')['ssh_key'],
        daemon.mikrotik_cfg('mikrotik')['ssh_password']),
       ('mikrotik', 'isemon', 'mt', 'MIKROTIK-PRIVATE', 'mt-password-1'))
    ok('...and the OPNsense’s settings are still there for another day',
       (isemon.CONFIG['mikrotik_opn_host'], isemon.CONFIG['mikrotik_opn_apikey']),
       ('127.0.0.1', 'KEY1'))
    ok('a Mikrotik is still asked the RouterOS way',
       'firewall address-list' in source and "fw_conf(fw, 'host')" in source, True)

    print('\nA renamed alias is emptied under its old name')
    daemon.save_settings({'mikrotik_kind': 'opnsense-api'}, by='test')
    daemon.mikrotik_sync('before the rename', fw='mikrotik')
    OPN['tables']['isemon_new'] = set()
    daemon.save_settings({'pf_list': 'isemon_new'}, by='test')
    for _ in range(100):
        if not OPN['tables']['isemon_ban']:
            break
        time.sleep(0.05)
    ok('the old one is emptied', len(OPN['tables']['isemon_ban']), 0)
    daemon.mikrotik_sync('after the rename', fw='mikrotik')
    ok('...and the new one filled', len(OPN['tables']['isemon_new']), 2)
    daemon.save_settings({'mikrotik_kind': 'mikrotik', 'pf_list': 'isemon_ban'}, by='test')

    print('\nThe published list for an OPNsense and a pfSense')
    ok('two more shapes', ('opnsense' in isemon.BANFEED_FORMATS,
                           'pfsense' in isemon.BANFEED_FORMATS), (True, True))
    daemon._banfeed_cache = {}
    body, n = daemon.banfeed_body('opnsense')
    ok('one address or network a line, nothing else', body.splitlines(),
       ['81.200.10.0/24', '2a01:430:17::5'])
    ok('...the same for a pfSense', daemon.banfeed_body('pfsense')[0], body)
    ok('the page shows how to set each up, behind the guide button (1.10.192)',
       ('opnsense: guideOpnsenseFeed' in page, 'pfsense: guidePfsenseFeed' in page,
        "(now === 'opnsense' || now === 'pfsense') && changed" in page), (True, True, False))

    print('\nA complete export')
    ok('carries the ssh keys of every kind', all(k in isemon.FW_OTHER_KEYS for k in (
        'mikrotik_opnssh_key', 'mikrotik2_pfssh_public')) and 'FW_OTHER_KEYS}' in source, True)

    print('\nThe page')
    ok('a kind’s settings are shown only while it is chosen',
       ('function fwFieldShown(key)' in page, "item.style.display = shown ? '' : 'none'" in page),
       (True, True))
    ok('every new setting is on a pane',
       [k for k in isemon.DEFAULTS if (k.endswith('_kind') or k.startswith('pf_')
                                       or '_opn' in k or '_pf' in k) and "'%s'" % k not in page],
       [])
    ok('each kind has a guide of its own', all(g in page for g in (
        'function guideFwMikrotik', 'function guideFwOpnApi', 'function guideFwPfrest',
        'function guideFwPfctl')), True)
    ok('the key buttons say which kind’s key',
       (page.count('kind: kindNow()'), "'&kind=' + encodeURIComponent(kindNow())" in page),
       (3, True))
finally:
    isemon.ssh_run = real_ssh
    opn_server.shutdown()
    pfr_server.shutdown()

shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
