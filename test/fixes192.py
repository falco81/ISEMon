#!/usr/bin/env python3
"""1.10.192: what a review of 1.10.190 found - bans let go on an OPNsense
or a pfSense without the sync, no API key carried along a redirect, a
firewall changed while it is being read, one change to a pfSense - the
command line for the firewall cards and the published list, and the
quicker paths.

    ./test/fixes192.py
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
folder = tempfile.mkdtemp(prefix='isemon-192-')
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


class Redirect(Quiet):
    def do_GET(self):
        self.send_response(302)
        self.send_header('Location', 'http://127.0.0.1:9/x')
        self.end_headers()
    do_POST = do_GET


redirect_server = serve(Redirect)
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
try:
    print('\nAn API that answers with a redirect')
    try:
        isemon.fw_http('POST', 'https://127.0.0.1:%d/api/x' % redirect_server.server_address[1],
                       {'a': 1}, {'Authorization': 'Basic c2VjcmV0'}, verify=False)
        ok('is refused, the key not carried along', False)
    except RuntimeError as e:
        ok('is refused, the key not carried along', 'redirect' in str(e), True)
    ok('one opener for each way of checking, made once',
       isemon._fw_opener(False) is isemon._fw_opener(False), True)

    print('\nAn OPNsense with the sync off')
    daemon.save_settings({'mikrotik1': 1, 'mikrotik_kind': 'opnsense-api',
                          'mikrotik_opn_host': '127.0.0.1',
                          'mikrotik_opn_port': opn_server.server_address[1],
                          'mikrotik_opn_apikey': 'KEY1', 'mikrotik_opn_apisecret': 'SECRET1',
                          'mikrotik_opn_verify': 0, 'mikrotik_sync': 0}, by='test')
    store.block('45.9.148.9', None, 'for good')
    store.block('198.51.100.7', time.time() + 3600, 'an hour')
    daemon.mikrotik_sync('by hand', fw='mikrotik')
    ok('both went on by hand', sorted(OPN['tables']['isemon_ban']),
       ['198.51.100.7', '45.9.148.9'])
    store.unblock('198.51.100.7')
    store.block('203.0.113.9', None, 'new, and not to be put on by itself')
    daemon.pf_let_go()
    for _ in range(100):
        if '198.51.100.7' not in OPN['tables']['isemon_ban']:
            break
        time.sleep(0.05)
    ok('a ban that ended is taken out of the alias without the sync',
       sorted(OPN['tables']['isemon_ban']), ['45.9.148.9'])
    ok('...and nothing is added by it', '203.0.113.9' in OPN['tables']['isemon_ban'], False)

    print('\nA firewall changed while it is being read')
    real_entries = daemon.mikrotik_entries

    def switching(*a, **k):
        got = real_entries(*a, **k)
        isemon.CONFIG['mikrotik_kind'] = 'mikrotik'
        return got
    daemon.mikrotik_entries = switching
    try:
        daemon.mikrotik_sync('racing', fw='mikrotik')
        ok('nothing is written to the other kind', False)
    except ValueError as e:
        ok('nothing is written to the other kind', 'changed in the settings' in str(e), True)
    daemon.mikrotik_entries = real_entries
    isemon.CONFIG['mikrotik_kind'] = 'opnsense-api'

    print('\nA pfSense: one change for a sync')
    daemon.save_settings({'mikrotik_kind': 'pfsense-api', 'mikrotik_pfa_host': '127.0.0.1',
                          'mikrotik_pfa_port': pfr_server.server_address[1],
                          'mikrotik_pfa_apikey': 'PFKEY', 'mikrotik_pfa_verify': 0}, by='test')
    applies = PFR['applies']
    daemon.mikrotik_sync('one change', fw='mikrotik')
    ok('the removing and the adding are one apply', PFR['applies'] - applies, 1)

    print('\nTaking ours off, one list after the other')
    a = daemon.mikrotik_purge_job('test', 'blocked')
    b = daemon.mikrotik_purge_job('test', 'geo')
    ok('two lists asked for are two jobs', a['id'] != b['id'], True)
    for _ in range(200):
        if a['done'] and b['done']:
            break
        time.sleep(0.05)

    print('\nThe published list, asked from an address that may not fetch it')
    isemon.CONFIG.update({'banfeed': 1, 'banfeed_auth': 'basic', 'banfeed_user': 'fw',
                          'banfeed_password': 'a-long-password-1', 'banfeed_from': '10.0.0.0/8'})
    wrong = daemon.banfeed_serve('', 'plain', client='192.0.2.1', user='fw', password='x')[0]
    right = daemon.banfeed_serve('', 'plain', client='192.0.2.1', user='fw',
                                 password='a-long-password-1')[0]
    ok('says nothing about whether the password was right', (wrong, right), (403, 403))
    ok('...and lets the one that may in', daemon.banfeed_serve(
        '', 'plain', client='10.1.1.1', user='fw', password='a-long-password-1')[0], 200)
    isemon.CONFIG.update({'banfeed': 0, 'banfeed_auth': 'none', 'banfeed_from': ''})

    print('\nThe quicker paths')
    ok('a list that shows no number does not wait for the count',
       (source.count('fw_rows(count=False, '), "or not count:" in source), (3, True))
    ok('the lines without a page are looked for within the window only',
       "'WHERE area IS NULL AND ts >= ?'" in source, True)
    ok('the names of addresses are not waited on to reach the disk',
       source.count('self.commit_lazily(db)') + source.count('store.commit_lazily(db)') >= 4,
       True)
    ok('the header is not every firewall read out of the database each time',
       "self.held('fw-marks/%d' % self._serial, 5," in source, True)
    ok('the Traffic overview, unchanged, is not sent again',
       ("said['same'] = True" in source, "'&ready_at=' + held" in page,
        'function tChartNote(d)' in page), (True, True, True))

    print('\nThe command line')
    parser_text = source[source.index("act.add_argument('--fw-test'"):]
    ok('the firewall cards and the published list are there',
       all(x in parser_text for x in ("'--fw-test'", "'--fw-key'", "'--fw-kind'",
                                      "'--banfeed'")), True)
    ok('...and wired', ('(bool(args.fw_test), cmd_fw_test)' in source,
                        '(bool(args.banfeed), cmd_banfeed)' in source), (True, True))

    print('\nThe page')
    ok('a firewall shown as a kind not saved yet is not tried',
       "id('test').disabled = !wall.host || kind !== saved;" in page, True)
    ok('a setting asked before the settings are in is nothing, not a throw',
       '((SETTINGS && SETTINGS.settings) || [])' in page, True)
    ok('the pair is drawn again when a kind is chosen',
       "drawFirewall('mt2', 'mikrotik2', MT_LAST);\n      drawPairState(MT_LAST);" in page, True)
    ok('the published-list guide names the alias as the settings do',
       ('isemon_bans' in page), False)
finally:
    isemon.ssh_run = real_ssh
    for one in (opn_server, pfr_server, redirect_server):
        one.shutdown()

shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
