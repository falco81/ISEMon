#!/usr/bin/env python3
"""1.10.268: Settings → Proxy, as otp 1.0.166 - 1.0.172 has it, for one server.

A fake HTTP proxy runs here, in the process, on a port of its own: CONNECT
for HTTPS (a tunnel to a TLS server of the test's, whatever name was asked)
and an absolute address for plain HTTP, both only with the right user name
and password (Basic, 407 otherwise). The TLS server's certificate is signed by
a root of the test's own, trusted through SSL_CERT_FILE.

What is checked:
  * off by default - nothing goes through it, an installation that never
    switches it on asks the web as it did;
  * on: the look for new versions (Upgrades.online_get), a request to the
    ACME CA and a list's download go through it, with Proxy-Authorization,
    the server at the end never seeing it;
  * a name, a .domain and a net in proxy_no go straight - a redirect to one
    too, without the password;
  * the password sealed in the database, never in the log, the events or
    config.json;
  * Try it: always tried, the way and each step with its time, errors in
    words; through the API, a full administrator's alone;
  * root's helper: the update's environment has the proxy (a fake dnf
    records it), its file 0600 and gone after, never on a command line;
  * the settings checked;
  * isemon --proxy-test [URL], and the console's item.

    ./test/fixes268_proxy.py
"""
import base64
import importlib.util
import io
import json
import os
import random
import re
import select
import socket
import socketserver
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

for k in list(os.environ):
    if k.lower() in ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy'):
        os.environ.pop(k)

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))

PASS = FAIL = 0
PX_PORT = 20700 + random.randint(0, 90)
API_PORT = PX_PORT + 100
USER, PW = 'squid', 'Pr0xy-S3cret!word@268'


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


def wait_for(fn, secs=20):
    end = time.time() + secs
    while time.time() < end:
        try:
            if fn():
                return True
        except Exception:                               # noqa: BLE001
            pass
        time.sleep(0.1)
    return False


def sh(args):
    return subprocess.run(args, capture_output=True)


work = Path(tempfile.mkdtemp(prefix='isemon-268-'))
state = work / 'state'
(state / 'web').mkdir(parents=True)

# ---- a root of the test's own, and the certificate of every name asked --------------
NAMES = ['upgrades.example.test', 'acme.example.test', 'lists.example.test', 'localhost',
         'download.db-ip.com', 'standards-oui.ieee.org']
for args in (
        ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '30', '-subj', '/CN=Proxy Test Root',
         '-keyout', str(work / 'root.key'), '-out', str(work / 'root.pem'),
         '-addext', 'basicConstraints=critical,CA:TRUE',
         '-addext', 'keyUsage=critical,keyCertSign,cRLSign'],
        ['req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=upgrades.example.test',
         '-keyout', str(work / 'srv.key'), '-out', str(work / 'srv.csr')]):
    assert sh(['openssl'] + args).returncode == 0, args
(work / 'srv.ext').write_text('subjectAltName=%s,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n'
                              % ','.join('DNS:' + n for n in NAMES))
assert sh(['openssl', 'x509', '-req', '-in', str(work / 'srv.csr'), '-CA', str(work / 'root.pem'),
           '-CAkey', str(work / 'root.key'), '-CAcreateserial', '-days', '30',
           '-extfile', str(work / 'srv.ext'), '-out', str(work / 'srv.pem')]).returncode == 0
os.environ['SSL_CERT_FILE'] = str(work / 'root.pem')
os.environ.pop('SSL_CERT_DIR', None)


# ---- the servers at the end: TLS, and plain HTTP ----------------------------------------
SEEN = []          # (scheme, method, Host, path, Proxy-Authorization or None)


class Origin(BaseHTTPRequestHandler):
    scheme = 'https'

    def log_message(self, *a):
        pass

    def answer(self, body=True):
        SEEN.append((self.scheme, self.command, self.headers.get('Host'), self.path,
                     self.headers.get('Proxy-Authorization')))
        if self.path.startswith('/redirect'):
            self.send_response(302)
            self.send_header('Location', 'https://localhost:%d/landed' % TLS_PORT)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        if self.path.startswith('/directory'):
            data = json.dumps({'newNonce': 'https://acme.example.test/nonce'}).encode()
        elif self.path.endswith('.netset'):
            data = b'# a list\n192.0.2.0/24\n198.51.100.7\n'
        else:
            data = b'hello from %s' % self.path.encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        if body:
            self.wfile.write(data)

    def do_GET(self):
        self.answer()

    def do_HEAD(self):
        self.answer(False)


class PlainOrigin(Origin):
    scheme = 'http'


tls_srv = ThreadingHTTPServer(('127.0.0.1', 0), Origin)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(str(work / 'srv.pem'), str(work / 'srv.key'))
tls_srv.socket = ctx.wrap_socket(tls_srv.socket, server_side=True)
TLS_PORT = tls_srv.server_address[1]
http_srv = ThreadingHTTPServer(('127.0.0.1', 0), PlainOrigin)
HTTP_PORT = http_srv.server_address[1]
for s_ in (tls_srv, http_srv):
    threading.Thread(target=s_.serve_forever, daemon=True).start()


# ---- the fake proxy ---------------------------------------------------------------------
PROXIED = []       # (method, target, the Proxy-Authorization it was given)
WANT_AUTH = 'Basic ' + base64.b64encode(('%s:%s' % (USER, PW)).encode()).decode()


class Proxy(socketserver.BaseRequestHandler):
    def handle(self):
        c = self.request
        c.settimeout(10)
        data = b''
        while b'\r\n\r\n' not in data:
            got = c.recv(4096)
            if not got:
                return
            data += got
        head, _, rest = data.partition(b'\r\n\r\n')
        lines = head.decode('latin-1').split('\r\n')
        method, target = lines[0].split(' ')[:2]
        hdrs = {}
        for ln in lines[1:]:
            k, _, v = ln.partition(':')
            hdrs[k.strip().lower()] = v.strip()
        auth = hdrs.get('proxy-authorization')
        PROXIED.append((method, target, auth))
        if auth != WANT_AUTH:
            c.sendall(b'HTTP/1.1 407 Proxy Authentication Required\r\n'
                      b'Proxy-Authenticate: Basic realm="test"\r\nContent-Length: 0\r\n'
                      b'Connection: close\r\n\r\n')
            return
        if method == 'CONNECT':
            up = socket.create_connection(('127.0.0.1', TLS_PORT), timeout=10)
            c.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
            if rest:
                up.sendall(rest)
            pipes = [c, up]
            while True:
                r, _, _ = select.select(pipes, [], [], 10)
                if not r:
                    break
                done = False
                for s in r:
                    try:
                        chunk = s.recv(65536)
                    except OSError:
                        chunk = b''
                    if not chunk:
                        done = True
                        break
                    (up if s is c else c).sendall(chunk)
                if done:
                    break
            up.close()
            return
        # plain HTTP: an absolute address, sent on as a path
        u = urllib.parse.urlsplit(target)
        out = [('%s %s HTTP/1.1' % (method, (u.path or '/') + ('?' + u.query if u.query else '')))]
        for ln in lines[1:]:
            if ln.lower().startswith(('proxy-authorization', 'proxy-connection', 'connection')):
                continue
            out.append(ln)
        out.append('Connection: close')
        up = socket.create_connection(('127.0.0.1', HTTP_PORT), timeout=10)
        up.sendall(('\r\n'.join(out) + '\r\n\r\n').encode('latin-1') + rest)
        while True:
            chunk = up.recv(65536)
            if not chunk:
                break
            c.sendall(chunk)
        up.close()


class PxServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


px_srv = PxServer(('127.0.0.1', PX_PORT), Proxy)
threading.Thread(target=px_srv.serve_forever, daemon=True).start()

# ---- the daemon ------------------------------------------------------------------------
PM = work / 'fake-dnf'
PM_LOG = work / 'pm-env.jsonl'
LOCK = work / 'osup.lock'
OSUP_PROXY = work / 'osup-proxy.json'
PM.write_text('''#!%s
import json, os, sys
with open(%r, 'a') as f:
    f.write(json.dumps({'argv': sys.argv, 'env': {k: v for k, v in os.environ.items()
                        if 'proxy' in k.lower()},
                        'file_there': os.path.exists(%r)}) + '\\n')
if sys.argv[1] == 'check':
    print('openssl.x86_64 3.2.2-6.el9 security')
elif sys.argv[1] == 'needs-restart':
    sys.exit(0)
''' % (sys.executable, str(PM_LOG), str(OSUP_PROXY)))
PM.chmod(0o755)
os.environ.update(ISEMON_WEB_HELPER='1')
HELPER_ENV = dict(os.environ, ISEMON_STATE=str(state), ISEMON_WEB_NO_SERVICES='1',
                  ISEMON_OSUP_PM=str(PM), ISEMON_OSUP_LOCK=str(LOCK),
                  ISEMON_OSUP_PROXY=str(OSUP_PROXY), ISEMON_RSYSLOG=str(work / 'none'),
                  ISEMON_NGINX_CONF=str(work / 'none.conf'))


def run_helper(*args):
    return subprocess.run([sys.executable, '-I', str(ROOT / 'deploy' / 'isemon_web.py')] +
                          list(args), capture_output=True, text=True, env=HELPER_ENV)


import isemon                                        # noqa: E402

isemon.STATE_DIR = state
isemon.DB_FILE = state / 'd.db'
isemon.BACKUP_DIR = state / 'backups'
isemon.DUMP_DIR = state / 'dumps'
isemon.RUN_DIR = state
isemon.LOG_DIR = state
isemon.CONFIG_FILE = state / 'config.json'
isemon._LOG_PATH = state / 'd.log'
isemon.TOKEN_FILE = state / 'api-token'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'api_port': API_PORT, 'geo': 0, 'mikrotik1': 0, 'upgrade_check': 0})
(state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
LOGS = []
_log = isemon.log


def _logged(msg, level='info'):
    LOGS.append(str(msg))
    return _log(msg, level)


isemon.log = _logged
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
daemon.add_user('boss', 'a-long-enough-password', 'fulladmin', by='test')
daemon.add_user('watcher', 'another-long-password', 'readonly', by='test')
api = isemon.ApiServer(daemon, API_PORT)
api.start()
time.sleep(0.4)


def call(path, method='GET', payload=None, session=None):
    url = 'http://127.0.0.1:%d%s' % (API_PORT, path)
    body = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header('X-Isemon-Token', isemon.API_TOKEN)
    if session:
        req.add_header('X-Isemon-Session', session)
    if body is not None:
        req.add_header('Content-Type', 'application/json')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=60) as answer:
            return answer.status, json.loads(answer.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except ValueError:
            return e.code, {}


def session_of(name, pw):
    st, got = call('/api/auth/login', 'POST', {'name': name, 'password': pw})
    return got.get('session') or got.get('token') or ''


def fetch(url):
    return isemon.Upgrades.online_get(url, timeout=10)[0]


def proxied_since(n):
    return PROXIED[n:]


def events_text():
    return '\n'.join(str(r['detail']) for r in store.db.execute('SELECT detail FROM events'))


try:
    # ------------------------------------------------------------------------
    print('\nOff by default: nothing goes through it')
    ok('the defaults: off, nothing set, localhost straight',
       (isemon.DEFAULTS['proxy'], isemon.DEFAULTS['proxy_url'], isemon.DEFAULTS['proxy_user'],
        isemon.DEFAULTS['proxy_no']), (0, '', '', 'localhost, 127.0.0.1, ::1'))
    ok('...a switch for every use, every one off',
       {u: isemon.DEFAULTS['proxy_' + u] for u in isemon.PROXY_USES},
       {u: 0 for u in ('upgrade', 'os', 'acme', 'acme_dns', 'lists', 'geo', 'mac')})
    ok('...the password one of the secrets', 'proxy_password' in isemon.SECRET_KEYS)
    ok('proxy_on, proxy_full: nothing', (isemon.proxy_on(), isemon.proxy_full(),
                                         isemon.proxy_on('os')), (False, '', False))
    n = len(PROXIED)
    got = fetch('https://localhost:%d/release/off' % TLS_PORT)
    ok('the look for new versions asked straight', (got, proxied_since(n)),
       (b'hello from /release/off', []))
    isemon.CONFIG['proxy_url'] = 'http://127.0.0.1:%d' % PX_PORT
    ok('an address with the switch off: still nothing', (isemon.proxy_on(), isemon.proxy_full()),
       (False, ''))
    isemon.CONFIG['proxy_url'] = ''

    # ------------------------------------------------------------------------
    print('\nThe settings checked')
    for key, value, words in (
            ('proxy_url', 'http://squid:pw@proxy.example.cz:3128',
             'proxy_url: http://host:port - the user name and the password go in the fields '
             'below, not in the address'),
            ('proxy_url', 'socks5://proxy.example.cz:1080', 'proxy_url: http://host:port'),
            ('proxy_url', 'http://proxy.example.cz:99999', 'proxy_url: the port'),
            ('proxy_url', 'http://proxy.example.cz:3128/path', 'proxy_url: http://host:port'),
            ('proxy_url', 'http://proxy example.cz', 'proxy_url: http://host:port'),
            ('proxy_user', 'two words', 'proxy_user: no spaces, no : @ or /'),
            ('proxy_user', 'a:b', 'proxy_user: no spaces, no : @ or /'),
            ('proxy_no', 'localhost, $(reboot)', 'proxy_no: names, .domains and addresses'),
            ('proxy', '2', 'proxy must be between 0 and 1')):
        try:
            isemon.check_setting(key, value)
            ok('refused: %s=%s' % (key, value), 'taken')
        except ValueError as e:
            ok('refused: %s=%s' % (key, value), str(e).startswith(words), True)
    ok('taken: http://host:port, https://, [IPv6], a trailing slash',
       [isemon.check_setting('proxy_url', v) for v in (
           'http://proxy.example.cz:3128', 'https://proxy.example.cz', 'http://[2001:db8::1]:8080',
           ' http://10.0.0.1:3128/ ')],
       ['http://proxy.example.cz:3128', 'https://proxy.example.cz', 'http://[2001:db8::1]:8080',
        'http://10.0.0.1:3128/'])
    ok('...a list of names, .domains, addresses and nets',
       isemon.check_setting('proxy_no', 'localhost, .example.cz;10.0.0.0/8 ::1 *.corp.local'),
       'localhost, .example.cz;10.0.0.0/8 ::1 *.corp.local')
    ok('...a user name', isemon.check_setting('proxy_user', 'svc_isemon.proxy-1'),
       'svc_isemon.proxy-1')

    # ------------------------------------------------------------------------
    print('\nSwitched on: the password sealed, an event without it')
    said = daemon.save_settings({'proxy': 1, 'proxy_url': 'http://127.0.0.1:%d' % PX_PORT,
                                 'proxy_user': USER, 'proxy_password': PW,
                                 'proxy_no': 'localhost, ::1'}, by='boss')
    ok('saved', sorted(said['changed']), ['proxy', 'proxy_no', 'proxy_password', 'proxy_url',
                                          'proxy_user'])
    raw = store.db.execute("SELECT value FROM settings WHERE key = 'proxy_password'").fetchone()
    ok('the password sealed in the database', (PW not in raw['value'],
                                                json.loads(raw['value']).startswith(isemon.SEALED)),
       (True, True))
    ok('...read back as it was', isemon.unseal_secret(json.loads(raw['value'])), PW)
    ev = events_text()
    ok('an event says what the way out is now - never the password',
       ('the way out to the web: on, 127.0.0.1:%d, as squid with a password; straight: '
        'localhost, ::1; through it: nothing yet - no use is switched on' % PX_PORT in ev,
        PW not in ev),
       (True, True))

    # ------------------------------------------------------------------------
    print('\nThe proxy on, every use off: everything straight, as it always went')
    daemon.save_settings({'proxy_no': ''}, by='boss')    # nothing reached straight by the list

    def every_use():
        """Each use asked once; {use: what the proxy was asked for it}."""
        out = {}
        n = len(PROXIED)
        try:
            fetch('https://localhost:%d/release/u' % TLS_PORT)
        except Exception:                            # noqa: BLE001
            pass
        out['upgrade'] = [p[:2] for p in proxied_since(n)]
        n = len(PROXIED)
        try:
            isemon.acme_fetch('https://localhost:%d/directory' % TLS_PORT)
        except Exception:                            # noqa: BLE001
            pass
        out['acme'] = [p[:2] for p in proxied_since(n)]
        n = len(PROXIED)
        try:
            isemon._acme_api_call('https://localhost:%d' % TLS_PORT, 'GET', '/dnsapi', None,
                                  {}).close()
        except Exception:                            # noqa: BLE001
            pass
        out['acme_dns'] = [p[:2] for p in proxied_since(n)]
        n = len(PROXIED)
        daemon._feed_fetch('test268', 'https://localhost:%d/drop.netset' % TLS_PORT)
        out['lists'] = [p[:2] for p in proxied_since(n)]
        n = len(PROXIED)
        try:
            daemon.geo_fetch()
        except Exception:                            # noqa: BLE001
            pass
        out['geo'] = sorted(set(p[1] for p in proxied_since(n)))
        n = len(PROXIED)
        try:
            daemon.mac_fetch()
        except Exception:                            # noqa: BLE001
            pass
        out['mac'] = sorted(set(p[1] for p in proxied_since(n)))
        return out
    SEEN.clear()
    got = every_use()
    ok('the new versions, the ACME CA, its DNS APIs, the lists, GeoIP, the cards: none through '
       'it', got, {u: [] for u in ('upgrade', 'acme', 'acme_dns', 'lists', 'geo', 'mac')})
    ok('...the ones that could be reached straight were',
       sorted(set(x[3].split('?')[0] for x in SEEN)),
       ['/directory', '/dnsapi', '/drop.netset', '/release/u'])
    for use, want in (('upgrade', [('CONNECT', 'localhost:%d' % TLS_PORT)]),
                      ('acme', [('CONNECT', 'localhost:%d' % TLS_PORT)]),
                      ('acme_dns', [('CONNECT', 'localhost:%d' % TLS_PORT)]),
                      ('lists', [('CONNECT', 'localhost:%d' % TLS_PORT)]),
                      ('geo', ['download.db-ip.com:443']),
                      ('mac', ['standards-oui.ieee.org:443'])):
        daemon.save_settings({'proxy_' + use: 1}, by='boss')
        got = every_use()
        ok('%s switched on: it alone through the proxy' % use,
           got, {u: (want if u == use else []) for u in got})
        daemon.save_settings({'proxy_' + use: 0}, by='boss')
    daemon.save_settings({'proxy': 0, 'proxy_upgrade': 1, 'proxy_acme': 1, 'proxy_lists': 1},
                         by='boss')
    got = every_use()
    ok('every switch on but the proxy off: none through it',
       got, {u: [] for u in ('upgrade', 'acme', 'acme_dns', 'lists', 'geo', 'mac')})
    daemon.save_settings({'proxy': 1, 'proxy_acme': 0, 'proxy_lists': 0,
                          'proxy_no': 'localhost, ::1'}, by='boss')
    ok('the event names what goes through it', 'through it: the new versions of isemon'
       in events_text())

    # ------------------------------------------------------------------------
    print('\nThrough it: with the password, never told to the server at the end')
    n = len(PROXIED)
    SEEN.clear()
    got = fetch('https://upgrades.example.test/release/isemon')
    ok('the look for new versions: through the proxy, by CONNECT with the password',
       (got, proxied_since(n)), (b'hello from /release/isemon',
                                 [('CONNECT', 'upgrades.example.test:443', WANT_AUTH)]))
    ok('...the server at the end saw its own name, and no Proxy-Authorization',
       SEEN, [('https', 'GET', 'upgrades.example.test', '/release/isemon', None)])
    daemon.save_settings({'proxy_acme': 1, 'proxy_lists': 1}, by='boss')
    n = len(PROXIED)
    body, _h, status = isemon.acme_fetch('https://acme.example.test/directory')
    ok('a request to the ACME CA (its switch on): through the proxy',
       (status, json.loads(body.decode()).get('newNonce'), proxied_since(n)),
       (200, 'https://acme.example.test/nonce',
        [('CONNECT', 'acme.example.test:443', WANT_AUTH)]))
    n = len(PROXIED)
    SEEN.clear()
    kept, words = daemon._feed_fetch('test268b', 'http://lists.example.test/plain.netset')
    ok('a list over plain HTTP (its switch on): the whole address asked of the proxy',
       (kept, proxied_since(n)),
       (2, [('GET', 'http://lists.example.test/plain.netset', WANT_AUTH)]))
    ok('...and the password not sent on to the server', SEEN,
       [('http', 'GET', 'lists.example.test', '/plain.netset', None)])
    daemon.save_settings({'proxy_acme': 0, 'proxy_lists': 0}, by='boss')
    n = len(PROXIED)
    try:
        isemon.acme_fetch('https://acme.example.test/directory')
        ok('the ACME CA with its switch off again: straight', 'reached through the proxy')
    except isemon.AcmeError:
        ok('the ACME CA with its switch off again: straight - the proxy never asked',
           proxied_since(n), [])
    src = (ROOT / 'isemon.py').read_text()
    ok('every request to the web names its use',
       sorted(re.findall(r"url_open\(req, '([a-z_]+)'", src)), ['geo', 'lists', 'mac', 'upgrade'])
    ok('...urllib\'s own urlopen only for the command line\'s road to the daemon',
       src.count('urllib.request.urlopen('), 1)
    try:
        isemon.url_open('https://x/', 'web')
        ok('a use not known: refused', 'opened')
    except ValueError:
        ok('a use not known: refused', True)

    # A wrong password: 407, said - the password nowhere in it.
    isemon.CONFIG['proxy_password'] = 'not-the-one'
    try:
        fetch('https://upgrades.example.test/release/x')
        ok('a wrong password: refused by the proxy', 'fetched')
    except Exception as e:                           # noqa: BLE001
        ok('a wrong password: refused by the proxy (407), said',
           ('407' in str(e), 'not-the-one' not in str(e)), (True, True))
    isemon.CONFIG['proxy_password'] = PW

    # ------------------------------------------------------------------------
    print('\nStraight: a name, a .domain, a net in the list')
    n = len(PROXIED)
    SEEN.clear()
    ok('localhost (a name in the list): straight',
       (fetch('https://localhost:%d/straight' % TLS_PORT), proxied_since(n)),
       (b'hello from /straight', []))
    daemon.save_settings({'proxy_no': 'localhost, .example.test, 127.0.0.0/8'}, by='boss')
    n = len(PROXIED)
    ok('127.0.0.1 (in a net of the list): straight',
       (fetch('https://127.0.0.1:%d/net' % TLS_PORT), proxied_since(n)),
       (b'hello from /net', []))
    try:
        fetch('https://upgrades.example.test/release/isemon')
        ok('a name under a .domain of the list: straight (and not known here)', 'fetched')
    except Exception:                                # noqa: BLE001
        ok('a name under a .domain of the list: straight - the proxy never asked',
           proxied_since(n), [])
    ok('proxy_skips, as otp: names, .domains, *.domains, nets, IPv6, *',
       [isemon.proxy_skips(h) for h in ('LOCALHOST', 'example.test', 'a.b.example.test',
                                         'example.testx', '127.9.9.9', '10.0.0.1', '[::1]', '')],
       [True, True, True, False, True, False, False, True])
    isemon.CONFIG['proxy_no'] = '*.corp.local, ::1, 2001:db8::/32'
    ok('...*.corp.local, ::1, a v6 net', [isemon.proxy_skips(h) for h in (
        'x.corp.local', 'corp.local', '::1', '2001:db8::5', '2001:db9::5')],
       [True, True, True, True, False])
    isemon.CONFIG['proxy_no'] = '*'
    ok('...* is everything', isemon.proxy_skips('upgrades.example.test'))
    daemon.save_settings({'proxy_no': 'localhost'}, by='boss')
    n = len(PROXIED)
    SEEN.clear()
    got = fetch('https://upgrades.example.test/redirect')
    ok('a redirect to an address reached straight: the first through the proxy, the second '
       'straight', (got, [p[1] for p in proxied_since(n)]),
       (b'hello from /landed', ['upgrades.example.test:443']))
    ok('...and the password not carried along to the server it went to',
       [(s[3], s[4]) for s in SEEN], [('/redirect', None), ('/landed', None)])

    # ------------------------------------------------------------------------
    print('\nTry it: always tried, the way drawn, each step with its time')
    x = isemon.proxy_try('https://upgrades.example.test/release/')
    ok('through the proxy: reached, HEAD answered 200',
       (x['ok'], x['mode'], x['proxy'], x['proxy_auth'], x['status'], x['host'], x['port']),
       (True, 'proxy', '127.0.0.1:%d' % PX_PORT, True, 200, 'upgrades.example.test', 443))
    ok('...the steps: the proxy looked up, connected, the tunnel, TLS, the answer',
       [s['what'] for s in x['steps']],
       ['the proxy looked up (127.0.0.1)', 'connected to the proxy',
        'a tunnel through the proxy to upgrades.example.test:443',
        'TLS, the certificate of upgrades.example.test checked', 'asked for /release/'])
    ok('...each with its time and what it found',
       (all(isinstance(s['ms'], int) and s['ms'] >= 0 and s['ok'] for s in x['steps']),
        x['steps'][2]['said'], 'by Proxy Test Root' in x['steps'][3]['said'],
        isinstance(x['ms'], int)),
       (True, '200 Connection established - with the user name and password', True, True))
    ok('...nothing said holds the password', PW not in json.dumps(x))
    isemon.CONFIG['proxy_password'] = 'wrong'
    x = isemon.proxy_try('https://upgrades.example.test/')
    ok('a wrong password: stopped at the tunnel, said in words',
       (x['ok'], [s['ok'] for s in x['steps']], x['steps'][-1]['said']),
       (False, [True, True, False], 'the proxy asks for a user name and a password (407) - '
                                    'they are wrong'))
    isemon.CONFIG['proxy_password'] = PW
    x = isemon.proxy_try('http://lists.example.test/plain.netset')
    ok('plain HTTP through the proxy: no tunnel, the whole address asked',
       (x['ok'], [s['what'] for s in x['steps']], x['status']),
       (True, ['the proxy looked up (127.0.0.1)', 'connected to the proxy',
               'asked for /plain.netset'], 200))
    x = isemon.proxy_try('https://localhost:%d/' % TLS_PORT)
    ok('an address in the list: straight, and why',
       (x['ok'], x['mode'], x['why_direct'], [s['what'] for s in x['steps']][:2]),
       (True, 'direct', 'localhost is in the list reached straight',
        ['localhost looked up', 'connected to localhost']))
    isemon.CONFIG['proxy_url'] = 'http://127.0.0.1:1'
    x = isemon.proxy_try('https://upgrades.example.test/')
    ok('a proxy that does not answer: stopped at the connection, in words',
       (x['ok'], x['steps'][-1]['what'], x['steps'][-1]['said']),
       (False, 'connected to the proxy', 'nothing answers on that port (connection refused)'))
    isemon.CONFIG['proxy_url'] = 'http://127.0.0.1:%d' % PX_PORT
    try:
        isemon.proxy_try('ftp://x')
        ok('not an http(s) address: refused', 'tried')
    except ValueError as e:
        ok('not an http(s) address: refused', str(e), 'an address starting https:// (or http://)')
    boss = session_of('boss', 'a-long-enough-password')
    st, got = call('/api/proxy', 'POST', {'action': 'try', 'url': 'https://upgrades.example.test/'},
                   session=boss)
    ok('through the API: the same, for a full administrator',
       (st, got.get('ok'), got.get('reached'), got.get('mode'), len(got.get('steps') or [])),
       (200, True, True, 'proxy', 5))
    st, got = call('/api/proxy', 'POST', {'action': 'try', 'url': 'gopher://x'}, session=boss)
    ok('...a bad address refused, in words', (st, got.get('error')),
       (400, 'an address starting https:// (or http://)'))
    watcher = session_of('watcher', 'another-long-password')
    st, got = call('/api/proxy', 'POST', {'action': 'try'}, session=watcher)
    ok('...refused to a read-only account', st in (401, 403), True)
    daemon.save_settings({'proxy': 0}, by='boss')
    x = isemon.proxy_try('https://localhost:%d/' % TLS_PORT)
    ok('switched off: tried all the same, straight, and why',
       (x['ok'], x['mode'], x['why_direct']), (True, 'direct', 'no proxy is set'))
    ok('...the event says it is off', 'the way out to the web: off - isemon goes to the web '
                                      'as it always went' in events_text())
    daemon.save_settings({'proxy': 1}, by='boss')

    # ------------------------------------------------------------------------
    print('\nThe system updates: dnf or apt given the proxy by root, never on a command line')
    W = None
    os.environ['ISEMON_OSUP_PROXY'] = str(OSUP_PROXY)
    spec = importlib.util.spec_from_file_location('isemon_web_268', str(ROOT / 'deploy' /
                                                                        'isemon_web.py'))
    W = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(W)
    W.osup_proxy_keep('http://u:p@proxy:3128', 'localhost')
    ok('the helper\'s file: root\'s alone (0600)', stat.S_IMODE(OSUP_PROXY.stat().st_mode), 0o600)
    ok('...read into an environment', W.osup_proxy_env({}),
       {'http_proxy': 'http://u:p@proxy:3128', 'https_proxy': 'http://u:p@proxy:3128',
        'HTTP_PROXY': 'http://u:p@proxy:3128', 'HTTPS_PROXY': 'http://u:p@proxy:3128',
        'no_proxy': 'localhost', 'NO_PROXY': 'localhost'})
    W.osup_proxy_keep('', '')
    ok('...taken away when there is none', OSUP_PROXY.exists(), False)
    for bad in ('ftp://proxy:21', 'http://proxy:3128/$(id)', 'http://a b'):
        try:
            W.osup_proxy_checked({'proxy': bad})
            ok('the helper refuses %s' % bad, 'taken')
        except W.Refused as e:
            ok('the helper refuses %s' % bad, str(e), 'the proxy is not an http:// address')

    stop = threading.Event()

    def path_unit():
        while not stop.is_set():
            if (state / 'web' / 'osup.ask').exists():
                run_helper()
            time.sleep(0.05)
    th = threading.Thread(target=path_unit, daemon=True)
    th.start()
    seen_ask = []
    real_write = daemon.webroot.write

    def spy(name, data):
        if name == 'osup.ask':
            seen_ask.append(dict(data))
        return real_write(name, data)
    daemon.webroot.write = spy
    isemon._osup_job(daemon, 'check', wait=20)
    ok('the updates of the system with their switch off: nothing in the ask',
       'proxy' in seen_ask[-1], False)
    wait_for(lambda: PM_LOG.exists() and not OSUP_PROXY.exists(), 20)
    wait_for(lambda: json.loads((state / 'web' / 'osup.json').read_text()).get('state') == 'done')
    if PM_LOG.exists():
        PM_LOG.unlink()
    daemon.save_settings({'proxy_os': 1}, by='boss')
    isemon._osup_job(daemon, 'check', wait=20)
    ok('the daemon\'s ask carries the proxy, with the user and password, and the list',
       (seen_ask[-1].get('proxy'), seen_ask[-1].get('proxy_no')),
       ('http://squid:%s@127.0.0.1:%d' % (urllib.parse.quote(PW, safe=''), PX_PORT), 'localhost'))
    ok('the work ran', wait_for(lambda: PM_LOG.exists() and len(PM_LOG.read_text().splitlines())
                                >= 1 and not OSUP_PROXY.exists(), 20))
    rec = [json.loads(ln) for ln in PM_LOG.read_text().splitlines()]
    want = 'http://squid:%s@127.0.0.1:%d' % (urllib.parse.quote(PW, safe=''), PX_PORT)
    ok('dnf ran with the proxy in its environment, the list as no_proxy',
       (rec[0]['env'].get('https_proxy'), rec[0]['env'].get('http_proxy'),
        rec[0]['env'].get('no_proxy')), (want, want, 'localhost'))
    ok('...never on its command line', any(PW in a or 'proxy' in a for r in rec for a in r['argv']),
       False)
    ok('...the file gone before dnf even ran, and after', (rec[0]['file_there'],
                                                           OSUP_PROXY.exists()), (False, False))
    ok('what the work wrote (osup.json) holds no password',
       wait_for(lambda: json.loads((state / 'web' / 'osup.json').read_text()).get('state') ==
                'done') and PW not in (state / 'web' / 'osup.json').read_text() and
       urllib.parse.quote(PW, safe='') not in (state / 'web' / 'osup.json').read_text())
    ok('...and the ask taken away', (state / 'web' / 'osup.ask').exists(), False)
    daemon.save_settings({'proxy_os': 0}, by='boss')
    PM_LOG.unlink()
    isemon._osup_job(daemon, 'check', wait=20)
    ok('the system updates not through it (proxy_os off): nothing in the ask',
       'proxy' in seen_ask[-1], False)
    ok('...nor in the environment of dnf', wait_for(lambda: PM_LOG.exists()) and
       json.loads(PM_LOG.read_text().splitlines()[0])['env'], {})
    daemon.save_settings({'proxy_os': 1}, by='boss')
    stop.set()
    daemon.webroot.write = real_write

    # ------------------------------------------------------------------------
    print('\nThe password nowhere unsealed: the database, the log, the events, config.json')
    time.sleep(0.3)
    blob = isemon.DB_FILE.read_bytes()
    for extra in ('-wal', '-journal'):
        p = Path(str(isemon.DB_FILE) + extra)
        if p.exists():
            blob += p.read_bytes()
    ok('the database file', (PW.encode() in blob,
                             urllib.parse.quote(PW, safe='').encode() in blob), (False, False))
    ok('the log', any(PW in ln or urllib.parse.quote(PW, safe='') in ln for ln in LOGS), False)
    ok('...nor the log file', PW in (isemon._LOG_PATH.read_text() if isemon._LOG_PATH.exists()
                                     else ''), False)
    ok('the events', PW in events_text() or urllib.parse.quote(PW, safe='') in events_text(),
       False)
    ok('config.json', PW in (state / 'config.json').read_text(), False)
    st, got = call('/api/settings', session=boss)
    ok('the page\'s settings', (st, PW in json.dumps(got), 'proxy_password' in json.dumps(got)),
       (200, False, True))
    st, got = call('/api/export', session=boss)
    ok('a plain export', (st, PW in json.dumps(got)), (200, False))

    # ------------------------------------------------------------------------
    print('\nThe command line: isemon --proxy-test [URL]; the console')

    class A(object):
        json = True
        proxy_test = 'https://upgrades.example.test/release/'
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = isemon.cmd_proxy_test(A(), isemon.Palette(False), store)
    got = json.loads(buf.getvalue())
    ok('--proxy-test URL --json: the way and the steps', (rc, got.get('mode'), got.get('reached'),
                                                         len(got.get('steps') or [])),
       (0, 'proxy', True, 5))
    A.json = False
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = isemon.cmd_proxy_test(A(), isemon.Palette(False), store)
    out = buf.getvalue()
    ok('--proxy-test in words: the way, each step with its time, reached',
       (rc, 'through the proxy 127.0.0.1:%d with a password' % PX_PORT in out,
        '-> 127.0.0.1:%d -> upgrades.example.test:443' % PX_PORT in out,
        out.count(' ms') >= 5, 'reached through the proxy - HTTP 200' in out, PW in out),
       (0, True, True, True, True, False))
    A.proxy_test = 'https://localhost:%d/' % TLS_PORT
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = isemon.cmd_proxy_test(A(), isemon.Palette(False), store)
    ok('--proxy-test of an address in the list: straight, and why',
       (rc, 'straight because localhost is in the list reached straight' in buf.getvalue()),
       (0, True))
    isemon.CONFIG['proxy_url'] = 'http://127.0.0.1:1'
    A.proxy_test = ''
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = isemon.cmd_proxy_test(A(), isemon.Palette(False), store)
    ok('--proxy-test (empty: the upgrades\' address) with the proxy away: 1, said',
       (rc, 'nothing answers on that port' in buf.getvalue(),
        'github.com' in buf.getvalue()), (1, True, True))
    isemon.CONFIG['proxy_url'] = 'http://127.0.0.1:%d' % PX_PORT
    got = subprocess.run([sys.executable, str(ROOT / 'isemon.py'), '--help'], capture_output=True,
                         text=True)
    ok('--help has --proxy-test', (got.returncode, '--proxy-test' in got.stdout), (0, True))
    ns = isemon.build_parser().parse_args(['--proxy-test']) if hasattr(isemon, 'build_parser') \
        else None
    if ns is not None:
        ok('--proxy-test alone: the upgrades\' address', ns.proxy_test, '')

    class Dry(isemon.Console):
        def __init__(self):
            super(Dry, self).__init__(isemon.Palette(False))
            self.ran, self.items = [], None

        def sub(self, title_, items):
            self.items = (title_, items)

        def ask_one(self, *a, **k):
            return ' https://example.cz/ '

        def act(self, *args, **k):
            self.ran.append(('act',) + args)
    dry = Dry()
    dry.m_machine()
    items = {it[1]: it for it in dry.items[1]}
    ok('the console: Network, time and power → an item of its own',
       (items.get('The way out (proxy): try it') or ('',))[0], '10')
    items['The way out (proxy): try it'][2]()
    ok('...asks the address and tries it', dry.ran, [('act', '--proxy-test', 'https://example.cz/')])

    # ------------------------------------------------------------------------
    print('\nThe page')
    page = (ROOT / 'web' / 'index.php').read_text()
    ok('Proxy under Server, after Network, with the globe',
       'data-pane="network"' in page and page.index('data-pane="proxy"') >
       page.index('data-pane="network"') and page.index('data-pane="proxy"') <
       page.index('data-pane="time"') and 'data-pane="proxy" data-icon="globe"' in page)
    ok('...its pane: the settings, then Try it', ('id="pane-proxy"' in page,
                                                 'id="sect-proxy"' in page, 'id="px-host"' in page,
                                                 "proxy:   ['proxy', 'proxy_url', 'proxy_user', "
                                                 "'proxy_password', 'proxy_no', 'proxy_upgrade',"
                                                 in page),
       (True, True, True, True))
    sect = page[page.index("proxy:   ['proxy'"):]
    sect = sect[:sect.index(']')]
    ok('...a switch for every use in it', all("'proxy_%s'" % u in sect for u in isemon.PROXY_USES))
    ow = page[page.index('var ONLY_WHEN = {'):]
    ow = ow[:ow.index('};')]
    ok('...each greyed while the proxy is off',
       all(("proxy_%s: ['proxy', '1']" % k) in ow for k in
           ('url', 'user', 'password', 'no') + isemon.PROXY_USES))
    ok('...the PHP side lets /api/proxy through, both ways',
       page.count("'proxy'        => '/api/proxy',"), 2)
finally:
    try:
        api.stop()
    except Exception:                                # noqa: BLE001
        pass
    for s_ in (px_srv, tls_srv, http_srv):
        try:
            s_.shutdown()
        except Exception:                            # noqa: BLE001
            pass

print('\n%d passed, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
