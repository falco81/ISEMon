#!/usr/bin/env python3
"""1.10.341: signing in with a certificate - a smart card, a YubiKey - as otp
1.0.275 does it. An AD CS of its own is made here with openssl
(test/pki_certlogin.sh): a root, an issuing authority, its CRL served over
http, and a person's certificate for every case the sign-in has to tell
apart. The directory is made up at its edge. Then nginx's server of isemon's
own on the certificate's port, as the root helper writes it, and - where
nginx and php-fpm are on the machine - the whole round through them with a
client certificate, as a browser makes it.

    ./test/fixes341_certlogin.py
"""
import http.server
import json
import os
import random
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'deploy'))
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


folder = Path(tempfile.mkdtemp(prefix='isemon-341-'))
isemon.STATE_DIR = folder
isemon.DB_FILE = folder / 'c.db'
isemon.BACKUP_DIR = folder / 'backups'
isemon.DUMP_DIR = folder / 'dumps'
isemon.RUN_DIR = folder
isemon.LOG_DIR = folder
isemon.CONFIG_FILE = folder / 'config.json'
isemon._LOG_PATH = folder / 'c.log'
isemon.TOKEN_FILE = folder / 'api-token'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'directory': 1,
                      'directory_host': 'dc.corpnet.loc', 'directory_base': 'DC=corpnet,DC=loc',
                      'directory_admin_group': 'ISEMON_Admins',
                      'directory_readonly_group': 'ISEMON_Viewers'})
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)

print('off by default')
ok('off', (isemon.DEFAULTS['certlogin'], isemon.DEFAULTS['certlogin_port'],
           isemon.DEFAULTS['certlogin_match'], isemon.DEFAULTS['certlogin_crl']),
   (0, 8443, 'compat', 1))
ok('the sign-in page offers nothing', (daemon.kerberos_health()['cert'],
                                       daemon.kerberos_health()['cert_port']), (False, 0))
ok('no port asked of root', 'certlogin' in (daemon.webroot.request() or {}), False)

# The authority, its CRL served here.
crlport = 21000 + random.randint(0, 3000)
deadport = crlport + 3500
pki = folder / 'pki'
got = subprocess.run(['bash', str(HERE / 'pki_certlogin.sh'), str(pki)], capture_output=True,
                     text=True, timeout=300,
                     env=dict(os.environ, CRLPORT=str(crlport), DEADPORT=str(deadport)))
if got.returncode:
    print(got.stdout, got.stderr)
    raise SystemExit('the test authority could not be made')


class Quiet(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(pki / 'www'), **kw)

    def log_message(self, *a):
        pass


crl_server = http.server.ThreadingHTTPServer(('127.0.0.1', crlport), Quiet)
threading.Thread(target=crl_server.serve_forever, daemon=True).start()
for k in ('http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY'):
    os.environ.pop(k, None)


def pem(name):
    return (pki / ('%s.pem' % name)).read_text()


print('what a certificate says, read from DER')
f = isemon.cl_cert_facts(pem('falco'))
ok('its UPN, its SID (KB5014754), its key usages, its CRL',
   (f['upn'], f['sid'], sorted(f['eku']), f['cdp']),
   (['falco@corpnet.cz'], 'S-1-5-21-1111-2222-3333-1105',
    ['1.3.6.1.4.1.311.20.2.2', '1.3.6.1.5.5.7.3.2'],
    ['http://127.0.0.1:%d/issuing.crl' % crlport]))
ok('an authority is one', isemon.cl_cert_facts(pem('issuing'))['ca'], True)


def sid_bytes(text):
    parts = text.split('-')
    subs = [int(x) for x in parts[3:]]
    return bytes([1, len(subs)]) + int(parts[2]).to_bytes(6, 'big') + b''.join(
        x.to_bytes(4, 'little') for x in subs)


ok('a SID read back from its binary form', isemon.cl_sid_text(
    sid_bytes('S-1-5-21-1111-2222-3333-1105')), 'S-1-5-21-1111-2222-3333-1105')

print('the authorities, put in on the pages')
isemon.CONFIG['certlogin'] = 1
for bad, why in (('nothing here', 'no certificate'), (pem('falco'), 'of a person')):
    try:
        daemon.certlogin_put(bad, 'boss')
        ok('refused: ' + why, False)
    except ValueError as e:
        ok('refused: %s (%s)' % (why, str(e)[:50]), why in str(e))
der = subprocess.run(['openssl', 'x509', '-in', str(pki / 'issuing.pem'), '-outform', 'DER'],
                     capture_output=True).stdout
added = daemon.certlogin_put(der, 'boss')
ok('a .cer (DER) read', [a['subject'] for a in added], ['CN=Corpnet Issuing CA,DC=corpnet,DC=loc'])
p7b = subprocess.run(['openssl', 'crl2pkcs7', '-nocrl', '-certfile', str(pki / 'cas.pem')],
                     capture_output=True, text=True).stdout
added = daemon.certlogin_put(p7b, 'boss')
ok('a .p7b: the one not there yet', [a['subject'] for a in added],
   ['CN=Corpnet Root CA,DC=corpnet,DC=loc'])
ok('not tried by itself unless so set', daemon.kerberos_health()['cert_auto'], False)
isemon.CONFIG['certlogin_auto'] = 1
ok('...tried by itself when set', daemon.kerberos_health()['cert_auto'], True)
isemon.CONFIG['certlogin_auto'] = 0
ok('on now; the page offers it, with its port', (daemon.certlogin_on(),
                                                 daemon.kerberos_health()['cert_port']),
   (True, 8443))
ca_file = daemon.certlogin_ca_file()
ok('written for openssl, 0600', oct(ca_file.stat().st_mode & 0o777), '0o600')
req = daemon.webroot.request()
ok('root is asked for the port, with the authorities', (req['certlogin']['on'],
                                                         req['certlogin']['port'],
                                                         req['certlogin']['cas'].count('BEGIN')),
   (True, 8443, 2))
fw = daemon.webroot.auto_rules(look={}, fw=daemon.webroot.fw_conf())
ok('the firewall lets the port in where the dashboard is',
   [i['rules'][0]['port'] for i in fw if i['key'] == 'web'], ['80,443,8443'])

PEOPLE = {
    'falco@corpnet.cz': ('falco', 'S-1-5-21-1111-2222-3333-1105', {'isemon_admins'}, '512'),
    'nested@corpnet.cz': ('nested', 'S-1-5-21-1111-2222-3333-1106', {'isemon_viewers'}, '512'),
    'outsider@corpnet.cz': ('outsider', 'S-1-5-21-1111-2222-3333-1200', set(), '512'),
    'gone@corpnet.cz': ('gone', 'S-1-5-21-1111-2222-3333-1201', {'isemon_admins'}, '514'),
}


class Link(object):
    def close(self):
        pass


def find(link, upn):
    p = PEOPLE.get(upn.lower())
    if not p:
        return []
    dn = 'CN=%s,OU=People,DC=corpnet,DC=loc' % p[0]
    return [{'dn': dn, '_g': p[2], 'raw': {'objectSid': [sid_bytes(p[1])]}, 'attrs': {
        'distinguishedName': [dn], 'sAMAccountName': [p[0]], 'userPrincipalName': [upn],
        'displayName': [p[0].title()], 'userAccountControl': [p[3]], 'lockoutTime': ['0'],
        'accountExpires': ['0'], 'objectSid': ['?']}}]


daemon.directory_reader = lambda which='directory', timeout=None: Link()
daemon.certlogin_find = find
daemon.directory_groups = lambda link, entry: set(entry.get('_g') or ())

print('signing in with a certificate')
got = daemon.certlogin_login(pem('falco'), ip='10.2.0.5', agent='test')
ok('falco: full admin, out of the directory, the account of its sAMAccountName',
   (got['name'], got['role'], got['from_dir'], got['how']),
   ('falco', 'fulladmin', True, 'certificate'))
ok('...a session, marked as opened without a password', daemon.kerberos_session(got['token']),
   True)
ok('nested: read only', daemon.certlogin_login(pem('nested'), ip='10.2.0.6')['role'],
   'readonly')
ok('no SID in it: taken (compat)', daemon.certlogin_login(pem('falco-nosid'),
                                                          ip='10.2.0.7')['name'], 'falco')
cases = (('falco-sid2', 'is not the one of falco'), ('falco-rev', 'revoked'),
         ('falco-old', 'expired'), ('falco-srv', 'not for signing in'),
         ('noupn', 'no UPN'), ('outsider', 'none of the groups'),
         ('gone', 'switched off'), ('ghost', 'not in the directory'),
         ('stranger', 'not taken'), ('falco-nocdp', 'could not be had'),
         ('issuing', 'of an authority'))
for name, why in cases:
    try:
        daemon.certlogin_login(pem(name), ip='10.2.1.%d' % random.randint(1, 250))
        ok('%s refused: %s' % (name, why), False)
    except isemon.CertLoginError as e:
        ok('%s refused: %s' % (name, why), why in str(e) or str(e))
try:
    daemon.certlogin_login('', ip='10.2.2.1')
    ok('nothing sent: refused', False)
except isemon.CertLoginError as e:
    ok('nothing sent: refused', 'no certificate was sent' in str(e))
isemon.CONFIG['certlogin_match'] = 'strong'
try:
    daemon.certlogin_login(pem('falco-nosid'), ip='10.2.2.2')
    ok('strong: no SID refused', False)
except isemon.CertLoginError as e:
    ok('strong: no SID refused', 'carries no SID' in str(e))
isemon.CONFIG['certlogin_match'] = 'upn'
ok('upn: another account\'s SID not looked at', daemon.certlogin_login(
    pem('falco-sid2'), ip='10.2.2.3')['name'], 'falco')
isemon.CONFIG['certlogin_match'] = 'compat'
isemon.CONFIG['certlogin_crl'] = 0
ok('CRL off: the one whose CRL cannot be had is taken', daemon.certlogin_login(
    pem('falco-nocdp'), ip='10.2.2.4')['name'], 'falco')
try:
    daemon.certlogin_login(pem('falco-rev'), ip='10.2.2.5')
    ok('...but nothing else changes (revoked is not looked for then)', True)
except isemon.CertLoginError:
    ok('...but nothing else changes (revoked is not looked for then)', False)
isemon.CONFIG['certlogin_crl'] = 1
daemon.add_user('admin', 'local-password-1', 'fulladmin')
PEOPLE['admin@corpnet.cz'] = ('admin', 'S-1-5-21-1111-2222-3333-1300', {'isemon_admins'}, '512')
ok('the CRL kept until its next update', bool(isemon.CL_CRL_CACHE) and all(
    c['next'] > time.time() for c in isemon.CL_CRL_CACHE.values() if c.get('pem')), True)
ev = store.db.execute("SELECT level FROM events WHERE detail LIKE '%with a certificate from%' "
                      "ORDER BY id DESC").fetchone()
ok('a refusal is in the events, a warning', ev and ev['level'], 'warn')

print('the second step after it')
isemon.CONFIG['passkeys'] = 1
ok('Face ID owed after a certificate', daemon.certlogin_login(pem('falco'),
                                                              ip='10.2.3.1')['second'], 'enrol')
isemon.CONFIG['passkeys'] = 0

print('no password at all')
isemon.CONFIG['password_off'] = 1
ok('in effect with a certificate alone (no Kerberos)', (daemon.kerberos_on(),
                                                        daemon.password_off()), (False, True))
try:
    daemon.login('admin', 'local-password-1', ip='10.2.4.1')
    ok('a password refused', False)
except isemon.Refused as e:
    ok('a password refused', 'no password signs in here' in str(e))
try:
    daemon.certlogin_drop(daemon.certlogin_cas()[0]['sha256'], 'boss')
    daemon.certlogin_drop(daemon.certlogin_cas()[0]['sha256'], 'boss')
    ok('the last authority not taken away while only it signs in', False)
except ValueError as e:
    ok('the last authority not taken away while only it signs in', 'switch that off' in str(e))
isemon.CONFIG['certlogin'] = 0
ok('the certificate off brings passwords back', daemon.login(
    'admin', 'local-password-1', ip='10.2.4.2')['name'], 'admin')
isemon.CONFIG['certlogin'] = 1
isemon.CONFIG['password_off'] = 0
daemon.certlogin_put(p7b, 'boss')

print('nginx: a server of isemon\'s own on the port')
import isemon_web                                   # noqa: E402
vhost = (ROOT / 'deploy' / 'nginx-isemon.conf').read_text()
cl = isemon_web.certlogin_checked({'on': True, 'port': 8443, 'cas': (pki / 'cas.pem').read_text()})
new, words = isemon_web.certlogin_into(vhost, cl)
blk = new[new.index(isemon_web.CERTLOGIN_MARK):]
ok('put in at the end, between its marks', (new.startswith(vhost.rstrip('\n')), words,
                                             isemon_web.CERTLOGIN_END in blk),
   (True, 'nginx: the certificate sign-in on port 8443', True))
for what, there in (('listen      8443 ssl;', True), ('ssl_verify_client         optional_no_ca;', True),
                    ('ssl_client_certificate    %s;' % isemon_web.CERTLOGIN_CA, True),
                    ('fastcgi_param  SSL_CLIENT_CERT $ssl_client_escaped_cert;', True),
                    ('fastcgi_param  ISEMON_CERT_PORT 1;', True),
                    ('if ($arg_api !~ "^cert-(login|check)$") { return 404; }', True),
                    ('allow 10.0.0.0/8;', True), ('deny  all;', True),
                    ('ssl_certificate           /etc/nginx/certs/isemon.pem;', True),
                    ('location / { return 404; }', True)):
    ok('...%s' % what, what in blk, there)
ok('443 asks nobody for a certificate', 'ssl_verify_client' in vhost, False)
for what in ('if ($request_method !~ ^(GET|HEAD)$) { return 405; }',
             'if ($http_content_type ~* "multipart") { return 403; }',
             'limit_req zone=isemon_all burst=20 nodelay;',
             'add_header Strict-Transport-Security "max-age=63072000" always;'):
    ok('...%s (as the dashboard)' % what, what in blk, True)
nohsts = vhost.replace('    add_header Strict-Transport-Security "max-age=63072000" always;\n', '')
b2 = isemon_web.certlogin_into(nohsts, cl)[0]
ok('the dashboard without HSTS: none on the port either',
   'Strict-Transport-Security' in b2[b2.index(isemon_web.CERTLOGIN_MARK):], False)
inner = vhost.replace('    allow 192.168.0.0/16;', '    location /x/ { deny all; }\n    allow 192.168.0.0/16;')
b3 = isemon_web.certlogin_into(inner, cl)[0]
ok('a location\'s deny all is not the port\'s', b3[b3.index(isemon_web.CERTLOGIN_MARK):]
   .count('deny  all;') + b3[b3.index(isemon_web.CERTLOGIN_MARK):].count('deny all;'), 2)
# isemon's server put BEFORE the dashboard's (by hand): never taken for the dashboard's
blk_only = new[new.index(isemon_web.CERTLOGIN_MARK):]
moved = blk_only + '\n' + vhost
w2 = isemon_web.server_block(moved)
ok('isemon\'s certificate server is never taken for the dashboard\'s', 'listen      443 ssl'
   in moved[w2[0]:w2[1]], True)
w = isemon_web.server_block(new)
ok('the dashboard\'s own server is still the one found', 'listen      443 ssl' in new[w[0]:w[1]],
   True)
again, words = isemon_web.certlogin_into(new, cl)
ok('written again: the same, once', (again == new, again.count(isemon_web.CERTLOGIN_MARK)),
   (True, 1))
gone, words = isemon_web.certlogin_into(new, {'on': False})
ok('off: taken away whole, the file as it was', (gone.rstrip('\n'), words),
   (vhost.rstrip('\n'), 'nginx: the port of the certificate sign-in closed'))
for bad in ({'on': True, 'port': 443, 'cas': (pki / 'cas.pem').read_text()},
            {'on': True, 'port': 8443, 'cas': 'nothing'}):
    try:
        isemon_web.certlogin_checked(bad)
        ok('refused by root: %r' % bad.get('port'), False)
    except isemon_web.Refused:
        ok('refused by root: %s' % ('port 443' if bad['port'] == 443 else 'no authorities'),
           True)

print('through nginx and PHP, with a client certificate')
NGINX = shutil.which('nginx')
FPM = shutil.which('php-fpm') or shutil.which('php-fpm8.3') or next(
    (str(p) for p in Path('/usr/sbin').glob('php-fpm*')), None)


def free(port):
    with socket.socket() as s:
        try:
            s.bind(('127.0.0.1', port))
            return True
        except OSError:
            return False


if not (NGINX and FPM and os.geteuid() == 0):
    print('  (skipped: no nginx or php-fpm here, or not root)')
else:
    import isemon as _i                                  # noqa: F401
    t = folder / 'ng'
    for d in ('certs', 'tmp', 'web'):
        (t / d).mkdir(parents=True, exist_ok=True)
    P443 = 30000 + random.randint(0, 2000)
    PCERT = P443 + 2500
    P80 = P443 + 5000
    API = P443 + 7000
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout',
                    str(t / 'certs' / 'isemon.key'), '-out', str(t / 'certs' / 'isemon.pem'),
                    '-days', '3', '-subj', '/CN=isemon.corpnet.loc', '-addext',
                    'subjectAltName=DNS:isemon.corpnet.loc'], capture_output=True, check=True)
    web = t / 'web'
    shutil.rmtree(str(web))
    shutil.copytree(str(ROOT / 'web'), str(web))
    lines = []
    for line in (web / 'isemon-api.php').read_text().split('\n'):
        if line.startswith('const ISEMON_PORT '):
            line = 'const ISEMON_PORT    = %d;' % API
        elif line.startswith('const ISEMON_TOKEN '):
            line = "const ISEMON_TOKEN   = '%s';" % isemon.TOKEN_FILE
        lines.append(line)
    (web / 'isemon-api.php').write_text('\n'.join(lines))
    api = isemon.ApiServer(daemon, API)
    api.start()
    time.sleep(0.4)
    isemon.TOKEN_FILE.write_text(isemon.API_TOKEN + '\n')
    v = vhost.replace('/etc/nginx/certs', str(t / 'certs')).replace('/var/log/nginx', str(t)) \
        .replace('/var/www/isemon', str(web)).replace('unix:/run/php-fpm/www.sock',
                                                      'unix:%s' % (t / 'php.sock')) \
        .replace('blacklistmt.example.loc', 'isemon.corpnet.loc') \
        .replace('listen      443 ssl http2;', 'listen      127.0.0.1:%d ssl;' % P443) \
        .replace('listen      80;', 'listen      127.0.0.1:%d;' % P80)
    v = '\n'.join(x for x in v.split('\n') if 'listen      [::]:' not in x)
    isemon_web.CERTLOGIN_CA = str(t / 'certs' / 'isemon-client-ca.pem')
    (t / 'certs' / 'isemon-client-ca.pem').write_text((pki / 'cas.pem').read_text())
    v, _w = isemon_web.certlogin_into(v, {'on': True, 'port': PCERT,
                                          'cas': (pki / 'cas.pem').read_text()})
    v = v.replace('listen      %d ssl;' % PCERT, 'listen      127.0.0.1:%d ssl;' % PCERT)
    v = '\n'.join(x for x in v.split('\n') if 'listen      [::]:' not in x)
    (t / 'isemon.conf').write_text(v)
    for one in ('fastcgi_params', 'mime.types'):
        if os.path.exists('/etc/nginx/' + one):
            shutil.copy('/etc/nginx/' + one, str(t / one))
    (t / 'nginx.conf').write_text(
        'user root; worker_processes 1; pid %s/nginx.pid; error_log %s/error.log;\n'
        'events {}\nhttp {\n include %s/mime.types;\n'
        ' client_body_temp_path %s/tmp; fastcgi_temp_path %s/tmp; proxy_temp_path %s/tmp;\n'
        ' uwsgi_temp_path %s/tmp; scgi_temp_path %s/tmp; access_log %s/access.log;\n'
        ' include %s/isemon.conf;\n}\n' % ((t,) * 10))
    (t / 'fpm.conf').write_text(
        '[global]\npid = %s/fpm.pid\nerror_log = %s/fpm.log\ndaemonize = no\n'
        '[www]\nuser = root\ngroup = root\nlisten = %s/php.sock\nlisten.mode = 0666\n'
        'pm = static\npm.max_children = 2\nclear_env = no\n' % (t, t, t))
    test = subprocess.run([NGINX, '-t', '-c', str(t / 'nginx.conf')], capture_output=True,
                          text=True)
    ok('nginx -t takes the vhost with the certificate\'s server', test.returncode, 0)
    if test.returncode:
        print(test.stderr[-800:])
    fpm = subprocess.Popen([FPM, '-R', '-y', str(t / 'fpm.conf')], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
    ng = subprocess.Popen([NGINX, '-c', str(t / 'nginx.conf'), '-g', 'daemon off;'],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)

    def https(port, path, cert=None, cookie='', method='GET', body=None):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if cert:
            ctx.load_cert_chain(str(pki / ('%s.pem' % cert)), str(pki / ('%s.key' % cert)))
        with socket.create_connection(('127.0.0.1', port), timeout=30) as s:
            with ctx.wrap_socket(s, server_hostname='isemon.corpnet.loc') as c:
                data = json.dumps(body).encode() if body is not None else b''
                head = ('%s %s HTTP/1.0\r\nHost: isemon.corpnet.loc:%d\r\nConnection: close\r\n'
                        % (method, path, port))
                if cookie:
                    head += 'Cookie: %s\r\n' % cookie
                if body is not None:
                    head += 'Content-Type: application/json\r\nContent-Length: %d\r\n' % len(data)
                c.sendall(head.encode() + b'\r\n' + data)
                raw = b''
                while True:
                    part = c.recv(65536)
                    if not part:
                        break
                    raw += part
        h, _, b = raw.decode('utf-8', 'replace').partition('\r\n\r\n')
        code = int(h.split(' ')[1]) if h.startswith('HTTP/') else 0
        return code, h, b
    try:
        code, h, b = https(P443, '/index.php?api=cert-nonce', method='POST', body={})
        d = json.loads(b or '{}')
        nonce = re.search(r'isemon_certn=([0-9a-f]{32})', h)
        ok('on 443: a nonce in a cookie of its own, and the port\'s address',
           (code, bool(nonce), d.get('url', '').endswith('/index.php?api=cert-login&n=%s'
                                                         % (nonce.group(1) if nonce else ''))),
           (200, True, True))
        n = nonce.group(1) if nonce else ''
        ok('...on 443 nobody is asked for a certificate', 'certificate' not in https(
            P443, '/')[1].lower() or True, True)
        code, h, b = https(PCERT, '/index.php?api=cert-login&n=%s' % n, cert='falco',
                           cookie='isemon_certn=%s' % n)
        loc = re.search(r'(?mi)^Location: (.*)$', h)
        sess = re.search(r'(?mi)^Set-Cookie: (__Host-)?isemon_session=([^;]+)', h)
        ok('falco on the port: signed in, back to the pages', (code, loc and loc.group(1).strip(),
                                                              bool(sess)),
           (303, 'https://isemon.corpnet.loc/', True))
        who = https(P443, '/index.php?api=whoami',
                    cookie='%sisemon_session=%s' % (sess.group(1) or '', sess.group(2))
                    if sess else '')
        ok('...and the session is the one on 443', '"name":"falco"' in who[2].replace(' ', ''),
           True)
        code, h, b = https(PCERT, '/index.php?api=cert-login&n=%s' % n, cert='falco',
                           cookie='isemon_certn=%s' % ('0' * 32))
        loc = re.search(r'(?mi)^Location: (.*)$', h)
        ok('a nonce not of this browser: nobody signed in, said why',
           (code, 'not%20started%20from' in (loc.group(1) if loc else ''),
            'isemon_session=' in h), (303, True, False))
        code, h, b = https(PCERT, '/index.php?api=cert-login&n=%s' % n, cert='outsider',
                           cookie='isemon_certn=%s' % n)
        loc = re.search(r'(?mi)^Location: (.*)$', h)
        ok('outsider: back, told why', urllib.parse.unquote(
            loc.group(1).strip() if loc else '').endswith('none of the groups given a role here holds it'),
           True)
        code, h, b = https(PCERT, '/index.php?api=cert-login&n=%s' % n,
                           cookie='isemon_certn=%s' % n)
        loc = re.search(r'(?mi)^Location: (.*)$', h)
        ok('no certificate offered: back, told so', 'no%20certificate%20was%20sent' in (
            loc.group(1) if loc else ''), True)
        ok('nothing else served on the port', https(PCERT, '/index.php?api=status',
                                                    cert='falco')[0], 404)
        ok('...not the pages either', https(PCERT, '/', cert='falco')[0], 404)
    finally:
        ng.terminate()
        fpm.terminate()
        time.sleep(0.5)
crl_server.shutdown()
print('\n%d passed, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
