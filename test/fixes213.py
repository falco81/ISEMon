#!/usr/bin/env python3
"""1.10.213: "TLS without a certificate" against an api-ssl that has one,
and against one that has none."""
import socket
import ssl
import sys
import tempfile
import threading
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
sys.argv = ['isemon']
import isemon  # noqa: E402

PASS = FAIL = 0


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    ' + what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


folder = Path(tempfile.mkdtemp(prefix='fixes213-'))
cert, key, fp = isemon.rosapi_make_certificate('127.0.0.1')
(folder / 'c.crt').write_text(cert)
(folder / 'c.key').write_text(key)
import subprocess  # noqa: E402
subprocess.run(['openssl', 'genpkey', '-genparam', '-algorithm', 'DH', '-pkeyopt',
                'dh_param:ffdhe2048', '-out', str(folder / 'dh.pem')], capture_output=True,
               timeout=60)


def handshake(ciphers, with_cert=True, mode='anon'):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if with_cert:
        ctx.load_cert_chain(str(folder / 'c.crt'), str(folder / 'c.key'))
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    if (folder / 'dh.pem').exists():
        ctx.load_dh_params(str(folder / 'dh.pem'))
    ctx.set_ciphers(ciphers)
    srv = socket.socket()
    srv.bind(('127.0.0.1', 0))
    srv.listen(1)
    got = {}

    def serve():
        c, _ = srv.accept()
        try:
            s = ctx.wrap_socket(c, server_side=True)
            got['cipher'] = s.cipher()[0]
            s.close()
        except (ssl.SSLError, OSError) as e:
            got['refused'] = str(e)
    th = threading.Thread(target=serve, daemon=True)
    th.start()
    said = ''
    try:
        isemon.RosApi('127.0.0.1', srv.getsockname()[1], mode, 'u', 'p', '', timeout=5).connect()
    except isemon.RosApiError as e:
        said = str(e)
    th.join(5)
    srv.close()
    return got, said


print('\nTLS without a certificate')
got, said = handshake('ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:@SECLEVEL=0')
ok('a router whose api-ssl has a certificate, old suites only: agreed',
   (got.get('cipher'), 'TLS with' in said), ('ECDHE-RSA-AES256-SHA', False))
got, said = handshake('ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA:@SECLEVEL=0')
ok('...one with GCM: GCM', got.get('cipher'), 'ECDHE-RSA-AES256-GCM-SHA384')
got, said = handshake('ADH-AES256-GCM-SHA384:ADH-AES128-SHA256:@SECLEVEL=0', with_cert=False)
ok('...and one with no certificate: anonymous, as before',
   (got.get('cipher'), 'TLS with' in said), ('ADH-AES256-GCM-SHA384', False))
got, said = handshake('ADH-AES256-GCM-SHA384:@SECLEVEL=0', with_cert=False, mode='pin')
ok('pinned against a router with no certificate still refuses, and says why',
   'TLS with' in said and 'flag K' in said, True)

print('\nTLS, its certificate checked by an authority')
ca_dir = folder / 'ca'
ca_dir.mkdir()


def run(*argv):
    return subprocess.run(list(argv), capture_output=True, timeout=60, cwd=str(ca_dir))


run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '30', '-subj',
    '/CN=Test Authority', '-keyout', 'ca.key', '-out', 'ca.crt')
run('openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=gw.example.net',
    '-keyout', 'gw.key', '-out', 'gw.csr')
(ca_dir / 'ext').write_text('subjectAltName=DNS:gw.example.net\n')
run('openssl', 'x509', '-req', '-in', 'gw.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key',
    '-CAcreateserial', '-days', '30', '-extfile', 'ext', '-out', 'gw.crt')
CA = (ca_dir / 'ca.crt').read_text()
page = (HERE / 'web' / 'index.php').read_text(encoding='utf-8')
src = (HERE / 'isemon.py').read_text(encoding='utf-8')


def checked(ca='', tls_name='', host='127.0.0.1', verify=True):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(ca_dir / 'gw.crt'), str(ca_dir / 'gw.key'))
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers('ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES256-GCM-SHA384:@SECLEVEL=0')
    srv = socket.socket()
    srv.bind(('127.0.0.1', 0))
    srv.listen(1)
    got = {}

    def serve():
        c, _ = srv.accept()
        try:
            s = ctx.wrap_socket(c, server_side=True)
            got['cipher'] = s.cipher()[0]
            s.close()
        except (ssl.SSLError, OSError) as e:
            got['refused'] = str(e)
    th = threading.Thread(target=serve, daemon=True)
    th.start()
    said = ''
    try:
        isemon.RosApi(host, srv.getsockname()[1], 'ca', 'u', 'p', '', timeout=5, ca=ca,
                      tls_name=tls_name, verify=verify).connect()
    except isemon.RosApiError as e:
        said = str(e)
    th.join(5)
    srv.close()
    return got, said


got, said = checked(CA, 'gw.example.net')
ok('signed by the authority given, for the name said: on to the sign-in',
   (bool(got.get('cipher')), 'not one this trusts' in said, 'TLS with' in said), (True, False, False))
got, said = checked(CA, '')
ok('...reached by its address, not the name on it: refused, and told where to write the name',
   ('not one this trusts' in said, 'The name on its certificate' in said), (True, True))
got, said = checked('', '', verify=False)
ok('...with the checking switched off: any certificate, any name, still encrypted',
   (bool(got.get('cipher')), 'TLS with' in said, 'not one this trusts' in said),
   (True, False, False))
ok('...the switch saved as it is, on by default',
   (isemon.rosapi_checked({'on': 1, 'host': 'gw', 'mode': 'ca'}, 'gw')['verify'],
    isemon.rosapi_checked({'on': 1, 'host': 'gw', 'mode': 'ca', 'verify': 0}, 'gw')['verify']),
   (1, 0))
ok('...and offered on the page', "item('Check its certificate', vsw," in page
   and "if (one.api.mode === 'ca') out.api.verify" in page)
got, said = checked('', 'gw.example.net')
ok('...an authority this machine does not trust: refused, and told to give it',
   ('not one this trusts' in said, 'Use my own authority' in said), (True, True))
ok('an authority pasted: every certificate in it, checked', isemon.rosapi_ca_pem('x\n' + CA), CA)
for bad in ('', 'hello', '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----'):
    try:
        isemon.rosapi_ca_pem(bad)
        said = None
    except ValueError as e:
        said = str(e)
    ok('...refused, said why: %r' % bad[:20], bool(said), True)
ok('...and shown by how many and the fingerprint of the first',
   isemon.rosapi_ca_said(CA)['n'], 1)
ok('the settings take it, with the name to check for',
   (isemon.rosapi_checked({'on': 1, 'host': '192.168.42.1', 'mode': 'ca',
                           'tls_name': 'gw.falco81.net'}, 'gw')['tls_name'],
    isemon.rosapi_checked({'on': 1, 'host': '192.168.42.1', 'mode': 'ca'}, 'gw')['port']),
   ('gw.falco81.net', 8729))
try:
    isemon.rosapi_checked({'on': 1, 'host': 'gw', 'mode': 'ca', 'tls_name': 'a b;c'}, 'gw')
    said = None
except ValueError as e:
    said = str(e)
ok('...but not a name no certificate carries', bool(said), True)
ok('the page offers it, the name to check for, and the authority\'s panel',
   all(w in page for w in ("['ca', 'TLS, its certificate checked by an authority (api-ssl, 8729)']",
                           "item('The name on its certificate'", "function rosApiCaPanel(",
                           "do: 'ca', name: name", "do: 'ca-forget'")))
ok('...and the daemon keeps it and reads with it',
   "if what == 'ca':" in src and "get_meta('rosapi_ca_%s' % self.name" in src)
ok('how one signs in over ssh - a key or a password - is saved, and kept when drawn again',
   "if (one.api.auth) out.api.auth = one.api.auth;" in page
   and "auth: String(a.auth || 'key') === 'password' ? 'password' : 'key'," in page)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
