#!/usr/bin/env python3
"""1.10.212: TLS to a RouterOS api-ssl that speaks only the AES-CBC/SHA-1
suites, which Python leaves out by default."""
import hashlib
import os
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


folder = Path(tempfile.mkdtemp(prefix='fixes212-'))
cert, key, fp = isemon.rosapi_make_certificate('127.0.0.1')
(folder / 'c.crt').write_text(cert)
(folder / 'c.key').write_text(key)


def handshake(ciphers, pin=fp):
    """A router offering only `ciphers` over TLS 1.2: what it agreed, and
    what this machine said."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(folder / 'c.crt'), str(folder / 'c.key'))
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
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
        isemon.RosApi('127.0.0.1', srv.getsockname()[1], 'pin', 'u', 'p', pin,
                      timeout=5).connect()
    except isemon.RosApiError as e:
        said = str(e)
    th.join(5)
    srv.close()
    return got, said


print('\nTLS to api-ssl as RouterOS speaks it')
for suites in ('ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:@SECLEVEL=0',
               'AES256-SHA:AES128-SHA:@SECLEVEL=0'):
    got, said = handshake(suites)
    ok('a router offering only %s: agreed, and on to the sign-in' % suites.split(':')[0],
       (got.get('cipher'), 'TLS with' in said), (suites.split(':')[0], False))
got, said = handshake('ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA:@SECLEVEL=0')
ok('...one that has GCM as well: GCM', got.get('cipher'), 'ECDHE-RSA-AES256-GCM-SHA384')
got, said = handshake('ECDHE-RSA-AES256-SHA:@SECLEVEL=0', pin='ab' * 32)
ok('...and the certificate is still checked by its fingerprint',
   'another certificate than the one pinned' in said, True)
src = (HERE / 'isemon.py').read_text(encoding='utf-8')
ok('a handshake that fails says what to look at on the router',
   'flag K' in src and 'no common ciphers' in src, True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
