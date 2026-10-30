#!/usr/bin/env python3
"""1.10.245: the otp logs received over TLS - Settings → The OTP logs →
Encrypted receiving, for otp 1.0.172's Settings → isemon → Encrypted sending.

The file otp makes (isemon-tls.zip, AES-256) is opened in memory - the one
in test/otp-tls/ is written by pyzipper, not by isemon - and root's helper
(otptls.ask, otptls.json) puts rsyslog's encrypted input in, beside the plain
one, which is never touched. rsyslog is a small script here (its version and
whether -N1 takes the files are the test's to say), the files are in folders
of the test's own and no service is restarted (ISEMON_WEB_NO_SERVICES): what
is checked is what is written, what is refused, and that everything is put
back when rsyslog says no.

    ./test/fixes245_otptls.py
"""
import base64
import json
import re
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
os.environ['ISEMON_WEB_HELPER'] = '1'
import isemon                                        # noqa: E402

PASS = FAIL = 0
PW = 'correct-horse-battery'
ZIP = (HERE / 'otp-tls' / 'isemon-tls.zip').read_bytes()


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


work = Path(tempfile.mkdtemp(prefix='isemon-245-'))
state = work / 'state'
(state / 'web').mkdir(parents=True)
etc = work / 'etc'
rsd = etc / 'rsyslog.d'
rsd.mkdir(parents=True)
(etc / 'rsyslog.conf').write_text('module(load="imuxsock")\n$IncludeConfig /etc/rsyslog.d/*.conf\n')
PLAIN = ('module(load="imudp")\ninput(type="imudp" port="514")\n'
         'module(load="imtcp")\ninput(type="imtcp" port="514")\n')
(rsd / '10-ise.conf').write_text(PLAIN)
(rsd / '11-otp.conf').write_text('if ($programname == "totp.cgi") then { stop }\n')
PKI = etc / 'pki' / 'rsyslog' / 'otp'
CONF = rsd / '99-otp-tls.conf'
OLD = rsd / '10-otp-tls.conf'
mods = work / 'lib64-rsyslog'
mods.mkdir()
(mods / 'lmnsd_gtls.so').write_text('')
VERSION = work / 'rsyslog-version'
BAD = work / 'rsyslog-bad'
VERSION.write_text('8.2310.0')
rsyslogd = work / 'rsyslogd'
rsyslogd.write_text('#!/bin/sh\ncase "$1" in\n'
                    '  -v) echo "rsyslogd  $(cat %s) (aka 2023.10) compiled with:"; exit 0;;\n'
                    '  -N1) [ -f %s ] && { echo "rsyslogd: error during config processing" >&2; '
                    'exit 1; }; exit 0;;\nesac\nexit 1\n' % (VERSION, BAD))
rsyslogd.chmod(0o755)
ENV = dict(os.environ, ISEMON_STATE=str(state), ISEMON_WEB_NO_SERVICES='1',
           ISEMON_RSYSLOG='%s:%s' % (etc / 'rsyslog.conf', rsd),
           ISEMON_OTPTLS_CONF=str(CONF), ISEMON_OTPTLS_OLD=str(OLD), ISEMON_OTPTLS_DIR=str(PKI),
           ISEMON_RSYSLOGD=str(rsyslogd), ISEMON_RSYSLOG_MODDIR=str(mods),
           ISEMON_NGINX_CONF=str(work / 'none.conf'))
HELPER = ROOT / 'deploy' / 'isemon_web.py'


def ask(req, fresh=True):
    if fresh and 'at' not in req:
        req = dict(req, at=time.time())
    (state / 'web' / 'otptls.ask').write_text(json.dumps(req))
    got = subprocess.run(['python3', '-I', str(HELPER)], env=ENV, capture_output=True, text=True)
    if got.returncode:
        print(got.stderr)
    return json.loads((state / 'web' / 'otptls.json').read_text())


def mode(p):
    return stat.S_IMODE(os.lstat(str(p)).st_mode)


def certs_of(path):
    return Path(path).read_text().count('BEGIN CERTIFICATE')


try:
    # ------------------------------------------------------------------------
    print('The file otp makes (isemon-tls.zip, AES-256)')
    files = isemon.otp_zip_open(ZIP, PW)
    ok('opened: what otp puts in it', sorted(files),
       ['10-otp-tls.conf', 'README.txt', 'ca.pem', 'isemon.crt', 'isemon.key'])
    ok('...the key as it was written', files['isemon.key'].startswith(b'-----BEGIN PRIVATE KEY'))
    try:
        isemon.otp_zip_open(ZIP, 'not-the-passphrase')
        ok('a wrong passphrase refused', False)
    except PermissionError as e:
        ok('a wrong passphrase refused, and said so', 'passphrase' in str(e))
    small = isemon.otp_zip_open((HERE / 'otp-tls' / 'aes128-stored.zip').read_bytes(), PW)
    ok('AES-128, stored rather than deflated: opened too', list(small), ['ca.pem'])
    bad = bytearray(ZIP)
    bad[200] ^= 0xff
    try:
        isemon.otp_zip_open(bytes(bad), PW)
        ok('a damaged file refused', False)
    except (ValueError, PermissionError):
        ok('a damaged file refused', True)
    try:
        isemon.otp_zip_open(b'not a zip at all', PW)
        ok('not a zip: refused', False)
    except ValueError as e:
        ok('not a zip: refused, and said so', 'not a zip' in str(e))
    # Without the cryptography module: openssl does the AES.
    real = sys.modules.get('cryptography')
    for name in ('cryptography', 'cryptography.hazmat', 'cryptography.hazmat.primitives',
                 'cryptography.hazmat.primitives.ciphers'):
        sys.modules[name] = None
    try:
        ok('without the cryptography module (openssl does the AES)',
           isemon.otp_zip_open(ZIP, PW)['isemon.crt'], files['isemon.crt'])
    finally:
        for name in ('cryptography', 'cryptography.hazmat', 'cryptography.hazmat.primitives',
                     'cryptography.hazmat.primitives.ciphers'):
            sys.modules.pop(name, None)
        if real is not None:
            sys.modules['cryptography'] = real

    got = isemon.otptls_open_zip(ZIP, PW)
    ok('what the page is shown: the certificate, its names and its issuer',
       (got['cert']['subject'], got['cert']['names'], got['cert']['issuer']),
       ('CN=isemon.example.net', ['isemon.example.net', '192.0.2.10'],
        'CN=otp cluster authority'))
    ok('...the port, the mode and the nodes from otp\'s 10-otp-tls.conf', got['conf'],
       {'port': 6514, 'mutual': True, 'peers': ['otp1', 'otp2']})
    ok('...and never the key', 'PRIVATE' in json.dumps(got), False)
    ok('...held here by a token, ten minutes', got['token'] in isemon.OTPTLS_OPENED)
    held = isemon.OTPTLS_OPENED[got['token']]

    # ------------------------------------------------------------------------
    print('\nRoot\'s helper: the file otp made, put in')
    r = ask({'id': 'a1', 'do': 'read'})
    ok('a read before: nothing there, nothing written', (r['ok'], r['data']['conf'], PKI.exists()),
       (True, {'there': False}, False))
    ok('...the driver there is and rsyslog\'s version', (r['data']['driver_there'],
                                                         r['data']['version']),
       ('gtls', '8.2310'))
    before_plain = (rsd / '10-ise.conf').read_text()
    r = ask({'id': 'a2', 'do': 'apply', 'ca': held['ca'], 'cert': held['cert'],
             'key': held['key'], 'port': 6514, 'mutual': True, 'peers': 'otp1 otp2',
             'how': 'otp'})
    ok('put in', (r['ok'], r['id']), (True, 'a2'))
    if not r['ok']:
        print(r)
    ok('...said what it did', any('6514/tcp' in s and 'otp1, otp2' in s for s in r['said']))
    ok('...the folder root\'s alone, the key 0600', (mode(PKI), mode(PKI / 'isemon.key'),
                                                    mode(PKI / 'isemon.crt'),
                                                    mode(PKI / 'ca.pem')),
       (0o750, 0o600, 0o644, 0o644))
    ok('...the files are the ones otp made', ((PKI / 'isemon.key').read_text().strip(),
                                             (PKI / 'ca.pem').read_text().strip()),
       (held['key'].strip(), held['ca'].strip()))
    text = CONF.read_text()
    ok('...rsyslog\'s file is isemon\'s own, marked', '# isemon: the otp logs over TLS' in text)
    ok('...the TLS files per input (rsyslog 8.2108 and later), no global()',
       ('StreamDriver.CertFile="%s"' % (PKI / 'isemon.crt') in text, 'global(' in text),
       (True, False))
    ok('...mutual TLS: the nodes by name', ('StreamDriver.AuthMode="x509/name"' in text,
                                           'PermittedPeer=["otp1", "otp2"]' in text), (True, True))
    ok('...imtcp loaded already (10-ise.conf): not loaded twice',
       'module(load="imtcp")' in text, False)
    ok('...the plain input untouched', (rsd / '10-ise.conf').read_text(), before_plain)
    ok('...nothing of otp\'s file put in as it is', 'DefaultNetstreamDriver' in text, False)
    v = r['data']
    ok('the read after: on, its port, its mode, its nodes, its certificate',
       (v['conf']['mine'], v['conf']['port'], v['conf']['auth'], v['conf']['peers'],
        v['cert']['names'], v['how']),
       (True, 6514, 'x509/name', ['otp1', 'otp2'], ['isemon.example.net', '192.0.2.10'], 'otp'))
    ok('...the plain input is said beside it', [p['port'] for p in v['others']
                                               if p['proto'] == 'tcp'], ['514'])
    ok('...the key never in the answer', 'PRIVATE' in (state / 'web' / 'otptls.json').read_text(),
       False)
    ok('...the question taken away (it held the key)', (state / 'web' / 'otptls.ask').exists(),
       False)

    print('\nWhat is refused')
    r = ask({'id': 'b1', 'do': 'apply', 'ca': held['ca'], 'cert': held['cert'], 'key': held['key'],
             'port': 514, 'mutual': False})
    ok('514: the plain logs\' port', (r['ok'], '514' in r['said']), (False, True))
    (rsd / '20-other.conf').write_text('input(type="imtcp" port="6600")\n')
    r = ask({'id': 'b2', 'do': 'set', 'port': 6600, 'mutual': False})
    ok('a port rsyslog listens on already', (r['ok'], 'listens on 6600/tcp already' in r['said']),
       (False, True))
    (rsd / '20-other.conf').unlink()
    r = ask({'id': 'b3', 'do': 'set', 'port': 6514, 'mutual': True, 'peers': 'otp1 "; drop'})
    ok('a node\'s name that is no name', (r['ok'], 'is not a name' in r['said']), (False, True))
    other_key = subprocess.run(['openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt',
                                'ec_paramgen_curve:P-256'], capture_output=True,
                               text=True).stdout
    r = ask({'id': 'b4', 'do': 'apply', 'ca': held['ca'], 'cert': held['cert'], 'key': other_key,
             'port': 6514, 'mutual': False})
    ok('a key that is not the certificate\'s', (r['ok'], 'not the one of this certificate' in
                                               r['said']), (False, True))
    r = ask({'id': 'b5', 'do': 'apply', 'ca': '', 'cert': held['cert'], 'key': held['key'],
             'port': 6514, 'mutual': True, 'peers': 'otp1'})
    ok('mutual TLS without otp\'s authority', (r['ok'], 'otp\'s authority' in r['said']),
       (False, True))
    r = ask({'id': 'b6', 'do': 'set', 'port': 6514, 'mutual': False,
             'at': time.time() - 3600}, fresh=False)
    ok('asked an hour ago: not done', (r['ok'], 'too long ago' in r['said']), (False, True))
    ok('...and after all that, the file as it was', CONF.read_text(), text)

    print('\nrsyslog says no: everything put back')
    BAD.write_text('1')
    r = ask({'id': 'c1', 'do': 'set', 'port': 6515, 'mutual': False})
    ok('refused, with what rsyslog said', (r['ok'], 'rsyslog does not take it' in r['said']),
       (False, True))
    ok('...the file as it was', CONF.read_text(), text)
    BAD.unlink()

    print('\nChanged: the nodes, the mode, the port')
    r = ask({'id': 'd1', 'do': 'set', 'port': 6514, 'mutual': True, 'peers': 'otp1, otp2 otp3'})
    ok('a node more', (r['ok'], 'PermittedPeer=["otp1", "otp2", "otp3"]' in CONF.read_text()),
       (True, True))
    r = ask({'id': 'd2', 'do': 'set', 'port': 6514, 'mutual': True, 'peers': ''})
    ok('mutual, no names: any node with a certificate of otp\'s authority',
       (r['ok'], 'AuthMode="x509/certvalid"' in CONF.read_text(),
        'PermittedPeer' in CONF.read_text()), (True, True, False))
    r = ask({'id': 'd3', 'do': 'set', 'port': 16514, 'mutual': False})
    ok('not mutual, another port: anon', (r['ok'], 'AuthMode="anon"' in CONF.read_text(),
                                          'port="16514"' in CONF.read_text()), (True, True, True))
    ok('...the certificate kept as it was', (PKI / 'isemon.key').read_text().strip(),
       held['key'].strip())

    print('\nSwitched off')
    r = ask({'id': 'e1', 'do': 'off'})
    ok('the encrypted input gone, the plain one as it was',
       (r['ok'], CONF.exists(), (rsd / '10-ise.conf').read_text()), (True, False, before_plain))
    ok('...the certificate and its key stay, to switch it on again',
       ((PKI / 'isemon.key').exists(), (PKI / 'isemon.crt').exists()), (True, True))
    r = ask({'id': 'e2', 'do': 'set', 'port': 6514, 'mutual': True, 'peers': 'otp1'})
    ok('...and on again from them', (r['ok'], CONF.exists()), (True, True))

    print('\nA certificate made here, by an authority of this machine\'s own')
    r = ask({'id': 'f1', 'do': 'make', 'names': 'isemon.example.net 192.0.2.10', 'port': 6514,
             'mutual': True, 'peers': 'otp1 otp2', 'otp_ca': held['ca']})
    ok('made and put in', r['ok'])
    if not r['ok']:
        print(r)
    ok('...the authority\'s key root\'s alone', (mode(PKI / 'isemon-ca.key'),
                                                mode(PKI / 'isemon.key')), (0o600, 0o600))
    v = r['data']
    ok('...the certificate for the names asked, from this machine\'s authority',
       (v['cert']['names'], v['cert']['issuer'] == v['own_ca']['subject'], v['how']),
       (['isemon.example.net', '192.0.2.10'], True, 'made'))
    ok('...the authority\'s certificate handed to the page, to paste into otp',
       v['own_ca']['pem'].startswith('-----BEGIN CERTIFICATE-----'))
    ok('...its key never', 'PRIVATE' in (state / 'web' / 'otptls.json').read_text(), False)
    ok('...ca.pem: otp\'s authority (the nodes) and this machine\'s', certs_of(PKI / 'ca.pem'), 2)
    chk = subprocess.run(['openssl', 'verify', '-CAfile', str(PKI / 'isemon-ca.crt'),
                          str(PKI / 'isemon.crt')], capture_output=True, text=True)
    ok('...openssl: the certificate is the authority\'s', chk.returncode, 0)
    ca_before = (PKI / 'isemon-ca.crt').read_text()
    r = ask({'id': 'f2', 'do': 'make', 'names': 'isemon.example.net', 'port': 6514,
             'mutual': False})
    ok('made again: the same authority (otp trusts it as it is), a new certificate',
       (r['ok'], (PKI / 'isemon-ca.crt').read_text() == ca_before,
        r['data']['cert']['names']), (True, True, ['isemon.example.net']))
    r = ask({'id': 'f2b', 'do': 'set', 'port': 6514, 'mutual': True, 'peers': 'otp1'})
    ok('made without otp\'s authority: mutual TLS refused until it is given',
       (r['ok'], 'otp\'s authority' in r.get('said', '')), (False, True))
    r = ask({'id': 'f2c', 'do': 'set', 'port': 6514, 'mutual': True, 'peers': 'otp1',
             'otp_ca': held['ca']})
    ok('...given: taken beside this machine\'s authority', (r['ok'], certs_of(PKI / 'ca.pem')),
       (True, 2))
    r = ask({'id': 'f3', 'do': 'make', 'names': '', 'port': 6514, 'mutual': False})
    ok('no name: refused', (r['ok'], 'one at least' in r['said']), (False, True))

    print('\nOne set up by hand before, as otp\'s README says (10-otp-tls.conf)')
    CONF.unlink()
    OLD.write_text('# by hand\nmodule(load="imtcp")\ninput(type="imtcp" port="6514")\n')
    r = ask({'id': 'g1', 'do': 'read'})
    ok('read as not isemon\'s, the file it is said', (r['data']['conf']['there'],
                                                    r['data']['conf']['mine'], r['data']['file']),
       (True, False, str(OLD)))
    r = ask({'id': 'g2', 'do': 'set', 'port': 6514, 'mutual': False})
    ok('set here: isemon\'s 99-otp-tls.conf, the one by hand kept beside - never loaded - and '
       'taken away (6514 is not taken twice)',
       (r['ok'], CONF.exists(), OLD.exists(),
        Path(str(OLD) + '.isemon-before').read_text().startswith('# by hand'),
        str(OLD.name + '.isemon-before').endswith('.conf')), (True, True, False, True, False))

    print('\nisemon 1.10.245\'s own 10-otp-tls.conf: taken over')
    OLD.write_text(CONF.read_text())
    CONF.unlink()
    r = ask({'id': 'g3', 'do': 'read'})
    ok('read as isemon\'s, by its old name', (r['data']['conf']['mine'], r['data']['file']),
       (True, str(OLD)))
    r = ask({'id': 'g4', 'do': 'set', 'port': 6514, 'mutual': False})
    ok('set again: 99-otp-tls.conf, the old one gone and not kept beside again',
       (r['ok'], CONF.exists(), OLD.exists(),
        Path(str(OLD) + '.isemon-before').read_text().startswith('# by hand')),
       (True, True, False, True))

    # The fault 1.10.245 had on a real machine: imtcp loaded by a file read
    # AFTER 10-otp-tls.conf (10-remote-logs.conf) - rsyslog refused the
    # input ("input module name 'imtcp' is unknown", every TLS parameter
    # "not known"). Checked with the real rsyslogd where there is one.
    real = shutil.which('rsyslogd')
    if real:
        print('\nThe real rsyslogd (%s): imtcp loaded by a file read after 10-otp' %
              subprocess.run([real, '-v'], capture_output=True, text=True).stdout.split('(')[0]
              .strip())
        main = etc / 'rsyslog-real.conf'
        main.write_text('$IncludeConfig %s/*.conf\naction(type="omfile" file="/dev/null")\n' % rsd)
        wrap = work / 'rsyslogd-real'
        wrap.write_text('#!/bin/sh\n[ "$1" = "-N1" ] && exec %s -N1 -f %s\nexec %s "$@"\n'
                        % (real, main, real))
        wrap.chmod(0o755)
        for f in rsd.iterdir():
            f.unlink()
        (rsd / '10-remote-logs.conf').write_text(
            'module(load="imudp")\ninput(type="imudp" port="514")\n'
            'module(load="imtcp")\ninput(type="imtcp" port="514")\n')
        (rsd / '11-otp.conf').write_text('if ($programname == "totp.cgi") then { stop }\n')
        OLD.write_text('input(type="imtcp" port="6514" name="otp-tls"\n'
                       '      StreamDriver.Name="gtls" StreamDriver.Mode="1"\n'
                       '      StreamDriver.AuthMode="anon")\n')
        chk = subprocess.run([str(wrap), '-N1'], capture_output=True, text=True)
        ok('...the fault as it was: rsyslog refuses a file named 10-otp-tls.conf',
           ('imtcp\' is unknown' in chk.stderr + chk.stdout, chk.returncode != 0), (True, True))
        OLD.unlink()
        env_real = dict(ENV, ISEMON_RSYSLOGD=str(wrap))
        env_real.pop('ISEMON_RSYSLOG_MODDIR')
        for one in ({'do': 'apply', 'ca': held['ca'], 'cert': held['cert'], 'key': held['key'],
                     'port': 6514, 'mutual': True, 'peers': 'otp1 otp2', 'how': 'otp'},
                    {'do': 'set', 'port': 6514, 'mutual': True, 'peers': ''},
                    {'do': 'set', 'port': 6514, 'mutual': False}):
            (state / 'web' / 'otptls.ask').write_text(json.dumps(dict(one, id='r', at=time.time())))
            subprocess.run(['python3', '-I', str(HELPER)], env=env_real, capture_output=True)
            r = json.loads((state / 'web' / 'otptls.json').read_text())
            ok('rsyslog takes it: %s' % (r['data']['conf'].get('auth') if r['ok'] else one),
               (r['ok'], r.get('said') if not r['ok'] else ''), (True, ''))
        chk = subprocess.run([str(wrap), '-N1'], capture_output=True, text=True)
        ok('...rsyslogd -N1 of the whole: no error', [l for l in (chk.stderr + chk.stdout)
                                                     .splitlines() if 'error' in l.lower()], [])
        (rsd / '10-remote-logs.conf').unlink()
        (rsd / '10-ise.conf').write_text(PLAIN)

    print('\nrsyslog\'s version')
    VERSION.write_text('8.2106.0')
    r = ask({'id': 'h1', 'do': 'set', 'port': 6514, 'mutual': False})
    ok('8.2106: the TLS files in global()', (r['ok'], 'global(' in CONF.read_text(),
                                             'DefaultNetstreamDriverKeyFile' in CONF.read_text()),
       (True, True, True))
    (rsd / '30-relp.conf').write_text('global(DefaultNetstreamDriverCAFile="/x.pem")\n')
    r = ask({'id': 'h2', 'do': 'set', 'port': 6514, 'mutual': False})
    ok('...refused when another file sets them already', (r['ok'], '30-relp.conf' in r['said']),
       (False, True))
    (rsd / '30-relp.conf').unlink()
    VERSION.write_text('8.2102.0')
    r = ask({'id': 'h3', 'do': 'set', 'port': 6514, 'mutual': False})
    ok('8.2102 (RHEL 8): refused, and said why', (r['ok'], '8.2106 or later' in r['said']),
       (False, True))
    VERSION.write_text('8.2310.0')

    print('\nNo imtcp anywhere else: loaded here')
    (rsd / '10-ise.conf').write_text('module(load="imudp")\ninput(type="imudp" port="514")\n')
    r = ask({'id': 'i1', 'do': 'set', 'port': 6514, 'mutual': False})
    ok('module(load="imtcp") in the file', (r['ok'], 'module(load="imtcp")' in CONF.read_text()),
       (True, True))
    (rsd / '10-ise.conf').write_text(PLAIN)

    print('\nNo TLS driver: ossl taken when it is the one there')
    (mods / 'lmnsd_gtls.so').unlink()
    (mods / 'lmnsd_ossl.so').write_text('')
    r = ask({'id': 'j1', 'do': 'set', 'port': 6514, 'mutual': False})
    ok('StreamDriver.Name="ossl"', (r['ok'], 'StreamDriver.Name="ossl"' in CONF.read_text()),
       (True, True))

    print('\nRemoved (1.10.246): the input, the certificate, its key and the authorities')
    ok('there before', (CONF.exists(), (PKI / 'isemon.key').exists()), (True, True))
    r = ask({'id': 'k1', 'do': 'remove'})
    ok('all of it gone, the folder too; the plain input as it was',
       (r['ok'], CONF.exists(), PKI.exists(), (rsd / '10-ise.conf').read_text()),
       (True, False, False, PLAIN))
    ok('...said', any('certificate, its key and the authorities' in w for w in r['said']))
    ok('...the read after: nothing', (r['data']['conf'], r['data'].get('cert'),
                                      r['data'].get('own_ca')), ({'there': False}, None, None))
    r = ask({'id': 'k2', 'do': 'remove'})
    ok('removed again: no fault', r['ok'])
    PKI.mkdir(parents=True)
    (PKI / 'isemon-ca.key').write_text('left from a set-up refused half way')
    r = ask({'id': 'k3', 'do': 'read'})
    ok('what is left in the folder is said (1.10.247), so Remove… has something to do',
       (r['data']['conf'], r['data']['left']), ({'there': False}, ['isemon-ca.key']))
    r = ask({'id': 'k4', 'do': 'remove'})
    ok('...and taken away', (r['ok'], PKI.exists()), (True, False))

    print('\nrsyslog\'s words about TLS: trouble only when something went wrong (1.10.248)')
    import importlib.util                               # noqa: E402
    spec = importlib.util.spec_from_file_location('isemon_web_248', str(HELPER))
    W = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(W)

    def trouble(line):
        return bool(re.search(W.TLS_WORDS, line, re.I) and re.search(W.TLS_BAD, line, re.I)
                    and not re.search(W.TLS_BENIGN, line, re.I))
    ok('starting up, listening: no trouble', [trouble(x) for x in (
        'rsyslogd: imtcp: module loaded, but no listeners defined',
        'rsyslogd: imtcp: listening on port 6514, driver gtls',
        'rsyslogd: [origin software="rsyslogd"] start')], [False, False, False])
    ok('a node hanging up (otp\'s Try it): no trouble', [trouble(x) for x in (
        'rsyslogd: unexpected GnuTLS error -110 - this could be caused by a broken connection',
        'rsyslogd: netstream session 0x55 from otp1 will be closed due to error',
        'rsyslogd[55121]: unexpected GnuTLS error -110 in nsd_gtls.c:646: The TLS connection was '
        'non-properly terminated.  [v8.2510.0-2.el9_8.2 try https://www.rsyslog.com/e/2078 ]',
        'rsyslogd[55121]: netstream session 0x7f6534004c0 from 192.168.42.32:38160 will be '
        'closed due to error [v8.2510.0-2.el9_8.2 try https://www.rsyslog.com/e/2078 ]')],
       [False, False, False, False])
    ok('a node refused, an authority not known, a certificate expired: trouble', [trouble(x) for x in (
        'rsyslogd: peer name not authorized - not permitted to talk to it. Names: DNS:otp3;',
        'rsyslogd: not permitted to talk to peer, certificate invalid: signer not found (unknown CA)',
        'rsyslogd: TLS certificate expired')], [True, True, True])

    # ------------------------------------------------------------------------
    print('\nThe daemon: the card\'s questions, done behind')
    isemon.STATE_DIR = state
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    store = isemon.Storage(state / 'isemon.db')

    class D(object):
        pass
    d = D()
    d.store = store
    wr = isemon.WebRoot(d)
    stop = threading.Event()

    def rootish():
        """isemon-web.path: the helper run whenever something is asked."""
        while not stop.is_set():
            if (state / 'web' / 'otptls.ask').exists() or (state / 'web' / 'look.ask').exists():
                subprocess.run(['python3', '-I', str(HELPER)], env=ENV, capture_output=True)
            time.sleep(0.1)
    t = threading.Thread(target=rootish, daemon=True)
    t.start()

    def settle(secs=30):
        end = time.time() + secs
        while time.time() < end and (isemon.OTPTLS_WORK['busy'] or isemon.OTPTLS_WORK['queue']):
            time.sleep(0.1)

    v = isemon.otptls_view(wr)
    settle()
    v = isemon.otptls_view(wr)
    ok('read by itself when the card is opened (removed just before: off)',
       (v['read'], v['on'], v['driver_there']), (True, False, 'ossl'))
    ok('...names this machine may be reached by, offered', bool(v['suggest']))
    got = isemon.otptls_api(wr, {'action': 'open', 'zip': base64.b64encode(ZIP).decode(),
                                 'passphrase': PW}, 'boss')
    ok('the file opened: what it holds, never the key', (got['conf']['peers'],
                                                        'PRIVATE' in json.dumps(got)),
       (['otp1', 'otp2'], False))
    try:
        isemon.otptls_api(wr, {'action': 'open', 'zip': base64.b64encode(ZIP).decode(),
                               'passphrase': 'nope'}, 'boss')
        ok('a wrong passphrase: said', False)
    except ValueError as e:
        ok('a wrong passphrase: said', 'passphrase' in str(e))
    isemon.otptls_api(wr, {'action': 'apply', 'token': got['token'], 'port': 6514,
                           'mutual': True, 'peers': got['conf']['peers']}, 'boss')
    try:
        isemon.otptls_api(wr, {'action': 'off'}, 'boss')
        ok('a second change while one is made: refused', False)
    except isemon.WebRootError as e:
        ok('a second change while one is made: refused', 'already' in str(e))
    settle()
    v = isemon.otptls_view(wr)
    ok('put in by root: the view says so', (v['on'], v['mine'], v['auth'], v['peers'],
                                           v['error'], v['last'].get('ok')),
       (True, True, 'x509/name', ['otp1', 'otp2'], '', True))
    ok('...the token is spent', got['token'] in isemon.OTPTLS_OPENED, False)
    ok('...said in the events, with who', any('boss set up the otp logs over TLS' in e['detail']
                                              for e in store.events(limit=50)[0]))
    ok('...the key nowhere in the database', b'PRIVATE KEY' in (state / 'isemon.db').read_bytes(),
       False)
    ok('...what is remembered: how and by whom', (wr._meta('otp_tls', {}).get('how'),
                                                 wr._meta('otp_tls', {}).get('by')),
       ('otp', 'boss'))
    try:
        isemon.otptls_api(wr, {'action': 'apply', 'token': got['token'], 'port': 6514}, 'boss')
        ok('the same token again: refused', False)
    except ValueError as e:
        ok('the same token again: refused', 'open it again' in str(e))
    isemon.otptls_api(wr, {'action': 'set', 'port': 6514, 'mutual': True,
                           'peers': 'otp1 otp2 otp3'}, 'boss')
    settle()
    ok('the nodes changed', isemon.otptls_view(wr)['peers'], ['otp1', 'otp2', 'otp3'])
    print('\nisemon\'s firewall: a card of its own, let in by itself (1.10.246)')
    look = wr.look(fresh_s=0)
    end = time.time() + 20
    while time.time() < end and not any(p.get('file') == CONF.name
                                        for p in (wr.read('look.json') or {}).get('rsyslog') or []):
        time.sleep(0.2)
    look = wr.read('look.json') or {}
    items = {i['key']: i for i in wr.auto_rules(look)}
    ok('The otp logs over TLS under What isemon lets in by itself',
       ('otptls' in items, [(r['proto'], r['port'], r['source']) for r in items['otptls']['rules']]
        if 'otptls' in items else None),
       (True, [('tcp', '6514', ''), ('tcp', '6514', '')]))
    ok('...and not among the plain logs\' ports', any(r['port'] == '6514'
                                                     for r in items['logs']['rules']), False)
    ok('...on unless turned off', items['otptls']['on'])
    wr._put('web_fw', {'on': True, 'otptls': {'any': False, 'from': ['192.0.2.21', '192.0.2.22']}})
    items = {i['key']: i for i in wr.auto_rules(look)}
    ok('...only from otp\'s nodes, when they are named',
       [r['source'] for r in items['otptls']['rules']], ['192.0.2.21', '192.0.2.22'])
    lines = wr.request(look)['fw']['rules']
    ok('...in the rules root puts in', [r['source'] for r in lines if r['port'] == '6514'],
       ['192.0.2.21', '192.0.2.22'])
    pushed = []
    wr.push = lambda why='', by='', force=False: pushed.append(why) or {'pushed': True}
    ok('a change of the otp logs over TLS: the firewall put in at once',
       (isemon.otptls_fw_follow(wr, wait=5), pushed[-1:]),
       (True, ['the otp logs over TLS changed the ports rsyslog listens on']))
    wr._put('web_fw', {'on': False})
    ok('...nothing where the firewall is not isemon\'s', isemon.otptls_fw_follow(wr, wait=1), False)
    del wr.push
    v = isemon.otptls_view(wr)
    ok('the card says what isemon\'s firewall does with it', v['fw_isemon'],
       {'on': False, 'let': True, 'any': True, 'from': []})
    page_ = (ROOT / 'web' / 'index.php').read_text()
    ok('the firewall pane draws its senders', ("otptls: dr.otptls" in page_,
                                              "item.key === 'otptls'" in page_), (True, True))

    isemon.otptls_api(wr, {'action': 'set', 'port': 6514, 'mutual': True,
                           'peers': 'bad name!'}, 'boss')
    settle()
    v = isemon.otptls_view(wr)
    ok('root refuses: said on the card, and in the events',
       ('is not a name' in v['error'], v['last'].get('ok'),
        any('were not changed' in e['detail'] for e in store.events(limit=50)[0])),
       (True, False, True))
    isemon.otptls_api(wr, {'action': 'off'}, 'boss')
    settle()
    v = isemon.otptls_view(wr)
    ok('switched off from the card', (v['on'], CONF.exists(), (rsd / '10-ise.conf').read_text()),
       (False, False, PLAIN))
    isemon.otptls_api(wr, {'action': 'remove'}, 'boss')
    settle()
    v = isemon.otptls_view(wr)
    ok('removed from the card: nothing left, said in the events',
       (v['on'], v['cert'], PKI.exists(), any('removed the otp logs over TLS' in e['detail']
                                              for e in store.events(limit=50)[0])),
       (False, {}, False, True))
    ok('...the page offers it', ("action: 'remove'" in page_, "'Remove…'" in page_), (True, True))
    ok('...Switch off and Remove always on the card, greyed when there is nothing to do',
       ("sw.disabled = off || !d.on;" in page_, "rm.disabled = off || !anything;" in page_,
        "(d.left && d.left.length)" in page_), (True, True, True))
    stop.set()

    print('\nThe pages, the command line, the path unit')
    page = (ROOT / 'web' / 'index.php').read_text()
    ok('the card on The OTP logs', ('id="otptls-card"' in page,
                                    page.index('id="pane-otp"') < page.index('id="otptls-card"')
                                    < page.index('id="pane-tacplus"')), (True, True))
    ok('...it asks /api/otptls', "api('otptls'" in page or "apiPost('otptls'" in page)
    unit = (ROOT / 'deploy' / 'isemon-web.path').read_text()
    ok('isemon-web.path watches otptls.ask', 'PathExists=/var/lib/isemon/web/otptls.ask' in unit)
    help_ = subprocess.run([sys.executable, str(ROOT / 'isemon.py'), '--help'],
                           capture_output=True, text=True).stdout
    ok('isemon --otp-tls, --otp-tls-import, --otp-tls-off',
       all(x in help_ for x in ('--otp-tls ', '--otp-tls-import', '--otp-tls-off')))
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
