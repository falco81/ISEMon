#!/usr/bin/env python3
"""1.10.319: SELinux (Settings → SELinux) and the system's trusted roots
(Settings → Certificates and TLS) - root's helper with a pretend machine
(getenforce, semanage, semodule, ausearch... on PATH), the daemon's half, the
installer, the units and the page.

    ./test/fixes319_selinux_osroots.py
"""
import base64
import importlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import io
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PASS = FAIL = 0


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


work = Path(tempfile.mkdtemp(prefix='isemon-319-'))
M = work / 'machine'
BIN = work / 'bin'
STATE = work / 'state'
for d in (M, BIN, STATE / 'web', work / 'rootstate', work / 'rsyslog.d'):
    d.mkdir(parents=True, exist_ok=True)

FAKES = {
    'getenforce': 'cat "$M/mode"',
    'getsebool': 'v=off; [ -f "$M/bool_$1" ] && v=$(cat "$M/bool_$1"); echo "$1 --> $v"',
    'setsebool': 'echo "setsebool $*" >> "$M/log"; echo on > "$M/bool_$2"',
    'semodule': 'if [ "$1" = -l ]; then cat "$M/modules" 2>/dev/null; exit 0; fi\n'
                'echo "semodule $*" >> "$M/log"\n'
                '[ -f "$M/semodule_fail" ] && { echo "semodule: no" >&2; exit 1; }\n'
                'echo "isemon_server 1.0" >> "$M/modules"',
    'semanage': 'if [ "$2" = -l ]; then cat "$M/ports"; exit 0; fi\n'
                'echo "semanage $*" >> "$M/log"\n'
                'n=$7; [ -f "$M/taken_$n" ] && { echo "ValueError: Port $6/$n already defined" >&2; exit 1; }\n'
                'echo "$4 $6 $n" >> "$M/ports"',
    'ausearch': 'cat "$M/avc" 2>/dev/null',
    'audit2why': 'while IFS= read -r l; do echo "$l"; case "$l" in *ALLOWED*) '
                 'echo "	Was caused by:"; echo "		Unknown - would be allowed by active policy";; esac; done',
    'setenforce': 'echo "setenforce $1" >> "$M/log"; if [ "$1" = 1 ]; then echo Enforcing > "$M/mode"; '
                  'else echo Permissive > "$M/mode"; fi',
}
for name, body in FAKES.items():
    p = BIN / name
    p.write_text('#!/bin/sh\nM=%s\n%s\n' % (M, body))
    p.chmod(0o755)

os.environ.update({
    'PATH': '%s:%s' % (BIN, os.environ.get('PATH', '/usr/bin:/bin')),
    'ISEMON_STATE': str(STATE), 'ISEMON_WEB_NO_SERVICES': '1',
    'ISEMON_ROOT_STATE': str(work / 'rootstate'),
    'ISEMON_SELINUX_CONFIG': str(M / 'config'), 'ISEMON_SELINUX_RELABEL': str(M / 'autorelabel'),
    'ISEMON_SELINUX_CMDLINE': str(M / 'cmdline'), 'ISEMON_SELINUX_CIL': str(M / 'isemon_server.cil'),
    'ISEMON_SELINUX_AUDITD': 'active', 'ISEMON_SELINUX_LABELS': str(M / 'labels.json'),
    'ISEMON_RSYSLOG': str(work / 'rsyslog.d'),
})
sys.path.insert(0, str(ROOT / 'deploy'))
web = importlib.import_module('isemon_web')
shutil.copy(str(ROOT / 'deploy' / 'isemon_server.cil'), str(M / 'isemon_server.cil'))


def machine(mode='Permissive', config='permissive', modules='', ports='', bools=None, avc='',
            labels=None):
    for f in M.iterdir():
        if f.name.startswith(('bool_', 'taken_')) or f.name in ('log', 'autorelabel', 'semodule_fail'):
            f.unlink()
    (M / 'mode').write_text(mode + '\n')
    (M / 'config').write_text('# SELinux\nSELINUX=%s\nSELINUXTYPE=targeted\n' % config)
    (M / 'cmdline').write_text('BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro\n')
    (M / 'modules').write_text(modules)
    (M / 'ports').write_text(ports or 'http_port_t tcp 80, 443\npostgresql_port_t tcp 5432\n'
                                      'syslogd_port_t udp 514, 601\n')
    (M / 'avc').write_text(avc)
    for k, v in (bools or {}).items():
        (M / ('bool_' + k)).write_text(v)
    (M / 'labels.json').write_text(json.dumps(labels if labels is not None else {
        '/run/isemon': 'httpd_var_run_t', '/run/isemon/api-token': 'httpd_var_run_t',
        '/var/www/isemon': 'httpd_sys_content_t'}))
    try:
        os.unlink(str(work / 'rootstate' / 'selinux-applied'))
    except OSError:
        pass


def log():
    try:
        return (M / 'log').read_text().splitlines()
    except OSError:
        return []


WANT = {'booleans': [{'name': 'httpd_can_network_connect', 'why': 'the pages ask the daemon'}],
        'ports': [{'port': 5433, 'proto': 'tcp', 'type': 'postgresql_port_t',
                   'why': 'PostgreSQL of this machine listens on it'}]}
AVC = ('type=AVC msg=audit(%d.120:501): avc:  denied  { read } for  pid=1 comm="php-fpm" '
       'name="api-token" scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:var_run_t:s0 '
       'tclass=file permissive=1\n' % (time.time() - 100)) * 3 + \
      ('type=AVC msg=audit(%d.130:502): avc:  denied  { name_bind } for  pid=2 comm="ALLOWED" '
       'scontext=system_u:system_r:syslogd_t:s0 tcontext=system_u:object_r:unreserved_port_t:s0 '
       'tclass=tcp_socket permissive=1\n' % (time.time() - 90)) + \
      ('type=AVC msg=audit(%d.140:503): avc:  denied  { read } for  pid=3 comm="cupsd" '
       'scontext=system_u:system_r:cupsd_t:s0 tcontext=system_u:object_r:etc_t:s0 '
       'tclass=file permissive=1\n' % (time.time() - 80))

print('SELinux: what root reads')
real_exists = os.path.exists
os.path.exists = lambda p: True if p in ('/run/isemon', '/run/isemon/api-token', '/var/www/isemon') \
    else real_exists(p)
machine(avc=AVC)
c = web.se_check(dict(WANT, do='check'))
ok('permissive, module out, boolean off, port not labelled: each said, not ready',
   (c['mode'], c['module'], [b['on'] for b in c['booleans']], [p['labelled'] for p in c['ports']],
    c['ready']), ('Permissive', False, [False], [False], False))
ok('...the labels read as the policy wants them', [x['ok'] for x in c['labels']], [True, True, True])
ok('...refused: grouped, the other programs\' left out, one allowed now settled',
   (c['denials']['total'], c['denials']['settled'], [g['source'] for g in c['denials']['groups']]),
   (3, 1, ['httpd_t']))
ok('...in the problems', any('refused 3 thing' in p for p in c['problems']))
machine(labels={'/run/isemon': 'httpd_runtime_t', '/run/isemon/api-token': 'var_run_t',
                '/var/www/isemon': 'httpd_sys_content_t'})
c = web.se_check(dict(WANT, do='check'))
ok('httpd_runtime_t (a newer policy) is as good; var_run_t is not',
   [x['ok'] for x in c['labels']], [True, False, True])

print('\nSELinux: what may be asked')
try:
    web.se_want_checked({'booleans': [{'name': 'ssh_sysadm_login'}]})
    ok('a boolean isemon does not set: refused', False)
except web.Refused:
    ok('a boolean isemon does not set: refused', True)
for bad in ({'port': 0, 'proto': 'tcp', 'type': 'http_port_t'}, {'port': '22; rm', 'proto': 'tcp',
                                                                   'type': 'http_port_t'},
            {'port': 80, 'proto': 'sctp', 'type': 'http_port_t'}):
    try:
        web.se_want_checked({'ports': [bad]})
        ok('a port %r: refused' % (bad,), False)
    except web.Refused:
        ok('a port %r: refused' % (bad,), True)
left = []
b, p = web.se_want_checked({'ports': [{'port': 9999, 'proto': 'tcp', 'type': 'newer_port_t'}]}, left)
ok('a port type this helper does not know: left out with a word, the rest goes on',
   (p, len(left), 'newer_port_t' in left[0]), ([], 1, True))
(work / 'rsyslog.d' / '99-otp-tls.conf').write_text('input(type="imtcp" port="7514")\n')
(work / 'rsyslog.d' / 'isemon.conf').write_text('input(type="imudp" port="514")\n'
                                                'input(type="imudp" port="5140")\n')
b, p = web.se_want_checked({})
ok('rsyslog\'s own ports read by root: TLS as syslog_tls_port_t, plain as syslogd_port_t, 514 not asked',
   sorted((x['port'], x['proto'], x['type']) for x in p),
   [(5140, 'udp', 'syslogd_port_t'), (7514, 'tcp', 'syslog_tls_port_t')])
for f in (work / 'rsyslog.d').iterdir():
    f.unlink()

print('\nSELinux: the steps')
machine(mode='Disabled', config='disabled')
out = web.se_do(dict(WANT, do='prepare'))
ok('disabled → made ready: SELINUX=permissive, every file labelled at the next start',
   ('SELINUX=permissive' in (M / 'config').read_text(), (M / 'autorelabel').exists(),
    'SELINUXTYPE=targeted' in (M / 'config').read_text()), (True, True, True))
ok('...the mode itself not touched now (no setenforce)', [x for x in log() if 'setenforce' in x], [])
ok('...and says to restart', any('restart the machine' in x for x in out['said']))
machine(avc=AVC)
out = web.se_do(dict(WANT, do='prepare'))
ok('permissive → put in: module, boolean, port - each said',
   (any('semodule -i' in x for x in log()), any('setsebool -P httpd_can_network_connect on' in x
                                                 for x in log()),
    any('semanage port -a -t postgresql_port_t -p tcp 5433' in x for x in log())), (True, True, True))
ok('...when it was put in noted in root\'s own folder: what was refused before counts no more',
   (web.se_applied_at() > time.time() - 60, out['denials']['total']), (True, 0))
ok('...the copy last put into the policy kept', (M / 'isemon_server.cil.in-policy').exists())
n = len(log())
web.se_do(dict(WANT, do='prepare'))
ok('asked again with everything there: nothing done again', log()[n:], [])
machine(avc=AVC)
(M / 'taken_5433').write_text('')
try:
    web.se_do(dict(WANT, do='prepare'))
    ok('a port of another service: refused, never taken from it', False)
except web.Refused as e:
    ok('a port of another service: refused, never taken from it',
       ('another service' in str(e), any('-m' in x.split() for x in log())), (True, False))
machine(avc=AVC)
try:
    web.se_do(dict(WANT, do='enforce'))
    ok('enforcing with something refused: refused', False)
except web.Refused as e:
    ok('enforcing with something refused: refused', ('not yet' in str(e),
                                                      [x for x in log() if 'setenforce' in x]), (True, []))
machine(modules='isemon_server 1.0\n', bools={'httpd_can_network_connect': 'on'},
        ports='postgresql_port_t tcp 5432, 5433\n')
shutil.copy(str(M / 'isemon_server.cil'), str(M / 'isemon_server.cil.in-policy'))
c = web.se_check(dict(WANT, do='check'))
ok('nothing missing, nothing refused: ready for enforcing', (c['ready'], c['problems']), (True, []))
out = web.se_do(dict(WANT, do='enforce'))
ok('...enforcing now and after a restart', ((M / 'mode').read_text().strip(),
                                            'SELINUX=enforcing' in (M / 'config').read_text()),
   ('Enforcing', True))
os.environ['ISEMON_SELINUX_AUDITD'] = 'inactive'
machine(mode='Permissive', modules='isemon_server 1.0\n', bools={'httpd_can_network_connect': 'on'},
        ports='postgresql_port_t tcp 5432, 5433\n')
c = web.se_check(dict(WANT, do='check'))
ok('auditd not running: not ready - nothing would be written down', (c['ready'], any(
    'auditd' in p for p in c['problems'])), (False, True))
os.environ['ISEMON_SELINUX_AUDITD'] = 'active'
machine(mode='Enforcing', config='enforcing')
web.se_do(dict(WANT, do='permissive'))
ok('back to permissive: setenforce 0, and SELINUX=permissive',
   ((M / 'mode').read_text().strip(), 'SELINUX=permissive' in (M / 'config').read_text()),
   ('Permissive', True))
machine(mode='Disabled', config='disabled')
try:
    web.se_do(dict(WANT, do='enforce'))
    ok('disabled → enforcing at once: refused', False)
except web.Refused:
    ok('disabled → enforcing at once: refused', True)
saved = os.environ['PATH']
os.environ['PATH'] = '/usr/bin:/bin'
try:
    ok('no SELinux on the machine (Debian): absent, nothing to do',
       web.se_check(dict(WANT))['mode'], 'absent')
finally:
    os.environ['PATH'] = saved

print('\nSELinux: the request, and the report')


def ask(name, answer, data):
    (STATE / 'web' / name).write_text(json.dumps(data))
    getattr(web, {'selinux.ask': 'selinux_part', 'osroots.ask': 'osroots_part'}[name])()
    return json.loads((STATE / 'web' / answer).read_text())


machine(mode='Enforcing', config='enforcing')
got = ask('selinux.ask', 'selinux.json', dict(WANT, do='permissive', id='abc', at=time.time() - 3600))
ok('a step asked an hour ago: not done', (got['ok'], 'too long ago' in got.get('said', ''),
                                          (M / 'mode').read_text().strip()), (False, True, 'Enforcing'))
ok('...and the request taken away', (STATE / 'web' / 'selinux.ask').exists(), False)
got = ask('selinux.ask', 'selinux.json', dict(WANT, do='check', id='abd'))
ok('a look: answered with its id', (got['ok'], got['id'], got['data']['mode']), (True, 'abd', 'Enforcing'))
os.symlink('/etc/passwd', str(STATE / 'web' / 'selinux.ask'))
web.selinux_part()
ok('a link in place of the request: taken away, never followed',
   os.path.lexists(str(STATE / 'web' / 'selinux.ask')), False)
machine(avc=AVC)
got = ask('selinux.ask', 'selinux.json', dict(WANT, do='report', id='abe'))
data = (STATE / 'web' / 'selinux-report.tar.gz').read_bytes()
names = sorted(m.name.split('/', 1)[1] for m in tarfile.open(fileobj=io.BytesIO(data)).getmembers())
ok('the report: one file with each part, nothing changed to make it',
   (got['ok'], all(x in names for x in ('README.txt', 'check.json', 'avc-raw.txt', 'labels.txt',
                                       'ports.txt', 'system.txt')), log()), (True, True, []))

print('\nThe system\'s trusted roots: root\'s half')
os.path.exists = real_exists
CERTS = work / 'certs'
CERTS.mkdir()


def run(*a):
    subprocess.run(list(a), check=True, capture_output=True, cwd=str(CERTS))


run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'root.key', '-out',
    'root.pem', '-days', '3650', '-subj', '/CN=Example Root CA', '-addext',
    'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
(CERTS / 'int.ext').write_text('basicConstraints=critical,CA:TRUE,pathlen:0\n'
                               'keyUsage=critical,keyCertSign,cRLSign\n')
run('openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'int.key', '-out', 'int.csr',
    '-subj', '/CN=Example Issuing CA')
run('openssl', 'x509', '-req', '-in', 'int.csr', '-CA', 'root.pem', '-CAkey', 'root.key',
    '-CAcreateserial', '-out', 'int.pem', '-days', '1800', '-extfile', 'int.ext')
run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'leaf.key', '-out',
    'leaf.pem', '-days', '300', '-subj', '/CN=www.example.org', '-addext', 'basicConstraints=CA:FALSE')
ROOTPEM = (CERTS / 'root.pem').read_text()
INTPEM = (CERTS / 'int.pem').read_text()
LEAFPEM = (CERTS / 'leaf.pem').read_text()
ANCH = work / 'anchors'
ANCH.mkdir(mode=0o755)
os.chmod(str(ANCH), 0o755)
BUNDLE = work / 'bundle.pem'
(BIN / 'fake-extract').write_text('#!/bin/sh\necho run >> "%s/extract.log"\ncat %s/*.pem > "%s" '
                                  '2>/dev/null; exit 0\n' % (M, ANCH, BUNDLE))
(BIN / 'fake-extract').chmod(0o755)
os.environ.update({'ISEMON_OSROOTS_FLAVOUR': 'rhel', 'ISEMON_OSROOTS_DIR': str(ANCH),
                   'ISEMON_OSROOTS_BUNDLE': str(BUNDLE), 'ISEMON_OSROOTS_EXTRACT': 'fake-extract',
                   'ISEMON_OSROOTS_PKG': 'true'})
(ANCH / 'their-ldaps.pem').write_text(ROOTPEM)
w = web.osroots_where()
said, refused = web.osroots_sync(w, [ROOTPEM, INTPEM])
files = sorted(os.listdir(str(ANCH)))
ok('two added: isemon-<sha256 16>.pem each, the system\'s tool run once',
   (len([f for f in files if f.startswith('isemon-')]), len((M / 'extract.log').read_text().split())),
   (2, 1))
ok('...0644 and in the system\'s list',
   all(stat.S_IMODE(os.stat(str(ANCH / f)).st_mode) == 0o644 for f in files if f.startswith('isemon-')))
st = web.osroots_read(w)
ok('...read back: ours in the bundle, somebody else\'s shown and left',
   (sorted(x['kind'] for x in st['ours']), all(x['in_bundle'] for x in st['ours']),
    [o['file'] for o in st['others']]), (['intermediate', 'root'], True, ['their-ldaps.pem']))
said, refused = web.osroots_sync(w, [ROOTPEM, INTPEM])
ok('asked again the same: nothing written, the tool not run', (said, len((M / 'extract.log').read_text().split())),
   ([], 1))
said, refused = web.osroots_sync(w, [ROOTPEM, LEAFPEM])
ok('a server\'s own certificate: refused, said; the intermediate no longer wanted taken away',
   (len(refused), 'CA:FALSE' in refused[0]['why'], any(x.startswith('removed isemon-') for x in said)),
   (1, True, True))
ok('...the file somebody else put there untouched', (ANCH / 'their-ldaps.pem').read_text(), ROOTPEM)
mine = [f for f in os.listdir(str(ANCH)) if f.startswith('isemon-')][0]
os.unlink(str(ANCH / mine))
os.symlink('/etc/hostname', str(ANCH / mine))
web.osroots_sync(w, [ROOTPEM])
ok('one of isemon\'s made a link by somebody: put back as a file, the link never followed',
   (os.path.islink(str(ANCH / mine)), (ANCH / mine).read_text()), (False, ROOTPEM))
web.osroots_sync(w, [])
ok('the set emptied: isemon\'s files gone, the others\' stay',
   sorted(os.listdir(str(ANCH))), ['their-ldaps.pem'])
try:
    web.osroots_blocks(ROOTPEM + (CERTS / 'root.key').read_text())
    ok('a private key in the text: the whole text refused', False)
except web.Refused:
    ok('a private key in the text: the whole text refused', True)
os.chmod(str(ANCH), 0o777)
try:
    web.osroots_sync(w, [ROOTPEM])
    ok('a folder anybody may write: nothing written there', False)
except web.Refused as e:
    ok('a folder anybody may write: nothing written there', 'root\'s alone' in str(e))
os.chmod(str(ANCH), 0o755)
got = ask('osroots.ask', 'osroots.json', {'do': 'sync', 'certs': [ROOTPEM], 'id': 'x1'})
ok('through osroots.ask: done and read back', (got['ok'], got['id'], len(got['data']['ours'])),
   (True, 'x1', 1))
got = ask('osroots.ask', 'osroots.json', {'do': 'rm -rf', 'id': 'x2'})
ok('anything else asked: refused', (got['ok'], got['said']), (False, 'list or sync'))

print('\nThe daemon\'s half')
sys.path.insert(0, str(ROOT))
import isemon                                        # noqa: E402
isemon.DB_FILE = work / 'd.db'
(work / 'config.json').write_text(json.dumps({'db_engine': 'sqlite'}))
isemon.CONFIG_FILE = work / 'config.json'
st = isemon.Storage(isemon.DB_FILE)
f = isemon.osr_facts(*isemon.osr_blocks(ROOTPEM)[0])
g = web.osroots_facts(*web.osroots_blocks(ROOTPEM)[0])
ok('the daemon and root read a certificate in the same words',
   {k: f[k] for k in ('fp', 'cn', 'kind', 'key', 'refused', 'warn', 'not_after')},
   {k: g[k] for k in ('fp', 'cn', 'kind', 'key', 'refused', 'warn', 'not_after')})
der = base64.b64decode(''.join(ROOTPEM.strip().splitlines()[1:-1]))
ok('one in DER (.cer) read as PEM', isemon.osr_blocks(isemon.osr_text(der))[0][1], der)


class WR(object):
    def helper_there(self):
        return False


class D(object):
    store = st
    webroot = WR()


d = D()
chk = isemon.osr_check(st, INTPEM)
ok('an intermediate alone: taken, with the word that its root is not here',
   (chk[0]['refused'], any('without its root' in x for x in chk[0]['warn'])), ([], True))
r = isemon.osr_add(d, ROOTPEM + INTPEM + LEAFPEM, 'boss')
ok('a chain added: the two authorities, the server\'s own refused',
   (sorted(x['kind'] for x in r['added']), len(r['refused'])), (['intermediate', 'root'], 1))
v = isemon.osr_view(d)
ok('...the set as the page shows it, waiting (root\'s half not here), no word of a missing root',
   (len(v['certs']), v['nodes'][0]['status'], [c['warn'] for c in v['certs']]),
   (2, 'waiting', [[], []]))
try:
    isemon.osr_add(d, ROOTPEM, 'boss')
    ok('the same again: nothing added', False)
except ValueError as e:
    ok('the same again: nothing added', 'there already' in str(e))
fp = [c['fp'] for c in v['certs'] if c['kind'] == 'intermediate'][0]
try:
    isemon.osr_remove(d, fp[:6], 'boss')
    ok('removed by 6 characters of the fingerprint: refused', False)
except ValueError:
    ok('removed by 6 characters of the fingerprint: refused', True)
isemon.osr_remove(d, fp[:16], 'boss')
ok('removed by its fingerprint: the set one shorter, in Events',
   (len(isemon.osr_want(st)['certs']), 'took away Example Issuing CA' in
    st.events(limit=5)[0][0]['detail']), (1, True))
row = {'at': time.time(), 'hash': isemon.osr_want(st)['hash'], 'ok': True, 'refused': []}
ok('a node whose row has the set\'s hash: as wanted',
   isemon.osr_node_status(isemon.osr_want(st), row, True)[0], 'applied')
ok('nothing ever asked: nothing added by isemon', isemon.osr_node_status(None, {}, True)[0], 'none')
for k in ('db_engine', 'db_host', 'db_port'):
    isemon.CONFIG.pop(k, None)
isemon.CONFIG.update(db_engine='postgres', db_host='127.0.0.1', db_port=5433)
want = isemon.selinux_want()
ok('what isemon needs: the boolean, and the local PostgreSQL on its own port',
   ([b['name'] for b in want['booleans']], [(p['port'], p['type']) for p in want['ports']]),
   (['httpd_can_network_connect'], [(5433, 'postgresql_port_t')]))
isemon.CONFIG.update(db_engine='postgres', db_host='db.example.org', db_port=5433)
ok('...a PostgreSQL elsewhere: no port asked here', isemon.selinux_want()['ports'], [])
ok('...nothing secret in the facts', 'db_password' not in json.dumps(isemon.selinux_facts()))
isemon.SE_WORK['asked'] = {'id': 'a', 'do': 'enforce', 'by': 'x', 'at': time.time()}
isemon.SE_WORK['busy'] = True
said = isemon.selinux_ask(d, 'check', 'boss')
ok('a look asked while a step is not done: the step stays', (isemon.SE_WORK['asked']['do'],
                                                             'still being done' in said), ('enforce', True))
try:
    isemon.selinux_ask(d, 'report', 'boss')
    ok('...and a report too', False)
except ValueError:
    ok('...and a report too', True)
try:
    isemon.selinux_ask(d, 'reboot', 'boss')
    ok('a step that is not one: refused', False)
except ValueError:
    ok('a step that is not one: refused', True)
isemon.SE_WORK.update(busy=False, asked=None)
v = isemon.selinux_view(d)
ok('the view without root\'s half: said so, nothing pending', (v['helper'], v['nodes'][0]['pending']),
   (False, ''))

print('\nThe installer, the units, the page')
inst = (ROOT / 'install.sh').read_text()
ok('install.sh: the module put in on an install and on every upgrade, and taken out by --uninstall',
   (inst.count('    selinux_module\n') + inst.count('\nselinux_module\n'), 'semodule -r isemon_server' in inst,
    'isemon_server.cil.in-policy' in inst), (2, True, True))
ok('...the mode never touched by the installer', ('setenforce' in inst, 'SELINUX=' in inst), (False, False))
path = (ROOT / 'deploy' / 'isemon-web.path').read_text()
ok('isemon-web.path hands selinux.ask and osroots.ask to root',
   ('web/selinux.ask' in path, 'web/osroots.ask' in path), (True, True))
ok('isemon-web.service: no start limit', 'StartLimitIntervalSec=0' in
   (ROOT / 'deploy' / 'isemon-web.service').read_text())
cil = (ROOT / 'deploy' / 'isemon_server.cil').read_text()
ok('the module labels /run/isemon by both spellings, its rule in a block of its own',
   ('"/run/isemon"' in cil, '"/var/run/isemon"' in cil, '(optional ' in cil), (True, True, True))
page = (ROOT / 'web' / 'index.php').read_text()
ok('the page: a SELinux pane, the trusted roots card, and both asked through the relay',
   ('id="pane-selinux"' in page, 'id="osr-card"' in page,
    page.count("'selinux'") >= 2 and page.count("'osroots'") >= 2), (True, True, True))
ok('...enforcing asked with a red confirmation, only once ready',
   ("enf.disabled = !!n.pending || !s.ready;" in page and
    "'Switch to enforcing', function () { seAsk('enforce'); }, true);" in page))
shutil.rmtree(str(work), ignore_errors=True)

print('\n%d passed, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
