#!/usr/bin/env python3
"""1.10.345: three rounds of looking for bugs and security problems - the
findings of each, checked to stay fixed.

    ./test/fixes345_hunt.py
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'deploy'))
import isemon                                        # noqa: E402
import isemon_web                                    # noqa: E402

PASS = FAIL = 0


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


folder = Path(tempfile.mkdtemp(prefix='isemon-345-'))
isemon.STATE_DIR = folder
isemon.DB_FILE = folder / 'c.db'
isemon.BACKUP_DIR = folder / 'backups'
isemon.DUMP_DIR = folder / 'dumps'
isemon.RUN_DIR = folder
isemon.LOG_DIR = folder
isemon.CONFIG_FILE = folder / 'config.json'
isemon._LOG_PATH = folder / 'c.log'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'directory': 1,
                      'directory_host': 'dc.corp.example', 'directory_base': 'DC=corp,DC=example'})
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
src = (ROOT / 'isemon.py').read_text()
page = (ROOT / 'web' / 'index.php').read_text()

print('round 1: a certificate is checked against the authorities put in, and nothing else')
pki = folder / 'pki'
subprocess.run(['bash', str(HERE / 'pki_certlogin.sh'), str(pki)], capture_output=True,
               timeout=300, env=dict(os.environ, CRLPORT='1', DEADPORT='2'))
stranger = (pki / 'stranger.pem').read_text()
old = os.environ.get('SSL_CERT_FILE')
os.environ['SSL_CERT_FILE'] = str(pki / 'other.pem')     # the system "trusts" another CA
try:
    isemon._cl_verify(pki / 'cas.pem', stranger)
    ok('a certificate of an authority the system trusts, not put in: refused', False)
except isemon.CertLoginError as e:
    ok('a certificate of an authority the system trusts, not put in: refused (%s)'
       % str(e)[:50], True)
if old is None:
    os.environ.pop('SSL_CERT_FILE', None)
else:
    os.environ['SSL_CERT_FILE'] = old
try:
    isemon._cl_verify(pki / 'cas.pem', (pki / 'falco.pem').read_text())
    ok('...one of the authorities put in: taken', True)
except isemon.CertLoginError as e:
    ok('...one of the authorities put in: taken (%s)' % e, False)

print('round 1: Kerberos - a person of the ticket\'s realm only')
ok('the entry\'s domain is compared with the realm', 'is a person of %s in the directory, not '
   'of the realm %s' in src, True)
ok('a down-level name of another domain is name@domain',
   (daemon.directory_principal_name('OTHER\\jnovak'), daemon.directory_principal_name(
       'CORP\\JNovak')), ('jnovak@other', 'jnovak'))

print('round 1: one person, one account - but a DN given again is somebody else')
dn = 'CN=John Smith,OU=Staff,DC=corp,DC=example'
with store.db_write() as db:
    for name in ('jsmith', 'jsmith2'):
        db.execute('INSERT INTO users (name, hash, role, made, made_by, from_dir, dn, display, '
                   'groups, note) VALUES (?,?,?,?,?,1,?,?,?,?)',
                   (name, '', 'fulladmin', 1.0, 'the directory', dn, 'John', '', ''))
store.put_passkeys([{'id': 'k-old', 'user': 'jsmith'}])
gone = store.merge_directory_person('jsmith2', dn, names=['jsmith2', 'jsmith2@corp.example'])
ok('the one who left is not put into the new one', (gone, bool(store.user('jsmith')),
                                                    [k['user'] for k in store.passkeys()]),
   ([], True, ['jsmith']))
with store.db_write() as db:
    db.execute('INSERT INTO users (name, hash, role, made, made_by, from_dir, dn, display, '
               'groups, note) VALUES (?,?,?,?,?,1,?,?,?,?)',
               ('jsmith2@corp.example', '', 'fulladmin', 1.0, 'x', dn, 'John', '', ''))
ok('...the same person\'s other name still is', store.merge_directory_person(
    'jsmith2', dn, names=['jsmith2', 'jsmith2@corp.example']), ['jsmith2@corp.example'])
ok('the sweep after an upgrade only puts name@domain into name',
   store.merge_directory_people(), [])

print('round 1: the keytab and the authorities that cannot be written are said, not a 500')
ok('the keytab', "raise KrbError('the keytab could not be written out: %s' % e)" in src, True)
ok('the authorities', "raise CertLoginError('the authorities could not be written out" in src,
   True)

print('round 1: an authority\'s address of a certificate: never link-local')
cert = (pki / 'falco.pem').read_text()
try:
    isemon.tls_fetch('http://169.254.169.254/latest/meta-data/')
    ok('169.254.169.254 refused', False)
except isemon.WebRootError as e:
    ok('169.254.169.254 refused', 'not an address an authority is fetched from' in str(e))

print('round 1: nginx\'s certificate server')
vhost = (ROOT / 'deploy' / 'nginx-isemon.conf').read_text()
cl = isemon_web.certlogin_checked({'on': True, 'port': 8443,
                                   'cas': (pki / 'cas.pem').read_text()})
blk = isemon_web.certlogin_into(vhost, cl)[0]
blk = blk[blk.index(isemon_web.CERTLOGIN_MARK):]
ok('GET only, no multipart body, the dashboard\'s rate',
   all(x in blk for x in ('if ($request_method !~ ^(GET|HEAD)$) { return 405; }',
                          'if ($http_content_type ~* "multipart") { return 403; }',
                          'limit_req zone=isemon_all burst=20 nodelay;')), True)
web = (ROOT / 'deploy' / 'isemon_web.py').read_text()
ok('built last, of the dashboard\'s server as this request leaves it',
   web.index("final, words = certlogin_into(final, cl)") > web.index("new, words = tls_into(new, t, dh_path)"),
   True)

print('round 1: the sign-in page')
ok('without the browser\'s storage nothing is tried by itself',
   'var krbTried = true, certTried = true;' in page and 'krbTried = certTried = true;' in page,
   True)
ok('NTLM offered by the browser counts as no ticket: the certificate next',
   "(x.d.code === 'no_ticket' || x.d.code === 'bad_ticket')" in page, True)
ok('a message of the certificate\'s port only for a tab that went there',
   "sessionStorage.getItem('isemon.cert.went')" in page and
   "sessionStorage.getItem('isemon.cert.trywent')" in page, True)
ok('the summary says Windows is tried by itself with no password at all',
   "k = Object.assign({}, k, {auto: k.on && (k.auto || only)});" in page, True)

print('round 2: wrong passwords from an address are not let go by signing in as yourself')
daemon.add_user('reader', 'reader-password-1', 'readonly')
daemon.add_user('boss', 'boss-password-12', 'fulladmin')
isemon.CONFIG['directory'] = 0
isemon.CONFIG['login_tries'] = 5
refused = 0
for round_ in range(3):
    for i in range(4):
        try:
            daemon.login('boss', 'guess-%d-%d' % (round_, i), ip='10.9.9.9')
        except isemon.Refused as e:
            refused += 1 if 'too many' in str(e) else 0
    try:
        daemon.login('reader', 'reader-password-1', ip='10.9.9.9')
    except isemon.Refused:
        pass
ok('guessing at boss, signing in as reader in between: the address still waits', refused > 0,
   True)
daemon._login_fails.clear()
for i in range(3):
    try:
        daemon.login('reader', 'wrong-%d' % i, ip='10.9.9.8')
    except isemon.Refused:
        pass
daemon.login('reader', 'reader-password-1', ip='10.9.9.8')
ok('...a name\'s own wrong passwords are let go when it gets in',
   len(daemon._login_fails.get('10.9.9.8') or []), 0)

print('round 2: an account that must change its password reaches no other account\'s passkeys')
ok('the passkeys road shut to it', "self.path.startswith('/api/auth/passkeys')" in src, True)

print('round 2: root never follows a link the service account put in its way')
inst = (ROOT / 'install.sh').read_text()
ok('the folders of the account made by the account', inst.count('user_dir "$STATE_DIR/') >= 3
   and 'install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$STATE_DIR/' not in inst, True)
ok('nothing copied from /run/isemon by root', '/run/isemon/known_hosts "$STATE_DIR' not in inst,
   True)
ok('config.json\'s mode set through a descriptor that follows no link', 'os.O_NOFOLLOW); '
   'os.fchmod(fd, 0o640)' in inst, True)
ok('the owner given to the new file before it is put in place, not to its name after',
   'os.fchown(fd, owner[0], owner[1])' in src and 'os.chown(str(where), st.st_uid' not in src,
   True)
w = folder / 'w.json'
isemon.write_replacing(w, '{}', 0o640, owner=(os.getuid(), os.getgid()))
ok('...and it still writes', w.read_text(), '{}')

print('round 2: a backup destination is checked as it is used, not only as it was typed')
store.set_meta('rbackup:targets', json.dumps([
    {'id': 'a', 'kind': 'sftp', 'host': 'backup.example', 'port': 22, 'user': 'isemon',
     'path': '/srv/backup\n!sh -c id', 'auth': 'password'},
    {'id': 'b', 'kind': 'folder', 'path': '/mnt/backup'}]))
ok('one with a newline in its folder is left out', [t['id'] for t in isemon.rb_targets(store)],
   ['b'])

print('round 2: a record\'s own words in a help panel make no tags')
ok('PTR names, hostnames, VLAN and group names, field values', all(x in page for x in (
    "'The reverse zone calls this address <b>' + wordsIn(called)",
    "'passed on, is <b>' + wordsIn(seen.calls_itself)",
    "'<code>' + wordsIn(g.name) + '</code>'",
    "'Every line where <code>' + wordsIn(term)")), True)

print('round 3: the domain')
ok('an account asked for as written is found as written', "forms = self.win_account_forms([raw, value], since)" in src, True)
ok('one flush of the 2025 counts at a time', 'with Storage._AD25_FLUSH_LOCK:' in src, True)
f = isemon.win_record_from if hasattr(isemon, 'win_record_from') else None
ok('4743 and 4781 read whole, and read again once', (
    'Target Computer' in isemon.WIN_SECTIONS, 'Old Account Name' in isemon.WIN_LABELS,
    isemon.Storage.WIN_SORT_VERSION, isemon.Storage.MARK_VERSIONS[9]),
   (True, True, 10, (4743, 4781)))
ok('a desktop rebuilt only when a MACHINE did it', 'win_is_machinery(event, fields, win_by(fields, event) or account)'
   in src, True)
ok('the 2025 strip opens a list whole', "else A25.only = '';" in page, True)

print('round 3: nothing takes seconds of the whole daemon')
import time
t = time.time()
isemon.ROS_FW.match('\t' * 65536)
ok('a RouterOS line of 64 KB of tabs', time.time() - t < 0.5, True)
ok('no line longer than 64 KB reaches a parser',
   max(len(x) for x in isemon.log_lines('a' * 200000 + '\n')), isemon.LOG_LINE_MOST)
ok('the firewall search\'s policy number asked plainly',
   "re.fullmatch(r'#?[\\d,\\s-]+', str(value).strip())" in src, True)

print('round 3: the ban list and acme')
st = daemon.banfeed_state(False)
ok('to a viewer, not the account the firewalls fetch with', st['user'], '')
ok('acme: a certificate for a dashboard with no name is no match',
   "if slot['names'] and all(push_name_holds(names, n) for n in slot['names']):" in src, True)

print('\n%d passed, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
