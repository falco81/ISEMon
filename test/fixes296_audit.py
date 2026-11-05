#!/usr/bin/env python3
"""1.10.296: what the third round of review found, fixed.

- Remote backups: a backup fetched from a destination is put back only if
  isemon locked it (a .tar.gz left there by whoever may write to it would
  have put their database in); a pinned FTPS server's data connection is
  checked against the pin too.
- Upgrades: a package whose tar header says it is gigabytes long is refused
  before tarfile holds it in memory.
- What the regression review of rounds 1 and 2 found:
  - the password made for a database is let go only once the job is done;
  - acme push checks the ECDSA twin against the RSA one whichever came first;
  - SELinux: a port of rsyslog's in any line is rsyslog's, a range such as
    ephemeral_port_t's is not another service's;
  - the acme tab's lines are asked again with the rest;
  - a quote is recovered only after a quoted value.

    ./test/fixes296_audit.py
"""
import gzip
import importlib.util
import io
import sys
import tarfile
import tempfile
import shutil
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
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


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


work = Path(tempfile.mkdtemp(prefix='isemon-296-'))
try:
    src = (ROOT / 'isemon.py').read_text()
    print('Remote backups')
    a = src.index('def rb_restore_start(')
    body = src[a:a + 3000]
    ok('from a destination, only a locked backup is put back',
       "if not f.read(8).startswith(b'Salted__'):" in body and 'is not locked' in body)
    a = src.index('class _ReuseMixin(object):')
    ok('a pinned FTPS server\'s data connection is checked against the pin',
       'hashlib.sha256(der).hexdigest() != self.pin' in src[a:a + 1800])

    print('\nUpgrades')
    up = load('isemon_upgrade_296', ROOT / 'deploy' / 'isemon_upgrade.py')
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz', format=tarfile.PAX_FORMAT) as t:
        ti = tarfile.TarInfo('isemon-1.0.0/' + 'a' * 200)
        ti.size = 3
        t.addfile(ti, io.BytesIO(b'abc'))
    good = work / 'good.tar.gz'
    good.write_bytes(buf.getvalue())
    up._headers_bounded(str(good))
    ok('a package with a long name (a PAX header of its own) walks through', True)
    h = bytearray(512)
    h[0:5] = b'x/evl'
    h[124:136] = b'%011o\0' % (3 * 1024 ** 3)
    h[156:157] = b'x'
    h[148:156] = b' ' * 8
    h[148:156] = b'%06o\0 ' % sum(h)
    evil = work / 'evil.tar.gz'
    evil.write_bytes(gzip.compress(bytes(h) + b'\0' * 4096))
    try:
        up._headers_bounded(str(evil))
        ok('a header that says it is 3 GB: refused before tarfile reads it', False)
    except up.Refused as e:
        ok('a header that says it is 3 GB: refused before tarfile reads it',
           'header far longer' in str(e))

    print('\nSELinux')
    web = load('isemon_web_296', ROOT / 'deploy' / 'isemon_web.py')
    listing = ('SELinux Port Type  Proto  Port Number\n'
               'ephemeral_port_t   tcp    32768-60999\n'
               'hi_reserved_port_t tcp    512-1023\n'
               'postgresql_port_t  tcp    5432, 9898\n'
               'syslog_tls_port_t  tcp    6514, 10514, 40514\n'
               'syslogd_port_t     tcp    601, 20514\n')

    class R(object):
        def __init__(self, rc, out=''):
            self.returncode, self.stdout, self.stderr = rc, out, ''

    def fake(args, **kw):
        if args[0] == 'getenforce':
            return R(0, 'Enforcing')
        if args[:3] == ['semanage', 'port', '-a']:
            return R(1)
        return R(0, listing)
    web.subprocess = types.SimpleNamespace(run=fake)
    web.NO_SERVICES = False
    web.shutil = types.SimpleNamespace(which=lambda n: '/usr/bin/' + n)
    said = {}
    for port in (40514, 601, 5432):
        try:
            web.otptls_selinux(port, [])
            said[port] = 'taken'
        except web.Refused:
            said[port] = 'refused'
    ok('rsyslog\'s port by any line taken; another service\'s own refused; a range is not one',
       said, {40514: 'taken', 601: 'taken', 5432: 'refused'})

    print('\nWhat the review of the fixes found')
    f, _ = isemon.acme_fields('level=info Started job=5 msg=x')
    ok('a bare value is not run on into the next key', f.get('level'), 'info')
    f, _ = isemon.acme_fields('level=bad kind=job node=a who=b error="said "[hidden]" back" '
                              'job=1 msg=x')
    ok('...a quoted one still is', (f.get('error'), f.get('job')), ('said "[hidden]" back', '1'))
    a = src.index('def push_install(')
    body = src[a:a + 4000]
    ok('acme push: the ECDSA twin checked against the RSA one, whichever came first',
       "rsa, ecd = (alt, main) if main['kind'].startswith('ec') else (main, alt)" in body)
    ok('the database password let go only once the job is done',
       "if job.get('by') == me.get('name') and job.get('done'):" in src)
    page = (ROOT / 'web' / 'index.php').read_text()
    ok('the acme tab\'s lines asked again with the rest', 'amEvents(!AM.ev, !!quiet);' in page)
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
