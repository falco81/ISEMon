#!/usr/bin/env python3
"""1.10.236: install.sh puts in what isemon uses and the machine lacks - on
an install and on every upgrade (from the pages too) alike. Only ever adds:
nothing installed is changed; a package that cannot be had is said and the
rest goes on. chronyd is started only where it was never set up and nothing
else keeps the time.

install.sh's own functions are run here in bash, with dnf, apt-get and
systemctl played by small scripts and a PATH that holds only those and the
few programs the functions need - so "missing" is what the test says it is.

    ./test/fixes236.py
"""
import os
import shutil
import subprocess
import sys
import tempfile
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


inst = (ROOT / 'install.sh').read_text()
funcs = inst[inst.index('PKG_UPDATED=""'):inst.index('install_console() {')]
work = Path(tempfile.mkdtemp(prefix='isemon-236-'))
bin_ = work / 'bin'
bin_.mkdir()
for prog in ('timeout', 'python3', 'ls', 'cat', 'touch', 'chmod', 'mkdir', 'sleep'):
    real = shutil.which(prog)
    if real:
        (bin_ / prog).symlink_to(real)
LOG = work / 'calls.log'
# dnf: a package "installed" puts its programs on the PATH. One that the
# repositories do not have fails, as a machine without network would.
(bin_ / 'dnf').write_text('''#!/bin/bash
echo "dnf $*" >> %(log)s
pkg="${@: -1}"
case "$pkg" in
  openssh-clients) progs="ssh ssh-keygen";;
  acl) progs="setfacl";;
  openssl) progs="openssl";;
  samba-client) exit 1;;
  chrony) progs="chronyc chronyd";;
  nginx) progs="nginx";;
  php-fpm) progs="php-fpm";;
  php-cli) progs="php";;
  *) exit 1;;
esac
for p in $progs; do printf '#!/bin/sh\\nexit 0\\n' > %(bin)s/$p; chmod +x %(bin)s/$p; done
''' % {'log': LOG, 'bin': bin_})
(bin_ / 'systemctl').write_text('''#!/bin/bash
echo "systemctl $*" >> %(log)s
case "$*" in
  *"is-active --quiet ntpd"*) [ -f %(work)s/ntpd-on ] && exit 0; exit 3;;
  *"is-active --quiet chronyd"*) [ -f %(work)s/chronyd-on ] && exit 0; exit 3;;
  *"enable --now chronyd"*) touch %(work)s/chronyd-on; exit 0;;
  *) exit 3;;
esac
''' % {'log': LOG, 'work': work})
for f in bin_.iterdir():
    if not f.is_symlink():
        f.chmod(0o755)


def run(mode, web=False, have=(), pre=''):
    for p in ('ssh', 'ssh-keygen', 'setfacl', 'openssl', 'smbclient', 'chronyc', 'chronyd',
              'nginx', 'php-fpm', 'php'):
        try:
            (bin_ / p).unlink()
        except OSError:
            pass
    for p in have:
        (bin_ / p).write_text('#!/bin/sh\nexit 0\n')
        (bin_ / p).chmod(0o755)
    for f in ('chronyd-on', 'ntpd-on'):
        try:
            (work / f).unlink()
        except OSError:
            pass
    LOG.write_text('')
    web_dir = work / 'web'
    if web:
        web_dir.mkdir(exist_ok=True)
        (web_dir / 'index.php').write_text('x')
    elif web_dir.exists():
        shutil.rmtree(str(web_dir))
    script = '''
set -u
good() { echo "GOOD $*"; }
warn() { echo "WARN $*"; }
note() { echo "NOTE $*"; }
say()  { echo "SAY $*"; }
run()  { "$@"; }
db_driver() { echo "DRIVER $*"; }
db_client() { echo "CLIENT $*"; }
PKG=dnf; DRY_RUN=""; WITH_WEB=""; WITH_DB=""; WEB_DIR=%s; CONFIG_FILE=%s
%s
%s
ensure_packages %s
chrony_check %s
''' % (web_dir, work / 'config.json', funcs, pre, mode, mode)
    r = subprocess.run(['/bin/bash', '-c', script], capture_output=True, text=True,
                       env={'PATH': str(bin_), 'HOME': str(work)}, timeout=120)
    return r.returncode, r.stdout + r.stderr, LOG.read_text()


print('An upgrade on a machine that lacks everything')
rc, out, calls = run('upgrade')
ok('it went through', rc, 0)
for pkg in ('openssh-clients', 'acl', 'openssl', 'samba-client', 'chrony'):
    ok('dnf install -y %s' % pkg, 'dnf install -y %s' % pkg in calls)
ok('one the repositories do not have: said, and the rest went on',
   ('could not be installed' in out and 'samba-client' in out, 'chrony installed' in out),
   (True, True))
ok('no pages here: nginx and PHP left alone', 'nginx' in calls or 'php' in calls, False)
ok('chronyd started - nothing else keeps the time', 'enable --now chronyd' in calls)

print('\nAn upgrade on a machine that has everything')
rc, out, calls = run('upgrade', web=True, have=('ssh', 'ssh-keygen', 'setfacl', 'openssl',
                                                 'smbclient', 'chronyc', 'chronyd', 'nginx',
                                                 'php-fpm', 'php'), pre='touch %s/chronyd-on' % work)
ok('nothing installed (but colorama, when this Python has none)',
   [x for x in calls.splitlines() if x.startswith('dnf') and 'colorama' not in x], [])
ok('nothing started', 'enable' in calls, False)

print('\nThe pages are here: their web server and PHP too')
rc, out, calls = run('upgrade', web=True, have=('ssh', 'ssh-keygen', 'setfacl', 'openssl',
                                                 'smbclient', 'chronyc', 'chronyd'))
ok('nginx, php-fpm and php-cli', all('dnf install -y %s' % p in calls
                                     for p in ('nginx', 'php-fpm', 'php-cli')))

print('\nThe time kept by something else')
rc, out, calls = run('upgrade', have=('ssh', 'ssh-keygen', 'setfacl', 'openssl', 'smbclient'),
                     pre='touch %s/ntpd-on' % work)
ok('chrony put in, chronyd not started over ntpd',
   ('dnf install -y chrony' in calls, 'enable --now chronyd' in calls, 'ntpd here' in out),
   (True, False, True))

print('\nThe database engine of config.json')
(work / 'config.json').write_text('{"db_engine": "postgres"}')
rc, out, calls = run('upgrade', have=('ssh', 'ssh-keygen', 'setfacl', 'openssl', 'smbclient',
                                      'chronyc', 'chronyd'))
ok('its driver and its dump program looked for', ('DRIVER PostgreSQL' in out or
                                                  'psycopg2' not in out,
                                                  'CLIENT PostgreSQL pg_dump' in out), (True, True))
(work / 'config.json').unlink()

print('\nIn install.sh')
ok('called on an install and on an upgrade', ('ensure_packages fresh' in inst,
                                              'ensure_packages upgrade' in inst), (True, True))
ok('an upgrade puts them in before the program is copied',
   inst.index('ensure_packages upgrade') < inst.index('progress 1 "copying the program"'))
ok('within a deadline (an upgrade from the pages has one)', 'PKG_UNTIL=$((SECONDS + 600))' in inst)
ok('only ever adds: never an upgrade, a remove or a swap of a package',
   not any(x in funcs for x in ('dnf upgrade', 'dnf remove', 'apt-get upgrade',
                                'apt-get remove', 'dnf swap', '--allowerasing')))

shutil.rmtree(str(work), ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
