#!/usr/bin/env python3
"""1.10.252: install.sh runs isemon on the newest Python the distribution
offers beside its own - python3.14 ... python3.11 on AlmaLinux / RHEL 9 -
when it imports what isemon needs (the database's driver too) and runs
isemon.py; else the next older, else the one there is. The system's python3
(dnf's) is never changed. What is chosen is LIB_DIR/python, which every unit
and the isemon command run through - put back by itself when isemon does not
start on it.

install.sh's own functions are run in bash with dnf, the Pythons and
systemctl played by small scripts keeping their state in files.

    ./test/fixes252_python.py
"""
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
funcs = inst[inst.index('PHP_TARGET="8.3"'):inst.index('ask() {          # ask VAR')]
work = Path(tempfile.mkdtemp(prefix='isemon-252-'))
W = str(work)
bin_ = work / 'bin'           # the PATH
pyd = work / 'usrbin'         # where the Pythons are (/usr/bin)
lib = work / 'lib'
LOG = work / 'calls.log'
for d in (bin_, pyd, lib):
    d.mkdir()
for prog in ('timeout', 'cat', 'touch', 'rm', 'sort', 'head', 'tail', 'grep', 'awk', 'cut',
             'printf', 'echo', 'mkdir', 'ln', 'readlink', 'chmod', 'sleep', 'cp', 'basename'):
    real = shutil.which(prog)
    if real:
        (bin_ / prog).symlink_to(real)

# A Python: it says its version, imports what its state files say it has,
# and runs isemon.py --version unless it is told it cannot.
PY = '''#!/bin/bash
v=%(v)s
echo "python$v $*" >> %(log)s
st=%(w)s/py-$v
case "$*" in
  *"sys.version_info"*) echo "$v"; exit 0;;
  *"import ssl"*) [ -f $st-broken ] && exit 1; exit 0;;
  *"import pymysql"*) [ -f $st-pymysql ] && exit 0; exit 1;;
  *"import psycopg2"*) [ -f $st-psycopg2 ] && exit 0; exit 1;;
  *"import colorama"*) exit 1;;
  *"--version"*) [ -f $st-noisemon ] && exit 1; echo "isemon x"; exit 0;;
esac
exit 0
'''


def python(v, where):
    p = where / ('python' + v)
    p.write_text(PY % {'v': v, 'log': LOG, 'w': W})
    p.chmod(0o755)
    return p


# dnf: python3.X put in when the repositories have it (repo-3.X); its
# PyMySQL / psycopg2 when they have that (repo-3.X-pymysql ...).
(bin_ / 'dnf').write_text('''#!/bin/bash
echo "dnf $*" >> %(log)s
pkg="${@: -1}"
case "$pkg" in
  python3.[0-9]*-PyMySQL) v="${pkg%%-PyMySQL}"; v="${v#python}"
     [ -f %(w)s/repo-$v-pymysql ] && touch %(w)s/py-$v-pymysql && exit 0; exit 1;;
  python3.[0-9]*-psycopg2) v="${pkg%%-psycopg2}"; v="${v#python}"
     [ -f %(w)s/repo-$v-psycopg2 ] && touch %(w)s/py-$v-psycopg2 && exit 0; exit 1;;
  python3.[0-9]*-colorama) exit 1;;
  python3.[0-9]*) v="${pkg#python}"
     [ -f %(w)s/repo-$v ] || exit 1
     cp %(w)s/template-$v %(pyd)s/python$v; chmod 755 %(pyd)s/python$v; exit 0;;
esac
exit 0
''' % {'log': LOG, 'w': W, 'pyd': pyd})
(bin_ / 'systemctl').write_text('''#!/bin/bash
echo "systemctl $*" >> %(log)s
case "$*" in
  "restart isemon.service") exit 0;;
  "is-active --quiet isemon.service")
     t=$(readlink -f %(lib)s/python); [ -f %(w)s/down-$(basename $t) ] && exit 3; exit 0;;
esac
exit 0
''' % {'log': LOG, 'w': W, 'lib': lib})
for f in bin_.iterdir():
    if not f.is_symlink():
        f.chmod(0o755)
(work / 'sys').mkdir()
python('3.9', work / 'sys')            # the system's own (dnf's)
# Templates of every Python the repositories may have.
for v in ('3.11', '3.12', '3.13', '3.14'):
    python(v, work).rename(work / ('template-' + v))


def machine(have=(), repo=(), state=(), link=None):
    for f in list(pyd.iterdir()) + list(lib.iterdir()):
        f.unlink()
    for f in work.iterdir():
        if f.is_file() and (f.name.startswith(('repo-', 'py-', 'down-'))):
            f.unlink()
    for v in have:
        shutil.copy(str(work / ('template-' + v)), str(pyd / ('python' + v)))
        (pyd / ('python' + v)).chmod(0o755)
    for r in repo:
        (work / ('repo-' + r)).write_text('1')
    for s in state:
        (work / s).write_text('1')
    if link:
        (lib / 'python').symlink_to(link)
    LOG.write_text('')


def run(engine='sqlite', update='yes', pkg='dnf', after=''):
    script = '''
set -u
good() { echo "GOOD $*"; }
warn() { echo "WARN $*"; }
note() { echo "NOTE $*"; }
say()  { echo "SAY $*"; }
run()  { "$@"; }
PKG=%s; DRY_RUN=""; PYTHON_UPDATE=%s; PHP_UPDATE=""
LIB_DIR=%s; BIN_LINK=%s/isemon-cmd; SOURCE_DIR=%s
export ISEMON_PY_BIN_DIR=%s
%s
PY_BIN_DIR=%s
python_pick %s
python_link
%s
echo "LINK $(readlink -f $PY_LINK)"
''' % (pkg, update or '""', lib, W, ROOT, pyd, funcs, pyd, engine, after)
    r = subprocess.run(['/bin/bash', '-c', script], capture_output=True, text=True,
                       env={'PATH': '%s:%s' % (bin_, work / 'sys'), 'HOME': W}, timeout=60)
    out = r.stdout + r.stderr
    link = [l for l in out.splitlines() if l.startswith('LINK ')]
    return out, LOG.read_text(), link[-1][5:] if link else ''


(work / 'sys' / 'python3').symlink_to(work / 'sys' / 'python3.9')

try:
    print('AlmaLinux 9: python3 is 3.9, the repositories have 3.11 and 3.12')
    machine(repo=('3.11', '3.12'))
    out, calls, link = run()
    ok('isemon on 3.12, the newest there is', link, str(pyd / 'python3.12'))
    ok('...3.14 and 3.13 asked for first', ('install -y -q python3.14' in calls,
                                            'install -y -q python3.13' in calls), (True, True))
    ok('...the system\'s python3 never touched', (work / 'sys' / 'python3').resolve().name,
       'python3.9')
    ok('...said', 'isemon runs on Python 3.12 from now on' in out)
    cmd = (work / 'isemon-cmd').read_text()
    ok('the isemon command runs isemon.py through LIB_DIR/python',
       'exec %s/python %s/isemon.py "$@"' % (lib, lib) in cmd)

    print('\nThe database is MariaDB')
    machine(repo=('3.11', '3.12', '3.11-pymysql'))
    out, calls, link = run('mariadb')
    ok('3.12 has no PyMySQL: 3.11, which has', link, str(pyd / 'python3.11'))
    ok('...said why 3.12 was passed over', 'python3.12 is there but does not run isemon' in out)
    machine(repo=('3.11', '3.12', '3.12-pymysql', '3.11-pymysql'))
    out, calls, link = run('mariadb')
    ok('3.12 with its PyMySQL put in', link, str(pyd / 'python3.12'))
    machine(repo=('3.11', '3.12'))
    out, calls, link = run('postgres')
    ok('PostgreSQL and no psycopg2 for any of them: the one it ran on', link,
       str(work / 'sys' / 'python3.9'))

    print('\nWhat does not run isemon is not taken')
    machine(repo=('3.12', '3.11'), state=('py-3.12-noisemon',))
    out, calls, link = run()
    ok('isemon.py does not start on 3.12: 3.11', link, str(pyd / 'python3.11'))
    machine(repo=('3.12',), state=('py-3.12-broken',))
    out, calls, link = run()
    ok('3.12 without ssl: the one it ran on', link, str(work / 'sys' / 'python3.9'))

    print('\nAlready on the newest')
    machine(have=('3.12',), link=str(pyd / 'python3.12'))
    out, calls, link = run()
    ok('on 3.12, nothing newer in the repositories: stays', (link, 'isemon runs on Python 3.12 ('
                                                             in out), (str(pyd / 'python3.12'), True))
    machine(have=('3.12',), repo=('3.13',), link=str(pyd / 'python3.12'))
    out, calls, link = run()
    ok('3.13 comes: to 3.13', link, str(pyd / 'python3.13'))

    print('\nisemon does not start on it: back on the one before')
    machine(repo=('3.12',), state=('down-python3.12',), link=str(work / 'sys' / 'python3.9'))
    out, calls, link = run(after='systemctl is-active --quiet isemon.service || python_back || '
                                 'echo STILL-DOWN')
    ok('back on 3.9, said, and it runs', (link, 'did not start on Python 3.12' in out,
                                          'STILL-DOWN' in out),
       (str(work / 'sys' / 'python3.9'), True, False))

    print('\nLeft alone')
    machine(repo=('3.12',))
    out, calls, link = run(update='')
    ok('--no-python-update: the one it runs on, nothing asked of dnf',
       (link, 'dnf' in calls), (str(work / 'sys' / 'python3.9'), False))
    out, calls, link = run(pkg='apt')
    ok('Debian, Ubuntu: their own python3', (link, 'dnf' in calls),
       (str(work / 'sys' / 'python3.9'), False))

    print('\nThe units and install.sh')
    for unit in ('isemon.service', 'isemon-web.service', 'isemon-upgrade.service'):
        text = (ROOT / 'deploy' / unit).read_text()
        ok('%s runs on /usr/local/lib/isemon/python' % unit,
           ('ExecStart=/usr/local/lib/isemon/python ' in text, '/usr/bin/python3 ' in text),
           (True, False))
    ok('an upgrade looks for it, links it before the units are put in, and goes back '
       'when isemon does not start', (
           'progress 1 "Python"\n    python_pick "$(config_engine)"' in inst,
           inst.index('    python_link\n    run install -D -m 0644 "$SOURCE_DIR/deploy/isemon.service"')
           < inst.index('progress 7 "restarting isemon"'),
           inst.count('systemctl is-active --quiet isemon.service || python_back || true')),
       (True, True, 2))
    ok('--no-python-update is an option, and in --help',
       ('--no-python-update) PYTHON_UPDATE=""' in inst, '  --no-python-update ' in inst),
       (True, True))
finally:
    shutil.rmtree(W, ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
