#!/usr/bin/env python3
"""1.10.250: install.sh moves the PHP of the pages to the release with the
php2shell fix - 8.3.36 (8.4.27 / 8.5.12 where it is on those) - from the
Remi repository, on an upgrade and on a fresh install; what Remi offers is
checked before a package is changed, and the stream it was on is put back
when anything does not work. --no-php-update leaves PHP alone.

install.sh's own functions are run in bash, with dnf, rpm, php and systemctl
played by small scripts keeping their state in files - so the machine is the
test's to say.

    ./test/fixes250_php.py
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
work = Path(tempfile.mkdtemp(prefix='isemon-250-'))
bin_ = work / 'bin'
bin_.mkdir()
for prog in ('timeout', 'cat', 'touch', 'rm', 'sort', 'head', 'tail', 'grep', 'awk', 'cut',
             'printf', 'echo', 'mkdir', 'sed'):
    real = shutil.which(prog)
    if real:
        (bin_ / prog).symlink_to(real)
LOG = work / 'calls.log'
W = str(work)
# php: the version in php-version.
(bin_ / 'php').write_text('#!/bin/bash\n[ -f %s/no-php ] && exit 1\ncat %s/php-version\n' % (W, W))
# php-fpm: says its version as php-fpm -v does (1.10.254: the pages' PHP when there is no php).
(bin_ / 'php-fpm').write_text('#!/bin/bash\necho "PHP $(cat %s/php-version) (fpm-fcgi) (built: Oct 1 2026)"\n' % W)
# rpm: -q NAME is there when NAME.rpm is; -E %%rhel says el.
(bin_ / 'rpm').write_text('''#!/bin/bash
echo "rpm $*" >> %(log)s
case "$1" in
  -E) cat %(w)s/el;;
  -q) [ -f %(w)s/$2.rpm ];;
esac
''' % {'log': LOG, 'w': W})
# dnf: the module stream in stream; what each stream offers in offer-STREAM;
# distro-sync puts the stream's version in php-version.
(bin_ / 'dnf').write_text('''#!/bin/bash
echo "dnf $*" >> %(log)s
args=" $* "
case "$args" in
  *" module list --enabled php "*)
    [ -s %(w)s/stream ] || { echo "Error: No matching Modules to list" >&2; exit 1; }
    echo "php  $(cat %(w)s/stream) [e]  common [d]  PHP scripting language"; exit 0;;
  *" module reset "*) : > %(w)s/stream; exit 0;;
  *" module enable "*)
    s="${@: -1}"; s="${s#php:}"
    [ -f %(w)s/no-$s ] && exit 1
    echo "$s" > %(w)s/stream; exit 0;;
  *" repoquery "*)
    s="$(cat %(w)s/stream)"; [ -f %(w)s/offer-$s ] || exit 1; cat %(w)s/offer-$s; exit 0;;
  *" distro-sync "*)
    [ -f %(w)s/sync-fail ] && exit 1
    s="$(cat %(w)s/stream)"; [ -z "$s" ] && s=appstream
    [ -f %(w)s/offer-$s ] && cp %(w)s/offer-$s %(w)s/php-version; exit 0;;
  *" install "*epel-release*) [ -f %(w)s/no-net ] && exit 1; touch %(w)s/epel-release.rpm; exit 0;;
  *" install "*remi-release*) [ -f %(w)s/no-net ] && exit 1; touch %(w)s/remi-release.rpm; exit 0;;
esac
exit 0
''' % {'log': LOG, 'w': W})
(bin_ / 'cp').symlink_to(shutil.which('cp'))
(bin_ / 'systemctl').write_text('''#!/bin/bash
echo "systemctl $*" >> %(log)s
case "$*" in
  "cat php-fpm.service") exit 0;;
  "list-unit-files"*) exit 0;;
  "restart php-fpm") [ -f %(w)s/fpm-fail ] && exit 1; exit 0;;
esac
exit 0
''' % {'log': LOG, 'w': W})
for f in bin_.iterdir():
    if not f.is_symlink():
        f.chmod(0o755)


def machine(version, stream, offers, el='9', **flags):
    for f in work.iterdir():
        if f.is_file():
            f.unlink()
    (work / 'php-version').write_text(version + '\n')
    (work / 'stream').write_text(stream + '\n' if stream else '')
    (work / 'el').write_text(el + '\n')
    for s, v in offers.items():
        (work / ('offer-' + s)).write_text(v + '\n')
    for f, on in flags.items():
        if on:
            (work / f.replace('_', '-')).write_text('1')
    LOG.write_text('')


def run(pkg='dnf', update='yes', dry=''):
    # As install.sh runs it: set -euo pipefail - a dnf that lists nothing
    # must not end the upgrade (1.10.254).
    script = '''
set -euo pipefail
good() { echo "GOOD $*"; }
warn() { echo "WARN $*"; }
note() { echo "NOTE $*"; }
say()  { echo "SAY $*"; }
PKG=%s; DRY_RUN=%s; PHP_UPDATE=%s; LIB_DIR=/nonexistent
%s
php_update
echo "RAN TO THE END"
''' % (pkg, dry or '""', update or '""', funcs)
    r = subprocess.run(['/bin/bash', '-c', script], capture_output=True, text=True,
                       env={'PATH': str(bin_), 'HOME': W}, timeout=60)
    return r.returncode, r.stdout + r.stderr, LOG.read_text(), \
        (work / 'php-version').read_text().strip(), (work / 'stream').read_text().strip()


try:
    print('PHP 8.3.8 of AlmaLinux 9 (php:8.3), Remi has 8.3.36')
    machine('8.3.8', '8.3', {'8.3': '8.3.8', 'remi-8.3': '8.3.36'})
    rc, out, calls, v, stream = run()
    ok('moved: 8.3.36 from php:remi-8.3, the upgrade went on', (rc, v, stream, 'RAN TO THE END' in out),
       (0, '8.3.36', 'remi-8.3', True))
    ok('...EPEL and Remi added first', ('install -y -q epel-release' in calls,
                                        'remi-release-9.rpm' in calls), (True, True))
    ok('...what Remi offers looked at before a package was changed',
       calls.index('repoquery') < calls.index('distro-sync'))
    ok('...every PHP package moved, php-fpm restarted, said',
       ("distro-sync php*" in calls, 'restart php-fpm' in calls,
        'GOOD PHP 8.3.36 from the Remi repository' in out), (True, True, True))
    ok('...what it found said on the way', ('PHP 8.3.8 runs the pages' in out,
                                           'the php stream enabled now: 8.3' in out), (True, True))
    ok('...never removed nor swapped anything', any(x in calls for x in (
        ' remove ', ' erase ', 'swap', '--allowerasing')), False)

    print('\nThe default PHP 8.0 of AlmaLinux 9 - no stream enabled, dnf says so with an error')
    machine('8.0.30', '', {'appstream': '8.0.30', 'remi-8.3': '8.3.36', '8.3': '8.3.19'})
    rc, out, calls, v, stream = run()
    ok('to 8.3.36 from Remi, and the upgrade went on (set -e)', (rc, v, stream, 'RAN TO THE END' in out),
       (0, '8.3.36', 'remi-8.3', True))
    ok('...said there was no stream', 'none, the default PHP of the distribution' in out)

    print('\nNo php command, only php-fpm (1.10.254)')
    machine('8.0.30', '', {'appstream': '8.0.30', 'remi-8.3': '8.3.36'}, no_php=True)
    rc, out, calls, v, stream = run()
    ok('php-fpm asked its version, and moved', (v, stream, 'PHP 8.0.30 runs the pages' in out),
       ('8.3.36', 'remi-8.3', True))

    print('\nPHP 8.2.35 - the 8.2 with the fix - from php:remi-8.2 (1.10.255: to 8.3 all the same)')
    machine('8.2.35', 'remi-8.2', {'remi-8.2': '8.2.35', 'remi-8.3': '8.3.36', '8.3': '8.3.19'},
            epel_release=False)
    (work / 'epel-release.rpm').write_text('1')
    (work / 'remi-release.rpm').write_text('1')
    rc, out, calls, v, stream = run()
    ok('to Remi\'s 8.3.36, the upgrade went on', (rc, v, stream, 'RAN TO THE END' in out),
       (0, '8.3.36', 'remi-8.3', True))
    ok('...said it takes only an 8.3 with the fix', 'only an 8.3 with it is taken' in out)
    machine('8.2.35', 'remi-8.2', {'remi-8.2': '8.2.35', 'remi-8.3': '8.3.30', '8.3': '8.3.19'})
    rc, out, calls, v, stream = run()
    ok('Remi\'s 8.3 without the fix: never in place of one with it - the distribution\'s '
       'php:8.3 (backported)', (v, stream), ('8.3.19', '8.3'))
    machine('8.2.35', 'remi-8.2', {'remi-8.2': '8.2.35', 'remi-8.3': '8.3.30'})
    rc, out, calls, v, stream = run()
    ok('...and no other 8.3: stays on 8.2.35, its stream back, said',
       (v, stream, 'could not be moved to 8.3' in out), ('8.2.35', 'remi-8.2', True))

    print('\nAlready fixed')
    machine('8.3.36', 'remi-8.3', {'remi-8.3': '8.3.36'})
    rc, out, calls, v, stream = run()
    ok('nothing done, said', (v, 'dnf' in calls, 'has the php2shell fix' in out), ('8.3.36', False, True))
    machine('8.4.27', 'remi-8.4', {})
    rc, out, calls, v, stream = run()
    ok('8.4.27: nothing done', (v, calls), ('8.4.27', ''))

    print('\nRemi has not got 8.3.36 yet: the newest 8.3 it has (1.10.254)')
    machine('8.3.8', '8.3', {'8.3': '8.3.8', 'remi-8.3': '8.3.30'})
    rc, out, calls, v, stream = run()
    ok('8.3.8 to Remi\'s 8.3.30, and said it is not 8.3.36 yet',
       (v, stream, 'is not 8.3.36 yet' in out), ('8.3.30', 'remi-8.3', True))
    machine('8.0.30', '', {'appstream': '8.0.30', 'remi-8.3': '8.3.30', '8.3': '8.3.19'})
    rc, out, calls, v, stream = run()
    ok('8.0 to Remi\'s 8.3.30', (v, stream), ('8.3.30', 'remi-8.3'))
    machine('8.3.30', 'remi-8.3', {'remi-8.3': '8.3.30'})
    rc, out, calls, v, stream = run()
    ok('on Remi\'s newest already: brought up to date, nothing moved', (v, stream,
                                                                     'distro-sync' in calls),
       ('8.3.30', 'remi-8.3', False))

    print('\nNo way to the repositories')
    machine('8.3.8', '8.3', {'8.3': '8.3.8', 'remi-8.3': '8.3.36'}, no_net=True)
    rc, out, calls, v, stream = run()
    ok('8.3 already: its stream brought up to date, said', (v, stream,
                                                          'could not be added' in out,
                                                          "upgrade php*" in calls,
                                                          'brought up to date' in out),
       ('8.3.8', '8.3', True, True, True))
    machine('8.0.30', '', {'appstream': '8.0.30', 'remi-8.3': '8.3.36', '8.3': '8.3.19'},
            no_net=True)
    rc, out, calls, v, stream = run()
    ok('8.0: the distribution\'s php:8.3', (v, stream, 'from the distribution (php:8.3)' in out),
       ('8.3.19', '8.3', True))
    machine('8.0.30', '', {'appstream': '8.0.30'}, no_net=True)
    rc, out, calls, v, stream = run()
    ok('...nor that: back to no stream, said', (v, stream, 'could not be moved to 8.3' in out),
       ('8.0.30', '', True))

    print('\nphp-fpm does not start on it')
    machine('8.3.8', '8.3', {'8.3': '8.3.8', 'remi-8.3': '8.3.36'}, fpm_fail=True)
    rc, out, calls, v, stream = run()
    ok('back on the stream and the PHP it was, said', (v, stream, 'did not start as it should' in out),
       ('8.3.8', '8.3', True))
    machine('8.0.30', '', {'appstream': '8.0.30', '8.3': '8.3.19'}, fpm_fail=True, no_net=True)
    rc, out, calls, v, stream = run()
    ok('...the distribution\'s 8.3 neither: back on 8.0', (v, stream), ('8.0.30', ''))

    print('\ndnf cannot move it')
    machine('8.3.8', '8.3', {'8.3': '8.3.8', 'remi-8.3': '8.3.36'}, sync_fail=True)
    rc, out, calls, v, stream = run()
    ok('back on its stream, said', (v, stream, 'dnf could not move PHP' in out), ('8.3.8', '8.3', True))

    print('\n8.4 below its fix')
    machine('8.4.10', 'remi-8.4', {'remi-8.4': '8.4.27'})
    rc, out, calls, v, stream = run()
    ok('8.4.10: to 8.4.27, never down to 8.3', (v, stream), ('8.4.27', 'remi-8.4'))

    print('\nLeft alone')
    machine('8.3.8', '8.3', {'remi-8.3': '8.3.36'})
    rc, out, calls, v, stream = run(update='')
    ok('--no-php-update: nothing, said', (v, calls, 'left as it is' in out), ('8.3.8', '', True))
    rc, out, calls, v, stream = run(pkg='apt')
    ok('Debian, Ubuntu: said, nothing changed', (v, calls, 'by hand' in out),
       ('8.3.8', '', True))
    rc, out, calls, v, stream = run(dry='1')
    ok('--dry-run: said what would be done', (v, calls, 'would move' in out), ('8.3.8', '', True))
    machine('8.3.8', '8.3', {'remi-8.3': '8.3.36'}, el='7')
    rc, out, calls, v, stream = run()
    ok('not RHEL 8, 9 or 10: said', (v, 'not a RHEL 8, 9 or 10' in out), ('8.3.8', True))

    print('\nIn install.sh')
    ok('an upgrade with the pages does it', 'progress 1 "PHP"\n        php_update' in inst)
    ok('...a fresh install with the pages too', '[[ -n "$WITH_WEB" ]] && php_update' in inst)
    ok('--no-php-update is an option, and said in --help',
       ('--no-php-update)   PHP_UPDATE=""' in inst, '  --no-php-update ' in inst), (True, True))
    ok('the dashboard\'s fixed releases are the installer\'s',
       all(x in inst for x in ('8.2) echo 8.2.35', '8.3) echo 8.3.36', '8.4) echo 8.4.27',
                               '8.5) echo 8.5.12')))
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
