#!/usr/bin/env python3
"""1.10.272: only errors on the machine's console, and systemd told of the
units once; a popup drawn again keeps what it does when it closes; a
directory's check says its verdict apart.

systemd's rc-local generator says "/etc/rc.d/rc.local is not marked
executable, skipping" at every daemon-reload, into the kernel's log, which a
kernel with a high console level prints over the isemon console on tty1.
install.sh's console_quiet writes /etc/sysctl.d/80-isemon-console.conf with
RHEL's own `kernel.printk = 4 4 1 7` (every message still in journalctl -k),
leaves an administrator's own kernel.printk alone, writes the same on every
run, and the file goes with --uninstall. The upgrade and the first install
reload systemd once, not twice.

install.sh's own functions are run in bash with sysctl and systemctl played
by small scripts.

    ./test/fixes272_console.py
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


def func(name):
    body = inst[inst.index('%s() {' % name):]
    return body[:body.index('\n}\n') + 3]


work = Path(tempfile.mkdtemp(prefix='isemon-272-'))
try:
    bin_ = work / 'bin'
    bin_.mkdir()
    log = work / 'calls.log'
    for prog in ('sysctl', 'systemctl'):
        (bin_ / prog).write_text('#!/bin/sh\necho "%s $*" >> %s\n' % (prog, log))
        (bin_ / prog).chmod(0o755)
    d = work / 'sysctl.d'
    conf = work / 'sysctl.conf'
    mine = d / '80-isemon-console.conf'

    def run(dry=''):
        script = ('set -u\ngood() { echo "GOOD $*"; }\nnote() { echo "NOTE $*"; }\n'
                  'run() { "$@"; }\nDRY_RUN="%s"\nCONSOLE_SYSCTL=%s\nSYSCTL_DIR=%s\n'
                  'SYSCTL_CONF=%s\n%s\nconsole_quiet\n' % (dry, mine, d, conf,
                                                          func('console_quiet')))
        r = subprocess.run(['/bin/bash', '-c', script], capture_output=True, text=True,
                           env={'PATH': '%s:/usr/bin:/bin' % bin_}, timeout=60)
        return r.stdout + r.stderr

    print('A machine with nothing set')
    d.mkdir()
    (d / '50-other.conf').write_text('net.ipv4.ip_forward = 0\n')
    log.write_text('')
    out = run()
    ok('the file written: errors only on the console', mine.read_text().splitlines()[-1],
       'kernel.printk = 4 4 1 7')
    ok('...readable by all, and put in at once', (oct(mine.stat().st_mode & 0o777),
                                               'sysctl -q -p %s' % mine in log.read_text()),
       ('0o644', True))
    ok('...and said', 'only errors on the console' in out)
    first = mine.read_bytes()
    out = run()
    ok('run again (an upgrade): the same file, written the same', mine.read_bytes(), first)
    ok('...one file of ours, not two', sorted(p.name for p in d.iterdir()),
       ['50-other.conf', '80-isemon-console.conf'])

    print('\nAn administrator\'s own kernel.printk')
    mine.unlink()
    (d / '10-mine.conf').write_text('# by hand\n  kernel.printk = 7 4 1 7\n')
    log.write_text('')
    out = run()
    ok('another file sets it: nothing written, nothing put in, and said',
       (mine.exists(), 'sysctl' in log.read_text(), 'set by hand' in out),
       (False, False, True))
    (d / '10-mine.conf').unlink()
    conf.write_text('kernel.printk=3 4 1 3\n')
    out = run()
    ok('...in /etc/sysctl.conf too', (mine.exists(), 'set by hand' in out), (False, True))
    conf.write_text('# kernel.printk = 7 4 1 7\n')
    out = run()
    ok('...but not a line that is only a comment', mine.exists())
    assert mine.exists()
    (d / '10-mine.conf').write_text('kernel.printk = 7 4 1 7\n')
    out = run()
    ok('ours there already and another file sets it: ours is not counted as the other',
       'set by hand (%s)' % (d / '10-mine.conf') in out)
    ok('...and ours goes, or it would have the last word over the administrator\'s',
       (mine.exists(), (d / '10-mine.conf').exists()), (False, True))
    (d / '10-mine.conf').unlink()

    print('\n--dry-run')
    if mine.exists():
        mine.unlink()
    log.write_text('')
    out = run('yes')
    ok('nothing written, nothing put in, and said what would be',
       (mine.exists(), log.read_text(), '[would write] %s' % mine in out), (False, '', True))

    print('\ninstall.sh')
    ok('install_console calls it (the first install and every upgrade)',
       func('install_console').count('    console_quiet\n'), 1)
    ok('--uninstall takes the file away', '"$CONSOLE_PROFILE" "$CONSOLE_FLAG" "$CONSOLE_SYSCTL"; do'
       in inst)
    ok('rc.local is never made executable', 'rc.local' in inst and 'chmod +x /etc/rc.d/rc.local'
       not in inst and 'chmod 0755 /etc/rc.d/rc.local' not in inst)

    print('\nsystemd told once')
    ok('root_helpers reloads after the last unit, and says so',
       'run systemctl daemon-reload\n    UNITS_RELOADED="yes"' in func('root_helpers'))
    ok('the upgrade and the first install: reload_units after it, not a second reload',
       ('    install_console upgrade\n    reload_units\n' in inst,
        '\ninstall_console fresh\nreload_units\n' in inst), (True, True))
    script = ('set -u\nrun() { "$@"; }\n%s\n%s\nreload_units\nreload_units\n' % (
        inst[inst.index('UNITS_RELOADED=""'):inst.index('not_a_link() {')], ''))
    log.write_text('')
    subprocess.run(['/bin/bash', '-c', script], env={'PATH': '%s:/usr/bin:/bin' % bin_},
                   timeout=60)
    ok('reload_units with nothing reloaded yet: once, however often it is asked',
       log.read_text().count('systemctl daemon-reload'), 1)
    script2 = script.replace('reload_units\nreload_units\n', 'UNITS_RELOADED=yes\nreload_units\n')
    log.write_text('')
    subprocess.run(['/bin/bash', '-c', script2], env={'PATH': '%s:/usr/bin:/bin' % bin_},
                   timeout=60)
    ok('...and not at all after root_helpers did it', log.read_text(), '')
    ok('every unit is in before root_helpers reloads (upgrade and first install)', (
        inst.index('run install -D -m 0644 "$SOURCE_DIR/deploy/isemon.service" "$UNIT_FILE"\n'
                   '    run install -D -m 0644 "$SOURCE_DIR/deploy/isemon.logrotate" '
                   '"$LOGROTATE_FILE"\n    root_helpers') > 0,
        inst.index('run install -D -m 0644 "$SOURCE_DIR/deploy/isemon.service" "$UNIT_FILE"\n'
                   'run install -D -m 0644 "$SOURCE_DIR/deploy/isemon.logrotate" '
                   '"$LOGROTATE_FILE"\nroot_helpers') > 0), (True, True))

    print('\nA popup drawn again in its own place')
    page = (ROOT / 'web' / 'index.php').read_text()
    m = page[page.index('function modal(title, build, buttons, narrow) {'):]
    m = m[:m.index('  MODAL_GEN = ++MODAL_SEQ;')]
    ok('...keeps what is to be done when it closes, for when it does',
       ('f0()' in m, 'MODAL_CLOSE = null' in m, 'modalPark();' in m), (False, False, True))
    ok('Tuning the database server keeps its state until it is closed',
       ('MODAL_CLOSE = tuneForget;' in page, 'TUNE = null;' in page), (True, True))

    print('\nChecking a directory')
    src = (ROOT / 'isemon.py').read_text()
    ok('the check\'s verdict is `passed`, not spread over the request\'s `ok`',
       ("got['passed'] = bool(got.pop('ok', False))" in src,
        "return self.send_json({'ok': True, **daemon.directory_check(which)})" in src),
       (True, False))
    ok('...and the popup reads it', 'if (d.passed !== undefined ? d.passed : d.ok) {' in page)
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
