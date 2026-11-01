#!/usr/bin/env python3
"""1.10.270: isemon started from its compiled form, and the panes that wait
for root asking more often while they wait.

- deploy/isemon_main.py runs isemon.py as `__main__` from LIB_DIR/__pycache__/
  (install.sh's py_cache compiles it, checked against the file's hash): the
  daemon's start and every `isemon` command no longer compile 85 000 lines.
  The same `__name__`, `__file__`, `sys.argv` and the same output as isemon.py
  run as a file; a changed isemon.py is never run from an old compiled form.
- Settings -> Firewall and access, Certificates and TLS: asked every 0.7 s
  while root has a change still to put in (5 s otherwise); SSH keys and the
  otp logs over TLS every 0.7 s while root has theirs to do.

    ./test/fixes270_speed.py
"""
import os
import shutil
import struct
import subprocess
import sys
import tempfile
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


inst = (ROOT / 'install.sh').read_text()
page = (ROOT / 'web' / 'index.php').read_text()
work = Path(tempfile.mkdtemp(prefix='isemon-270-'))
TAG = sys.implementation.cache_tag


def py_cache(lib):
    """install.sh's own py_cache, run in bash on this Python."""
    body = inst[inst.index('py_cache() {'):]
    body = body[:body.index('\n}\n') + 3]
    (lib / 'python').symlink_to(sys.executable)
    script = 'set -u\nwarn() { echo "WARN $*"; }\nnote() { echo "NOTE $*"; }\n' \
             'py_mm() { echo x; }\nDRY_RUN=""; LIB_DIR=%s; PY_LINK=%s/python\n%s\npy_cache\n' \
             % (lib, lib, body)
    return subprocess.run(['/bin/bash', '-c', script], capture_output=True, text=True,
                          timeout=300)


def run(lib, *args, flags=()):
    return subprocess.run([str(lib / 'python')] + list(flags) + [str(lib / args[0])] +
                          list(args[1:]), capture_output=True, text=True, timeout=300,
                          cwd=str(work), env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))


try:
    print('isemon.py, compiled ahead')
    lib = work / 'lib'
    lib.mkdir()
    shutil.copy(str(ROOT / 'isemon.py'), str(lib / 'isemon.py'))
    shutil.copy(str(ROOT / 'deploy' / 'isemon_main.py'), str(lib / 'isemon_main.py'))
    got = py_cache(lib)
    pyc = lib / '__pycache__' / ('isemon.%s.pyc' % TAG)
    ok('py_cache: LIB_DIR/__pycache__/isemon.%s.pyc, said nothing' % TAG,
       (got.returncode, pyc.exists(), got.stdout.strip()), (0, True, ''))
    flags = struct.unpack('<I', pyc.read_bytes()[4:8])[0]
    ok('...checked against the file\'s hash, not its time', flags, 3)
    t = time.time()
    a = run(lib, 'isemon_main.py', '--version')
    t_main = time.time() - t
    t = time.time()
    b = run(lib, 'isemon.py', '--version')
    t_file = time.time() - t
    ok('isemon_main.py --version says what isemon.py --version says',
       (a.returncode, a.stdout), (0, b.stdout))
    print('          (%.2f s from the compiled form, %.2f s from the file)' % (t_main, t_file))
    v = run(lib, 'isemon_main.py', '--version', flags=('-v',))
    ok('...and runs from the compiled form', "code object from '%s'" % pyc in v.stderr)
    a = run(lib, 'isemon_main.py', '--help')
    b = run(lib, 'isemon.py', '--help')
    ok('--help the same, its program name too', (a.returncode, a.stdout), (b.returncode, b.stdout))
    bad = run(lib, 'isemon_main.py', '--no-such-option')
    worse = run(lib, 'isemon.py', '--no-such-option')
    ok('an unknown option: the same refusal, the same exit code',
       (bad.returncode, bad.stderr), (worse.returncode, worse.stderr))

    print('\nThe same as run as a file')
    st = work / 'stub'
    st.mkdir()
    shutil.copy(str(ROOT / 'deploy' / 'isemon_main.py'), str(st / 'isemon_main.py'))
    (st / 'isemon.py').write_text(
        'import sys\nsys.stdout.write("%s|%s|%s|%s\\n" % (__name__, __file__, sys.argv[0], '
        'sys.argv[1:]))\nWORD = "old"\nif __name__ == "__main__":\n'
        '    import json\n    print(WORD, sys.modules["__main__"].WORD)\n    sys.exit(3)\n')
    py_cache(st)
    a = run(st, 'isemon_main.py', 'one', '--two')
    b = run(st, 'isemon.py', 'one', '--two')
    ok('__name__, __file__, sys.argv, sys.modules["__main__"], the exit code',
       (a.returncode, a.stdout), (3, b.stdout))
    ok('...as isemon.py itself gives them', a.stdout.splitlines()[0],
       '__main__|%s|%s|[\'one\', \'--two\']' % (st / 'isemon.py', st / 'isemon.py'))
    (st / 'isemon.py').write_text((st / 'isemon.py').read_text().replace('"old"', '"new"'))
    a = run(st, 'isemon_main.py')
    ok('isemon.py changed after it was compiled: the new one runs, not the old compiled form',
       a.stdout.splitlines()[1], 'new new')
    shutil.rmtree(str(st / '__pycache__'))
    a = run(st, 'isemon_main.py')
    ok('...and with nothing compiled ahead, it runs as before', a.stdout.splitlines()[1], 'new new')

    print('\ninstall.sh and the unit')
    unit = (ROOT / 'deploy' / 'isemon.service').read_text()
    ok('the unit starts isemon_main.py', 'ExecStart=/usr/local/lib/isemon/python '
       '/usr/local/lib/isemon/isemon_main.py\n' in unit)
    pl = inst[inst.index('python_link() {'):inst.index('py_cache() {')]
    ok('python_link puts isemon_main.py in, writes the command through it, then compiles', (
        'run install -D -m 0644 "$SOURCE_DIR/deploy/isemon_main.py" "$LIB_DIR/isemon_main.py"' in pl,
        '[ -f %s/isemon_main.py ] || exec %s %s/isemon.py "$@"\\nexec %s %s/isemon_main.py "$@"' in pl,
        pl.rstrip().endswith('py_cache\n}') or pl.count('    py_cache\n') == 1),
       (True, True, True))
    pb = inst[inst.index('python_back() {'):]
    pb = pb[:pb.index('\n}\n')]
    ok('...and python_back compiles for the Python it goes back to', '    py_cache\n' in pb)
    ok('python_link comes after isemon.py is copied, on an upgrade and on a first install', (
        inst.index('run install -D -m 0755 "$SOURCE_DIR/isemon.py" "$LIB_DIR/isemon.py"\n    for extra')
        < inst.index('    python_link\n    run install -D -m 0644 "$SOURCE_DIR/deploy/isemon.service"'),
        inst.index('\nrun install -D -m 0755 "$SOURCE_DIR/isemon.py" "$LIB_DIR/isemon.py"\n')
        < inst.index('\npython_link\ngood "$BIN_LINK"')), (True, True))
    # The command, as python_link writes it, run by sh.
    fmt = pl[pl.index("printf '") + 8:pl.index("' \\\n")]
    cmd = (fmt.encode().decode('unicode_escape')
           % (lib / 'python', lib, lib / 'python', lib, lib / 'python', lib))
    (work / 'isemon-cmd').write_text(cmd)
    (work / 'isemon-cmd').chmod(0o755)
    a = subprocess.run([str(work / 'isemon-cmd'), '--version'], capture_output=True, text=True,
                       timeout=300)
    ok('the isemon command: the version', (a.returncode, a.stdout.startswith('isemon ')),
       (0, True))
    (lib / 'isemon_main.py').unlink()
    a = subprocess.run([str(work / 'isemon-cmd'), '--version'], capture_output=True, text=True,
                       timeout=300)
    ok('...and isemon.py itself when isemon_main.py is not there',
       (a.returncode, a.stdout.startswith('isemon ')), (0, True))

    print('\nThe panes that wait for root')
    ok('Firewall and access, Certificates and TLS: 0.7 s while root has it to do, 5 s otherwise',
       ('rootWaits(S.last) ? 700 : 5000' in page, "var next = paneAgain('fw', step), gen = FW.gen;" in page,
        "var next = paneAgain('tls', step), gen = TLS.gen;" in page), (True, True, True))
    ok('...only while root\'s helper is there to do it',
       'return !!(r && typeof r === \'object\' && r.pending && r.helper);' in page)
    ok('...loaded again, the old chain ends rather than going on beside the new one',
       (page.count('    if (S.gen !== mine) return;'), page.count('if (FW.gen !== gen) return;'),
        page.count('if (TLS.gen !== gen) return;')), (1, 1, 1))
    ok('...the next question only once the last is answered',
       page.count(".catch(function () {}).then(next);"), 2)
    ok('...the TLS pane\'s root state and the firewall\'s both read',
       'var r = d && (d.root_state || d.root);' in page)
    ok('Try again on the firewall asks for the pane again',
       "toast(x.message, 'good'); loadFw(); }).catch(oops);" in page)
    ok('SSH keys, the otp logs over TLS: 0.7 s while root has it to do',
       page.count('}, 700);      /* only while root has it to do'), 2)
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
