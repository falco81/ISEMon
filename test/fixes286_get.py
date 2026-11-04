#!/usr/bin/env python3
"""1.10.286: isemon --get KEY - what --set changes, read back.

One key alone: its value bare, for a script ($(isemon --get block_tries)).
Several, or a pattern ('mikrotik_*'): key=value lines. --json: an object.
The value as it stands - saved in the database, from config.json, or the
default. A secret never in clear, as --settings shows it. An unknown key:
said, with the names near it, and exit 2.

    ./test/fixes286_get.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PASS = FAIL = 0


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


work = Path(tempfile.mkdtemp(prefix='isemon-286-'))
try:
    (work / 'state').mkdir()
    (work / 'config.json').write_text(json.dumps({'db_engine': 'sqlite', 'site_name': 'From the file',
                                                  'api_port': 1}))
    env = dict(os.environ, ISEMON_STATE=str(work / 'state'), ISEMON_CONFIG=str(work / 'config.json'),
               NO_COLOR='1')

    def cli(*args, **more):
        return subprocess.run([sys.executable, str(ROOT / 'isemon.py')] + list(args),
                              capture_output=True, text=True, stdin=subprocess.DEVNULL,
                              env=dict(env, **more), timeout=120)

    print('One setting')
    r = cli('--get', 'block_tries')
    ok('the default, bare', (r.returncode, r.stdout), (0, '5\n'))
    r = cli('--get', 'site_name')
    ok('from config.json', r.stdout, 'From the file\n')
    r = cli('--set', 'block_tries=8')
    ok('--set it (the daemon not running: written straight away)', r.returncode, 0)
    r = cli('--get', 'block_tries')
    ok('...--get reads it back', (r.returncode, r.stdout), (0, '8\n'))
    ok('...as a script takes it', subprocess.run(
        ['/bin/sh', '-c', 'x=$(%s %s --get block_tries); test "$x" -gt 5 && echo more'
         % (sys.executable, ROOT / 'isemon.py')], capture_output=True, text=True,
        env=env, timeout=120).stdout, 'more\n')

    print('\nSeveral, a pattern, JSON')
    r = cli('--get', 'block_tries', '--get', 'site_name')
    ok('several: key=value lines', r.stdout, 'block_tries=8\nsite_name=From the file\n')
    r = cli('--get', 'block_*')
    lines = r.stdout.splitlines()
    ok('a pattern: every one it names, as key=value', (r.returncode, 'block_tries=8' in lines,
                                                       all(l.startswith('block_') for l in lines),
                                                       len(lines) > 2), (0, True, True, True))
    r = cli('--get', 'block_tries', '--get', 'site_name', '--json')
    ok('--json: an object', json.loads(r.stdout), {'block_tries': 8, 'site_name': 'From the file'})

    print('\nA secret')
    r = cli('--set', 'mikrotik_password=a-secret-of-ours-42')
    r = cli('--get', 'mikrotik_password')
    ok('never in clear: by its last two letters', (r.stdout.strip().endswith('42'),
                                                   'a-secret' not in r.stdout,
                                                   set(r.stdout.strip()[:-2]) == {'•'}),
       (True, True, True))
    r = cli('--get', 'mikrotik_*', '--json')
    ok('...not by a pattern either, nor as JSON', 'a-secret' not in r.stdout)

    print('\nNot a setting')
    r = cli('--get', 'block_triez')
    ok('said, with the names near it, exit 2', (r.returncode, 'there is no setting' in r.stdout + r.stderr),
       (2, True))
    r = cli('--get', 'tries')
    ok('...a part of a name: the ones it is part of', 'block_tries' in r.stdout + r.stderr)
    r = cli('--get', 'nothing_like_this_*')
    ok('a pattern naming nothing: exit 2', r.returncode, 2)
    r = cli('--help')
    ok('--help says it', '--get KEY' in r.stdout)
finally:
    shutil.rmtree(str(work), ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
