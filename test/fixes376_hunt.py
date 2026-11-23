#!/usr/bin/env python3
"""1.10.376: bug hunt, round 5 of 10 - the pages' PHP and sign-in, the
command line and the text console.

    ./test/fixes376_hunt.py
"""
import os
import subprocess
import sys
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


def run(*args, **env):
    e = dict(os.environ, **env)
    r = subprocess.run([sys.executable, str(ROOT / 'isemon.py')] + list(args),
                       capture_output=True, text=True, env=e, timeout=120)
    return r.returncode, r.stdout + r.stderr


print('The command line')
rc, out = run('--users', '--add-user', 'carol')
ok('two commands on one line: said, nothing done', (rc != 0, 'give one at a time' in out),
   (True, True))
rc, out = run('--help', PYTHONIOENCODING='ascii')
ok('--help on a terminal that is not UTF-8', (rc, 'Traceback' in out), (0, False))
src = (ROOT / 'isemon.py').read_text()
ok('--export --secrets made the owner\'s before a byte is written',
   "os.fchmod(out.fileno(), 0o600 if args.secrets else 0o644)" in src)
ok('the CRL and OCSP clears say only JSON under --json',
   src.count("if not getattr(args, 'json', False):          # JSON alone under --json (1.10.376)")
   == 2)

print('The console')
ok('a trusted root added or taken away asks here, then says yes',
   "self.act('--os-roots-add', f, '--yes')" in src
   and "self.act('--os-roots-remove', fp, '--yes')" in src)
ok('a letter of more than one byte read whole', "return raw.decode('utf-8')" in src)
ok('a search or a reason beginning with "-" is no option',
   "['--search=%s' % got['q']]" in src and "['--why=%s' % got['why']]" in src)

print('The pages')
page = (ROOT / 'web' / 'index.php').read_text()
api = (ROOT / 'web' / 'isemon-api.php').read_text()
ok('more than 4 MB of JSON only from a full admin',
   "if ($told > 4 * 1024 * 1024 && !in_array($what, ['db-restore', 'upgrade-package'," in page)
ok('the sign-in form never sends the password in the address',
   'id="signin-form" method="post" action="?api=login"' in page)
ok('a busy daemon is "busy", not "sign in"',
   "'the daemon is busy - try again in a moment'" in api)
r = subprocess.run(['php', '-l', str(ROOT / 'web' / 'index.php')], capture_output=True, text=True)
ok('index.php reads', r.returncode, 0)

print('SQLite and letters beyond A to Z')
import sqlite3                                        # noqa: E402
import tempfile                                       # noqa: E402
import time                                           # noqa: E402
sys.path.insert(0, str(ROOT))
import isemon                                         # noqa: E402
folder = Path(tempfile.mkdtemp(prefix='isemon-376-'))
for k, v in dict(STATE_DIR=folder, DB_FILE=folder / 'c.db', BACKUP_DIR=folder / 'b',
                 DUMP_DIR=folder / 'd', RUN_DIR=folder, LOG_DIR=folder,
                 CONFIG_FILE=folder / 'config.json', _LOG_PATH=folder / 'c.log',
                 TOKEN_FILE=folder / 'tok').items():
    setattr(isemon, k, v)
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0})
store = isemon.Storage(isemon.DB_FILE)
store.block('203.0.113.9', why='Útok z Číny', by='Šárka')
for q in ('Šárka', 'šárka', 'Číny', 'útok', 'z Č', 'rka'):
    ok('the ban history finds "%s"' % q, store.block_events(text=q)[1] >= 1)
# An index over LOWER() as SQLite's own LOWER() made it, before 1.10.200.
raw = sqlite3.connect(str(isemon.DB_FILE))
raw.execute('DROP INDEX IF EXISTS failed_user_lc')
raw.execute('CREATE INDEX failed_user_lc ON failed (LOWER(username), ts)')
old = time.time() - 400 * 86400
raw.execute("INSERT INTO failed (session, ts, ip, username, kind) VALUES "
            "('x1', ?, '198.51.100.1', 'ŠÁRKA.NOVÁ', 'vpn')", (old,))
raw.execute("DELETE FROM meta WHERE key = 'mended_lower_reindex'")
raw.commit()
raw.close()
store = isemon.Storage(isemon.DB_FILE)
ok('the indexes over LOWER() built again: the file is sound',
   [str(r[0]) for r in store.db.execute('PRAGMA integrity_check')], ['ok'])
store.prune_auth(30, 30)
ok('...and old rows with Š in them can be let go', store.db.execute(
    "SELECT COUNT(*) AS n FROM failed WHERE session = 'x1'").fetchone()['n'], 0)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
