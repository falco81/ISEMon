#!/usr/bin/env python3
"""1.10.228: the isemon console, as otp's - `isemon --console`, its menus run
by the arrows and Enter, every action the `isemon ...` command it shows, the
live log with a grep as you type, and `isemon --console-at-login on|off|status`
with the profile script that opens it when root signs in.

curses cannot be driven from here key by key in every detail, so:

- every menu is walked with the windows answered by the test, and every
  command it would run is parsed by the real parser - or is one this version
  does not have, which the console says rather than runs;
- the checks of a window's fields, the live view's grep, the log's colours
  (which never move a column), the choice at login read and written in a
  folder of the test's, the profile script in bash in a few situations, and
  install.sh's part of it run on its own;
- and the console itself is started on a pseudo-terminal, a menu opened and
  left with q.

    ./test/fixes228_console.py
"""
import os
import pty
import re
import select
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT))
work = Path(tempfile.mkdtemp(prefix='isemon-228c-'))
os.environ['ISEMON_CONSOLE_FLAG'] = str(work / 'console-login')
os.environ['ISEMON_STATE'] = str(work / 'state')
os.environ['ISEMON_CONFIG'] = str(work / 'config.json')
(work / 'state').mkdir()
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


def title(text):
    print('\n%s' % text)


def env_for(**more):
    e = dict(os.environ)
    e.update({k: str(v) for k, v in more.items()})
    return e


# ---------------------------------------------------------------------------
title('The options this version has, from its own parser')
known = isemon.cli_options()
ok('the parser is reached without running anything', '--status' in known and '--ban' in known)
ok('...and it has --console and --console-at-login', '--console' in known
   and known.get('--console-at-login') == ('on', 'off', 'status'))
ok('a choice is known with its words', known.get('--purge'), ('both', 'blocked', 'geo'))
ok('an option it does not have is named', isemon.cli_missing(['--no-such-thing'], known),
   '--no-such-thing')
ok('a word an option does not take is named',
   isemon.cli_missing(['--mikrotik', '--purge', 'all'], known), '--purge all')
ok('a whole command it has is not', isemon.cli_missing(['--ban', '192.0.2.1', '--forever'],
                                                        known), None)
ok('HelpfulParser.parse_args is put back', isemon.HelpfulParser.parse_args
   is isemon.argparse.ArgumentParser.parse_args)


def parses(args):
    """The command line as the real parser takes it: True, or what it said."""
    parser = isemon.cli_parser()
    try:
        parser.parse_args([str(a) for a in args])
        return True
    except SystemExit:
        return False


# ---------------------------------------------------------------------------
title('Every menu walked: each command parses, or is not in this version')
backups = work / 'state' / 'backups'
backups.mkdir()
(backups / 'isemon-20261028-0330.json.gz').write_bytes(b'x')
isemon.BACKUP_DIR = backups
isemon.DUMP_DIR = work / 'state' / 'dumps'

SAMPLE = {
    '--blocked': {'blocked': [{'ip': '192.0.2.7', 'country': 'NL', 'left': 600,
                               'forever': False, 'why': 'too many', 'by': None, 'auto': True}]},
    '--whitelist': {'rows': [{'ip': '198.51.100.0/24', 'from': 'list', 'at': 1, 'by': 'me'},
                             {'ip': '203.0.113.1', 'from': 'setting'}]},
    '--users': {'users': [{'name': 'alice', 'role': 'readonly', 'disabled': False},
                          {'name': 'bob', 'role': 'fulladmin', 'disabled': True}]},
    '--jobs': {'jobs': [{'id': 'tidy', 'kind': 'tidy', 'done': False}]},
    '--status': {'trials': [{'kind': 'net', 'until': time.time() + 300}]},
    '--upgrade-check': {'url': 'https://example.org/isemon/', 'packages': [
        {'version': '99.0.0'}, {'version': '1.0.0'}]},
}
CANDIDATES = ['192.0.2.10', 'alice', 'backup_keep', '10', '/root/isemon-config.json',
              str(backups / 'isemon-20261028-0330.json.gz')]


class Dry(isemon.Console):
    """The console with every window answered by the test: a choice is the
    round's one, a Yes is a yes, a field the first candidate its checks take."""

    def __init__(self):
        super(Dry, self).__init__(isemon.Palette(False))
        self.round = 0
        self.ran = []           # (args, env, how)
        self.titles = []
        self.depth = 0

    def out(self, *args):
        if self.missing(args):
            return None
        return SAMPLE.get(args[0])

    def sub(self, title_, items):
        self.titles.append(title_)
        if self.depth > 3:
            return None
        self.depth += 1
        try:
            for it in items:
                for self.round in range(6):
                    try:
                        it[2]()
                    except isemon.ConsoleBack:
                        pass
        finally:
            self.depth -= 1
        return None

    def form(self, title_, fields, words='', check=None, ok='OK'):
        vals = {}
        for f in fields:
            kind = f.get('kind', 'text')
            if kind == 'choice':
                opts = [o[0] for o in f['options']]
                vals[f['key']] = opts[self.round % len(opts)]
        for f in fields:
            kind = f.get('kind', 'text')
            if kind == 'choice':
                continue
            if kind == 'secret':
                vals[f['key']] = 'correct horse battery'
                continue
            if kind == 'number':
                lo = (f.get('range') or (1, 1))[0]
                vals[f['key']] = str(f.get('value') or lo) if f.get('need') else ''
                continue
            pick = str(f.get('value') or '')
            if f.get('check'):
                pick = next((c for c in ([pick] if pick else []) + CANDIDATES
                             if not f['check'](c, vals)), None)
                if pick is None:
                    return None             # nothing it takes: as Esc
            vals[f['key']] = pick or ('' if not f.get('need') else 'x')
        bad, _at = self.check_fields(fields, vals)
        if bad:
            return None
        return {f['key']: vals[f['key']] for f in fields
                if not f.get('when') or f['when'](vals)}

    def confirm(self, *a, **k):
        return True

    def choose(self, title_, options, words='', cur=0):
        return options[self.round % len(options)][0] if options else None

    def pick(self, title_, load, cols, act=None, empty='', words=''):
        rows = load() or []
        for r in rows:
            for c in cols:
                c[1](r)
        for r in rows if act else []:
            act(r)

    def note(self, *a, **k):
        pass

    def working(self, *a):
        pass

    def details(self, *a, **k):
        pass

    def act(self, *args, env=None, title=None, quiet_ok=None):
        self.ran.append((tuple(str(a) for a in args), env, 'act'))

    def show_live(self, *args, env=None):
        self.ran.append((tuple(str(a) for a in args), env, 'live'))

    def act_argv(self, argv, title_, env=None, quiet_ok=None):
        self.ran.append((tuple(argv), env, 'argv'))

    def go_plain(self, fn):
        return fn()

    def settings_tui(self):
        self.ran.append((('settings_tui',), None, 'tui'))

    def _edit_one(self, st):
        self.ran.append((('edit', st['key']), None, 'tui'))

    def live_log(self, what=''):
        self.ran.append((('live_log',), None, 'view'))

    def journal(self):
        self.ran.append((('journal',), None, 'view'))


dry = Dry()
for item in dry.main_menu():
    for dry.round in range(6):
        item[2]()
isemon_cmds = [(a, e, how) for a, e, how in dry.ran if how in ('act', 'live')]
ok('the walk reached all eleven menus', len(set(dry.titles)), 10)   # 2 is the live log
ok('...and ran a good many commands', len(set(a for a, _e, _h in isemon_cmds)) > 60, True)
guarded, bad = set(), []
for args, env, how in isemon_cmds:
    gone = isemon.cli_missing(args, known)
    if gone:
        guarded.add(gone.split()[0])
        continue
    if not parses(args):
        bad.append(args)
ok('every command this version has parses as typed', bad, [])
ok('those it has not are the ones being added beside it', guarded <= {
    '--net', '--time', '--time-step', '--reboot', '--poweroff', '--change-keep',
    '--change-back', '--rbackup-status', '--rbackup-now', '--upgrade-check',
    '--upgrade-online', '--upgrade-follow'}, True)
ok('...and they are offered all the same', {'--net', '--rbackup-now', '--upgrade-follow',
                                            '--change-keep', '--reboot'} <= set(
    a[0] for a, _e, _h in isemon_cmds), True)
said = set(a[0] for a, _e, _h in isemon_cmds)
for opt in ('--status', '--check', '--files', '--jobs', '--failed', '--passed', '--blocked',
            '--address', '--ban', '--unban', '--allow', '--unallow', '--mikrotik',
            '--fw-test', '--users', '--add-user', '--passwd', '--set-role', '--disable-user',
            '--enable-user', '--del-user', '--settings', '--database', '--backup',
            '--restore', '--export', '--erase', '--geo-sync', '--ban-sources'):
    ok('a menu runs isemon %s' % opt, any(opt in a for a, _e, _h in isemon_cmds), True)
pw = [(a, e) for a, e, _h in isemon_cmds if a[0] in ('--add-user', '--passwd')]
ok('passwords go by ISEMON_PASSWORD...', bool(pw) and all(
    (e or {}).get('ISEMON_PASSWORD') == 'correct horse battery' for _a, e in pw), True)
ok('...and never on the command line', any('correct horse battery' in ' '.join(a)
                                           for a, _e, _h in dry.ran), False)
ok('--password is never used', any('--password' in a for a, _e, _h in dry.ran), False)
ok('a destructive one carries --yes after the Yes', ('--restore', str(
    backups / 'isemon-20261028-0330.json.gz'), '--yes') in [a for a, _e, _h in isemon_cmds],
   True)
ok('the service menu runs systemctl for isemon', any(
    a[1:3] == ('restart', 'isemon') for a, _e, how in dry.ran if how == 'argv'), True)
ok('the live log and the journal are offered', {('live_log',), ('journal',)} <= set(
    a for a, _e, _h in dry.ran), True)


class Missing(Dry):
    """What the console says of an option this version has not."""

    def note(self, title_, text, tone=''):
        self.said = (title_, text, tone)

    def act(self, *args, **k):
        return isemon.Console.act(self, *args, **k)


m = Missing()
m.said = None
# An option of a later version - every one the menus offer is here now.
ok('an option not in this version is not run', m.act('--from-a-later-version'), None)
ok('...and the window says so', bool(m.said) and 'not in this version' in m.said[1]
   and m.said[0] == '$ isemon --from-a-later-version', True)
ok('every option the menus offer is in this version',
   [o for o in ('--rbackup-now', '--rbackup-status', '--net', '--reboot', '--poweroff',
                '--change-keep', '--change-back', '--time', '--time-step', '--upgrade-check',
                '--upgrade-online', '--upgrade-follow') if isemon.cli_missing([o], isemon.cli_options())], [])

# ---------------------------------------------------------------------------
title('The fields of a window, checked before anything is run')
C = isemon.Console
fields = [{'key': 'name', 'label': 'name', 'need': True},
          {'key': 'n', 'label': 'how many', 'kind': 'number', 'range': (1, 10)},
          {'key': 'ip', 'label': 'address', 'check': lambda v, _: C.ip_bad(v)},
          {'key': 'pw', 'label': 'password', 'kind': 'secret'},
          {'key': 'again', 'label': 'again', 'kind': 'secret',
           'check': lambda v, vals: None if v == vals.get('pw') else 'not the same'},
          {'key': 'mins', 'label': 'minutes', 'kind': 'number', 'need': True,
           'when': lambda v: v.get('how') == 'minutes'},
          {'key': 'how', 'label': 'how', 'kind': 'choice', 'options': [('set', ''),
                                                                        ('minutes', '')]}]


def check(**vals):
    base = {'name': 'a', 'n': '', 'ip': '', 'pw': '', 'again': '', 'mins': '', 'how': 'set'}
    base.update(vals)
    return C.check_fields(fields, base)


ok('all good', check(), (None, None))
ok('a needed one left empty', check(name='  '), ('name - it is needed', 'name'))
ok('a number out of its limits', check(n='11'), ('how many - a whole number from 1 to 10', 'n'))
ok('a number that is none', check(n='1x'), ('how many - a whole number', 'n'))
ok('an address that is none', check(ip='192.0.2.300'), ('not an address or a subnet', 'ip'))
ok('an address or a subnet is taken', check(ip='2001:db8::/32'), (None, None))
ok('two passwords not the same', check(pw='abcdefgh', again='abcdefgx'), ('not the same',
                                                                          'again'))
ok('a field not shown is not asked for', check(how='set', mins=''), (None, None))
ok('...and shown it is', check(how='minutes', mins=''), ('minutes - it is needed', 'mins'))
ok('a choice that is none of them', check(how='later'), ('how - one of the choices', 'how'))
vals = {'name': '  bob  ', 'pw': ' spaced '}
C.check_fields(fields[:1] + fields[3:4], vals)
ok('text is taken without its spaces, a password as typed', (vals['name'], vals['pw']),
   ('bob', ' spaced '))
ok('a setting checked as the daemon checks it', (C.setting_check('backup_keep', '20'),
                                                 bool(C.setting_check('backup_keep', '9999'))),
   (None, True))
ok('...a setting that is none', 'not a setting' in (C.setting_check('no_such', '1') or ''),
   True)
ok('a switch is a switch, a range a number, words a choice',
   (C.setting_kind('blacklist')[0], C.setting_kind('backup_keep'),
    C.setting_kind('db_engine')[0]), ('switch', ('number', [1, 365]), 'choice'))
rows = dry.settings_rows({'settings': {k: isemon.CONFIG.get(k) for k in isemon.DEFAULTS
                                       if k not in isemon.SECRET_KEYS},
                          'saved_in_db': ['backup_keep'], 'file_only': ['db_engine']})
sets = [r[1] for r in rows if r[0] == 'set']
ok('every setting is in the browser, under a heading', (len(sets), rows[0][0]),
   (len(isemon.DEFAULTS), 'head'))
one = next(r for r in sets if r['key'] == 'backup_keep')
ok('...with its words, its source and its help', (one['name'], one['source'], bool(one['says'])),
   ('Dumps kept', 'saved', True))
ok('...a secret shown as nothing', all(r['value'] is None for r in sets if r['secret']), True)
ok('...grouped by what it is about', next(r[1] for i, r in enumerate(rows)
                                          if r[0] == 'head' and rows[i + 1][1]['key']
                                          .startswith('backup_')), 'Backups')

# ---------------------------------------------------------------------------
title('The live view: whatever is typed is a grep -i')
lines = ['28-10-2026 10:00:01 [info] ban: 192.0.2.7 banned for 10 min',
         '28-10-2026 10:00:02 [warn] mikrotik: the router is not answering',
         '28-10-2026 10:00:03 [info] unban: 192.0.2.7 let back in by alice',
         '28-10-2026 10:00:04 [error] a [weird] line']
g = C.grep
ok('nothing typed: every line', len([x for x in lines if g('')(x)]), 4)
ok('any case', [x[20:26] for x in lines if g('MIKROTIK')(x)], ['[warn]'])
ok('a regular expression', len([x for x in lines if g('banned|let back')(x)]), 2)
ok('text that is not one is taken as it is', [x[20:27] for x in lines if g('[weird')(x)],
   ['[error]'])
ok('a regular expression across the line', len([x for x in lines if g('ban.*alice')(x)]), 1)

# ---------------------------------------------------------------------------
title('The log in colour: only colour added, every column where it was')
os.environ['FORCE_COLOR'] = '1'
colour = isemon.Console(isemon.Palette(True))
del os.environ['FORCE_COLOR']
ok('the palette is on', colour.pal.on, True)
for ln in lines + ['not a log line at all', '28-10-2026 10:00:05 [debug]   two  spaces']:
    painted = colour.log_text(ln)
    ok('plain again it is the line: %s' % ln[:44], C._plain_text(painted), ln)
painted = colour.log_text(lines[0])
ok('an address is magenta, banned red', ('\x1b[35m192.0.2.7' in painted,
                                         colour.pal.c_bad + 'banned' in painted), (True, True))
ok('a warning is yellow whole', colour.log_text(lines[1]).count(colour.pal.c_warn) >= 2, True)
marked = colour.mark(painted, '192')
ok('the hits are marked, the text not moved', ('\x1b[7m192' in marked,
                                               C._plain_text(marked) == lines[0]), (True, True))
ok('a slice keeps its colours and its columns', C._plain_text(C._slice(painted, 20, 6)),
   lines[0][20:26])
ok('plain, nothing is added', isemon.Console(isemon.Palette(False)).log_text(lines[0]), lines[0])

# ---------------------------------------------------------------------------
title('The bar at the top')
st = {'_answered': True, 'blocked': {'now': 1234}, 'users': 3, 'blacklist_on': False,
      'logs': [{'looked': 1000.0}, {'looked': 990.0}],
      'health': {'level': 'crit', 'says': 'no ISE log is there'},
      'jobs': [{'kind': 'tidy'}], 'trials': [{'kind': 'fw', 'until': 1000 + 125}]}
ok('bans, the logs, the accounts', C.bar_bits(st, now=1010.0),
   ['1,234 banned', 'logs read', '3 account(s)'])
ok('logs not read lately are said', C.bar_bits(dict(st, logs=[{'looked': 10.0}]), now=1000.0)[1]
   .startswith('logs NOT read for'), True)
said = C.status_lines(st, now=1000.0)
ok('banning off, the problem, the job and the change on trial', [t for _w, t in said],
   ['warn', 'bad', '', 'warn'])
ok('...the change on trial with its time left', 'the change of the firewall waits to be '
   'kept: 2:05 left' in said[3][0], True)
ok('a daemon not answering is said in red', C.status_lines({'_answered': False}),
   [('the daemon is not answering (isemon --status)', 'bad')])

# ---------------------------------------------------------------------------
title('The console at login: the choice in a file only root writes')
flag = Path(os.environ['ISEMON_CONSOLE_FLAG'])
ok('the walk switched it from the service menu', flag.is_file(), True)
flag.unlink()
ok('no file is off', (flag.exists(), isemon.console_at_login()), (False, False))
isemon.console_at_login_set(True)
ok('on', (flag.read_text(), isemon.console_at_login()), ('on\n', True))
ok('...a plain file of 0644', oct(flag.stat().st_mode & 0o7777), '0o644')
isemon.console_at_login_set(False)
ok('off', (flag.read_text(), isemon.console_at_login()), ('off\n', False))
victim = work / 'victim'
victim.write_text('on\n')
flag.unlink()
flag.symlink_to(victim)
ok('a link is not followed when read', isemon.console_at_login(), False)
isemon.console_at_login_set(True)
ok('...and replaced, not written through, when set', (flag.is_symlink(), victim.read_text(),
                                                      isemon.console_at_login()),
   (False, 'on\n', True))
flag.unlink()
os.mkfifo(str(flag))
t0 = time.time()
ok('a pipe is not waited on', (isemon.console_at_login(), time.time() - t0 < 2), (False, True))
isemon.console_at_login_set(True)
ok('...and replaced by the file', (flag.is_file(), isemon.console_at_login()), (True, True))
ok('nothing is left beside it', sorted(p.name for p in work.iterdir()
                                       if p.name.startswith('console-login')), ['console-login'])


def cli(*args, **env):
    return subprocess.run([sys.executable, str(ROOT / 'isemon.py')] + list(args),
                          capture_output=True, text=True, stdin=subprocess.DEVNULL,
                          env=env_for(NO_COLOR=1, **env), timeout=120)


r = cli('--console-at-login', 'off')
ok('isemon --console-at-login off', (r.returncode, flag.read_text()), (0, 'off\n'))
r = cli('--console-at-login', 'status')
ok('isemon --console-at-login status', (r.returncode, 'the console at login is off' in r.stdout),
   (0, True))
r = cli('--console-at-login', 'on')
ok('isemon --console-at-login on', (r.returncode, flag.read_text()), (0, 'on\n'))
r = cli('--console-at-login', 'maybe')
ok('a word it does not take is refused', r.returncode, 2)
r = cli('--console')
ok('the console without a terminal says so', (r.returncode, 'needs a terminal' in r.stdout),
   (2, True))
ok('...and opened no database for it', (work / 'state' / 'isemon.db').exists(), False)

# ---------------------------------------------------------------------------
title('isemon --set KEY=@env: a value off the command line')
r = cli('--set', 'backup_keep=@env')
ok('without the variable nothing is saved', (r.returncode, 'ISEMON_VALUE_BACKUP_KEEP is not set'
                                             in r.stdout), (1, True))
r = cli('--set', 'backup_keep=@env', ISEMON_VALUE_BACKUP_KEEP='21')
ok('with it, it is saved', r.returncode, 0)
r = cli('--settings', '--json')
import json                                          # noqa: E402
ok('...as the value of the variable', json.loads(r.stdout)['settings']['backup_keep'], 21)

# ---------------------------------------------------------------------------
title('The profile script: root, a terminal, a login shell - nothing else')
script = (ROOT / 'deploy' / 'isemon-console-login.sh').read_text()
ok('it reads the choice where only root writes',
   '/etc/isemon-console-login' in script and '/usr/local/bin/isemon --console' in script, True)
fake = work / 'profile'
fake.mkdir()
marker = fake / 'started'
binary = fake / 'isemon'
binary.write_text('#!/bin/sh\necho "$ISEMON_CONSOLE $*" > %s\n' % marker)
binary.chmod(0o755)
pflag = fake / 'flag'
idbin = fake / 'bin'
idbin.mkdir()
(idbin / 'id').write_text('#!/bin/sh\necho 1000\n')
(idbin / 'id').chmod(0o755)
copy = fake / 'zz-isemon-console.sh'
copy.write_text(script.replace('/usr/local/bin/isemon', str(binary))
                .replace('/etc/isemon-console-login', str(pflag)))


def login(tty=True, ps1=True, flag_='on', **env):
    """The script sourced as a login shell would; whether it started it."""
    if marker.exists():
        marker.unlink()
    if pflag.is_symlink() or pflag.exists():
        pflag.unlink()
    if flag_ is not None:
        pflag.write_text(flag_ + '\n')
    e = {k: v for k, v in os.environ.items() if not k.startswith(('ISEMON_CONSOLE', 'SSH_'))}
    e.update(env)
    line = '%s. %s; exit 0' % ('PS1="# "; ' if ps1 else '', copy)
    if not tty:
        subprocess.run(['bash', '--norc', '--noprofile', '-c', line], env=e,
                       stdin=subprocess.DEVNULL, capture_output=True, timeout=20)
    else:
        pid, fd = pty.fork()
        if pid == 0:
            os.execve('/bin/bash', ['bash', '--norc', '--noprofile', '-c', line], e)
        end = time.time() + 10
        while time.time() < end:
            r_, _w, _x = select.select([fd], [], [], 0.2)
            if r_:
                try:
                    if not os.read(fd, 4096):
                        break
                except OSError:
                    break
        os.waitpid(pid, 0)
        os.close(fd)
    return marker.read_text().strip() if marker.exists() else None


ok('root, a terminal, on: the console', login(), '1 --console')
ok('the choice off: the shell', login(flag_='off'), None)
ok('no choice at all: the shell', login(flag_=None), None)
ok('not a terminal (scp, sftp, a script): nothing', login(tty=False), None)
ok('not interactive (no prompt): nothing', login(ps1=False), None)
ok('a command over SSH: nothing', login(SSH_ORIGINAL_COMMAND='uptime'), None)
ok('ISEMON_NO_CONSOLE=1: nothing', login(ISEMON_NO_CONSOLE='1'), None)
ok('a shell opened from the console itself: nothing', login(ISEMON_CONSOLE='1'), None)
ok('not root: nothing', login(PATH='%s:%s' % (idbin, os.environ.get('PATH', ''))), None)
victim.write_text('on\n')
if marker.exists():
    marker.unlink()
pflag.unlink()
pflag.symlink_to(victim)
e = dict(os.environ)
pid, fd = pty.fork()
if pid == 0:
    os.execve('/bin/bash', ['bash', '--norc', '--noprofile', '-c',
                            'PS1="# "; . %s; exit 0' % copy], e)
time.sleep(1.5)
try:
    while select.select([fd], [], [], 0.2)[0] and os.read(fd, 4096):
        pass
except OSError:
    pass
os.waitpid(pid, 0)
os.close(fd)
ok('the choice as a link: not followed, nothing', marker.exists(), False)

# ---------------------------------------------------------------------------
title('install.sh: the profile script always, the choice only when fresh')
text = (ROOT / 'install.sh').read_text()
fn = re.search(r'\ninstall_console\(\) \{.*?\n\}\n', text, re.S).group(0)
ok('a fresh install switches it on', 'install_console fresh' in text, True)
ok('an upgrade only puts the script in', text.count('install_console upgrade'), 1)
ok('uninstall takes the script away', '"$CONSOLE_PROFILE" "$CONSOLE_FLAG"; do' in text, True)
inst = work / 'inst'
inst.mkdir()


def install(mode, before=None):
    prof, cflag = inst / 'zz-isemon-console.sh', inst / 'isemon-console-login'
    for p in (prof, cflag):
        if p.is_symlink() or p.exists():
            p.unlink()
    if before == 'link':
        cflag.symlink_to(victim)
    elif before is not None:
        cflag.write_text(before + '\n')
    sh = ('run() { "$@"; }; note() { :; }; good() { :; }; DRY_RUN=""; SOURCE_DIR=%s; '
          'CONSOLE_PROFILE=%s; CONSOLE_FLAG=%s;\n%s\ninstall_console %s'
          % (ROOT, prof, cflag, fn, mode))
    r_ = subprocess.run(['bash', '-c', sh], capture_output=True, text=True, timeout=20)
    return (r_.returncode, prof.exists(), cflag.read_text().strip()
            if cflag.is_file() and not cflag.is_symlink() else
            ('link' if cflag.is_symlink() else None))


ok('upgrade, no choice: the script, still no choice', install('upgrade'), (0, True, None))
ok('upgrade, off: off it stays', install('upgrade', 'off'), (0, True, 'off'))
ok('fresh: on', install('fresh'), (0, True, 'on'))
ok('fresh again over off (a reinstall): off it stays', install('fresh', 'off'), (0, True, 'off'))
victim.write_text('keep me\n')
ok('fresh over a link: a plain file, the link\'s target untouched',
   (install('fresh', 'link'), victim.read_text()), ((0, True, 'on'), 'keep me\n'))

# ---------------------------------------------------------------------------
title('The console itself, on a pseudo-terminal')
stub = work / 'systemctl'
stub.write_text('#!/bin/sh\necho inactive\nexit 3\n')
stub.chmod(0o755)


def drive(keys, start='menu', lang='C.UTF-8', size=(30, 100), wait=3.0):
    env = dict(os.environ, TERM='xterm', ISEMON_SYSTEMCTL=str(stub),
               ISEMON_JOURNALCTL='/bin/false', LANG=lang, LC_ALL=lang)
    env.pop('ISEMON_CONSOLE_START', None)
    if start:
        env['ISEMON_CONSOLE_START'] = start
    pid, fd = pty.fork()
    if pid == 0:
        import fcntl
        import termios
        fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack('HHHH', size[0], size[1], 0, 0))
        os.execve(sys.executable, [sys.executable, str(ROOT / 'isemon.py'), '--console'], env)
    buf = [b'']

    def pump(sec):
        end = time.time() + sec
        while time.time() < end:
            r_, _w, _x = select.select([fd], [], [], 0.1)
            if r_:
                try:
                    got = os.read(fd, 65536)
                except OSError:
                    return
                if not got:
                    return
                buf[0] += got
    pump(wait)
    for k in keys:
        os.write(fd, {'ESC': b'\x1b', 'ENTER': b'\r', 'DOWN': b'\x1b[B', 'UP': b'\x1b[A',
                      'CTRL-C': b'\x03'}.get(k, k.encode()))
        pump(1.5)
    status = None
    end = time.time() + 20
    while time.time() < end:
        p_, status = os.waitpid(pid, os.WNOHANG)
        if p_:
            break
        pump(0.3)
    else:
        os.kill(pid, 9)
        os.waitpid(pid, 0)
    pump(0.3)
    try:
        os.close(fd)
    except OSError:
        pass
    text = re.sub(rb'\x1b[\[\]()][0-9;?]*[A-Za-z]?', b' ', buf[0]).decode('utf-8', 'replace')
    return (os.WEXITSTATUS(status) if status is not None and os.WIFEXITED(status) else None,
            text)


rc, text = drive(['3', 'ESC', 'q'])
ok('it opens on the menu, a menu opened and left with q: exit 0', rc, 0)
ok('...the main menu and the bar were drawn', ('Main menu' in text, 'isemon %s' %
                                               isemon.__version__ in text,
                                               'service inactive' in text), (True, True, True))
ok('...the menu opened', 'Failed attempts, logins and who is kept out' in text
   and 'Main menu >' in text, True)
ok('...the daemon not answering is said', 'the daemon is not answering' in text, True)
ok('...and it says how to open it again', 'isemon --console` opens it again' in text, True)
ok('...nothing went wrong in it', 'Traceback' in text, False)
rc, text = drive(['7', '1', 'ENTER', 'ESC', 'ESC', 'ESC', 'q'], wait=2.0)
ok('Settings, browsed, one opened and left: exit 0', (rc, 'Traceback' in text), (0, False))
ok('...its window drawn with its help', 'as it comes:' in text and 'Enter save' in text, True)
rc, text = drive(['6', '2', 'ESC', 'ESC', 'q'], wait=2.0)
ok('a window with fields opened and closed: exit 0', (rc, 'Traceback' in text), (0, False))
ok('...the fields were drawn', 'password' in text and 'Make an account' in text, True)
rc, text = drive(['ESC', 'q'], start=None)
ok('it opens on the live log; Esc the menu; q: exit 0', (rc, 'Live log' in text,
                                                         'Main menu' in text), (0, True, True))
rc, text = drive(['1', '1', 'ESC', 'q'], lang='C', size=(10, 30), wait=2.0)
ok('a small terminal that is not UTF-8: still a menu, still exit 0',
   (rc, 'Traceback' in text, 'Main menu' in text), (0, False, True))
ok('...its frames in ASCII', '─' in text or '│' in text, False)
rc, text = drive(['CTRL-C'], wait=2.0)
ok('Ctrl+C leaves it cleanly', (rc in (0, 130), 'Traceback' in text), (True, False))

shutil.rmtree(str(work), ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
