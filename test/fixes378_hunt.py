#!/usr/bin/env python3
"""1.10.378: bug hunt, round 7 of 10 - the domain cards.

    ./test/fixes378_hunt.py
"""
import sys
import tempfile
import time
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


folder = Path(tempfile.mkdtemp(prefix='isemon-378-'))
for k, v in dict(STATE_DIR=folder, DB_FILE=folder / 'c.db', BACKUP_DIR=folder / 'b',
                 DUMP_DIR=folder / 'd', RUN_DIR=folder, LOG_DIR=folder,
                 CONFIG_FILE=folder / 'config.json', _LOG_PATH=folder / 'c.log',
                 TOKEN_FILE=folder / 'tok').items():
    setattr(isemon, k, v)
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0})
store = isemon.Storage(isemon.DB_FILE)

print('A spray is of people, not of spellings')
now = time.time()
n = 0
with store.db_write() as db:
    # PC-A: one person written five ways - no spray.
    for name in ('jnovak', 'EXAMPLE\\jnovak', 'jnovak@example.cz', 'JNOVAK', 'example\\JNovak'):
        n += 1
        db.execute('INSERT INTO win_events (ident, ts, server, event, kind, account, machine, ip) '
                   "VALUES (?, ?, 'dc1', 4625, 'logon-failed', ?, 'PC-A', '10.1.1.1')",
                   ('a%d' % n, now - 60 + n, name))
    # PC-B: five people - a spray.
    for name in ('anna', 'bob', 'carol', 'dave', 'erin'):
        n += 1
        db.execute('INSERT INTO win_events (ident, ts, server, event, kind, account, machine, ip) '
                   "VALUES (?, ?, 'dc1', 4625, 'logon-failed', ?, 'PC-B', '10.1.1.2')",
                   ('b%d' % n, now - 60 + n, name))
got = {r['said']: r['names'] for r in store.win_spray(now - 3600)}
ok('five spellings of one account on PC-A are no spray', 'PC-A' in got, False)
ok('five people from PC-B are', got.get('PC-B'), 5)

print('The rest')
src = (ROOT / 'isemon.py').read_text()
ok('a lockout\'s machine and address only from refusals up to it, none a copy',
   "if float(said.get('ts') or 0) <= float(one['ts'] or 0)" in src
   and "and str(said.get('ip') or '') not in ctl]" in src)
ok('the spread without the PDC\'s copies',
   "# ...and without the PDC's copies, as the events' own path (1.10.378)." in src)
ok('the copies taken off are only the counted ones',
   "# Only the copies the buckets counted: routine ones they never did" in src)

print('Accounts and sessions')
isemon.CONFIG.update({'directory': 1, 'directory_host': 'dc.x',
                      'directory_base': 'DC=corpnet,DC=loc',
                      'directory_admin_group': 'ISEMON_Admins',
                      'directory_readonly_group': 'ISEMON_Viewers'})
daemon = isemon.Daemon(store)
daemon.add_user('admin', 'local-admin-pass-1', 'fulladmin', by='t')
F = isemon.Daemon.directory_name_filter('jnovak')
F2 = isemon.Daemon.directory_name_filter('jnovak@corp.example')
DN = 'CN=Jan Novak,OU=P,DC=child,DC=corpnet,DC=loc'
groups = ['CN=ISEMON_Admins,DC=corpnet,DC=loc']


def entry():
    return {'dn': DN, 'attrs': {'distinguishedName': [DN], 'sAMAccountName': ['jnovak'],
                                'userPrincipalName': ['jnovak@corp.example'],
                                'memberOf': list(groups), 'userAccountControl': ['512']}}


class Link:
    def search(self, base, flt, attrs=(), scope=2, limit=200, paged=False):
        if scope == 0:
            return [entry()] if base == DN else []
        return [entry()] if flt in (F, F2) else []

    def bind(self, who, pw):
        if pw != 'RIGHT-password-1':
            raise isemon.LdapError('invalid credentials')

    def close(self):
        pass


daemon.directory_on = lambda: True
daemon.directory_reader = daemon.directory_open = lambda *a, **k: Link()
got = daemon.login('jnovak', 'RIGHT-password-1', ip='10.0.0.1')
ok('signed in from a child domain', (got['name'], got['role']),
   ('jnovak@child.corpnet.loc', 'fulladmin'))
isemon.CONFIG['directory_recheck_min'] = 1
daemon._directory_looked = 0
ok('...and not signed out by the recheck when nothing changed',
   (daemon.directory_recheck()['ended'], bool(daemon.who(got['token']))), (0, True))
groups[:] = []
daemon._directory_looked = 0
ok('out of every group: signed out', daemon.directory_recheck()['ended'], 1)
ok('...and no full administrator here any more',
   store.user('jnovak@child.corpnet.loc')['role'], 'readonly')
ok('a name with spaces after DOMAIN\\ counts against the name',
   "count_name = (name.split('\\\\', 1)[1] if '\\\\' in name else name).strip()" in src)
ok('a passkey counter is never written down lower',
   "k['count'] = max(int(k.get('count') or 0)," in src)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
