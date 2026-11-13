#!/usr/bin/env python3
"""1.10.339: one directory person, one account. Signing in as `jnovak`, as
`jnovak@corp.example` or as `CORP\\jnovak` is the same account - kept under
the name the directory gives them (sAMAccountName). The pairs made before
are put together once, and at the next sign-in; a local account of the same
name stays what that name is; a Kerberos principal maps to the same name.
The directory is faked here at its edge (search and bind), so the real
sign-in path runs.

    ./test/fixes339_one_person.py
"""
import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
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


folder = Path(tempfile.mkdtemp(prefix='isemon-339-'))
isemon.STATE_DIR = folder
isemon.DB_FILE = folder / 'c.db'
isemon.BACKUP_DIR = folder / 'backups'
isemon.DUMP_DIR = folder / 'dumps'
isemon.RUN_DIR = folder
isemon.LOG_DIR = folder
isemon.CONFIG_FILE = folder / 'config.json'
isemon._LOG_PATH = folder / 'c.log'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'directory': 1,
                      'directory_host': 'dc.corp.example', 'directory_base': 'DC=corp,DC=example',
                      'directory_admin_group': 'ISEMON_Admins'})
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)

PEOPLE = {
    'jnovak': {'dn': 'CN=Jan Novak,OU=People,DC=corp,DC=example', 'upn': 'jnovak@corp.example',
               'pw': 'Domain-Pass1'},
    'admin': {'dn': 'CN=Admin Domain,OU=People,DC=corp,DC=example', 'upn': 'admin@corp.example',
              'pw': 'Domain-Pass2'},
    'pkral': {'dn': 'CN=Petr Kral,OU=People,DC=branch,DC=corp,DC=example',
              'upn': 'pkral@branch.corp.example', 'pw': 'Domain-Pass3'},
}


class Link(object):
    def close(self):
        pass

    def bind(self, who, pw):
        for p in PEOPLE.values():
            if p['dn'] == who and p['pw'] == pw:
                return
        raise isemon.LdapError('invalid credentials')


def find(link, name):
    n = str(name).strip().lower()
    if '\\' in n:
        n = n.split('\\', 1)[1]
    for sam, p in PEOPLE.items():
        if n in (sam, p['upn']):
            return {'dn': p['dn'], 'attrs': {
                'distinguishedName': [p['dn']], 'sAMAccountName': [sam.upper() if sam == 'jnovak'
                                                                   else sam],
                'userPrincipalName': [p['upn']], 'displayName': [sam],
                'memberOf': ['CN=ISEMON_Admins,OU=Groups,DC=corp,DC=example']}}
    return None


daemon.directory_reader = lambda which='directory', timeout=None: Link()
daemon.directory_open = lambda which='directory', timeout=None: Link()
daemon.directory_find = find
daemon.directory_groups = lambda link, entry: {'isemon_admins'}

print('the same person under each of their names')
for typed in ('jnovak', 'jnovak@corp.example', 'CORP\\jnovak', 'JNovak@Corp.Example'):
    got = daemon.login(typed, 'Domain-Pass1', ip='10.0.0.5')
    ok('%s signs in as jnovak' % typed, (got['name'], got['from_dir']), ('jnovak', True))
ok('...one account, not one per name', sorted(u['name'] for u in store.users()
                                              if u.get('from_dir')), ['jnovak'])
ok('...its sessions all under it', sorted({s['name'] for s in store.sessions()}), ['jnovak'])

print('another domain of the forest: name@domain, never the short name alone')
got = daemon.login('pkral@branch.corp.example', 'Domain-Pass3', ip='10.0.0.6')
ok('kept as pkral@branch.corp.example', got['name'], 'pkral@branch.corp.example')
got = daemon.login('pkral', 'Domain-Pass3', ip='10.0.0.6')
ok('...the short name typed: the same', got['name'], 'pkral@branch.corp.example')

print('a local account of the same name stays what that name is')
daemon.add_user('admin', 'local-password-1', 'fulladmin')
got = daemon.login('admin', 'local-password-1', ip='10.0.0.7')
ok('admin with its local password: the local account', bool(got.get('from_dir')), False)
got = daemon.login('admin@corp.example', 'Domain-Pass2', ip='10.0.0.7')
ok('the domain\'s admin by its whole name: kept apart, as before', got['name'],
   'admin@corp.example')
ok('...the local account untouched', (store.user('admin')['from_dir'],
                                      bool(store.user('admin')['hash'])), (0, True))

print('the pairs made before: put together')
s = '\n'
dn = PEOPLE['jnovak']['dn']
with store.db_write() as db:
    db.execute('DELETE FROM users WHERE name=?', ('jnovak',))
    for name in ('jnovak', 'jnovak@corp.example'):
        db.execute('INSERT INTO users (name, hash, role, made, made_by, from_dir, dn, display, '
                   'groups, note) VALUES (?,?,?,?,?,1,?,?,?,?)',
                   (name, '', 'fulladmin', 1.0, 'the directory', dn, 'Jan', '', 'from the '
                    'directory'))
    db.execute('UPDATE users SET disabled=1 WHERE name=?', ('jnovak@corp.example',))
    db.execute('INSERT INTO user_prefs (name, prefs, at) VALUES (?,?,?)',
               ('jnovak@corp.example', '{"a":1}', 1.0))
store.put_passkeys([{'id': 'k1', 'user': 'jnovak@corp.example'}])
gone = store.merge_directory_people()
ok('the one with @ taken into the short one', gone, ['jnovak@corp.example'])
ok('...one row left', [u['name'] for u in store.users() if u['dn'] == dn], ['jnovak'])
ok('...switched off under either name: off', store.user('jnovak')['disabled'], 1)
ok('...its settings and passkeys moved', (
    store.db.execute("SELECT prefs FROM user_prefs WHERE name='jnovak'").fetchone()['prefs'],
    [k['user'] for k in store.passkeys()]), ('{"a":1}', ['jnovak']))
ev = store.db.execute("SELECT detail FROM events WHERE detail LIKE '%one person%' ORDER BY id "
                      "DESC").fetchone()
ok('...and said in the events', ev and ev['detail'].startswith(
    'jnovak@corp.example and jnovak are one person'), True)

print('known only by its whole name: one account at the next sign-in')
store.set_disabled('jnovak', False)
with store.db_write() as db:
    db.execute("UPDATE users SET name='jnovak@corp.example' WHERE name='jnovak'")
got = daemon.login('jnovak@corp.example', 'Domain-Pass1', ip='10.0.0.5')
ok('signed in as jnovak', got['name'], 'jnovak')
ok('...the old row put into it', [u['name'] for u in store.users() if u['dn'] == dn], ['jnovak'])

print('a row with a password set here is never touched')
with store.db_write() as db:
    db.execute('INSERT INTO users (name, hash, role, made, made_by, from_dir, dn, display, '
               'groups, note) VALUES (?,?,?,?,?,1,?,?,?,?)',
               ('jnovak@corp.example', 'h1:x', 'readonly', 1.0, 'x', dn, 'Jan', '', ''))
daemon.login('jnovak', 'Domain-Pass1', ip='10.0.0.5')
ok('kept', bool(store.user('jnovak@corp.example')), True)

print('Kerberos (single sign-on later): a principal as the account it is')
ok('the directory\'s own realm: the short name',
   daemon.directory_principal_name('JNOVAK@CORP.EXAMPLE'), 'jnovak')
ok('another realm: name@realm', daemon.directory_principal_name('pkral@BRANCH.CORP.EXAMPLE'),
   'pkral@branch.corp.example')
ok('a down-level name', daemon.directory_principal_name('CORP\\JNovak'), 'jnovak')

print('\n%d passed, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
