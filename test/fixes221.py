#!/usr/bin/env python3
"""1.10.221: somebody from the directory signs in only through a group that
is named for a role and that they are in. A role whose group is empty is
given to nobody; with no group named at all nobody from the directory gets
in (before, everybody it knew got in, read only), and whoever is signed in
from it then is signed out at once. Tried against mockldap, which answers
the way a domain controller does.

    ./test/fixes221.py
"""
import sys
import tempfile
import shutil
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import isemon                                        # noqa: E402
import mockldap                                      # noqa: E402

PASS = FAIL = 0


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


folder = tempfile.mkdtemp(prefix='isemon-221-')
isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = Path(folder) / 'd.db'
isemon.BACKUP_DIR = Path(folder) / 'backups'
isemon.DUMP_DIR = Path(folder) / 'dumps'
isemon.RUN_DIR = Path(folder)
isemon.LOG_DIR = Path(folder)
isemon.CONFIG_FILE = Path(folder) / 'config.json'
isemon._LOG_PATH = Path(folder) / 'd.log'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
port, stop = mockldap.serve()
time.sleep(0.3)

ADMINS = 'CN=ISE Admins,OU=Groups,DC=corpnet,DC=loc'
WATCHERS = 'CN=ISE Watchers,OU=Groups,DC=corpnet,DC=loc'
HELPDESK = 'CN=Helpdesk,OU=Groups,DC=corpnet,DC=loc'
PEOPLE = (('jnovak', 'a-good-long-password'),        # in ISE Admins
          ('edvorak', 'another-good-password'),      # in Helpdesk, inside ISE Watchers
          ('nogroups', 'still-a-good-password'))     # in no group


def groups(admin='', ban='', read=''):
    isemon.CONFIG.update({
        'directory': 1, 'directory_host': '127.0.0.1', 'directory_port': port,
        'directory_tls': 'none', 'directory_verify': 0,
        'directory_base': 'DC=corpnet,DC=loc',
        'directory_bind': 'CN=isemon,OU=Service,DC=corpnet,DC=loc',
        'directory_password': 'the-service-password',
        'directory_user_attr': 'sAMAccountName', 'directory_nested': 1,
        'directory_admin_group': admin, 'directory_banadmin_group': ban,
        'directory_readonly_group': read})


def who_gets_in():
    out = {}
    for name, pw in PEOPLE:
        try:
            out[name] = daemon.login(name, pw, ip='10.9.9.%d' % (len(out) + 1))['role']
        except isemon.Refused as e:
            out[name] = 'refused: ' + str(e)
    return out


NO = 'refused: this account is in none of the groups that may use this'

try:
    daemon.add_user('admin', 'a-local-long-password', 'fulladmin', by='test')

    print('\nEvery group filled in, as before')
    groups(ADMINS, '', WATCHERS)
    ok('each gets the role of their group, nobody else gets in', who_gets_in(),
       {'jnovak': 'fulladmin', 'edvorak': 'readonly', 'nogroups': NO})

    print('\nNo group named for any role')
    groups('', '', '')
    ok('nobody from the directory gets in - not even read only', who_gets_in(),
       {'jnovak': NO, 'edvorak': NO, 'nogroups': NO})
    ev = str(store.events(limit=10))
    ok('...and the events say the fix is a setting', 'no group is named for any role' in ev)
    ok('a local account still does', daemon.login('admin', 'a-local-long-password',
                                                  ip='10.9.9.50')['role'], 'fulladmin')
    try:
        daemon.login('jnovak', 'a-wrong-password', ip='10.9.9.60')
        said = 'let in'
    except isemon.Refused as e:
        said = str(e)
    ok('a wrong password is still only a wrong password', said,
       'that name and password do not go together')
    check = daemon.directory_check()
    step = [s for s in check['steps'] if s['what'] == 'the groups chosen for the roles']
    ok('the check says it as the problem it is',
       (check['ok'], step[0]['ok'], 'nobody from the directory can sign in' in step[0]['said']),
       (False, False, True))

    print('\nOnly blanks and separators')
    groups(' ; ;\n', ';', '  ')
    ok('count as none', who_gets_in(), {'jnovak': NO, 'edvorak': NO, 'nogroups': NO})

    print('\nSome roles filled in, some not')
    groups(ADMINS, '', '')
    ok('only the admin group: only its people, the rest nowhere', who_gets_in(),
       {'jnovak': 'fulladmin', 'edvorak': NO, 'nogroups': NO})
    groups('', '', WATCHERS)
    ok('only the read-only group: an admin elsewhere is not let in by it', who_gets_in(),
       {'jnovak': NO, 'edvorak': 'readonly', 'nogroups': NO})
    groups('', HELPDESK, '')
    ok('only the ban group', who_gets_in(),
       {'jnovak': NO, 'edvorak': 'banadmin', 'nogroups': NO})
    groups('CN=No Such Group,OU=Groups,DC=corpnet,DC=loc', '', '')
    ok('a group that does not exist lets nobody in', who_gets_in(),
       {'jnovak': NO, 'edvorak': NO, 'nogroups': NO})
    groups('ISE Admins', '', '')
    ok('a group by its name alone still matches', who_gets_in()['jnovak'], 'fulladmin')

    print('\nThe role, worked out')
    groups('', '', '')
    for given in (set(), {'cn=other,dc=x'}, {ADMINS.lower()}, {''}):
        ok('no group named: %r earns nothing' % (sorted(given),),
           daemon.directory_role(given), None)
    groups(ADMINS, '', WATCHERS)
    ok('no groups at all earns nothing, even with roles named',
       daemon.directory_role(set()), None)
    ok('...and None is taken as none', daemon.directory_role(None), None)

    print('\nWho is signed in when the groups go')
    groups(ADMINS, '', WATCHERS)
    store.drop_session(everyone=True)
    jn = daemon.login('jnovak', 'a-good-long-password', ip='10.9.9.70')
    ed = daemon.login('edvorak', 'another-good-password', ip='10.9.9.71')
    ad = daemon.login('admin', 'a-local-long-password', ip='10.9.9.72')
    ok('three signed in', all(store.session(t['token']) for t in (jn, ed, ad)))
    daemon.save_settings({'directory_admin_group': '', 'directory_readonly_group': ''},
                         by='admin')
    ok('emptied on the settings page: the directory\'s are signed out at once',
       (bool(store.session(jn['token'])), bool(store.session(ed['token']))), (False, False))
    ok('...the local administrator is not', bool(store.session(ad['token'])), True)
    ok('...and it is in the events', 'no group is named for any role' in str(
        store.events(limit=20)))
    # A daemon started with the groups already empty - a config edited by
    # hand, or an upgrade from a version that let them in: the minute's pass.
    groups(ADMINS, '', WATCHERS)
    jn = daemon.login('jnovak', 'a-good-long-password', ip='10.9.9.73')
    groups('', '', '')
    daemon._directory_pass()
    ok('...and by the pass every minute', bool(store.session(jn['token'])), False)
    ok('...which leaves the local one', bool(store.session(ad['token'])), True)
    groups(ADMINS, '', WATCHERS)
    jn = daemon.login('jnovak', 'a-good-long-password', ip='10.9.9.74')
    ok('with a group named, nobody is signed out by it',
       (daemon.directory_without_groups_sweep(), bool(store.session(jn['token']))), (0, True))
    isemon.CONFIG['directory'] = 0
    ok('...nor with the directory switched off', daemon.directory_without_groups_sweep(), 0)

    print('\nWhat the settings say')
    src = (HERE.parent / 'isemon.py').read_text(encoding='utf-8')
    ok('the help no longer promises everybody gets in',
       'everybody the directory knows may look' in src, False)
    ok('...and says nobody does', 'with no group filled in at all nobody from the directory '
                                  'may sign in' in src)
    ok('...and that several are separated by semicolons, which is how they are read',
       'More than one, comma separated' in src, False)
finally:
    stop.set() if hasattr(stop, 'set') else None
    shutil.rmtree(folder, ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
