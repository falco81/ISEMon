#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
carry.py - taking an installation to another machine, and back from nothing.

The question this answers is the one somebody asks the morning after a server
dies: if I install this on a new machine and load the file I exported, is it
the same installation? So there are two machines here. One is set up the way
a real one is - settings, accounts, a never-banned list, bans, a router key,
a domain certificate. The other has never been run. The file goes from the
first to the second and everything on the second is held against the first.

Both shapes of the file are tested, because they are for different things and
the dangerous mistake is thinking the safe one is the complete one: a plain
export deliberately carries no password, no ssh key and no certificate, and
what is tested there is that it says so rather than leaving somebody to find
out when the router stops being written to.

    ./test/carry.py
"""
import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import isemon                                        # noqa: E402

PASS = FAIL = 0
LEFT = []


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


def machine(tag):
    """A machine with nothing on it."""
    folder = tempfile.mkdtemp(prefix='isemon-%s-' % tag)
    LEFT.append(folder)
    isemon.STATE_DIR = Path(folder)
    isemon.DB_FILE = Path(folder) / 'isemon.db'
    isemon.BACKUP_DIR = Path(folder) / 'backups'
    isemon.DUMP_DIR = Path(folder) / 'dumps'
    isemon.RUN_DIR = Path(folder)
    isemon.LOG_DIR = Path(folder)
    isemon._LOG_PATH = Path(folder) / 'd.log'
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    store = isemon.Storage(isemon.DB_FILE)
    return store, isemon.Daemon(store)


SET_UP = {
    'site_name': 'blacklistmt', 'block_tries': 3, 'block_window_min': 300,
    'block_ladder': '15, 60, 1440, forever', 'block_lots': 5,
    'block_bogus_names': 'INVALID', 'feeds': 'firehol1, spamhaus, ipsum3',
    'mikrotik_host': '192.168.252.155', 'mikrotik_user': 'isemon',
    'mikrotik_list': 'ISEMonDROP', 'mikrotik_password': 'the-router-password',
    # Signed in with a password rather than a key, so that a password this
    # machine really needs is what the plain export is held against.
    'mikrotik_auth': 'password',
    'geolist': 1, 'geolist_countries': 'AF, KP',
    'tacacs_from': '192.168.251.10=LogHost', 'tacacs_from_mark': 1,
    'directory': 1, 'directory_host': 'dc01.example.loc',
    'directory_base': 'DC=corpnet,DC=loc', 'directory_bind': 'isemon@example.loc',
    'directory_password': 'the-service-password',
    'directory_admin_group': 'CN=ISEMON_Admins,OU=Groups,DC=corpnet,DC=loc',
    'directory_readonly_group': 'CN=ISEMON_ReadOnly,OU=Groups,DC=corpnet,DC=loc',
}
CA = '-----BEGIN CERTIFICATE-----\nMIInotreallyone\n-----END CERTIFICATE-----\n'
KEY = '-----BEGIN OPENSSH PRIVATE KEY-----\nbbbbnotreallyone\n-----END OPENSSH PRIVATE KEY-----\n'


def set_up():
    """A machine as somebody who uses it would leave it."""
    store, daemon = machine('from')
    daemon.save_settings(dict(SET_UP), by='setup')
    daemon.add_user('jan', 'a-long-enough-password', 'fulladmin', by='setup')
    daemon.add_user('petr', 'another-long-password', 'readonly', by='setup')
    daemon.add_user('old', 'a-third-long-password', 'readonly', by='setup')
    store.put_user('old', disabled=True)
    store.add_whitelist('192.168.0.0/16', 'our own networks', by='setup')
    store.add_whitelist('10.20.30.40', 'the jump host', by='setup')
    store.block('203.0.113.9', None, 'a failed VPN login as INVALID', auto=True)
    store.block('198.51.100.5', time.time() + 3600, 'three failures', auto=True)
    store.block('198.51.100.6', time.time() - 60, 'this one has run out', auto=True)
    store.set_meta('directory_ca', CA)
    store.set_meta('mikrotik_key', KEY)
    store.set_meta('mikrotik_public', 'ssh-ed25519 AAAA isemon')
    return store, daemon


try:
    title('A plain export: what anybody may read')
    was, from_ = set_up()
    plain = json.loads(json.dumps(from_.export_config()))
    ok('it says what it is', plain['_what'], 'isemon configuration')
    ok('...and that it is not the complete one', plain['_complete'], False)
    ok('the router password is not in it', 'mikrotik_password' in plain['settings'], False)
    ok('...nor the directory one', 'directory_password' in plain['settings'], False)
    ok('...nor the ssh key', 'keys' in plain or 'mikrotik_key' in plain, False)
    ok('...nor anybody’s password',
       any(u.get('hash') for u in plain['users']), False)
    ok('but the accounts are named, with what they may do',
       sorted((u['name'], u['role']) for u in plain['users']),
       [('jan', 'fulladmin'), ('old', 'readonly'), ('petr', 'readonly')])
    ok('...and what is never banned', sorted(r['ip'] for r in plain['whitelist']),
       ['10.20.30.40', '192.168.0.0/16'])
    ok('...and who is banned', len(plain['blocked']), 3)

    title('...loaded onto a machine that has never been run')
    to_store, to = machine('to')
    ok('it really has nothing on it',
       (len(to_store.users()), len(to_store.whitelist()), len(to_store.blocked_all())),
       (0, 0, 0))
    said = to.import_config(plain, by='the rebuild')
    ok('every setting that was set is set again',
       [isemon.CONFIG[k] for k in ('site_name', 'block_tries', 'block_window_min',
                                   'block_ladder', 'mikrotik_host', 'directory_host')],
       ['blacklistmt', 3, 300, '15, 60, 1440, forever', '192.168.252.155', 'dc01.example.loc'])
    ok('the accounts are back', sorted((u['name'], u['role']) for u in to_store.users()),
       [('jan', 'fulladmin'), ('old', 'readonly'), ('petr', 'readonly')])
    ok('...including which of them was switched off',
       bool(to_store.user('old')['disabled']), True)
    ok('the never-banned list is back',
       sorted(r['ip'] for r in to_store.whitelist()), ['10.20.30.40', '192.168.0.0/16'])
    ok('...with the note somebody wrote on it',
       [r['note'] for r in to_store.whitelist() if r['ip'] == '10.20.30.40'],
       ['the jump host'])
    ok('who was banned is banned again', len(to_store.blocked_all()), 2)
    ok('...and the one whose ban had run out is not',
       '198.51.100.6' in to_store.blocked_states(['198.51.100.6']), False)

    title('...and it says what it could not bring, rather than leaving it to be found')
    ok('the router password is named', 'mikrotik_password' in said['missing'], True)
    ok('...and the directory one', 'directory_password' in said['missing'], True)
    ok('...and the key and the certificate',
       any('router key' in m for m in said['missing']), True)
    ok('...and that nobody can sign in yet',
       any('password' in m for m in said['missing']), True)
    try:
        to.login('jan', 'a-long-enough-password', ip='10.0.0.1')
        ok('...which is true: the old password does not work', False)
    except ValueError:
        ok('...which is true: the old password does not work', True)

    title('A complete export: enough to stand a machine up with nothing typed in')
    isemon.CONFIG.clear()
    isemon.CONFIG.update(isemon.DEFAULTS)
    was, from_ = set_up()
    FEED = from_.banfeed_key(make=True)
    whole = json.loads(json.dumps(from_.export_config(secrets_too=True)))
    ok('it says that it is the complete one', whole['_complete'], True)
    ok('...and it carries the key in the published ban list\u2019s URL',
       whole['keys'].get('banfeed_key'), FEED)
    ok('the plain one does not',
       'banfeed_key' in json.dumps(from_.export_config()), False)
    ok('the router password is in it',
       whole['settings'].get('mikrotik_password'), 'the-router-password')
    ok('...and the directory one',
       whole['settings'].get('directory_password'), 'the-service-password')
    ok('...and the ssh key, both halves',
       (whole['keys']['mikrotik_key'], bool(whole['keys']['mikrotik_public'])), (KEY, True))
    ok('...and the domain’s certificate', whole['keys']['directory_ca'], CA)
    ok('...and every account’s password as it is kept',
       all(u.get('hash') for u in whole['users']), True)

    to_store, to = machine('to2')
    said = to.import_config(whole, by='the rebuild')
    ok('nothing is left to be typed in', said['missing'], [])
    ok('the router password came across',
       isemon.CONFIG['mikrotik_password'], 'the-router-password')
    ok('...and the ssh key', to_store.get_meta('mikrotik_key'), KEY)
    ok('...and the certificate', to_store.get_meta('directory_ca'), CA)
    ok('...and the ban list\u2019s URL keeps its key, so the firewalls fetching it '
       'are not refused', to.banfeed_key(), FEED)
    got = to.login('jan', 'a-long-enough-password', ip='10.0.0.1')
    ok('an administrator signs in with the password they always used', got['role'], 'fulladmin')
    got = to.login('petr', 'another-long-password', ip='10.0.0.1')
    ok('...and so does somebody who may only look', got['role'], 'readonly')
    try:
        to.login('old', 'a-third-long-password', ip='10.0.0.1')
        ok('...and the account that was switched off is still switched off', False)
    except ValueError as e:
        ok('...and the account that was switched off is still switched off',
           'switched off' in str(e), True)
    try:
        to.login('jan', 'not-the-password', ip='10.0.0.1')
        ok('...and a wrong password is still wrong', False)
    except ValueError:
        ok('...and a wrong password is still wrong', True)

    title('What may be left out on purpose')
    to_store, to = machine('to3')
    to.import_config(whole, by='the rebuild', with_blocked=False, with_users=False)
    ok('the settings came without the bans', isemon.CONFIG['site_name'], 'blacklistmt')
    ok('...and nobody is banned', to_store.blocked_all(), [])
    ok('...and no account was made', to_store.users(), [])
    ok('...but the never-banned list still came', len(to_store.whitelist()), 2)

    title('Something that is not one of these files')
    for bad in ({'hello': 'there'}, {'_what': 'something else'}, [], 'a string'):
        try:
            to.import_config(bad, by='a test')
            ok('%r is refused' % (bad,), False)
        except ValueError:
            ok('%r is refused' % (str(bad)[:24],), True)

    title('A file written by the version before this one still loads')
    old = {'_what': 'isemon configuration', '_version': '1.3.0',
           'settings': {'site_name': 'older', 'block_tries': 9},
           'users': [], 'blocked': [],
           'mikrotik_key': KEY}          # where the key used to live
    to_store, to = machine('to4')
    said = to.import_config(old, by='a test')
    ok('its settings are applied', isemon.CONFIG['block_tries'], 9)
    ok('...and the key it carried is found where it used to be kept',
       to_store.get_meta('mikrotik_key'), KEY)
    ok('...and it is said that it had no never-banned list',
       'whitelist' in said['missing'], True)

    # A carried never-banned list has to let out what it spares, the way the
    # button on the page does. Writing the rows and leaving the bans standing
    # is a list that says "never" beside a rule on the router that says
    # otherwise, and nobody reading either one can tell which is true.
    from_store, frm = machine('from5')
    frm.whitelist_add('10.9.9.9', 'the printer', by='a test')
    carried = json.loads(json.dumps(frm.export_config()))
    to_store, to = machine('to5')
    to.ban('10.9.9.9', minutes=60, why='banned before the list arrived', by='a test')
    to.ban('203.0.113.77', minutes=60, why='and this one is not on it', by='a test')
    ok('an address is banned on the machine the list is about to arrive at',
       sorted(r['ip'] for r in to_store.blocked_all()), ['10.9.9.9', '203.0.113.77'])
    said = to.import_config(carried, by='a test')
    ok('the carried list is written down',
       [r['ip'] for r in to_store.whitelist()], ['10.9.9.9'])
    ok('...and the ban it spares is let go with it',
       sorted(r['ip'] for r in to_store.blocked_all()), ['203.0.113.77'])
    ok('...and the import says so rather than doing it quietly',
       any('let back in' in one for one in said['done']), True)

finally:
    for folder in LEFT:
        shutil.rmtree(folder, ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
