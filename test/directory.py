#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
directory.py - signing in against Active Directory, against one that is not
there.

mockldap.py answers the way a domain controller does, including over TLS with
a certificate this makes on the spot. What is being tested is the part nobody
can test against a real directory without an outage: that a name in the
directory is answered by the directory and never by a local password of the
same name, that a name which is NOT in it still falls back to the local
accounts, that groups decide the role, that a group inside a group counts,
and that a certificate nobody trusts is refused rather than shrugged at.

    ./test/directory.py
"""
import json
import os
import shutil
import ssl
import subprocess
import sys
import importlib.util
import tempfile
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


def title(text):
    print('\n%s' % text)


folder = tempfile.mkdtemp(prefix='isemon-dir-')
isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = Path(folder) / 'd.db'
isemon.BACKUP_DIR = Path(folder) / 'backups'
isemon.DUMP_DIR = Path(folder) / 'dumps'
isemon.RUN_DIR = Path(folder)
isemon.LOG_DIR = Path(folder)
isemon._LOG_PATH = Path(folder) / 'd.log'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)

plain_port, plain_stop = mockldap.serve()
time.sleep(0.3)


def as_plain():
    isemon.CONFIG.update({
        'directory': 1, 'directory_host': '127.0.0.1', 'directory_port': plain_port,
        'directory_tls': 'none', 'directory_verify': 0,
        'directory_base': 'DC=corpnet,DC=loc',
        'directory_bind': 'CN=isemon,OU=Service,DC=corpnet,DC=loc',
        'directory_password': 'the-service-password',
        'directory_user_attr': 'sAMAccountName',
        'directory_admin_group': 'CN=ISE Admins,OU=Groups,DC=corpnet,DC=loc',
        'directory_readonly_group': 'CN=ISE Watchers,OU=Groups,DC=corpnet,DC=loc',
        'directory_nested': 1})


try:
    as_plain()

    title('Is it there, and what is in it')
    said = daemon.directory_check()
    ok('every step of the check passes', said['ok'], True)
    ok('...and it found the people', said['people'], 6)
    ok('...and the groups', len(said['groups']), 3)
    ok('...and says each group’s name, not only its distinguished name',
       sorted(g['name'] for g in said['groups']),
       ['Helpdesk', 'ISE Admins', 'ISE Watchers'])
    ok('...and reads what a group is for', [g['says'] for g in said['groups']
                                            if g['name'] == 'ISE Admins'],
       ['may change everything'])

    title('Somebody types their name, and nothing else')
    got = daemon.login('jnovak', 'a-good-long-password', ip='10.0.0.9')
    ok('no domain is needed', (got['name'], got['role']), ('jnovak', 'fulladmin'))
    ok('...and it says the sign-in came from the directory', got.get('from_dir'), True)
    ok('...and the name is written down here, with no password',
       store.user('jnovak')['hash'], '')
    ok('...and nothing about it has to be made up', store.user('jnovak')['dn'],
       'CN=Jan Novak,OU=People,DC=corpnet,DC=loc')
    ok('...and marked as the directory’s', bool(store.user('jnovak')['from_dir']), True)
    ok('...and the session is real', bool(store.session(got['token'])), True)

    got = daemon.login('jnovak@corpnet.loc', 'a-good-long-password', ip='10.0.0.9')
    ok('the whole address works too', got['role'], 'fulladmin')

    title('What somebody is told when it does not work')
    # One short sentence for the person, and the directory's own words kept
    # beside it for whoever hovers over it. "80090308: LdapErr: DSID-0C09044E,
    # comment: AcceptSecurityContext error, data 52e" is the line that told
    # somebody setting this up what was wrong and told everybody else
    # nothing.
    ok('what the directory meant, without what it said',
       isemon.ad_reason('80090308: LdapErr: DSID-0C09044E, comment: '
                        'AcceptSecurityContext error, data 52e'),
       'the password is not right')
    ok('...and a switched-off account is not a wrong password',
       isemon.ad_reason('80090308: LdapErr: data 533'), 'the account is disabled')
    ok('...and a number nobody has a sentence for is passed through as it came',
       isemon.ad_reason('something nobody planned for'), 'something nobody planned for')
    try:
        daemon.login('jnovak', 'not-the-right-password-at-all', ip='10.0.0.9')
        ok('a wrong password is one plain sentence', False)
    except ValueError as e:
        ok('a wrong password is one plain sentence', str(e),
           'that name and password do not go together')
        ok('...the same one a name that does not exist gets, so the sentence tells '
           'a guesser nothing', 'LdapErr' in getattr(e, 'detail', '')
           or 'AcceptSecurityContext' in getattr(e, 'detail', ''), False)
        ok('...and the NUL a domain controller ends its words with does not stop '
           'them being written down', any('v4563' in (ev.get('detail') or '')
                                         and '\x00' not in (ev.get('detail') or '')
                                         for ev in store.events(limit=5)[0]), True)
        ok('...with what the directory said in the events, for an administrator',
           any('AcceptSecurityContext' in (ev.get('detail') or '')
               for ev in store.events(limit=5)[0]), True)
    # The wrong password above was counted against this address, as a wrong
    # password should be. Every test below types a right one.
    daemon._login_forget('10.0.0.9')


    title('Groups decide the role')
    got = daemon.login('edvorak', 'another-good-password', ip='10.0.0.9')
    # Eva is in Helpdesk, which is inside ISE Watchers. Only the nested
    # question finds that.
    ok('a group inside a group counts', got['role'], 'readonly')
    isemon.CONFIG['directory_nested'] = 0
    try:
        daemon.login('edvorak', 'another-good-password', ip='10.0.0.9')
        ok('...and without it, she is in neither group', False)
    except ValueError as e:
        ok('...and without it, she is in neither group', 'none of the groups' in str(e), True)
    isemon.CONFIG['directory_nested'] = 1

    try:
        daemon.login('nogroups', 'still-a-good-password', ip='10.0.0.9')
        ok('somebody in no group at all is refused', False)
    except ValueError as e:
        ok('somebody in no group at all is refused', 'none of the groups' in str(e), True)

    isemon.CONFIG['directory_admin_group'] = ''
    isemon.CONFIG['directory_readonly_group'] = ''
    # Changed in 1.10.221: with no group named for any role, nobody from the
    # directory gets in - before, everybody in it could look.
    for who, pw in (('nogroups', 'still-a-good-password'), ('jnovak', 'a-good-long-password')):
        try:
            daemon.login(who, pw, ip='10.0.0.9')
            ok('with no groups named, %s from the directory is refused' % who, False)
        except ValueError as e:
            ok('with no groups named, %s from the directory is refused' % who,
               'none of the groups' in str(e), True)
    as_plain()

    title('A wrong password is the directory’s answer, not a fallback')
    # Made the way an older version let it be made: "add" over a name that
    # was already there. 1.10.97 refuses that (below), but a database may
    # still hold one.
    store.put_user('jnovak', password='a-local-password-nobody-should-use', role='fulladmin',
                   by='a test')
    try:
        daemon.add_user('jnovak', 'another-local-password', 'readonly', by='a test')
        ok('an account that is there is never made again over itself', False)
    except isemon.StorageError:
        ok('an account that is there is never made again over itself', True)
    try:
        daemon.login('jnovak', 'a-local-password-nobody-should-use', ip='10.0.0.9')
        ok('a local password does not get a directory name in', False)
    except ValueError:
        ok('a local password does not get a directory name in', True)
    got = daemon.login('jnovak', 'a-good-long-password', ip='10.0.0.9')
    ok('...while the domain password still does', got['role'], 'fulladmin')

    title('The password and the role live in the domain, not here')
    got = daemon.login('jnovak', 'a-good-long-password', ip='10.0.0.9')
    who = daemon.who(got['token'])
    ok('a session says the account belongs to the directory', who.get('from_dir'), True)
    ok('...which is what hides "change my password" from the page',
       bool(who.get('from_dir')), True)
    mine = daemon.who(daemon.login('localonly2', 'a-local-password-here', ip='10.0.0.9')
                      ['token']) if store.user('localonly2') else None
    ok('...and a local account is not marked that way',
       bool((mine or {}).get('from_dir')), False)

    title('A name the directory has never heard of falls back')
    daemon.add_user('localonly', 'a-local-password-here', 'readonly', by='a test')
    got = daemon.login('localonly', 'a-local-password-here', ip='10.0.0.9')
    ok('a local-only account still signs in', got['role'], 'readonly')
    ok('...and is not marked as the directory’s',
       bool(store.user('localonly')['from_dir']), False)

    title('When the directory cannot be reached at all')
    # A domain controller being rebooted must not lock everybody out of this
    # dashboard. The directory not answering is not an answer about anybody.
    isemon.CONFIG['directory_port'] = 1        # nothing is listening there
    got = daemon.login('localonly', 'a-local-password-here', ip='10.0.0.9')
    ok('a local-only account still signs in', got['role'], 'readonly')
    # jnovak has BOTH: the directory owns the name, and somebody also gave it
    # a local password. That password is never used while the directory is
    # answering - and it is the way back in when the directory is not.
    got = daemon.login('jnovak', 'a-local-password-nobody-should-use', ip='10.0.0.9')
    ok('...and a local password kept on purpose is the way back in', got['role'], 'fulladmin')
    ok('...which is not what happens to an account that only ever came from the directory',
       store.user('edvorak')['hash'], '')
    try:
        daemon.login('edvorak', 'anything-at-all-here', ip='10.0.0.9')
        ok('...that one is told the directory cannot be asked', False)
    except ValueError as e:
        # ...in words that do not say what kind of account it is: that was
        # telling whoever typed a name whether the directory owns it.
        ok('...that one is told the directory cannot be asked',
           'directory is not answering' in str(e), True)
    try:
        daemon.login('localonly', 'not-that-password', ip='10.0.0.9')
        ok('...and a wrong local password is still one plain sentence', False)
    except ValueError as e:
        ok('...and a wrong local password is still one plain sentence',
           str(e), 'that name and password do not go together')
        # Why the directory was not the one to answer belongs under the
        # pointer, not in the sentence: somebody typing a password wrongly
        # should not have to read about LDAP, and somebody whose password is
        # right and is being refused anyway should be able to find out that
        # the directory is down without going to the server.
        ok('...with why the directory was not the one to answer, for the tooltip',
           'could not be reached' in getattr(e, 'detail', ''), True)
    daemon._login_forget('10.0.0.9')
    said = daemon.directory_check()
    ok('...and the check says what is wrong rather than nothing',
       said['ok'] is False and bool(said['steps'][-1]['said']), True)
    isemon.CONFIG['directory_port'] = plain_port

    title('Finding the groups, so nobody has to type them')
    found = daemon.directory_group_list(None, 'ise')
    ok('a fragment finds the groups that hold it',
       sorted(g['name'] for g in found), ['ISE Admins', 'ISE Watchers'])
    found = daemon.directory_group_list(None, '')
    ok('...and nothing finds them all', len(found), 3)

    # A real domain has thousands of groups, and a domain controller hands
    # back only so many in one answer however many are asked for - a
    # thousand on Active Directory unless somebody has lowered it. Without
    # asking for them a page at a time, a domain of three thousand groups
    # looked like a domain of four hundred and nobody could tell which four
    # hundred. mockldap has a ceiling of its own, so this needs four pages.
    mockldap.make_groups(1000)
    many = daemon.directory_group_list(None, '')
    ok('a domain with a great many groups hands back all of them',
       len(many), 1003)
    ok('...more than any one answer holds', len(many) > mockldap.MAX_PAGE, True)
    ok('...in one long list with no repeats',
       len({g['dn'] for g in many}), 1003)
    ok('...and in order', [g['name'] for g in many][:2], ['Group 0001', 'Group 0002'])
    some = daemon.directory_group_list(None, 'group 09')
    ok('...and a fragment still narrows it down', len(some), 100)
    ok('...to the right ones', all(g['name'].startswith('Group 09') for g in some), True)
    held = daemon.directory_group_list(None, '', limit=120)
    ok('...while a limit is still a limit', len(held), 120)
    for dn in [d for d in mockldap.GROUPS if d.startswith('CN=Group ')]:
        mockldap.GROUPS.pop(dn, None)
    ok('the small domain is itself again', len(daemon.directory_group_list(None, '')), 3)

    title('Over TLS, with a certificate')
    keys = tempfile.mkdtemp(prefix='isemon-ca-')
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                    '-keyout', keys + '/key.pem', '-out', keys + '/cert.pem',
                    '-days', '2', '-nodes', '-subj', '/CN=localhost',
                    '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'],
                   capture_output=True, check=True)
    pem = open(keys + '/cert.pem', encoding='utf-8').read()
    tls_port, tls_stop = mockldap.serve(tls=(keys + '/cert.pem', keys + '/key.pem'))
    time.sleep(0.3)
    isemon.CONFIG.update({'directory_port': tls_port, 'directory_tls': 'ldaps',
                          'directory_host': 'localhost', 'directory_verify': 1})

    said = isemon.describe_certificate(pem)
    ok('a pasted certificate is read, not just stored', said['subject'], 'localhost')
    ok('...and it says whether it signed itself', said['self_signed'], True)
    ok('something that is not a certificate is refused',
       isemon.describe_certificate('hello'), None)

    try:
        daemon.login('edvorak', 'another-good-password', ip='10.0.0.9')
        ok('a certificate nobody trusts is refused', False)
    except ValueError as e:
        # The sentence says what happened to the person signing in; WHICH
        # certificate nobody trusts is the tooltip's half of it.
        ok('a certificate nobody trusts is refused',
           'directory is not answering' in str(e).lower(), True)
        ok('...and what was wrong with it is there to hover over',
           'certificate' in getattr(e, 'detail', '').lower(), True)

    store.set_meta('directory_ca', pem)
    got = daemon.login('jnovak', 'a-good-long-password', ip='10.0.0.9')
    ok('...and with its authority imported, it works', got['role'], 'fulladmin')
    ok('the whole check passes over TLS', daemon.directory_check()['ok'], True)

    store.set_meta('directory_ca', '')
    isemon.CONFIG['directory_verify'] = 0
    got = daemon.login('jnovak', 'a-good-long-password', ip='10.0.0.9')
    ok('with the check switched off it works and says nothing', got['role'], 'fulladmin')
    tls_stop.set()
    shutil.rmtree(keys, ignore_errors=True)

    title('An empty password is never a way in')
    isemon.CONFIG.update({'directory_port': plain_port, 'directory_tls': 'none',
                          'directory_host': '127.0.0.1'})
    try:
        daemon.login('jnovak', '', ip='10.0.0.9')
        ok('an empty password is refused', False)
    except ValueError:
        ok('an empty password is refused', True)

    title('Somebody is moved between the groups while they are using it')
    # The whole of what an administrator expects when they change somebody's
    # groups: it takes effect here, without anybody restarting anything, and
    # without a domain administrator having to say which application to tell.
    isemon.CONFIG.update({'directory_port': plain_port, 'directory_tls': 'none',
                          'directory_host': '127.0.0.1'})
    as_plain()
    got = daemon.login('jnovak', 'a-good-long-password', ip='10.0.0.9')
    ok('an administrator signs in as one', got['role'], 'fulladmin')
    first = got['token']

    mockldap.move('jnovak', 'CN=ISE Watchers,OU=Groups,DC=corpnet,DC=loc')
    got = daemon.login('jnovak', 'a-good-long-password', ip='10.0.0.9')
    ok('moved to the watchers, the next sign-in is read only', got['role'], 'readonly')
    ok('...and the account says so too', store.user('jnovak')['role'], 'readonly')

    mockldap.move('jnovak', 'CN=ISE Admins,OU=Groups,DC=corpnet,DC=loc')
    got = daemon.login('jnovak', 'a-good-long-password', ip='10.0.0.9')
    ok('...and moved back, an administrator again', got['role'], 'fulladmin')

    mockldap.move('jnovak', None)                      # out of both groups
    try:
        daemon.login('jnovak', 'a-good-long-password', ip='10.0.0.9')
        ok('taken out of both groups, they cannot sign in at all', False)
    except ValueError as e:
        ok('taken out of both groups, they cannot sign in at all',
           'none of the groups' in str(e), True)
    mockldap.move('jnovak', 'CN=ISE Admins,OU=Groups,DC=corpnet,DC=loc')

    title('...and while they are already signed in')
    # A sign-in lasts hours. Taking the rights away and having them last until
    # tomorrow is not taking them away, so the question is asked again.
    isemon.CONFIG['directory_recheck_min'] = 1
    daemon._directory_looked = 0
    got = daemon.login('jnovak', 'a-good-long-password', ip='10.0.0.9')
    live = got['token']
    ok('their sign-in works', bool(store.session(live)), True)
    said = daemon.directory_recheck()
    ok('nothing is changed about somebody whose groups have not moved',
       said['changed'], 0)
    ok('...and they are still signed in', bool(store.session(live)), True)

    mockldap.move('jnovak', 'CN=ISE Watchers,OU=Groups,DC=corpnet,DC=loc')
    daemon._directory_looked = 0
    said = daemon.directory_recheck()
    # Other accounts from the checks above are signed in too, so what is
    # asserted is that this one moved - not how many did.
    ok('moved to the watchers, it notices', said['changed'] >= 1, True)
    ok('...and the account is read only now', store.user('jnovak')['role'], 'readonly')
    ok('...and the sign-in they were holding as an administrator has ended',
       store.session(live), None)
    got = daemon.login('jnovak', 'a-good-long-password', ip='10.0.0.9')
    ok('...so the next one comes back as what they now are', got['role'], 'readonly')
    live = got['token']

    mockldap.move('jnovak', None)
    daemon._directory_looked = 0
    said = daemon.directory_recheck()
    ok('taken out of both groups, the sign-in ends', said['ended'] >= 1, True)
    ok('...and it really is gone', store.session(live), None)
    try:
        daemon.login('jnovak', 'a-good-long-password', ip='10.0.0.9')
        ok('...and they cannot get back in', False)
    except ValueError:
        ok('...and they cannot get back in', True)
    mockldap.move('jnovak', 'CN=ISE Admins,OU=Groups,DC=corpnet,DC=loc')

    # An outage must never sign anybody out: not being able to ask is not an
    # answer about anybody.
    got = daemon.login('jnovak', 'a-good-long-password', ip='10.0.0.9')
    live = got['token']
    isemon.CONFIG['directory_port'] = 1
    daemon._directory_looked = 0
    said = daemon.directory_recheck()
    ok('a directory that cannot be reached changes nothing',
       (said['changed'], said['ended']), (0, 0))
    ok('...and nobody is signed out over it', bool(store.session(live)), True)
    isemon.CONFIG['directory_port'] = plain_port
    isemon.CONFIG['directory_recheck_min'] = 0

    title('A lock on this machine beats the directory')
    store.put_user('jnovak', disabled=True)
    try:
        daemon.login('jnovak', 'a-good-long-password', ip='10.0.0.9')
        ok('switched off here, the domain password does not get them in', False)
    except ValueError as e:
        ok('switched off here, the domain password does not get them in',
           'switched off' in str(e), True)
    ok('...and it is still switched off afterwards',
       bool(store.user('jnovak')['disabled']), True)
    store.put_user('jnovak', disabled=False)
    got = daemon.login('jnovak', 'a-good-long-password', ip='10.0.0.9')
    ok('switched back on, they sign in again', got['role'], 'fulladmin')

    title('Asking the directory who somebody is, and only asking')
    isemon.CONFIG['directory'] = 1
    said = daemon.directory_person('pkolar')
    ok('the person is found', (said['found'], said['title']), (True, 'Petr Kolář'))
    words = [m['words'] for m in said['marks']]
    ok('...and the directory says why nothing they type works',
       ('locked out' in words, 'password has expired' in words), (True, True))
    facts = {f['words']: f['said'] for f in said['facts']}
    ok('...with who they are beside it',
       (facts.get('Who this is'), facts.get('Email')),
       ('Petr Kolář', 'petr.kolar@corpnet.loc'))
    ok('...and the department, because a name in a log is not a person',
       facts.get('Department'), 'Odbor informatiky \u2014 Správce sítě')
    ok('...and the wrong passwords the controller has counted',
       str(facts.get('Wrong passwords counted', '')).startswith('7'), True)
    ok('...and which groups they are in', [g['name'] for g in said['groups']], ['Helpdesk'])

    ok('somebody with nothing against them is said to have nothing against them',
       [m['words'] for m in daemon.directory_person('jnovak')['marks']],
       ['nothing in the way'])
    ok('a name written with its realm is the same person',
       daemon.directory_person('jnovak@corpnet.loc')['title'], 'Jan Novák')
    ok('...and so is one written with a domain in front of it',
       daemon.directory_person('CORPNET\\jnovak')['title'], 'Jan Novák')
    ok('a name nobody has is simply not there',
       (daemon.directory_person('nosuchperson')['found'],
        daemon.directory_person('nosuchperson')['trouble']), (False, ''))
    ok('a MAC address is not a name and is not asked about',
       'MAC address' in daemon.directory_person('98-FC-84-E1-16-5D')['trouble'], True)

    title('A machine is in the directory too')
    box = daemon.directory_person('host/pc123.corpnet.loc')
    ok('802.1X signs in as a machine, and the machine is looked up',
       (box['found'], box['machine']), (True, True))
    kit = {f['words']: f['said'] for f in box['facts']}
    ok('...with what it runs', kit.get('Running'), 'Windows 11 Enterprise 10.0 (22631)')
    ok('...and the same machine by its short name is the same machine',
       daemon.directory_person('PC123')['title'], 'PC123')

    title('Nothing is ever written to the directory')
    # Not a matter of policy: the client has no way to write. Anything that
    # could would be a method on the connection, and there is none.
    link_methods = [m for m in dir(isemon.Ldap)
                    if not m.startswith('_') and callable(getattr(isemon.Ldap, m))]
    ok('the whole LDAP client is open, bind, search and close',
       sorted(link_methods), ['bind', 'close', 'open', 'search'])
    ok('...and nothing anywhere sends a modify, add or delete to a directory',
       [w for w in ('ldap_modify', 'ldap_add', 'ldap_delete', 'modifyRequest')
        if w in open(str(HERE.parent / 'isemon.py')).read()], [])
    # ...and it is not left to the code happening not to do it. The socket
    # refuses: every LDAP message is checked on its way out, and anything
    # that is not a bind, a search, an unbind or StartTLS cannot leave this
    # program even if somebody writes the code to build one.
    ok('the only messages it may send are the four that read',
       sorted(isemon.Ldap.MAY_SAY), [0x42, 0x60, 0x63, 0x77])
    link = isemon.Ldap('127.0.0.1', plain_port, 'none')
    link.open()
    try:
        link.bind('CN=isemon,OU=Service,DC=corpnet,DC=loc', 'the-service-password')
        for tag, words in sorted(isemon.Ldap.WRITES.items()):
            try:
                link._send(isemon._ber(tag, isemon._ber_str('CN=anybody')))
                ok('a %s is refused before it reaches the wire' % words, False)
            except isemon.LdapError as e:
                ok('a %s is refused before it reaches the wire' % words,
                   ('only ever READS' in str(e)), True)
        # ...and the reading itself still works through the same door.
        ok('...while a search still goes through',
           bool(link.search('DC=corpnet,DC=loc',
                            isemon.ldap_equal('sAMAccountName', 'jnovak'),
                            ('sAMAccountName',), limit=1)), True)
    finally:
        link.close()

    title('A second directory, asked only who somebody is')
    # The situation this exists for: the people who sign in to this dashboard
    # are in one domain, and the people in the ISE logs are in another. A
    # second copy of the mock, with its own people, is that other domain.
    import importlib.util
    spec = importlib.util.spec_from_file_location('mockldap2', str(HERE / 'mockldap.py'))
    other = importlib.util.module_from_spec(spec)
    sys.modules['mockldap2'] = other
    spec.loader.exec_module(other)
    other.PEOPLE = {
        'CN=Marie Vesela,OU=Lide,DC=other,DC=int': {
            'sAMAccountName': ['mvesela'],
            'userPrincipalName': ['mvesela@other.int'],
            'displayName': ['Marie Veselá'],
            'mail': ['marie.vesela@other.int'],
            'department': ['Odbor dopravy'],
            'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
            'userAccountControl': ['514'],          # a disabled account
            'memberOf': [],
            '_password': 'nobody-signs-in-with-this',
        },
        # The same person as in the first directory, under the same account
        # name. A second domain that is a copy of the first - a secondary
        # controller answering under another name - is the ordinary shape of
        # this, not the exception, and both of them knowing a name has to
        # give the card one answer rather than two.
        'CN=Jan Novak,OU=Lide,DC=other,DC=int': {
            'sAMAccountName': ['jnovak'],
            'userPrincipalName': ['jnovak@other.int'],
            'displayName': ['Jan Novák (the other domain)'],
            'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
            'userAccountControl': ['512'],
            'memberOf': [],
            '_password': 'nobody-signs-in-with-this',
        },
        'CN=reader,OU=Service,DC=other,DC=int': {
            'sAMAccountName': ['reader'],
            'objectClass': ['top', 'person', 'user'],
            'memberOf': [],
            '_password': 'the-other-reading-password',
        },
    }
    other.GROUPS = {}
    other_port, other_stop = other.serve()
    isemon.CONFIG.update({
        'directory': 1, 'directory_port': plain_port,
        'directory2': 1, 'directory2_host': '127.0.0.1', 'directory2_port': other_port,
        'directory2_tls': 'none', 'directory2_base': 'DC=other,DC=int',
        'directory2_bind': 'CN=reader,OU=Service,DC=other,DC=int',
        'directory2_password': 'the-other-reading-password',
    })
    try:
        ok('both directories are asked, in order',
           daemon.directory_lookups(), ['directory', 'directory2'])
        first = daemon.directory_person('jnovak')
        ok('a name the first one has is answered by the first one',
           (first['found'], first['where']), (True, 'directory'))
        second = daemon.directory_person('mvesela')
        ok('...and a name it does not have is asked of the second',
           (second['found'], second['where'], second['title']),
           (True, 'directory2', 'Marie Veselá'))
        ok('...which answers about it exactly as the first one would',
           [m['words'] for m in second['marks']], ['switched off'])
        ok('a name neither of them has is not found, and says nothing went wrong',
           [daemon.directory_person('nobody-at-all')[k] for k in ('found', 'trouble')],
           [False, ''])
        # What the card in the find box draws from: whether two were asked,
        # and which of them answered. Without the first of those the card
        # cannot tell "there is no such account" from "the one directory
        # that was asked has not got it", and on a site with a second domain
        # those are not the same sentence.
        ok('...and the answer says two were asked, so the card can say so',
           [first['asked_both'], second['asked_both'],
            daemon.directory_person('nobody-at-all')['asked_both']],
           [True, True, True])
        ok('...and which of them answered, in words',
           [first['where_words'], second['where_words']],
           ['the directory', 'the second directory'])
        # The site this was built for has two directories that are the same
        # domain twice - a secondary controller under another name - so the
        # ordinary case is both of them knowing the name. The first wins,
        # once, and the card gets one answer rather than two.
        both = daemon.directory_person('jnovak')
        ok('a name both of them have is answered by the first',
           [both['found'], both['where'], both['title'], both['asked_both']],
           [True, 'directory', 'Jan Novák', True])
        # ...and the other one is not thrown away. Two domains that both hold
        # an account of that name hold two accounts: different groups, and
        # one of them can be locked out while the other signs in perfectly
        # well. Somebody looking a name up on a site with two domains is
        # usually looking for exactly that, and it used to be dropped on the
        # floor the moment the first directory said yes.
        ok('...and what the second one has is carried back beside it',
           [o['where'] for o in (both.get('also') or [])], ['directory2'])
        ok('...with who it says that is, which is not what the first one says',
           [o['title'] for o in (both.get('also') or [])], ['Jan Novák (the other domain)'])
        ok('...and which domain it is', [o['domain'] for o in (both.get('also') or [])],
           [daemon.directory_domain('directory2')])
        ok('a name only one of them has has nothing beside it',
           daemon.directory_person('mvesela').get('also'), [])
        # The domain the record named is the one shown; the other is still
        # asked, because "she is in both" is the fact being looked for.
        named = daemon.directory_person('jnovak', realm='other.int')
        ok('a record that names a domain is shown that domain\u2019s account',
           [named['found'], named['where'], named['matched']],
           [True, 'directory2', 'directory2'])
        ok('...and the other directory is asked all the same',
           [o['where'] for o in (named.get('also') or [])], ['directory'])
        # Asking one of them on purpose - the button on a directory's own
        # settings page - is still one of them and no other.
        alone = daemon.directory_person('jnovak', only='directory2')
        ok('asking one directory on purpose asks that one only',
           [alone['found'], alone['where'], alone.get('also')],
           [True, 'directory2', []])
        # A machine, across two directories, which is the other half of the
        # same card: the name in the log is `host/PC123.corpnet.loc` and the
        # account in the directory is `PC123$`.
        pc = daemon.directory_person('host/pc123.corpnet.loc')
        ok('...and a machine is found across them the same way',
           [pc['found'], pc['where'], pc['machine'], pc['asked_both']],
           [True, 'directory', True, True])

        title('...and the record says which of them to ask')
        # ISE writes down the domain it resolved somebody in. A site with two
        # domains has it in every login, and it is the answer to "which
        # directory" from the thing that already asked.
        ok('a directory knows which domain it is, off its own base',
           [daemon.directory_domain('directory'), daemon.directory_domain('directory2')],
           ['corpnet.loc', 'other.int'])
        ok('...so a realm out of a record picks one of them',
           [daemon.directory_for_realm('other.int'),
            daemon.directory_for_realm('corpnet.loc'),
            daemon.directory_for_realm('somewhere.else')],
           ['directory2', 'directory', ''])
        ok('...and that one is asked, and no other',
           [daemon.directory_person('mvesela', realm='other.int')[k]
            for k in ('found', 'where', 'matched')],
           [True, 'directory2', 'directory2'])
        ok('a realm nobody has falls back to asking them all',
           daemon.directory_person('mvesela', realm='nowhere.example')['found'], True)
        ok('...and so does a record with no realm in it at all',
           daemon.directory_person('mvesela')['found'], True)
        ok('the realm is read out of what ISE writes',
           [isemon.ise_realm({'AD-User-Resolved-Identities': ['jk@corpnettech.loc']}),
            isemon.ise_realm({'AD-User-Resolved-DNs': ['CN=A,OU=B,DC=corpnet,DC=loc']}),
            isemon.ise_realm({'UserName': ['mdolezal@corpnet.loc']}),
            isemon.ise_realm({'UserName': ['jnovak']})],
           ['corpnettech.loc', 'corpnet.loc', 'corpnet.loc', ''])

        title('...and a directory says for itself which names belong to it')
        # A domain called corpnet.loc whose people sign in as somebody@corpnet.cz is
        # the ordinary shape of a directory. Active Directory publishes that
        # list, so nothing has to be typed anywhere - and nothing about any
        # particular site is written into this program.
        isemon.CONFIG['directory_realms'] = ''
        store.drop_meta('directory_suffixes')
        ok('it is asked, and it answers',
           daemon.directory_suffixes('directory', force=True),
           ['corpnet.loc', 'corpnet.cz', 'corpnet.example'])
        ok('...so a name carrying one of those goes to it',
           [daemon.directory_for_realm('corpnet.cz'),
            daemon.directory_for_realm('corpnet.example'),
            daemon.directory_for_realm('corpnet.loc')],
           ['directory', 'directory', 'directory'])
        ok('...and it is not asked again for a while',
           bool(store.meta_json('directory_suffixes', {}).get('at')), True)
        ok('somebody may still name them by hand, and both count',
           (isemon.CONFIG.update({'directory_realms': 'typed-in.example'})
            or sorted(daemon.directory_domains('directory'))),
           ['corpnet.cz', 'corpnet.example', 'corpnet.loc', 'typed-in.example'])
        isemon.CONFIG['directory_realms'] = ''

        title('...and it is never a way in')
        # The whole point: signing in is the first directory's business and
        # nobody else's. Somebody who exists only in the second one cannot
        # sign in with their password there, and gets no role from it.
        try:
            daemon.login('mvesela', 'nobody-signs-in-with-this', ip='10.0.0.9')
            ok('somebody who is only in the second directory cannot sign in', False)
        except ValueError:
            ok('somebody who is only in the second directory cannot sign in', True)
        ok('...and no account was made for them on this machine',
           store.user('mvesela'), None)
        said = daemon.directory_check('directory2')
        ok('checking it reads it and stops there',
           (said['ok'], said['lookup_only'],
            [step['what'] for step in said['steps']][-1]),
           (True, True, 'never a way in'))
        ok('...and it asks that directory for no groups at all', said['groups'], [])

        title('...and switched off it is not asked')
        isemon.CONFIG['directory2'] = 0
        ok('only the first one is asked', daemon.directory_lookups(), ['directory'])
        ok('...so a name that is only in the second is simply not found',
           daemon.directory_person('mvesela')['found'], False)
        isemon.CONFIG['directory2'] = 1

        title('...and one that will not answer is said, not hidden')
        isemon.CONFIG['directory2_port'] = 1
        got = daemon.directory_person('mvesela')
        ok('the trouble names which directory it was',
           'second directory' in got['trouble'], True)
        ok('...while a name the first one has is still answered',
           daemon.directory_person('jnovak')['found'], True)
        isemon.CONFIG['directory2_port'] = other_port
    finally:
        other_stop.set()
        isemon.CONFIG['directory2'] = 0

    title('Switched off, none of this happens')
    isemon.CONFIG['directory'] = 0
    got = daemon.login('jnovak', 'a-local-password-nobody-should-use', ip='10.0.0.9')
    ok('the local password works again once the directory is off', got['role'], 'fulladmin')


    title('What goes into the debug log, and what never does')
    # The switch on its own is "everything". Under it, one switch a thing, so
    # a machine being chased for the directory need not carry a thousand
    # statements a minute as well.
    as_plain()
    isemon.CONFIG['debug'] = 0
    ok('with the debug switch off, nothing is being written down',
       [isemon.debugging(), isemon.debugging('ldap'), isemon.debugging('sql')],
       [False, False, False])
    isemon.CONFIG['debug'] = 1
    ok('...and with it on, everything is', isemon.debugging('ldap'), True)
    isemon.CONFIG['debug_ldap'] = 0
    ok('...until the directory is switched out of it',
       [isemon.debugging('ldap'), isemon.debugging('sql')], [False, True])
    ok('...and a kind nobody has a switch for is still written',
       isemon.debugging('something-new'), True)
    isemon.CONFIG['debug_ldap'] = 1

    title('A filter is written into the log as the directory was asked it')
    # Read back off the BER that goes on the wire rather than passed down
    # beside it: a second argument on every caller would go out of step with
    # the real filter the first time somebody changed one and forgot.
    ok('a name, a group, a flag and a bit, all four shapes',
       isemon.ldap_filter_words(isemon.ldap_and(
           isemon.ldap_equal('objectClass', 'user'),
           isemon.ldap_or(isemon.ldap_equal('sAMAccountName', 'jnovak'),
                          isemon.ldap_contains('cn', 'nov')),
           isemon.ldap_present('servicePrincipalName'),
           isemon.ldap_bits('userAccountControl', 4194304))),
       '(&(objectClass=user)(|(sAMAccountName=jnovak)(cn=*nov*))'
       '(servicePrincipalName=*)(userAccountControl:1.2.840.113556.1.4.803:=4194304))')
    ok('...and the one that walks a chain of groups',
       isemon.ldap_filter_words(
           isemon.ldap_in_chain('memberOf', 'CN=ISE Admins,OU=Groups,DC=corpnet,DC=loc')),
       '(memberOf:1.2.840.113556.1.4.1941:=CN=ISE Admins,OU=Groups,DC=corpnet,DC=loc)')
    ok('...and rubbish is said to be rubbish rather than thrown',
       isemon.ldap_filter_words(b'\x99\x01\x00'), '(?)')

    title('...and the answer beside it, without the one thing that is secret')
    log_path = Path(folder) / 'debug-ldap.log'
    isemon.close_log()
    isemon.open_log(log_path)
    isemon.CONFIG.update({'debug': 1, 'debug_ldap': 1})
    got = daemon.directory_person('jnovak')
    isemon.CONFIG['debug'] = 0
    wrote = log_path.read_text(encoding='utf-8', errors='replace') if log_path.exists() else ''
    ok('the name was found, which is what was being logged', got['found'], True)
    ok('the question is in the log, as a filter', '(sAMAccountName=jnovak)' in wrote, True)
    ok('...saying which directory was asked and where',
       ('127.0.0.1' in wrote and 'DC=corpnet,DC=loc' in wrote), True)
    ok('...and how many entries came back', 'entry in' in wrote or 'entries in' in wrote, True)
    ok('...with what was in them', 'jnovak' in wrote, True)
    ok('the sign-in is in it too, by name', 'signing in as CN=isemon' in wrote, True)
    ok('...and the password is NOT, anywhere in the file',
       'the-service-password' in wrote, False)

    title('...and switched off, the directory writes nothing')
    isemon.close_log()
    log_path.write_text('', encoding='utf-8')
    isemon.open_log(log_path)
    isemon.CONFIG.update({'debug': 1, 'debug_ldap': 0})
    daemon._people = {}
    daemon.directory_person('mvesela')
    isemon.CONFIG['debug'] = 0
    again = log_path.read_text(encoding='utf-8', errors='replace')
    ok('not one line of it', 'sAMAccountName=mvesela' in again, False)
    isemon.CONFIG['debug_ldap'] = 1
    isemon.close_log()
    isemon.open_log(Path(folder) / 'd.log')


    title('What the directory itself says about the accounts in the logs')
    # Read only, and the one thing this program asks Active Directory that is
    # not about signing somebody in. Four questions a domain cannot answer
    # from a log: which accounts a service runs as, which have their
    # pre-authentication off on purpose, which are switched off altogether,
    # and who is in the groups that run the domain.
    as_plain()
    isemon.CONFIG.update({'winsec': 1, 'winsec_directory': 1,
                          'winsec_directory_h': 24})
    store.set_meta('directory_facts', '')
    daemon._facts_at = 0
    # Asked directly as well as through the fold, because the two names for
    # these were once the same name and one silently replaced the other.
    ok('a whole domain can be asked, and it is not the per-entry reader',
       sorted(daemon.domain_facts('directory')) != [], True)
    said = daemon.what_directory_says(force=True)
    ok('the directory was asked', said['asked'], True)
    ok('...and it says which directory answered',
       [w['which'] for w in said['where']], ['directory'])
    ok('...and when', bool(said['at']), True)
    ok('...and it answered all four questions',
       sorted(k for k in ('service', 'nopreauth', 'disabled', 'privileged')
              if k in said), ['disabled', 'nopreauth', 'privileged', 'service'])
    # ...and, where the mock puts somebody in one, who is in a group that
    # runs the domain. Asked the way Active Directory is asked - "who is in
    # this group, through groups inside it" - which is the other way round
    # from the question the sign-in asks.
    mockldap.GROUPS.setdefault('CN=Domain Admins,OU=Groups,DC=corpnet,DC=loc',
                               {'cn': ['Domain Admins'],
                                'sAMAccountName': ['Domain Admins'],
                                'objectClass': ['top', 'group'],
                                'distinguishedName':
                                    ['CN=Domain Admins,OU=Groups,DC=corpnet,DC=loc']})
    mockldap.move('pkolar', 'CN=Domain Admins,OU=Groups,DC=corpnet,DC=loc')
    store.set_meta('directory_facts', '')
    daemon._facts_at = 0
    said = daemon.what_directory_says(force=True)
    ok('...and who is in the groups that run the domain',
       'pkolar' in said['privileged'], True)
    # A group whose question fails this time is a group nothing new is known
    # about - not one that was emptied overnight.
    real_chain = isemon.ldap_in_chain

    def broken_chain(*a, **k):
        raise OSError('the controller dropped the connection')
    isemon.ldap_in_chain = broken_chain
    daemon._facts_at = 0
    try:
        said = daemon.what_directory_says(force=True)
    finally:
        isemon.ldap_in_chain = real_chain
    where = said['where'][0]
    ok('a group that could not be asked keeps who was known to be in it',
       'pkolar' in (where.get('groups') or {}).get('domain admins', []), True)
    ok('...and is said to be unread rather than emptied',
       'domain admins' in (store.meta_json('directory_facts', None) or {}).get(
           'groups_unread', []), True)

    title('...and it is a switch, off as well as on')
    isemon.CONFIG['winsec_directory'] = 0
    daemon._facts_at = 0
    off = daemon.what_directory_says(force=True)
    ok('switched off, nothing is asked', off['asked'], False)
    ok('...and the page is told so, rather than told nothing',
       (off['on'], daemon.directory_state()['on']), (False, False))
    isemon.CONFIG['winsec_directory'] = 1
    daemon._facts_at = 0

    title('...and a directory that will not answer is said, not faked')
    # Four noughts read as "the domain has no service accounts and nobody
    # runs it". A failure wrote the clock that says when it last ANSWERED,
    # so the page said it had answered a moment ago with nothing in it.
    was_port = isemon.CONFIG['directory_port']
    isemon.CONFIG['directory_port'] = 1
    store.set_meta('directory_facts', '')
    daemon._facts_at = 0
    dead = daemon.what_directory_says(force=True)
    ok('a directory that cannot be reached did not answer', dead['asked'], False)
    ok('...and the page is told why', bool(dead['trouble']), True)
    ok('...and nothing pretends to be an answer', dead['at'], 0.0)
    # ...and it is not knocked on again on every question the page asks.
    kept = store.meta_json('directory_facts', {}) or {}
    ok('...and when it was last knocked on is written down', bool(kept.get('tried')), True)
    ok('...while when it last ANSWERED is not', float(kept.get('at') or 0), 0.0)
    isemon.CONFIG['directory_port'] = was_port
    store.set_meta('directory_facts', '')
    daemon._facts_at = 0
    ok('...and once it is back, it answers again',
       daemon.what_directory_says(force=True)['asked'], True)

    title('...and the button asks again rather than throttling itself')
    # What went wrong on a real site: the button cleared the clock that says
    # when the directory last ANSWERED and left the one that says when this
    # last KNOCKED - so it threw away the last answer and then refused to go
    # and get another for fifteen minutes. The page said "nothing has
    # answered yet" and not one LDAP query was made.
    daemon._facts_at = 0
    first = daemon.what_directory_says(force=True)
    ok('it answered once', first['asked'], True)
    was_at = float((store.meta_json('directory_facts', {}) or {}).get('at') or 0)
    ok('...and wrote down when', bool(was_at), True)
    # Straight away again, without forcing: neither clock has run out.
    daemon._facts_at = 0
    daemon.what_directory_says()
    ok('...and asking again at once does not knock again',
       float((store.meta_json('directory_facts', {}) or {}).get('at') or 0), was_at)
    # ...and the button, which forces both.
    time.sleep(1.1)
    daemon.ask_directory_now()
    ok('...while the button does knock again',
       float((store.meta_json('directory_facts', {}) or {}).get('at') or 0) > was_at, True)

    title('...and with the LDAP debug on, those searches are in the log')
    # The other half of what was reported: the debug switch was on, the LDAP
    # switch was on, and there was not one line about a query in the log -
    # because nothing was being asked at all.
    facts_log = Path(folder) / 'facts.log'
    isemon.close_log()
    isemon.open_log(facts_log)
    isemon.CONFIG.update({'debug': 1, 'debug_ldap': 1})
    daemon.ask_directory_now()
    isemon.CONFIG['debug'] = 0
    wrote_facts = facts_log.read_text(encoding='utf-8', errors='replace')
    isemon.close_log()
    isemon.open_log(Path(folder) / 'd.log')
    ok('the search for the service accounts is in the log',
       'servicePrincipalName=*' in wrote_facts, True)
    ok('...and the one for pre-authentication, bit and all',
       '1.2.840.113556.1.4.803:=4194304' in wrote_facts, True)
    ok('...and the one for the accounts that are switched off',
       '1.2.840.113556.1.4.803:=2' in wrote_facts, True)
    ok('...and the walk of the groups that run the domain',
       '1.2.840.113556.1.4.1941' in wrote_facts, True)
    ok('...each with how many entries came back',
       ('entries in' in wrote_facts or 'entry in' in wrote_facts), True)
    ok('...and the line that says what it all came to',
       'the directory answered' in wrote_facts, True)
    ok('...and never a password', 'the-service-password' in wrote_facts, False)

    title('...and an answer with nothing in it is not an answer')
    # What a real site was left with. An earlier version wrote the clock that
    # says "it answered" when the asking had FAILED, so the page said the
    # directory had answered and knew of no service accounts at all, the
    # daily clock said there was no need to ask again, and the button could
    # not get past either. Every domain has service accounts - krbtgt alone
    # has a service principal name - so four empty lists mean the asking did
    # not work, whatever clock is written beside them.
    store.set_meta('directory_facts', json.dumps(
        {'at': time.time(), 'service': [], 'nopreauth': [],
         'disabled': [], 'privileged': []}))
    daemon._facts_at = 0
    mended = daemon.what_directory_says()
    ok('a stored answer holding nothing is asked again at once',
       mended['asked'], True)
    ok('...and this time it holds something',
       any(mended[k] for k in ('service', 'nopreauth', 'disabled', 'privileged')), True)
    # ...but a directory that was knocked on a minute ago is left alone all
    # the same, or a domain that is down is a socket every twenty seconds.
    store.set_meta('directory_facts', json.dumps(
        {'at': time.time(), 'tried': time.time(), 'service': [],
         'nopreauth': [], 'disabled': [], 'privileged': []}))
    daemon._facts_at = 0
    ok('...while one knocked on a moment ago is left alone',
       daemon.what_directory_says()['asked'], False)
    store.set_meta('directory_facts', '')
    daemon._facts_at = 0
    daemon.what_directory_says(force=True)

    title('...and it reads the shape of the domain, not just its accounts')
    # The question this answers: what did switching it on actually add?
    # Four counts is what it knows; this is what it says. After how many
    # wrong passwords the domain locks an account, what it will accept as
    # encryption, which other domains it trusts, which machines are its
    # controllers and who is in each group that runs it - none of which is
    # in any log, and all of which changes what a line in one MEANS.
    store.set_meta('directory_facts', '')
    daemon._facts_at = 0
    daemon.what_directory_says(force=True)
    shape = (store.meta_json('directory_facts', {}) or {}).get('shape') or {}
    ok('it read the domain object itself', shape.get('base'), 'DC=corpnet,DC=loc')
    ok('...and how many wrong passwords lock an account', shape.get('lock_after'), 5)
    ok('...and for how long', int(shape.get('lock_for_s') or 0), 1800)
    ok('...and over what window', int(shape.get('lock_window_s') or 0), 1800)
    ok('...and the shortest password it will take', shape.get('password_least'), 8)
    ok('...and whether complexity is required', shape.get('password_complex'), True)
    ok('...and how long a password lasts',
       round((shape.get('password_age_s') or 0) / 86400.0), 90)
    ok('...and how many machines an account may join', shape.get('machines_each'), 10)
    ok('...and what the domain is running as', shape.get('level_words'),
       'Windows 2016 or later')
    ok('...and which machines it says are its controllers',
       [c['name'] for c in shape.get('controllers') or []], ['dc01.corpnet.loc'])
    ok('...and what they are running',
       'Windows Server 2022' in (shape.get('controllers') or [{}])[0].get('os', ''), True)
    ok('...and which other domains it trusts',
       [t['with'] for t in shape.get('trusts') or []], ['corpnettech.loc'])
    ok('...and which way round', (shape.get('trusts') or [{}])[0].get('way'), 'both ways')
    ok('...and that it reaches across the forest',
       (shape.get('trusts') or [{}])[0].get('forest'), True)
    ok('...and the top of its tree, one level down and no further',
       sorted(shape.get('top') or []), ['Groups', 'People', 'Service'])
    ok('...and the sites the forest is divided into',
       sorted(shape.get('sites') or []), ['Hometown', 'Prostejov'])
    ok('...and which address ranges belong to which',
       sorted((one['range'], one['site']) for one in shape.get('subnets') or []),
       [('172.29.11.0/24', 'Hometown'), ('172.30.0.0/16', 'Prostejov')])
    ok('...which is read from beside the domain, not inside it',
       isemon.dn_forest_root('OU=People,DC=corpnet,DC=loc'), 'DC=corpnet,DC=loc')
    ok('...and a policy that covers some accounts rather than all of them',
       [(p['name'], p['lock_after']) for p in shape.get('extra_policies') or []],
       [('Admins PSO', '3')])
    ok('...and who is in each group that runs the domain, group by group',
       'pkolar' in ((store.meta_json('directory_facts', {}) or {})
                    .get('groups', {}).get('domain admins') or []), True)

    title('...and a domain bigger than one page is read whole')
    # Active Directory hands back its MaxPageSize - a thousand on an ordinary
    # domain - and says nothing about the rest. Asked without paging, a
    # domain with four thousand service accounts had a thousand of them read
    # and three thousand quietly missing, with nothing anywhere saying so.
    for _n in range(mockldap.MAX_PAGE * 2 + 40):
        mockldap.PEOPLE['CN=svc%04d,OU=Service,DC=corpnet,DC=loc' % _n] = {
            'sAMAccountName': ['svc%04d' % _n],
            'objectClass': ['top', 'person', 'user'],
            'servicePrincipalName': ['HTTP/svc%04d.corpnet.loc' % _n],
            'memberOf': [],
        }
    store.set_meta('directory_facts', '')
    daemon._facts_at = 0
    big = daemon.what_directory_says(force=True)
    kept = store.meta_json('directory_facts', {}) or {}
    ok('every page of them was read, not the first',
       kept.get('service_n') > mockldap.MAX_PAGE, True)
    ok('...all of them', kept.get('service_n'), mockldap.MAX_PAGE * 2 + 40)
    ok('...and the one at the far end is known',
       'svc%04d' % (mockldap.MAX_PAGE * 2 + 39) in big['service'], True)

    title('...and one bigger than anybody would carry says so')
    was_keep = isemon.Daemon.FACTS_KEEP
    isemon.Daemon.FACTS_KEEP = 20
    try:
        store.set_meta('directory_facts', '')
        daemon._facts_at = 0
        daemon.what_directory_says(force=True)
        kept = store.meta_json('directory_facts', {}) or {}
        ok('the names stop at what is worth carrying', len(kept.get('service') or []), 20)
        ok('...while the count is the domain\u2019s own',
           kept.get('service_n'), mockldap.MAX_PAGE * 2 + 40)
        ok('...and it is said which of them were cut short',
           'service' in (kept.get('cut') or []), True)
        ok('...and the page is handed the real number',
           [w['counts']['service'] for w in daemon.directory_state()['where']
            if w['which'] == 'directory'], [mockldap.MAX_PAGE * 2 + 40])
    finally:
        isemon.Daemon.FACTS_KEEP = was_keep
        for _n in range(mockldap.MAX_PAGE * 2 + 40):
            mockldap.PEOPLE.pop('CN=svc%04d,OU=Service,DC=corpnet,DC=loc' % _n, None)
        store.set_meta('directory_facts', '')
        daemon._facts_at = 0
        daemon.what_directory_says(force=True)

    title('...and that rule is what an alarm is weighed against')
    # "A hundred refusals against one account" reads one way on a domain that
    # locks after five and quite another on a domain that never locks.
    facts = daemon.what_directory_says()
    ok('the domain\u2019s own lockout rule is carried to the reading',
       facts.get('lock_after'), 5)
    made = {'kind': 'brute', 'who': 'pkolar', 'level': 'warn', 'reads': []}
    daemon.ask_the_directory(made, facts, store, time.time() - 3600, '')
    ok('...and the alarm says what will happen next',
       any('locks an account after 5' in w for w in made['reads']), True)
    # ...and a domain that does NOT lock is the one worth saying out loud.
    loose = dict(facts, lock_after=0)
    other = {'kind': 'brute', 'who': 'pkolar', 'level': 'warn', 'reads': []}
    daemon.ask_the_directory(other, loose, store, time.time() - 3600, '')
    ok('...while a domain that never locks is said out loud',
       any('does NOT lock' in w for w in other['reads']), True)
    ok('...and that makes the alarm worse', other['level'], 'crit')

    title('...and a page never goes and knocks')
    # Thirty-odd searches of somebody else's domain controller, on the thread
    # that is drawing a page, is a page that waits for a domain controller.
    daemon._facts_at = 0
    ok('there is something stored to draw',
       daemon.what_directory_says(force=True)['asked'], True)
    was_port2 = isemon.CONFIG['directory_port']
    isemon.CONFIG['directory_port'] = 1                  # nothing is listening
    knocked = []
    real_reader = daemon.directory_reader
    daemon.directory_reader = lambda *a, **k: (knocked.append(1) or real_reader(*a, **k))
    daemon._facts_at = 0
    state = daemon.directory_state()
    daemon.directory_reader = real_reader
    isemon.CONFIG['directory_port'] = was_port2
    ok('drawing the page opened nothing at all', knocked, [])
    ok('...and it still says what was last found',
       (state['on'], state['asked']), (True, True))

    title('...and what the page draws of it is counts, never names')
    state = daemon.directory_state()
    ok('it says whether there is a directory at all', state['any'], True)
    ok('...whether it is being asked', state['on'], True)
    ok('...how often', state['every_h'], 24)
    ok('...and how much each answer held, as a number',
       all(isinstance(state[k], int)
           for k in ('service', 'nopreauth', 'disabled', 'privileged')), True)
    ok('...with no account name anywhere in it',
       'jnovak' in json.dumps(state), False)
    isemon.CONFIG['winsec'] = 0


    title('...and an alarm is weighed by what the directory says the account is')
    # The whole point of being joined to it. A service ticket asked for in
    # RC4 is what taking a service password away to crack looks like - but
    # only if the account it names IS a service account, and no log anywhere
    # says which are. That is one small read of the directory, and it is the
    # difference between waking somebody and not.
    isemon.CONFIG.update({'winsec': 1, 'winsec_directory': 1,
                          'winsec_machines': 1, 'winsec_ignore': ''})
    when_rc4 = time.strftime('%b %d %H:%M:%S', time.localtime(time.time() - 60))
    TICKET = ('A Kerberos service ticket was requested.  Account Information:  '
              'Account Name:  %s@CORPNET.LOC  Account Domain:  CORPNET.LOC  '
              'Service Information:  Service Name:  MSSQLSvc/db1  '
              'Network Information:  Client Address:  ::ffff:10.0.0.44  '
              'Client Port:  51000  Additional Information:  Ticket Options:  0x40810000  '
              'Ticket Encryption Type:  0x17  Failure Code:  0x0  Transited Services:  -')
    daemon.read_records(
        ['%s bdcx01 WinSecurity: EventID=4769 | %s' % (when_rc4, TICKET % 'pkolar')
         for _n in range(6)], 'winsec')
    daemon.flush_win_events()

    def rc4_says():
        daemon._facts_at = 0
        store.set_meta('directory_facts', '')
        out = [one for one in daemon.win_incidents(time.time() - 3600, None)
               if one['kind'] == 'rc4']
        return (' '.join(' '.join(one.get('reads') or []) for one in out),
                (out[0]['level'] if out else ''))

    # As the directory has it now: pkolar runs nothing, so this is far more
    # likely an old application than anybody fishing - and the alarm says so
    # instead of leaving somebody to find out.
    words, level = rc4_says()
    ok('the alarm carries what the directory said',
       'none of these is a service account' in words, True)
    ok('...and it is not made worse for it', level, 'warn')
    # ...and with the same account made a service account in the directory,
    # the same six tickets mean something else entirely.
    for dn, one in mockldap.PEOPLE.items():
        if (one.get('sAMAccountName') or [''])[0].lower() == 'pkolar':
            one['servicePrincipalName'] = ['MSSQLSvc/db1.corpnet.loc:1433']
    words, level = rc4_says()
    ok('...and when the directory says it IS one, the alarm says that',
       'is a service account' in words, True)
    ok('...and says which account it was about', 'pkolar' in words, True)
    ok('...and the alarm is made worse for it', level, 'crit')
    # ...and the alarm is about THOSE accounts, not about every account
    # behind the mark. A card that counts two hundred events, names three
    # accounts in its own sentence and then opens all two hundred is a card
    # that sends somebody looking for the three by eye.
    when_rc4b = time.strftime('%b %d %H:%M:%S', time.localtime(time.time() - 50))
    daemon.read_records(
        ['%s bdcx01 WinSecurity: EventID=4769 | %s' % (when_rc4b, TICKET % 'edvorak')
         for _n in range(4)], 'winsec')
    daemon.flush_win_events()

    def opens(one):
        """What pressing this alarm actually opens - the same filters the
        page passes, asked of the same rows."""
        w = dict(one.get('where') or {})
        over = w.pop('machines', None)
        _rows, total = store.win_rows(
            limit=1, since=time.time() - 3600, kind=w.get('kind', ''),
            account=w.get('account', ''), ip=w.get('ip', ''),
            machine=w.get('machine', ''), accounts=w.get('accounts', ''),
            mark=w.get('mark', ''), unmark=w.get('not', ''),
            routine=False if w.get('routine') == '0' else None,
            dead=w.get('dead') == '1',
            machines=None if over else None)
        return total

    daemon._facts_at = 0
    store.set_meta('directory_facts', '')
    # The breakdown behind an alarm is kept for half a minute, and these
    # rows were written a moment ago: the same thing the daemon does when it
    # knows the answer has moved.
    daemon.forget_held('win-by-account/')
    alarms = daemon.win_incidents(time.time() - 3600, None)
    rc4 = [one for one in alarms if one['kind'] == 'rc4']
    ok('the alarm counts only the accounts it is about', [one['n'] for one in rc4], [6])
    ok('...and says which they are, so that pressing it opens those',
       'pkolar' in str((rc4[0].get('where') or {}).get('accounts') or ''), True)
    ok('...and not the ones the directory says are nobody',
       'edvorak' in str((rc4[0].get('where') or {}).get('accounts') or ''), False)
    # The rule, for every alarm on the page rather than for this one: what a
    # card counts and what pressing it opens are one question asked twice.
    ok('every alarm opens exactly what it counted',
       [one['kind'] for one in alarms if opens(one) != one['n']], [])

    # ...and with the reading switched off it says nothing of the sort, which
    # is the state every site was in until this was found.
    isemon.CONFIG['winsec_directory'] = 0
    daemon._facts_at = 0
    quiet = ' '.join(
        ' '.join(one.get('reads') or []) for one in
        daemon.win_incidents(time.time() - 3600, None) if one['kind'] == 'rc4')
    ok('...and with the directory not being asked, it says nothing of the sort',
       'The directory says' in quiet, False)
    isemon.CONFIG.update({'winsec_directory': 1, 'winsec': 0, 'winsec_machines': 0})


    title('Two domains read into one of these are two domains')
    # A site can send the logs of the controllers of TWO domains here - a
    # main one and a test one, a merger, a forest with two of them. The same
    # name in both is TWO accounts: they can be in different groups, and one
    # of them can run the domain while the other is nobody. Folded into one
    # set, what one domain said about a name was being applied to the other
    # domain's events.
    spec2 = importlib.util.spec_from_file_location('mockldap3', str(HERE / 'mockldap.py'))
    second = importlib.util.module_from_spec(spec2)
    sys.modules['mockldap3'] = second
    spec2.loader.exec_module(second)
    second.PEOPLE = {
        'CN=Big,OU=People,DC=two,DC=loc': {
            'sAMAccountName': ['shared'],
            'objectClass': ['top', 'person', 'user'],
            'userAccountControl': ['512'],
            'memberOf': ['CN=Domain Admins,OU=Groups,DC=two,DC=loc'],
            '_password': 'the-other-reading-password',
        },
        'CN=reader,OU=Service,DC=two,DC=loc': {
            'sAMAccountName': ['reader'],
            'objectClass': ['top', 'person', 'user'],
            'memberOf': [],
            '_password': 'the-other-reading-password',
        },
    }
    second.GROUPS = {
        'CN=Domain Admins,OU=Groups,DC=two,DC=loc': {
            'cn': ['Domain Admins'], 'sAMAccountName': ['Domain Admins'],
            'objectClass': ['top', 'group'],
            'distinguishedName': ['CN=Domain Admins,OU=Groups,DC=two,DC=loc'],
            'member': ['CN=Big,OU=People,DC=two,DC=loc'],
        },
    }
    # ...and a domain of its own that locks after three rather than five.
    second.DOMAIN = {
        'DC=two,DC=loc': dict(mockldap.DOMAIN['DC=corpnet,DC=loc'],
                              lockoutThreshold=['3'], name=['two']),
    }
    # A forest of its own, so that its alternative name suffixes are not the
    # first domain's. Both mocks are the same file and would otherwise claim
    # the same ones, which is itself a thing this has to get right.
    second.PARTITIONS = dict(second.PARTITIONS,
                             uPNSuffixes=['two.cz'], dnsRoot=['two.loc'])
    second.TRUSTS = {}
    second.TREE = {}
    second.CONTROLLERS = {}
    second.POLICIES = {}
    two_port, two_stop = second.serve()
    time.sleep(0.3)
    was2 = {k: isemon.CONFIG.get(k) for k in
            ('directory2', 'directory2_host', 'directory2_port', 'directory2_tls',
             'directory2_base', 'directory2_bind', 'directory2_password',
             'directory2_realms')}
    try:
        as_plain()
        isemon.CONFIG.update({
            'winsec': 1, 'winsec_directory': 1,
            'directory2': 1, 'directory2_host': '127.0.0.1',
            'directory2_port': two_port, 'directory2_tls': 'none',
            'directory2_base': 'DC=two,DC=loc',
            'directory2_bind': 'CN=reader,OU=Service,DC=two,DC=loc',
            'directory2_password': 'the-other-reading-password',
            'directory2_realms': ''})
        # The same name in both, and only the SECOND one runs its domain.
        for _dn, _one in mockldap.PEOPLE.items():
            if (_one.get('sAMAccountName') or [''])[0].lower() == 'nogroups':
                _one['sAMAccountName'] = ['shared']
        store.set_meta('directory_facts', '')
        store.set_meta('directory2_facts', '')
        daemon._facts_at = 0
        facts = daemon.what_directory_says(force=True)

        ok('both domains were asked',
           sorted(w['which'] for w in facts['where']), ['directory', 'directory2'])
        ok('...and each is kept under its own name',
           ('corpnet.loc' in facts['by_domain'], 'two.loc' in facts['by_domain']),
           (True, True))
        ok('...and under the flat name an event writes too',
           ('corpnet' in facts['by_domain'], 'two' in facts['by_domain']), (True, True))
        ok('the name runs the SECOND domain',
           'shared' in daemon.facts_for(facts, 'two.loc')['privileged'], True)
        ok('...and not the first',
           'shared' in daemon.facts_for(facts, 'corpnet.loc')['privileged'], False)
        ok('...however the event spells the domain',
           'shared' in daemon.facts_for(facts, 'TWO')['privileged'], True)
        ok('...while an event that does not say falls back to everything known',
           'shared' in daemon.facts_for(facts, '')['privileged'], True)

        title('...and an alarm is weighed against the domain it happened in')
        one = {'kind': 'brute', 'who': 'shared', 'domain': 'TWO', 'level': 'warn',
               'reads': []}
        daemon.ask_the_directory(one, facts, store, time.time() - 3600, '')
        ok('in the domain where it runs things, the alarm says so',
           any('runs the domain' in w for w in one['reads']), True)
        ok('...and is made worse for it', one['level'], 'crit')
        other = {'kind': 'brute', 'who': 'shared', 'domain': 'CORPNET', 'level': 'warn',
                 'reads': []}
        daemon.ask_the_directory(other, facts, store, time.time() - 3600, '')
        ok('...and in the domain where it is nobody, it does not',
           any('runs the domain' in w for w in other['reads']), False)
        ok('...and the alarm is left where it was', other['level'], 'warn')

        title('...and each domain\u2019s own lockout rule is the one used')
        ok('the first domain locks after five',
           daemon.facts_for(facts, 'corpnet.loc')['lock_after'], 5)
        ok('...and the second after three',
           daemon.facts_for(facts, 'two.loc')['lock_after'], 3)
        ok('...and an alarm in the second says three',
           any('after 3 wrong password' in w for w in one['reads']), True)
        ok('...while one in the first says five',
           any('after 5 wrong password' in w for w in other['reads']), True)
    finally:
        two_stop.set()
        isemon.CONFIG.update(was2)
        isemon.CONFIG['winsec'] = 0
        store.set_meta('directory2_facts', '')
        daemon._facts_at = 0

finally:
    # -----------------------------------------------------------------------
    title('Nothing arrives in the clear after StartTLS is agreed')
    # Whatever sat in the read buffer when the connection was made secure used
    # to be read back afterwards as if it had come over TLS - so somebody on
    # the path could append a forged "bind succeeded" to the server's reply
    # and the next person to sign in would be let in with any password.
    as_plain()
    link = isemon.Ldap('127.0.0.1', plain_port, tls='none', timeout=5)
    link.connect() if hasattr(link, 'connect') else None
    # Stand in for the wire: a StartTLS reply with a forged bind response
    # glued on behind it.
    class _Wire(object):
        def __init__(self, data): self.data = data
        def recv(self, n): out, self.data = self.data[:n], self.data[n:]; return out
        def sendall(self, b): pass
        def settimeout(self, t): pass
        def close(self): pass
    ok_result = isemon._ber(0x0A, b'\x00') + isemon._ber_str('') + isemon._ber_str('')
    tls_reply = isemon._ber(0x30, isemon._ber_int(1) + isemon._ber(0x78, ok_result))
    forged = isemon._ber(0x30, isemon._ber_int(2) + isemon._ber(0x61, ok_result))
    link.sock = _Wire(tls_reply + forged)
    link.buffer = b''
    link.next_id = 1
    link._wrap = lambda sock: sock
    try:
        link._start_tls()
        ok('a StartTLS reply with bytes glued on behind it is refused', False, True)
    except isemon.LdapError as e:
        ok('a StartTLS reply with bytes glued on behind it is refused',
           'in the clear after agreeing to TLS' in str(e), True)
    ok('...and nothing of it is left to be read as if it were secure',
       link.buffer, b'')
    # ...and the honest case still works: a reply and nothing after it.
    link.sock = _Wire(tls_reply)
    link.buffer = b''
    link.next_id = 1
    try:
        link._start_tls()
        ok('...while a clean StartTLS reply is taken', True, True)
    except Exception as e:
        ok('...while a clean StartTLS reply is taken', str(e), 'no error')
    ok('only StartTLS may be sent as an extended operation',
       isemon.Ldap.START_TLS_OID, '1.3.6.1.4.1.1466.20037')
    try:
        link.sock = _Wire(b'')
        link._send(isemon._ber(0x77, isemon._ber_str('1.3.6.1.4.1.4203.1.11.1', tag=0x80)))
        ok('...and a password-change extended operation is not', False, True)
    except isemon.LdapError as e:
        ok('...and a password-change extended operation is not',
           'not StartTLS' in str(e), True)

    # -----------------------------------------------------------------------
    title('A filter carries a name exactly as it is, because it goes as BER')
    # RFC 4515 escaping is for filters written as text. These are built as
    # BER, where the value goes as raw bytes - so escaping corrupted it, and a
    # user whose distinguished name has a comma in it (`CN=Novak\, Jan`) was
    # never found inside a nested group.
    ber = isemon.ldap_equal('sAMAccountName', 'a(b)c*')
    ok('brackets and a star go on the wire as themselves', b'a(b)c*' in ber, True)
    ok('...not escaped', b'\\28' in ber, False)
    chain = isemon.ldap_in_chain('member', 'CN=Novak\\, Jan,OU=Users,DC=corpnet,DC=loc')
    ok('...and a DN with an escaped comma stays an escaped comma',
       b'CN=Novak\\, Jan,' in chain and b'\\5c' not in chain, True)
    ok('the program no longer escapes into a BER filter',
       [n for n, line in enumerate(open(HERE.parent / 'isemon.py', encoding='utf-8'))
        if 'ldap_escape(' in line and not line.strip().startswith('#')
        and 'def ldap_escape' not in line], [])

    # -----------------------------------------------------------------------
    title('A search cut short at the page limit is the rows it read, not nothing')
    was_most = isemon.Ldap.PAGES_MOST
    isemon.Ldap.PAGES_MOST = 2
    try:
        mockldap.make_groups(1000)
        rows = daemon.directory_group_list(like='', limit=None)
        ok('two pages\u2019 worth comes back rather than None',
           isinstance(rows, list) and len(rows) > 0, True)
        ok('...and it is not the whole thousand, because it was cut short',
           len(rows) < 1000, True)
    finally:
        isemon.Ldap.PAGES_MOST = was_most
        mockldap.make_groups(0)

    ok('the smart-card flag is the smart-card bit',
       [bit for bit, words, _ in isemon.Daemon.UAC_BITS if words == 'smart card required'],
       [0x040000])

    plain_stop.set()
    shutil.rmtree(folder, ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
