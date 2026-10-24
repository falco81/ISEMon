#!/usr/bin/env python3
"""What the Windows domain controllers saw, read the way this program reads it.

A domain controller's Security log is not an authentication log in the sense
the rest of this program means: nothing in it is ever judged and nothing in it
can earn anybody a ban. It is here because half of what a VPN refusal means is
written on a controller and nowhere else - whether the account was locked, from
which machine the bad password came, which program had the old one saved.

The lines below are the real shapes, as NXLog actually ships them: one event a
line, with every newline and tab in the Windows event turned into spaces. That
flattening is the whole difficulty - the only thing between one field and the
next is a run of spaces, and a value may hold spaces, colons and the name of
the next field.

    ./test/domain.py
"""
import json
import shutil
import sys
import threading
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import isemon                                        # noqa: E402

DAEMON_SRC = (HERE.parent / 'isemon.py').read_text(encoding='utf-8')
PAGE_SRC = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')

PASS = FAIL = 0


def ok(what, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print('  ok    %s' % what)
    else:
        FAIL += 1
        print('  FAIL  %s\n          got  %r\n          want %r' % (what, got, want))


def title(words):
    print('\n%s' % words)


def fresh():
    folder = tempfile.mkdtemp(prefix='isemon-win-')
    isemon.STATE_DIR = Path(folder)
    isemon.DB_FILE = Path(folder) / 'win.db'
    isemon.BACKUP_DIR = Path(folder) / 'backups'
    isemon.DUMP_DIR = Path(folder) / 'dumps'
    isemon.RUN_DIR = Path(folder)
    isemon.LOG_DIR = Path(folder)
    isemon._LOG_PATH = Path(folder) / 'win.log'
    isemon.CONFIG.update({
        'blacklist': 0, 'geo': 0, 'mikrotik_host': '', 'debug': False,
        'ise': 0, 'ise_paths': [str(Path(folder) / 'nothing')],
        'winsec': 1, 'winsec_ignore': '', 'winsec_machines': 0,
        'winsec_paths': [str(Path(folder) / 'dc1')],
        'winsec_name': 'WinSecurity.log', 'winsec_zone': '',
    })
    store = isemon.Storage(isemon.DB_FILE)
    daemon = isemon.Daemon(store)
    return folder, store, daemon


NOW = time.time()


def when(off=0):
    return time.strftime('%b %d %H:%M:%S', time.localtime(NOW - off))


def line(host, event, rest, off=0):
    return '%s %s WinSecurity: EventID=%d | %s' % (when(off), host, event, rest)


# The real shapes, taken from three controllers of a live domain.
SIGNED_IN = (
    'An account was successfully logged on.  Subject:  Security ID:  S-1-0-0  '
    'Account Name:  -  Account Domain:  -  Logon ID:  0x0  Logon Information:  '
    'Logon Type:  3  Restricted Admin Mode: -  Virtual Account:  No  '
    'Elevated Token:  Yes  Impersonation Level:  Impersonation  New Logon:  '
    'Security ID:  S-1-5-21-1345087706-903693047-1615293757-7642  '
    'Account Name:  APPSRV01$  Account Domain:  CORP-EXAMPLE.INT  '
    'Logon ID:  0x747CD851  Linked Logon ID:  0x0  Network Account Name: -  '
    'Network Account Domain: -  Logon GUID:  {F27DD9AE-1694-98B3-4A95-8B07A6DD8670}  '
    'Process Information:  Process ID:  0x0  Process Name:  -  '
    'Network Information:  Workstation Name: -  Source Network Address: 172.29.152.66  '
    'Source Port:  52492  Detailed Authentication Information:  '
    'Logon Process:  Kerberos  Authentication Package: Kerberos  '
    'Transited Services: -  Package Name (NTLM only): -  Key Length:  0  '
    'This event is generated when a logon session is created.')
# The compact shape, whose fields are one space apart rather than two. It is
# what made a splitter that cuts on whitespace useless.
CHECKED = ('The computer attempted to validate the credentials for an account.  '
           'Authentication Package: MICROSOFT_AUTHENTICATION_PACKAGE_V1_0 '
           'Logon Account: firepower Source Workstation: BDCX02 Error Code: 0x0')
KERBEROS_NO = (
    'Kerberos pre-authentication failed.  Account Information:  '
    'Security ID:  S-1-5-21-1345087706-903693047-1615293757-37798  '
    'Account Name:  pdf  Service Information:  Service Name:  krbtgt/CORP-EXAMPLE.INT  '
    'Network Information:  Client Address:  ::ffff:172.29.11.7  Client Port:  62746  '
    'Additional Information:  Ticket Options:  0x40810010  Failure Code:  0x18  '
    'Pre-Authentication Type: 2  Certificate Information:  Certificate Issuer Name:    '
    'Certificate information is only provided if a certificate was used.')
LOCKED = (
    'A user account was locked out.  Subject:  Security ID:  S-1-5-18  '
    'Account Name:  DCX01$  Account Domain:  CORP-EXAMPLE  Logon ID:  0x3E7  '
    'Account That Was Locked Out:  Security ID:  S-1-5-21-1-2-3-4  '
    'Account Name:  novak  Additional Information:  Caller Computer Name:  NB-NOVAK')
REFUSED = (
    'An account failed to log on.  Subject:  Security ID:  S-1-0-0  '
    'Account Name:  -  Logon ID:  0x0  Account For Which Logon Failed:  '
    'Security ID:  S-1-0-0  Account Name:  novak  Account Domain:  CORP-EXAMPLE  '
    'Failure Information:  Failure Reason:  Unknown user name or bad password.  '
    'Status:   0xC000006D  Sub Status:  0xC000006A  Process Information:  '
    'Caller Process Name: C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE  '
    'Network Information:  Workstation Name: NB-NOVAK  Source Network Address: 172.29.40.11  '
    'Source Port:  51118  Detailed Authentication Information:  Logon Process:  NtLmSsp  '
    'Authentication Package: NTLM')
CHANGED = (
    'A directory service object was modified.   Subject:  '
    'Security ID:  S-1-5-21-1-2-3-49734  Account Name:  PVVDI01CONN$  '
    'Account Domain:  CORP-EXAMPLE  Logon ID:  0x74818DD7  Directory Service:  '
    'Name: corp-example.int  Type: Active Directory Domain Services   Object:  '
    'DN: CN=Jan Novak,OU=Users,DC=corp-example,DC=int  GUID: {50F2BF5C}  Class: user   '
    'Attribute:  LDAP Display Name: userAccountControl  Syntax (OID): 2.5.5.9  '
    'Value: 512   Operation:  Type: Value Added  Correlation ID: {1B476B85}')
REPLICATE = (
    'An operation was performed on an object.  Subject :  '
    'Security ID:  S-1-5-21-1-2-3-7712  Account Name:  MSOL_329  '
    'Account Domain:  CORP-EXAMPLE  Logon ID:  0x741FE5CA  Object:  '
    'Object Server:  DS  Object Type:  %{19195a5b-6da0-11d0-afd3-00c04fd930c9}  '
    'Object Name:  %{313dfcec-ae90}  Handle ID:  0x0  Operation:  '
    'Operation Type:  Object Access  Accesses:  Control Access    Access Mask:  0x100  '
    'Properties:  ---  Control Access  {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  '
    '{19195a5b-6da0-11d0-afd3-00c04fd930c9}')
# ...and the same thing asked for by a member server, which is the shape of a
# domain being taken whole rather than of a domain working.
REPLICATE_BAD = REPLICATE.replace('MSOL_329', 'PC-DESK-41$')
BIG_GROUP = (
    'A member was added to a security-enabled global group.  Subject:  '
    'Security ID:  S-1-5-21-1-2-3-500  Account Name:  spravce  '
    'Account Domain:  CORP-EXAMPLE  Logon ID:  0x99  Member:  '
    'Security ID:  S-1-5-21-1-2-3-1111  '
    'Account Name:  CN=Jan Novak,OU=Users,DC=corp-example,DC=int  Group:  '
    'Security ID:  S-1-5-21-1-2-3-512  Group Name:  Domain Admins  '
    'Group Domain:  CORP-EXAMPLE')
CLEARED = ('The audit log was cleared.  Subject:  Security ID:  S-1-5-21-1-2-3-500  '
           'Account Name:  admin.badguy  Domain Name:  CORP-EXAMPLE  Logon ID:  0x12345')


# ---------------------------------------------------------------------------
title('One line of a controller, read')
one = isemon.win_record_from(line('bdcx02', 4624, SIGNED_IN))
ok('a sign-in is read at all', one is not None)
ok('...as the machine it is about, not as the blank subject above it',
   one.facts['account'], 'APPSRV01$')
ok('...and it is known to be a machine', one.facts['is_machine'], 1)
ok('...from the address it came from', one.facts['ip'], '172.29.152.66')
ok('...with the way it signed in', one.facts['logon_type'], '3')
ok('...under the door this program files it in', one.facts['kind'], 'logon')
ok('...and the controller that wrote it', one.facts['server'], 'bdcx02')
ok('...and the paragraph of explanation at the end is not a field',
   any('This event is generated' in str(v) for v in one.facts['fields'].values()), False)
ok('...while the fields that are fields are all there',
   [one.facts['fields'].get(k) for k in ('Subject / Logon ID', 'New Logon / Account Name',
                                         'Detailed Authentication Information / Logon Process')],
   ['0x0', 'APPSRV01$', 'Kerberos'])

# The compact shape. A splitter that cuts on runs of spaces reads
# `Source Workstation: BDCX02 Error Code: 0x0` as one field called
# "DCX02 Error Code", which is why the fields are found by name.
two = isemon.win_record_from(line('bdcx02', 4776, CHECKED))
ok('the compact shape is read field by field', two.facts['account'], 'firepower')
ok('...including the one after a value with no double space',
   two.facts['fields'].get('Source Workstation'), 'BDCX02')
ok('...and the code after that', two.facts['fields'].get('Error Code'), '0x0')
ok('...which is read as what it means', two.facts['said'], 'it worked')

three = isemon.win_record_from(line('dcx01', 4771, KERBEROS_NO))
ok('a Kerberos refusal names the account', three.facts['account'], 'pdf')
ok('...and says why in words rather than in a code',
   three.facts['said'], 'the password was wrong')
ok('...and an IPv4 address written the IPv6 way is written down the one way',
   three.facts['ip'], '172.29.11.7')
ok('...under its own door', three.facts['kind'], 'kerberos-failed')

# ---------------------------------------------------------------------------
title('Whom an event is about, and who did it')
lock = isemon.win_record_from(line('dcx01', 4740, LOCKED))
ok('a lockout is about the account that was locked', lock.facts['account'], 'novak')
ok('...not the controller that noticed it', lock.facts['by'], 'DCX01$')
ok('...and it says which machine the bad password came from',
   lock.facts['machine'], 'NB-NOVAK')
bad = isemon.win_record_from(line('dcx01', 4625, REFUSED))
ok('a refusal is about the account that was refused', bad.facts['account'], 'novak')
ok('...and says why, out of the status code', bad.facts['said'], 'the password was wrong')
ok('...and which program asked', bad.facts['process'].endswith('OUTLOOK.EXE'), True)
ok('...and from which machine', bad.facts['machine'], 'NB-NOVAK')
group = isemon.win_record_from(line('dcx01', 4728, BIG_GROUP))
ok('a group change is about the member that was added',
   group.facts['account'], 'CN=Jan Novak,OU=Users,DC=corp-example,DC=int')
ok('...and says who did it', group.facts['by'], 'spravce')
ok('...and which group it was', group.facts['object'], 'Domain Admins')

# ---------------------------------------------------------------------------
title('What an event was about, in words rather than in GUIDs')
seen = isemon.win_record_from(line('bdcx02', 4662, REPLICATE))
ok('an operation on a directory object says what kind of object',
   seen.facts['object'], 'the directory\u2019s own replication rights')
ok('...and is marked as the thing it is',
   seen.facts['mark'].split(',')[0], 'replication')
said = isemon.win_record_from(line('dcx01', 5136, CHANGED))
ok('a directory change says what was changed and which attribute',
   said.facts['object'],
   'CN=Jan Novak,OU=Users,DC=corp-example,DC=int \u00b7 userAccountControl (value added)')
ok('...and who changed it', said.facts['by'], 'PVVDI01CONN$')
plain = isemon.win_record_from(line('bdcx02', 4662, REPLICATE.replace(
    '{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}', '{aaaaaaaa-0000-0000-0000-000000000000}')))
ok('...and one that is no such thing carries no mark', plain.facts['mark'], '')
ok('...and says what kind of object it was instead',
   plain.facts['object'], 'an operation on the domain itself')

# ---------------------------------------------------------------------------
title('The same event read twice is the same row')
folder, store, daemon = fresh()
where = Path(folder) / 'dc1'
where.mkdir(parents=True, exist_ok=True)
LINES = [line('dcx01', 4625, REFUSED, off=n * 4) for n in range(5)]
LINES += [line('dcx01', 4740, LOCKED, off=1),
          line('bdcx02', 4624, SIGNED_IN, off=30),
          line('bdcx02', 4776, CHECKED, off=40),
          line('dcx01', 4771, KERBEROS_NO, off=50),
          line('dcx01', 5136, CHANGED, off=60),
          line('bdcx02', 4662, REPLICATE, off=70),
          line('bdcx02', 4662, REPLICATE_BAD, off=71),
          line('dcx01', 4728, BIG_GROUP, off=80),
          line('dcx02', 1102, CLEARED, off=90)]
(where / 'WinSecurity.log').write_text('\n'.join(LINES) + '\n')
daemon.restore_tails()
daemon.read_logs()
ok('every line was written down', store.win_size(), len(LINES))
daemon.read_logs()
ok('...and reading the file again adds nothing', store.win_size(), len(LINES))
# The five refusals are the same event five times over, a few seconds apart.
# Five wrong passwords in a row is exactly the thing worth seeing, so they are
# five rows and not one.
same = [l for l in LINES if 'EventID=4625' in l]
(where / 'WinSecurity.log').write_text('\n'.join(same) + '\n')
daemon2 = isemon.Daemon(store)
daemon2.restore_tails()
daemon2.read_logs()
ok('...and the same event at the same second is kept as many times as it happened',
   store.win_rows(kind='logon-failed')[1], 5)
# An event is never an authentication: nothing here may reach the lists the
# banning is made of.
ok('nothing of this is in the refusals the banning counts',
   store.failed_rows(limit=5)[1], 0)
ok('...nor in the sign-ins', store.passed_rows(limit=5)[1], 0)

# The record beside each event is packed, and on a server engine it lives in a
# column whose type the schema decides. Declared the wrong kind of blob it is
# sixty-four bytes, and every record longer than that comes back cut in the
# middle of its compression - readable on the file engine, gone on the others.
title('The record beside an event survives being stored')
long_fields = {'Field %02d' % n: ('a value that is worth compressing %d ' % n) * 8
               for n in range(40)}
store.note_win_event({'ts': NOW, 'server': 'dc1', 'event': 4740, 'kind': 'lockout',
                      'account': 'wide', 'domain': '', 'by': '', 'machine': '', 'ip': '',
                      'logon_type': '', 'process': '', 'service': '', 'object': '',
                      'said': '', 'mark': '', 'ident': 'win/wide/0',
                      'fields': long_fields})
back = store.win_detail('win/wide/0')
ok('a long record comes back whole', len(back['fields']), len(long_fields))
ok('...with its values unchanged',
   back['fields'].get('Field 39'), long_fields['Field 39'])
# ...and again, now that a dictionary has been made out of the first few.
for n in range(12):
    store.note_win_event({'ts': NOW - n, 'server': 'dc1', 'event': 4740, 'kind': 'lockout',
                          'account': 'wide%d' % n, 'domain': '', 'by': '', 'machine': '',
                          'ip': '', 'logon_type': '', 'process': '', 'service': '',
                          'object': '', 'said': '', 'mark': '', 'ident': 'win/wide%d/0' % n,
                          'fields': long_fields})
ok('...and so does one packed against the dictionary the others made',
   store.win_detail('win/wide11/0')['fields'].get('Field 39'), long_fields['Field 39'])
with store.db_write() as db:
    db.execute("DELETE FROM win_events WHERE ident LIKE 'win/wide%'")

# ---------------------------------------------------------------------------
title('A lockout, with what led to it')
locks = store.win_lockouts(NOW - 3600, 5)
ok('the lockout is there', len(locks), 1)
ok('...about the right account', locks[0]['account'], 'novak')
ok('...and the refusals before it came with it', len(locks[0]['before']), 5)
ok('...so the machine is known even where the lock did not say',
   locks[0]['machine'], 'NB-NOVAK')
ok('...and the program that had the old password',
   locks[0]['process'].endswith('OUTLOOK.EXE'), True)

# ---------------------------------------------------------------------------
title('The patterns worth looking at')
got = daemon.win_summary(24, wait=True)
kinds = {one['kind']: one for one in got['incidents']}
ok('the audit log being cleared is the worst of them',
   got['incidents'][0]['kind'], 'cleared')
ok('...and it is said in red', got['incidents'][0]['level'], 'crit')
ok('...and names who did it', got['incidents'][0]['who'], 'admin.badguy')
ok('an account asking to replicate the directory is found', 'replication' in kinds)
# ...and the directory doing its own work is NOT. Two of these events were
# read: one by Entra Connect's own account, which replicates every password
# by design and is in `winsec_expected` out of the box, and one by a desk PC,
# which is the thing worth waking somebody for. Only the second is counted,
# and pressing it opens only the second.
ok('...and only the one that is not the directory itself is counted',
   kinds.get('replication', {}).get('n'), 1)
ok('...and it names the machine that asked rather than the synchroniser',
   kinds.get('replication', {}).get('who'), 'PC-DESK-41$')
ok('...and what it opens leaves the expected ones out',
   kinds.get('replication', {}).get('where'),
   {'mark': 'replication', 'not': 'expected', 'machines': 1})
# ...and the machine accounts are counted for this one whatever the page was
# told. A member server asking to replicate IS a machine account, and the
# tick box that hides the noise of ticket renewals must never hide an alarm.
ok('...and an alarm about a machine account is not hidden by that tick box',
   daemon.win_summary(24, wait=True)["machines_shown"], False)
ok('...and asking for those rows gives exactly the one',
   store.win_rows(mark='replication', unmark='expected')[1], 1)
ok('...while both are still there, read, kept and searchable',
   store.win_rows(mark='replication')[1], 2)
ok('...and a change to a group that runs the domain', 'big-group' in kinds)
ok('none of it claims to have banned anything',
   any('ban' in one['says'].lower() and 'never' not in one['says'].lower()
       for one in got['incidents']), False)
ok('the cards are only the ones with something behind them',
   all(view['rows'] for view in got['views']), True)
people = [v for v in got['views'] if v['key'] == 'people']
ok('the accounts card is there', len(people), 1)
ok('...with the refused account on it',
   [r['said'] for r in people[0]['rows']], ['novak', 'pdf'])
ok('...and the newest attempt beside it, so the row says something',
   (people[0]['rows'][0]['newest'].get('machine'),
    people[0]['rows'][0]['newest'].get('said')),
   ('NB-NOVAK', 'the password was wrong'))

# ---------------------------------------------------------------------------
title('The machine accounts are counted apart, never hidden')
isemon.CONFIG['winsec_machines'] = 0
without = store.win_counts(NOW - 3600, False)
withall = store.win_counts(NOW - 3600, None)
ok('a machine signing in is not counted with the people',
   without.get('logon', 0), 0)
ok('...but it is there when it is asked for', withall.get('logon', 0), 1)
ok('...and it is in the events themselves either way',
   store.win_rows(limit=50)[1] > store.win_rows(limit=50, machines=False)[1], True)

# ---------------------------------------------------------------------------
title('Accounts nobody wants to see')
isemon.CONFIG['winsec_ignore'] = 'firepower'
ok('an ignored account is not read at all',
   [r.facts['account'] for r in isemon.win_parse_lines(
       [line('bdcx02', 4776, CHECKED)])], [])
isemon.CONFIG['winsec_ignore'] = ''
ok('...and with nothing ignored it is read again',
   [r.facts['account'] for r in isemon.win_parse_lines(
       [line('bdcx02', 4776, CHECKED)])], ['firepower'])

# ---------------------------------------------------------------------------
title('What this version makes of a row it wrote earlier')
# The id is made from the LINE, so a better reading of that line must not
# write the row again beside itself - it has to change the row that is there.
with store.db_write() as db:
    db.execute("UPDATE win_events SET object='nonsense', kind='other', mark='' "
               "WHERE event=4662")
store.set_meta('win_sorted', '0')
store.fill_in_win_marks()
row = store.db.execute("SELECT object, kind, mark FROM win_events WHERE event=4662"
                       ).fetchone()
ok('a row written by an older reading is brought up to this one',
   (row['object'], row['kind'], row['mark'].split(',')[0]),
   ('the directory\u2019s own replication rights', 'read', 'replication'))
ok('...and it is not written twice', store.win_rows(event=4662)[1], 2)
# The note says which version read these rows AND who it believed the
# controllers to be, because both change what a stored row means: name a
# controller a month later and the rows it wrote are read again rather than
# going on saying what they said.
ok('...and the sorting is marked as done',
   store.get_meta('win_sorted').startswith(str(store.WIN_SORT_VERSION) + '/'), True)
ok('...and by who was believed to be the directory when it was done',
   store.get_meta('win_sorted').split('/')[1], isemon.win_expected_mark())

# ---------------------------------------------------------------------------
title('What is holding the old password')
# The question a lockout leaves behind, which no single Windows event
# answers: the refusal says which machine and which address, the
# explicit-credential event beside it says which program went and used the
# password, and a Kerberos refusal says neither - only an address.
blame = store.win_blame('novak', 0, 0, 8)
ok('what has been trying an account is counted by machine and by program',
   bool(blame), True)
ok('...and the machine is named', blame[0]['machine'], 'NB-NOVAK')
ok('...and the program with it', blame[0]['process'].endswith('OUTLOOK.EXE'), True)
ok('...and what the domain kept answering it',
   bool(blame[0].get('why')), True)
holders = store.win_holders(0, 12, False)
ok('...and the same question asked of every account at once', bool(holders), True)
ok('...answering with the account it is about', holders[0]['said'], 'novak')

# ...and an address with no name on it anywhere, given the machine that signs
# in from it. Windows writes the client's ADDRESS on a Kerberos refusal and no
# name at all; a server signs in as itself, so the database can answer its
# own question.
where = Path(folder) / 'dc1'
(where / 'WinSecurity.log').write_text('\n'.join(LINES + [
    line('dcx01', 4771, KERBEROS_NO.replace('::ffff:172.29.11.7', '172.29.153.5')
         .replace('Account Name:  pdf', 'Account Name:  mladek'), off=20),
    line('bdcx02', 4624, SIGNED_IN.replace('172.29.152.66', '172.29.153.5')
         .replace('APPSRV01$', 'PVEXC05$'), off=22),
]) + '\n')
daemon.restore_tails()
daemon.read_logs()
rows = [{'ip': '172.29.153.5', 'machine': ''}]
store.name_the_machines(rows)
ok('an address with no name anywhere is given the machine that signs in from it',
   rows[0]['machine'], 'PVEXC05')
ok('...and it says that it was worked out rather than written down',
   rows[0].get('machine_guessed'), True)

# ---------------------------------------------------------------------------
title('A controller named in the settings is a controller')
# The fault this check exists for: `same_address` is a NORMALISER, not a
# test - handed a name it hands the name straight back - so asking it "is
# this an address?" answered yes to every controller anybody typed, and not
# one of them was ever added to the list. The setting looked filled in, the
# page went on crying wolf, and nothing anywhere said why.
ok('a name typed into the settings is read as a name',
   isemon.is_address('dcx01$'), False)
ok('...and an address as an address', isemon.is_address('172.29.11.5'), True)
ok('...and a normaliser is not a test',
   isemon.same_address('dcx01$'), 'dcx01$')
was = dict(isemon.CONFIG)
isemon.CONFIG['winsec_controllers'] = 'DCX01$, dc02.corp-example.int, CORP-EXAMPLE\\DC03$'
daemon.note_controllers(force=True)
for said in ('dcx01', 'dc02', 'dc03'):
    ok('...so "%s" is one of them however it was written' % said,
       said in isemon.WIN_CONTROLLERS, True)
ok('...and a controller replicating the directory is expected',
   isemon.win_is_expected('DCX01$'), True)
ok('...while a member server doing it is not',
   isemon.win_is_expected('PC-DESK-41$'), False)
isemon.CONFIG.clear()
isemon.CONFIG.update(was)
daemon.note_controllers(force=True)

# ---------------------------------------------------------------------------
title('A domain that rebuilds its desktops every day')
# Non-persistent desktops rebuild thousands of computer accounts a day and
# every one is an account created, an account changed and a directory object
# written. Switched on, that SHAPE is machinery. The shape is narrow in two
# directions at once: a machine account doing it, to a computer. Either half
# missing and it is drawn exactly as it always was.
MACHINE_MADE = REPLICATE.replace('MSOL_329', 'PVVDI01CONN$').replace(
    '{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}', '{aaaaaaaa-0000-0000-0000-000000000000}'
).replace('Object Type:  %{19195a5b-6da0-11d0-afd3-00c04fd930c9}',
          'Object Type:  %{bf967a86-0de6-11d0-a285-00aa003049e2}')
PERSON_MADE = MACHINE_MADE.replace('Account Name:  PVVDI01CONN$', 'Account Name:  spravce')
USER_TOUCHED = MACHINE_MADE.replace(
    'Object Type:  %{bf967a86-0de6-11d0-a285-00aa003049e2}',
    'Object Type:  %{bf967aba-0de6-11d0-a285-00aa003049e2}')

isemon.WIN_VDI[0] = False
ok('with the switch off, a desktop being rebuilt is drawn like anything else',
   'routine' in (isemon.win_record_from(line('bdcx02', 4662, MACHINE_MADE))
                 .facts['mark']), False)
isemon.WIN_VDI[0] = True
ok('...and with it on, it is machinery',
   'routine' in (isemon.win_record_from(line('bdcx02', 4662, MACHINE_MADE))
                 .facts['mark']), True)
ok('...but the same thing done by a PERSON is not',
   'routine' in (isemon.win_record_from(line('bdcx02', 4662, PERSON_MADE))
                 .facts['mark']), False)
ok('...and a machine account writing a USER is not either',
   'routine' in (isemon.win_record_from(line('bdcx02', 4662, USER_TOUCHED))
                 .facts['mark']), False)
ok('...nor is the audit log being cleared, whoever cleared it',
   'routine' in (isemon.win_record_from(line('dcx02', 1102, CLEARED)).facts['mark']),
   False)
ok('...nor somebody being put into a group that runs the domain',
   'routine' in (isemon.win_record_from(line('dcx01', 4728, BIG_GROUP)).facts['mark']),
   False)
isemon.WIN_VDI[0] = False

# ...and the machinery leaves the cards without leaving the database. Both
# marks mean the same thing to a card and neither means anything to the list
# of events, which is still whole and still searchable.
ok('the machinery is named in one place',
   isemon.Storage.ROUTINE_MARKS, ('expected', 'routine'))
# An operation on a directory object is the directory being READ, not
# changed: it is event 4662, object-access auditing, and on a controller it
# is most of the log. A card headed "What was changed" that counted a
# service reading a group five thousand times was a card whose title was not
# true, so reading has a kind of its own and the cards about changes leave
# it alone.
changed = store.win_subjects(0, 'object', ('directory', 'account', 'group'), 12, None)
ok('a card about changes counts no reading',
   [r for r in changed if 'replication' in str(r['said'])], [])
reads = store.win_subjects(0, 'object', ('read',), 12, None)
said = [r for r in reads if 'replication' in str(r['said'])]
# ...and the one that IS worth seeing is found by its MARK, whatever kind
# it is: the member server asking, and not the synchroniser, which does it
# by design. Two events of one shape, and the difference between them is
# the whole feature.
ok('...while the reading itself is still counted somewhere', len(said), 1)
ok('...and the one worth seeing is found by its mark, not by its kind',
   store.win_marked(0, 'replication', None, unless='expected')['who'], 'PC-DESK-41$')
ok('...while the events themselves still hold every one of them',
   store.win_rows(mark='replication')[1] >= 2, True)

# ---------------------------------------------------------------------------
title('Asking the right directory about a name')
# A site with two domains has two directories here, and a Windows event says
# which domain it is about in the short name: `CORP-EXAMPLE`, where the
# directory calls itself `corp-example.int`.
isemon.CONFIG.update({'directory': 1, 'directory_host': 'dc1.corp-example.int',
                      'directory_base': 'DC=corp-example,DC=int',
                      'directory2': 1, 'directory2_host': 'dc1.example.cz',
                      'directory2_base': 'DC=corpnet,DC=cz'})
store.set_meta('directory_suffixes', json.dumps({'at': time.time(), 'said': []}))
store.set_meta('directory2_suffixes', json.dumps({'at': time.time(), 'said': []}))
ok('the short name Windows writes finds the right directory',
   daemon.directory_for_realm('CORP-EXAMPLE'), 'directory')
ok('...and so does the long one', daemon.directory_for_realm('corp-example.int'),
   'directory')
ok('...and the other domain finds the other directory',
   daemon.directory_for_realm('CORPNET'), 'directory2')
ok('...while a domain that is neither is nobody\u2019s, so both are asked',
   daemon.directory_for_realm('SOMEWHERE-ELSE'), '')

shutil.rmtree(folder, ignore_errors=True)

# ---------------------------------------------------------------------------
title('A long job says how far along it is, where anybody can see it')
# It runs in the daemon, so where it has got to is the DAEMON'S to say - not
# the browser's. That is what makes the bar survive a reload, a tab being
# changed, and somebody else opening the page at the same moment.
went = isemon.Going('doing a thing', 10, name='a-test')
# Keyed by its own name and a number of its own: two jobs of one kind are
# ordinary - the nightly copy while somebody presses "make a copy now" - and
# keyed by the kind alone the first to finish deleted the entry of the one
# still running.
ok('a job says what it is doing while it does it',
   went.name in isemon.Going.NOW, True)
ok('...under a key of its own, not one shared with every job of its kind',
   went.name != 'a-test' and went.name.startswith('a-test'), True)
twin = isemon.Going('doing the same thing', 10, name='a-test')
ok('...so a second one of the same kind does not replace it',
   sorted(isemon.Going.NOW).count(went.name) + sorted(isemon.Going.NOW).count(twin.name), 2)
twin.done_now()
ok('...and finishing the second leaves the first alone',
   went.name in isemon.Going.NOW, True)
went.step(5)
ok('...and how far along it is', isemon.Going.NOW[went.name]['part'], 0.5)
ok('...in a shape the page can draw',
   sorted(isemon.Going.NOW[went.name]),
   ['began', 'done', 'kind', 'now', 'part', 'size', 'stopping', 'total', 'what'])
went.done_now()
ok('...and says nothing once it is finished', went.name in isemon.Going.NOW, False)
quiet = isemon.Going('a thing with nothing to do', 0, name='b-test')
quiet.done_now()
ok('...and a job with nothing to do never says anything at all',
   'b-test' in isemon.Going.NOW, False)
ok('the page is told about it beside everything else',
   "going" in daemon.win_summary(24, wait=True), True)

# ---------------------------------------------------------------------------
title('A version that changes its mind says so')
# The fault this exists for: 1.10.51 moved event 4662 to a kind of its own
# and excused a controller from two more things - and did not raise the note
# that decides whether the rows already stored are read again. On a site that
# upgraded, every row kept yesterday's kind and yesterday's marks, every card
# went on showing exactly what it had shown before, and it looked as though
# nothing had been fixed at all.
#
# The note is the version AND who the controllers are. The settings half
# looks after itself; the version half is a number somebody has to raise, so
# this is the check that says which reading it was raised for.
ok('the reading has a version of its own', store.WIN_SORT_VERSION >= 2, True)
ok('...and it is in the note beside the rows',
   store.get_meta('win_sorted').split('/')[0], str(store.WIN_SORT_VERSION))
# ...and a note from an older version makes the rows be read again, whatever
# the settings say.
store.set_meta('win_sorted', '1/%s' % isemon.win_expected_mark())
store.set_meta('win_reading', '')
ok('...so a database written by an older reading is read again',
   bool(store.win_marks_plan()[0]), True)
store.fill_in_win_marks()
ok('...and once it has been, it is not read again for nothing',
   store.win_marks_plan()[0], {})

# ...and WHAT is read again is the smallest set that can have changed. A
# version that changed the reading of two event numbers has no business
# walking a billion rows to rewrite the handful that are those two.
was = store.meta_json('win_reading', None) or {}
store.set_meta('win_reading', json.dumps(dict(was, version=3)))
plan, why = store.win_marks_plan()
ok('a version that changed two events asks for those two events',
   plan, {'events': [4648, 4768, 4769]})
ok('...and says so in one line', '4768' in why and '4648' in why, True)
store.set_meta('win_reading', json.dumps(dict(was, version=4)))
plan, why = store.win_marks_plan()
ok('...one version behind: only what that version changed (1.10.200)',
   plan, {'events': [4648]})
store.set_meta('win_reading', json.dumps(dict(was, version=1)))
plan, _why = store.win_marks_plan()
ok('...while a version nobody wrote down is the whole table',
   plan, {'all': True})
# The commonest change of all: a controller named, or the domain adding one.
# Only the rows ABOUT that machine can change, and they are found by name.
store.set_meta('win_reading', json.dumps(dict(was, names=sorted(
    set(was.get('names') or []) | {'newdc01'}))))
plan, why = store.win_marks_plan()
ok('a controller named asks only for the rows about that machine',
   plan, {'accounts': ['newdc01']})
ok('...and says which one', 'newdc01' in why, True)
store.set_meta('win_reading', json.dumps(dict(was, vdi=not was.get('vdi'))))
plan, _why = store.win_marks_plan()
ok('...while the desktop-pool setting really is about every row',
   plan, {'all': True})
store.set_meta('win_reading', json.dumps(was))
ok('...and with nothing changed, nothing is read again at all',
   store.win_marks_plan()[0], {})
# ...and what that reading now makes of a 4662, which is the thing 1.10.51
# changed its mind about.
row = store.db.execute("SELECT kind FROM win_events WHERE event=4662 LIMIT 1").fetchone()
ok('...and an operation on a directory object is READING it',
   row['kind'] if row else None, 'read')

# ---------------------------------------------------------------------------
title('A pass over the logs is one write, not thirty thousand')
# A domain controller writes tens of thousands of lines an hour and every one
# of them used to be a transaction of its own: a lock taken and let go, a
# round trip and a commit, thirty thousand times an hour. Nothing was slow
# about any single one and the daemon spent its life doing them - and
# anything else that wanted to write, a person at the command line included,
# queued behind a stream that never stopped. `isemon --status` took half a
# minute to answer.
folder3, store3, daemon3 = fresh()
where3 = Path(folder3) / 'dc1'
where3.mkdir(parents=True, exist_ok=True)
MANY = [line('dcx01', 4624, SIGNED_IN, off=n) for n in range(300)]
(where3 / 'WinSecurity.log').write_text('\n'.join(MANY) + '\n')
writes = []
was = store3.db_write


def counted():
    writes.append(1)
    return was()


store3.db_write = counted
daemon3.restore_tails()
daemon3.read_logs()
store3.db_write = was
ok('every line of the pass was written down', store3.win_size(), len(MANY))
ok('...in a handful of transactions rather than one each', len(writes) < 40, True)
# ...and it is still written once, however often the file is read again.
daemon3.restore_tails()
daemon3.read_logs()
ok('...and reading the file again still adds nothing', store3.win_size(), len(MANY))
shutil.rmtree(folder3, ignore_errors=True)

# ---------------------------------------------------------------------------
title('Reading it out: a program on a clock, or somebody typing')
# The one thing nobody can see in a list of refusals and the one thing
# everybody wants: a person retries when they notice, a PROGRAM retries on a
# timer. Five tries, then a wait, over and over - the gaps are five different
# lengths and the PERIOD is one number, which is why it is measured by phase.
folder2, store2, daemon2 = fresh()
where2 = Path(folder2) / 'dc1'
where2.mkdir(parents=True, exist_ok=True)
BEAT = []
for round_n in range(8):                       # eight five-minute rounds...
    for at in (0, 28, 48, 75, 91):             # ...five tries in each
        BEAT.append(line('dcx01', 4771,
                         KERBEROS_NO.replace('Account Name:  pdf',
                                             'Account Name:  scanner'),
                         off=9000 - (round_n * 300 + at)))
(where2 / 'WinSecurity.log').write_text('\n'.join(BEAT) + '\n')
daemon2.restore_tails()
daemon2.read_logs()
beat = store2.win_rhythm('scanner', 0)
ok('something on a timer is seen to be on a timer', beat.get('steady'), True)
ok('...and the timer is read off to the second', beat.get('every'), 300)
ok('...and so is how many tries it makes each time', beat.get('per'), 5)
read = daemon2.win_verdict({'account': 'scanner', 'ip': '172.29.11.7', 'n': 40}, 0)
ok('...and it is said in words rather than in numbers',
   any('every five minutes' in one for one in read['reads']), True)
ok('...with what that means beside it',
   any('Nobody types a password on a clock' in one for one in read['reads']), True)
ok('...and somewhere to go', bool(read['next']), True)

# ...and somebody typing is not called a program.
HAND = [line('dcx01', 4771, KERBEROS_NO.replace('Account Name:  pdf',
                                                    'Account Name:  novakova'),
             off=9000 - at) for at in (0, 7, 19, 140, 141, 900, 2311, 2390)]
(where2 / 'WinSecurity.log').write_text('\n'.join(BEAT + HAND) + '\n')
daemon2.restore_tails()
daemon2.read_logs()
ok('...while attempts at no particular interval are not called a timer',
   store2.win_rhythm('novakova', 0).get('steady'), None)

# ...and where somebody has to go depends on what is at the address: the
# password is ON a workstation and is NOT on a server, which is signing in for
# whatever is talking to IT.
place = store2.win_place('172.29.11.7', 0)
ok('an address says what sort of machine is at it', 'server' in place, True)
shutil.rmtree(folder2, ignore_errors=True)

# ---------------------------------------------------------------------------
title('The domain on the front page\u2019s chart')
# The bars have always been this site's own doors. The domain is not one of
# them - it is counted on a controller, and a sign-in checked against the
# directory is already counted at the door it came through - so it is a band
# ON TOP of the bar rather than part of it. Two keys of its own, and the two
# totals untouched.
folder4, store4, daemon4 = fresh()
where4 = Path(folder4) / 'dc1'
where4.mkdir(parents=True, exist_ok=True)
CHART = [line('dcx01', 4771, KERBEROS_NO, off=120 + n) for n in range(7)]
CHART += [line('dcx01', 4624, SIGNED_IN, off=300 + n) for n in range(5)]
# ...and a directory READ, which is neither and is drawn as neither: on a
# controller with object auditing on there are a hundred of those for every
# sign-in, and a wall of them would stand for nobody.
CHART += [line('dcx01', 4662, REPLICATE, off=400 + n) for n in range(9)]
(where4 / 'WinSecurity.log').write_text('\n'.join(CHART) + '\n')
daemon4.restore_tails()
daemon4.read_logs()


def band(bars, key):
    return sum(int(b.get(key) or 0) for b in bars)


bars = store4.auth_counts(24, 3600, True)
ok('the refusals a controller wrote are a band of their own',
   band(bars, 'failed_domain'), 7)
ok('...and nothing of it leaked into what came through a door here',
   (band(bars, 'failed'), band(bars, 'passed')), (0, 0))
ok('...nor into any of the doors\u2019 own bands',
   (band(bars, 'failed_tacacs'), band(bars, 'failed_network'),
    band(bars, 'failed_otp'), band(bars, 'failed_eduroam')), (0, 0, 0, 0))
ok('a machine signing in is left out while the tick box is off',
   band(bars, 'passed_domain'), 0)
isemon.CONFIG['winsec_machines'] = 1
bars = store4.auth_counts(24, 3600, True)
ok('...and counted with it on', band(bars, 'passed_domain'), 5)
isemon.CONFIG['winsec_machines'] = 0
ok('the directory being read is in neither band',
   band(store4.auth_counts(24, 3600, True), 'failed_domain'), 7)
bars = store4.auth_counts(24, 3600, False)
ok('with the domain not being read, the keys are there and empty',
   ('failed_domain' in bars[0], band(bars, 'failed_domain'),
    band(bars, 'passed_domain')), (True, 0, 0))
shutil.rmtree(folder4, ignore_errors=True)

# ---------------------------------------------------------------------------
title('Pressing a card opens what that card counted, and nothing else')
# The complaint this is here for: a row reading "the password was wrong,
# 118" opened a list that was a mixture of accounts, because the row was
# opened as a free-text SEARCH over nine columns rather than as the filter it
# was counted with. A number on a row and the number at the top of what it
# opens have to be the same number.
folder5, store5, daemon5 = fresh()
where5 = Path(folder5) / 'dc1'
where5.mkdir(parents=True, exist_ok=True)
MIX = []
for n in range(6):                               # one account, one machine
    MIX.append(line('dcx01', 4771, KERBEROS_NO, off=100 + n))
for n in range(4):                               # ...and another account,
    MIX.append(line('dcx01', 4771,            # same answer, same shape
                    KERBEROS_NO.replace('Account Name:  pdf',
                                        'Account Name:  novakova'), off=200 + n))
(where5 / 'WinSecurity.log').write_text('\n'.join(MIX) + '\n')
daemon5.restore_tails()
daemon5.read_logs()
since5 = NOW - 86400
ok('both accounts were read', store5.win_size(), 10)

# The card, as the page draws it.
cards = store5.win_subjects(since5, 'said', ('kerberos-failed',), 12, False)
ok('the answers card has the one answer on it', len(cards), 1)
ok('...counting both accounts', cards[0]['n'], 10)
ok('...and saying that it is more than one account', cards[0]['names'], 2)
# ...and the list that card opens.
rows, total = store5.win_rows(limit=500, since=since5, kind='kerberos-failed',
                              said=cards[0]['said'], routine=False)
ok('pressing it opens exactly that many', total, cards[0]['n'])
ok('...and every row of them really is that answer',
   sorted({str(r['said']) for r in rows}), [cards[0]['said']])

title('...and the kinds asked for do not eat the filter beside them')
# `kind` was split into a local called `said`, which is also the name of the
# column holding the answer the domain gave. Once that column became a filter
# of its own, every press sent the list of kinds as the value of it and every
# card opened an empty list.
rows, total = store5.win_rows(limit=10, since=since5, kind='kerberos-failed',
                              account='pdf')
ok('an account and a kind together still find the rows', total, 6)
ok('...and so do an account and several kinds',
   store5.win_rows(limit=1, since=since5,
                   kind='kerberos-failed,ntlm-failed', account='pdf')[1], 6)

title('...for every column a card can be grouped by')
for by in ('account', 'machine', 'ip', 'said'):
    got = store5.win_subjects(since5, by, ('kerberos-failed',), 12, False)
    if not got:
        continue
    one = got[0]
    _rows, many = store5.win_rows(limit=1, since=since5, kind='kerberos-failed',
                                  routine=False, **{by: one['said']})
    ok('by %s: the card says %d and the list says the same'
       % (by, one['n']), many, one['n'])

title('...and the newest row of each subject is that subject\u2019s own')
# The twelve "newest of each" lookups used to be twelve queries, one a
# subject - and on `said`, `object`, `by_who` and `process`, which have no
# index, twelve walks of the whole window. Measured on a domain of seven and
# a half million events: 3.4 to 3.8 seconds EACH. They are now one seek by
# the moments the counting has already found, which is only safe if a moment
# shared by two subjects still gives each of them its own row - and the
# clock here is one second, so on a busy controller they share them all day.
folderX = tempfile.mkdtemp(prefix='isemon-newest-')
WAS_STATE, WAS_DB = isemon.STATE_DIR, isemon.DB_FILE
isemon.STATE_DIR = Path(folderX)
isemon.DB_FILE = Path(folderX) / 'newest.db'
# The suite's own store, so that the float this asks back for is the float
# the engine under test really hands back - on a server engine a new path is
# not a new database, so these rows are taken out again at the end of it.
storeX = store5
SAME = float(int(time.time()) - 600)      # one second, to the very tick
for n, (said, who, at) in enumerate((
        ('nw:wrong password', 'novak', SAME),
        ('nw:wrong password', 'novak', SAME - 300),
        ('nw:no such account', 'nikdo', SAME),        # the SAME second
        ('nw:no such account', 'nikdo', SAME - 300),
        ('nw:locked', 'stary', SAME - 60))):
    storeX.note_win_event({'ident': 'nw-%d' % n, 'ts': at, 'event': 4771,
                           'kind': 'kerberos-failed', 'account': who,
                           'machine': 'NB-%s' % who, 'ip': '10.0.0.%d' % (n + 1),
                           'said': said, 'server': 'dc1'})
allX = storeX.win_subjects(SAME - 86400, 'said', ('kerberos-failed',), 40, None)
cardsX = [c for c in allX if str(c['said']).startswith('nw:')]
ok('three answers, each counted', sorted((c['said'], c['n']) for c in cardsX),
   [('nw:locked', 1), ('nw:no such account', 2), ('nw:wrong password', 2)])
ok('...every one of them with its newest row beside it',
   all(c['newest'] for c in cardsX), True)
ok('...and that row really is the subject it is under',
   sorted((c['said'], c['newest'].get('said')) for c in cardsX),
   [('nw:locked', 'nw:locked'), ('nw:no such account', 'nw:no such account'),
    ('nw:wrong password', 'nw:wrong password')])
ok('...and the newest of them, not just any',
   sorted((c['said'], c['newest'].get('account')) for c in cardsX),
   [('nw:locked', 'stary'), ('nw:no such account', 'nikdo'),
    ('nw:wrong password', 'novak')])
ok('...the moment on it being the one the counting found',
   sorted({float(c['newest']['ts']) == float(c['last']) for c in cardsX}), [True])
# ...and the old question is still there for whatever the fast one misses.
ok('there is a way back if a clock does not come back the same',
   "more = sql2 + 'ts >= ? AND %s = ?' % by" in DAEMON_SRC, True)
with storeX.db_write() as dbX:
    dbX.execute("DELETE FROM win_events WHERE said LIKE 'nw:%'")
isemon.STATE_DIR, isemon.DB_FILE = WAS_STATE, WAS_DB
shutil.rmtree(folderX, ignore_errors=True)

title('...and what is holding a password opens that machine, not the account')
# A row of that card is one account FROM one machine THROUGH one program.
# Rebuilt out of the name at the front of it, it opened every refusal that
# account had anywhere.
held = store5.win_holders(since5, 12, False)
ok('there is such a row', bool(held), True)
if held:
    ok('...and it carries the filter it was counted with',
       sorted(held[0].get('ask') or {}), ['account', 'ip'])
    _rows, many = store5.win_rows(limit=1, since=since5,
                                  kind=','.join(isemon.Storage.BAD_KINDS),
                                  routine=False, **held[0]['ask'])
    ok('...which opens exactly what it counted', many, held[0]['n'])

title('...and the machinery a card leaves out is left out of the list too')
isemon.CONFIG['winsec_controllers'] = 'dcx01'
daemon5.note_controllers(force=True)
store5.fill_in_win_marks(again=True)
REPL = [line('dcx01', 4662, REPLICATE, off=300 + n) for n in range(5)]
(where5 / 'WinSecurity.log').write_text('\n'.join(MIX + REPL) + '\n')
daemon5.restore_tails()
daemon5.read_logs()
cards = store5.win_subjects(since5, 'account', ('directory', 'read'), 12, None)
plain = store5.win_rows(limit=1, since=since5, kind='directory,read')[1]
kept = store5.win_rows(limit=1, since=since5, kind='directory,read', routine=False)[1]
ok('the replication is in the events themselves', plain > 0, True)
ok('...and left out where the cards leave it out', kept < plain, True)
ok('...so a card of nothing opens a list of nothing',
   (sum(c['n'] for c in cards), kept), (0, 0))
isemon.CONFIG['winsec_controllers'] = ''
shutil.rmtree(folder5, ignore_errors=True)

# ---------------------------------------------------------------------------
title('The box at the top looks in the domain too')
# It says it looks through everything this machine has recorded, and on a
# site reading its controllers that is the half of a refusal that is written
# down on a controller and nowhere else. A name that had never touched the
# VPN and was being hammered on the domain came back "nothing here matches".
folder6, store6, daemon6 = fresh()
where6 = Path(folder6) / 'dc1'
where6.mkdir(parents=True, exist_ok=True)
BOX = [line('dcx01', 4771, KERBEROS_NO, off=100 + n) for n in range(9)]
BOX += [line('dcx01', 4624, SIGNED_IN, off=200 + n) for n in range(4)]
BOX += [line('dcx01', 4740, LOCKED, off=300)]
(where6 / 'WinSecurity.log').write_text('\n'.join(BOX) + '\n')
daemon6.restore_tails()
daemon6.read_logs()
since6 = NOW - 7 * 86400

got = {one['what'] + '/' + one['said']: one
       for one in store6.win_find('pdf', 8, since6)}
ok('a name only the domain has ever seen is found', 'account/pdf' in got, True)
one = got.get('account/pdf') or {}
ok('...and the line says how many times it was refused', one.get('failed'), 9)
ok('...and that it never got in', one.get('passed'), 0)
ok('...and where from', one.get('places'), 1)
ok('...and when the last one was', bool(one.get('last')), True)

ok('a machine is found by its name',
   [r['what'] for r in store6.win_find('nb-novak', 8, since6)], ['machine'])
ok('an address is found by part of it',
   sorted({r['what'] for r in store6.win_find('172.29.11', 8, since6)}), ['address'])
ok('an account that was locked out says so',
   [r['locked'] for r in store6.win_find('novak', 8, since6)
    if r['what'] == 'account' and r['said'] == 'novak'], [1])
ok('half a letter is not a search', store6.win_find('p', 8, since6), [])
ok('...and a word nothing matches finds nothing',
   store6.win_find('zznothing', 8, since6), [])

title('...and pressing one of those opens exactly those events')
for hit in store6.win_find('pdf', 8, since6):
    column = {'account': 'account', 'machine': 'machine', 'address': 'ip',
              'done by': 'by_who', 'program': 'process',
              'object': 'object'}[hit['what']]
    _rows, many = store6.win_rows(limit=1, since=since6, routine=False,
                                  **{column: hit['said']})
    ok('%s "%s": the line says %d and the list says the same'
       % (hit['what'], hit['said'][:20], hit['n']), many, hit['n'])

title('...and the box says so only where there is a domain to look in')
isemon.CONFIG['winsec'] = 0
ok('with the controller logs switched off it is not asked at all',
   'domain' in daemon6.find('pdf', 8), False)
isemon.CONFIG['winsec'] = 1
said = daemon6.find('pdf', 8)
ok('...and switched on it is', bool(said.get('domain')), True)
ok('...with the window it looked over said out loud',
   said.get('domain_days'), isemon.Daemon.FIND_DOMAIN_DAYS)
shutil.rmtree(folder6, ignore_errors=True)

# ---------------------------------------------------------------------------
title('Pressing the button says so at once, and only once')
folder7, store7, daemon7 = fresh()
where7 = Path(folder7) / 'dc1'
where7.mkdir(parents=True, exist_ok=True)
(where7 / 'WinSecurity.log').write_text(
    '\n'.join(line('dcx01', 4624, SIGNED_IN, off=n) for n in range(80)) + '\n')
daemon7.restore_tails()
daemon7.read_logs()

# A job that has nothing to count still says it is going. The directory half
# of the button is thirty searches of somebody else's domain controller and
# there is no number to put on it; saying nothing until it is over is a
# button that looks like it did nothing at all.
quiet = isemon.Going('asking the directory about its accounts',
                     name='win-directory', speak_up=True)
ok('a job with nothing to count is in what the page reads',
   quiet.name in isemon.Going.NOW, True)
ok('...under a key the page can still pick out by kind',
   quiet.name.startswith('win-directory'), True)
ok('...with no total, so the bar moves rather than sitting at nought',
   isemon.Going.NOW[quiet.name]['total'], 0)
quiet.done_now()
ok('...and it is gone when it is done', quiet.name in isemon.Going.NOW, False)

title('...and two presses are one pass, not two')
# A second press during the minute the directory takes went straight past
# the guard and started a second walk of the same table, with both of them
# writing the same progress.
started = []
real_thread = threading.Thread


class Held(real_thread):
    def start(self):
        started.append(self.name)
        # not run: what is being tested is how many were let through


threading.Thread = Held
try:
    first = daemon7.reread_win_marks(by='a test')
    second = daemon7.reread_win_marks(by='a test')
finally:
    threading.Thread = real_thread
ok('the first press starts it', bool(first.get('started')), True)
ok('...and the second is told it is already going',
   bool(second.get('already')), True)
ok('...so only one pass was ever started', started.count('win-marks'), 1)
ok('...and the settings road cannot start a second either',
   daemon7.start_reread(), False)
daemon7._rereading = False

title('...and the answer the page gets is not the one from before the press')
# The kept answer is ten seconds old, and ten seconds before the press is a
# world where nothing was going. That is what left the bar hidden until the
# job was over.
daemon7.held('winsec/24', 600, lambda: {'made': 'before the press'})
ok('the answer was kept', daemon7.held('winsec/24', 600, dict)['made'],
   'before the press')
daemon7.forget_held('winsec/')
ok('...and the button throws it away',
   daemon7.held('winsec/24', 600, lambda: {'made': 'after'})['made'], 'after')
ok('...and leaves everything else alone',
   (daemon7.held('today/1', 600, lambda: {'made': 'other'})
    or {}).get('made'), 'other')
shutil.rmtree(folder7, ignore_errors=True)

# ---------------------------------------------------------------------------
title('The marks are a number as well as words, so they can be indexed')
# `mark LIKE '%replication%'` is a walk of every row in the window whatever
# is indexed, and the Domain page asks that question ten times over. On five
# million events the page took eleven seconds. The same answer as a number,
# one bit a mark, is an index scan of the rows that are marked at all.
folder8, store8, daemon8 = fresh()
where8 = Path(folder8) / 'dc1'
where8.mkdir(parents=True, exist_ok=True)
MARKED = [line('dcx01', 4662, REPLICATE_BAD, off=100 + n) for n in range(5)]
MARKED += [line('dcx01', 4624, SIGNED_IN, off=200 + n) for n in range(6)]
MARKED += [line('dcx01', 1102, CLEARED, off=300)]
(where8 / 'WinSecurity.log').write_text('\n'.join(MARKED) + '\n')
daemon8.restore_tails()
daemon8.read_logs()
since8 = NOW - 86400

ok('a mark has a bit', isemon.WIN_MARK_BITS['replication'], 1)
ok('...and every mark the reader can write has one',
   sorted(set(isemon.WIN_MARK_BITS)), sorted(set(isemon.WIN_MARK_BITS)))
ok('the words are written down exactly as before',
   any('replication' in str(r['mark'] or '')
       for r in store8.win_rows(limit=50, since=since8)[0]), True)
ok('...and the number beside them says the same thing',
   [int(r['marks'] or 0) & isemon.WIN_MARK_BITS['replication'] > 0
    for r in store8.win_rows(limit=50, since=since8)[0]
    if 'replication' in str(r['mark'] or '')][:1], [True])
ok('...and a row with no mark has no bits',
   [int(r['marks'] or 0) for r in store8.win_rows(limit=50, since=since8)[0]
    if not str(r['mark'] or '')][:1], [0])

title('...and a question about a mark is asked of the number')
said, holes = store8.mark_clause('replication', True)
ok('a mark this program knows is asked as a number', 'marks &' in said, True)
ok('...and says the index\u2019s own rule out loud, or no engine uses it',
   'marks <> 0' in said, True)
ok('...and needs no values beside it', holes, [])
said, holes = store8.mark_clause('something-nobody-writes', True)
ok('...while a word it does not know is still a search', 'LIKE' in said.upper(), True)
ok('the machinery is left out by number too',
   ('marks' in store8.routine_clause()[0]
    and 'LIKE' not in store8.routine_clause()[0].upper()), True)

title('...and all ten cards are counted in one pass')
got = store8.win_marked_all(since8, [one[1] for one in isemon.Daemon.WIN_MARK_CARDS],
                            None, 'expected')
ok('every card asked for got an answer',
   sorted(got), sorted(one[1] for one in isemon.Daemon.WIN_MARK_CARDS))
ok('...and the replication one counted them', got['replication']['n'], 5)
ok('...and named the last of them', bool(got['replication']['who']), True)
ok('...and the audit one too', got['audit']['n'], 1)
ok('...and a card with nothing behind it says nought', got['rc4']['n'], 0)
one_at_a_time = store8.win_marked(since8, 'replication', None, 'expected')
ok('...and one at a time says exactly the same',
   (one_at_a_time['n'], one_at_a_time['who']),
   (got['replication']['n'], got['replication']['who']))

title('...and a database written before the numbers is brought up')
# The words are already right; this only writes the same answer in the other
# shape, and it is done once.
with store8.db_write() as db:
    db.execute('UPDATE win_events SET marks = 0')
store8.set_meta('win_bits_done', '')
ok('with the numbers wiped, the question finds nothing',
   store8.win_marked(since8, 'replication', None, 'expected')['n'], 0)
ok('...and the one-off walk puts them back', store8.fill_in_win_bits() > 0, True)
ok('...so the answer is the one it was again',
   store8.win_marked(since8, 'replication', None, 'expected')['n'], 5)
ok('...and it does not walk them twice', store8.fill_in_win_bits(), 0)

title('...and old rows are let go a stride at a time')
# Said as one DELETE, a year of a busy domain is one transaction the size of
# the year: minutes of write lock with the page waiting behind it.
before = store8.win_size()
went = store8.tidy_older('win_events', NOW - 250, stride=2)
ok('the old ones went', went > 0, True)
ok('...and the newer ones stayed', store8.win_size(), before - went)
ok('...and asking again takes nothing away',
   store8.tidy_older('win_events', NOW - 250, stride=2), 0)

title('...and how many there are is counted while that is cheap')
ok('a small table is counted properly', store8.rows_in('win_events'),
   store8.win_size())
ok('...and the engine is asked for a guess first',
   isinstance(store8.dialect.rows_guess(store8.db, 'win_events'), int), True)
shutil.rmtree(folder8, ignore_errors=True)

# ---------------------------------------------------------------------------
title('The whole life of one account, including one that no longer exists')
# Who made it, who changed it, who unlocked it, who deleted it. The lines
# below are the real ones, off a controller of a live domain, for an account
# that was created, unlocked and deleted inside seven minutes - which is the
# case that matters, because by the time anybody asks, the directory holds
# not one word about it.
MADE = (
    'A user account was created.  Subject:  Security ID:  S-1-5-21-1-2-3-16480  '
    'Account Name:  mdolezal  Account Domain:  CORP-EXAMPLE  Logon ID:  0x6DA26C37  '
    'New Account:  Security ID:  S-1-5-21-1-2-3-52889  Account Name:  testlock  '
    'Account Domain:  CORP-EXAMPLE  Attributes:  SAM Account Name: testlock  '
    'Display Name:  testlock  User Principal Name: testlock@corp-example.int  '
    'Home Directory:  -  Password Last Set: <never>  Account Expires:  <never>  '
    'Primary Group ID: 513  Old UAC Value:  0x0  New UAC Value:  0x15')
RESET = (
    "An attempt was made to reset an account's password.  Subject:  "
    'Security ID:  S-1-5-21-1-2-3-16480  Account Name:  mdolezal  '
    'Account Domain:  CORP-EXAMPLE  Logon ID:  0x6DA28F07  Target Account:  '
    'Security ID:  S-1-5-21-1-2-3-52889  Account Name:  testlock  '
    'Account Domain:  CORP-EXAMPLE')
UNLOCKED = (
    'A user account was unlocked.  Subject:  Security ID:  S-1-5-21-1-2-3-16480  '
    'Account Name:  mdolezal  Account Domain:  CORP-EXAMPLE  Logon ID:  0x6DA549E5  '
    'Target Account:  Security ID:  S-1-5-21-1-2-3-52889  Account Name:  testlock  '
    'Account Domain:  CORP-EXAMPLE')
DELETED = (
    'A user account was deleted.  Subject:  Security ID:  S-1-5-21-1-2-3-16480  '
    'Account Name:  mdolezal  Account Domain:  CORP-EXAMPLE  Logon ID:  0x6DA6F4CB  '
    'Target Account:  Security ID:  S-1-5-21-1-2-3-52889  Account Name:  testlock  '
    'Account Domain:  CORP-EXAMPLE  Additional Information:  Privileges -')
# ...and the directory's own three, which name the person who did it in the
# `account` field and the thing it was done TO only inside a distinguished
# name. That is why a life is looked for two ways round.
DIR_MADE = (
    'A directory service object was created.   Subject:  '
    'Security ID:  S-1-5-21-1-2-3-16480  Account Name:  mdolezal  '
    'Account Domain:  CORP-EXAMPLE  Logon ID:  0x6DA26C37   Directory Service:  '
    'Name: corp-example.int  Type: Active Directory Domain Services   Object:  '
    'DN: cn=testlock,OU=Users,OU=ISE,DC=corp-example,DC=int  '
    'GUID: {AC038CA0-8B37-4ACD-AF18-8DCCA4B5484F}  Class: user   Operation:  '
    'Correlation ID: {27050CBE-713A-4611-BAD7-57F18631795B}')
DIR_CHANGED = (
    'A directory service object was modified.   Subject:  '
    'Security ID:  S-1-5-21-1-2-3-16480  Account Name:  mdolezal  '
    'Account Domain:  CORP-EXAMPLE  Logon ID:  0x6DA26C37  Directory Service:  '
    'Name: corp-example.int  Type: Active Directory Domain Services   Object:  '
    'DN: cn=testlock,OU=Users,OU=ISE,DC=corp-example,DC=int  '
    'GUID: {AC038CA0-8B37-4ACD-AF18-8DCCA4B5484F}  Class: user   Attribute:  '
    'LDAP Display Name: sAMAccountName  Syntax (OID): 2.5.5.12  Value: testlock   '
    'Operation:  Type: Value Added')
DIR_GONE = (
    'A directory service object was deleted.   Subject:  '
    'Security ID:  S-1-5-21-1-2-3-16480  Account Name:  mdolezal  '
    'Account Domain:  CORP-EXAMPLE  Logon ID:  0x6DA6F4CB   Directory Service:  '
    'Name: corp-example.int  Type: Active Directory Domain Services   Object:  '
    'DN: CN=testlock,OU=Users,OU=ISE,DC=corp-example,DC=int  '
    'GUID: {AC038CA0-8B37-4ACD-AF18-8DCCA4B5484F}  Class: user   Operation:  '
    'Tree Delete: No')
# One line that is somebody ELSE's account, with `testlock` nowhere in it
# except as part of a longer name - a life must not swallow it.
OTHER = RESET.replace('Account Name:  testlock', 'Account Name:  testlocker')

folder9, store9, daemon9 = fresh()
daemon9.read_records([
    line('dcx01', 4720, MADE, 400),
    line('dcx01', 5137, DIR_MADE, 399),
    line('dcx01', 4724, RESET, 398),
    line('dcx01', 5136, DIR_CHANGED, 397),
    line('dcx01', 4740, LOCKED.replace('novak', 'testlock'), 300),
    line('dcx01', 4767, UNLOCKED, 200),
    line('dcx01', 4726, DELETED, 100),
    line('dcx01', 5141, DIR_GONE, 99),
    line('dcx01', 4724, OTHER, 98),
], 'winsec')
daemon9.flush_win_events()

life = store9.win_life('testlock')
ok('every one of them is in the life', len(life), 8)
ok('...and somebody else’s account is not', 
   [one for one in life if 'testlocker' in str(one.get('account') or '')], [])
ok('...oldest first', [int(one['event']) for one in life],
   [4720, 5137, 4724, 5136, 4740, 4767, 4726, 5141])
ok('...each with what it SAYS, not which group it is in',
   life[0]['words'], 'an account was created')
ok('...and who did it, off an account event', life[0]['who'], 'mdolezal')
ok('...and off a directory event, where the subject IS the account column',
   life[1]['who'], 'mdolezal')
ok('...with the attribute that changed, where one did',
   'sAMAccountName' in str(life[3].get('object') or ''), True)
ok('a name that is only part of a distinguished name is not a life',
   store9.win_life('Users'), [])
ok('...nor is nothing at all', store9.win_life('  '), [])

title('...read out as a story rather than as a list')
story = daemon9.win_story('testlock')
ok('it is the same events', story['n'], 8)
ok('...and it knows when it was made', bool(story['made']), True)
ok('...by whom', story['made']['who'], 'mdolezal')
ok('...and that it is gone', bool(story['gone']), True)
ok('...and who took it away', story['gone']['who'], 'mdolezal')
ok('...and that it was locked once', len(story['locks']), 1)
ok('...and unlocked once', len(story['unlocks']), 1)
ok('...and which domain it was in', story['domain'], 'CORP-EXAMPLE')
said = ' '.join(story['reads'])
ok('the story says it was made, by name', 'Made ' in said and 'by mdolezal' in said, True)
ok('...that it was unlocked, and by whom', 'Unlocked once' in said, True)
ok('...that its password was set', 'Its password was set once' in said, True)
ok('...that it is deleted', 'Deleted ' in said, True)
ok('...and that asking the directory would now find nothing',
   'would find nothing' in said, True)
ok('...and it names everybody who touched it',
   'All of that was mdolezal, and nobody else.' in said, True)
# The subject of a lockout is the controller that noticed it. Naming it as
# somebody who "did something to" the account would be true of the event and
# false of the account.
ok('...and a controller is not one of them', 'DCX01$' in said, False)
ok('an account nothing was ever done to has no story',
   daemon9.win_story('nobody')['n'], 0)
ok('...and says nothing rather than something wrong',
   daemon9.win_story('nobody')['reads'], [])

title('...and a life longer than fits gives up its middle, not its ends')
# The obvious thing is the oldest N, because a life is read forwards - and on
# an account that has been in a domain for eleven years that throws away the
# end of the story, which is the half somebody is usually asking about.
many = store9.win_life('testlock', limit=4)
ok('it is cut to what was asked for, plus the row that says so', len(many), 5)
ok('...and the oldest is still the oldest', int(many[0]['event']), 4720)
ok('...and the newest is still the newest', int(many[-1]['event']), 5141)
ok('...with a row in the middle saying what is missing',
   [one for one in many if one.get('gap')][0]['words'],
   'more than 4 things were done to this account — the middle of them '
   'is not shown')
ok('...and a life that fits has no such row',
   [one for one in store9.win_life('testlock') if one.get('gap')], [])
# ...and the story does not count that row as something done to the account.
ok('...which is not counted as one of the things done',
   daemon9.win_story('testlock')['n'], 8)

title('...and a lockout says how it ended, and who ended it')
# Off the lock's own moment rather than off the clock: a syslog stamp is
# whole seconds and `NOW` is not, so subtracting one from the other is a
# second out as often as not.
locked_at = [one['ts'] for one in life if int(one['event']) == 4740][0]
unlocked_at = [one['ts'] for one in life if int(one['event']) == 4767][0]
freed = store9.win_unlock_after('testlock', locked_at)
ok('the unlock after the lock is found', bool(freed), True)
ok('...naming who did it', freed['who'], 'mdolezal')
ok('...and how long it was locked for', freed['after'], unlocked_at - locked_at)
ok('a lock with nothing after it is still locked',
   store9.win_unlock_after('testlock', NOW - 10), None)
ok('...and an account that was never locked has none',
   store9.win_unlock_after('nobody', NOW - 400), None)
locks = store9.win_lockouts(NOW - 3600)
ok('the lockout carries it', bool(locks) and bool(locks[0].get('freed')), True)
ok('...naming who unlocked it', locks[0]['freed']['who'], 'mdolezal')
ok('...and saying it was an unlock that ended it', locks[0]['freed']['how'], 'unlocked')

# ...and the card that lists accounts things were done TO must list the
# account, not the administrator who did them.
rows = store9.win_subjects(NOW - 3600, 'account', ('account', 'group', 'unlock'), 12, None)
ok('the card lists what was done to', sorted(r['said'] for r in rows),
   ['testlock', 'testlocker'])

# A deletion ends a lockout as surely as an unlock does. Saying "still
# locked" about an account somebody deleted is the page arguing with its own
# data - the events two rows down name who deleted it.
folder10, store10, daemon10 = fresh()
daemon10.read_records([
    line('dcx01', 4720, MADE, 500),
    line('dcx01', 4740, LOCKED.replace('novak', 'testlock'), 300),
    line('dcx01', 4726, DELETED, 100),
    line('dcx01', 5141, DIR_GONE, 99),
], 'winsec')
daemon10.flush_win_events()
ended = store10.win_unlock_after('testlock', NOW - 300)
ok('a lockout on an account that was then deleted has an ending',
   bool(ended), True)
ok('...and it is a deletion, not an unlock', ended['how'], 'deleted')
ok('...naming who deleted it', ended['who'], 'mdolezal')
gone = daemon10.win_story('testlock')
ok('...and the story does not call it locked still',
   'locked still' in ' '.join(gone['reads']), False)
ok('...but says what did happen',
   'Nothing here unlocked it — it was locked and then deleted.' in gone['reads'],
   True)
# ...and a deletion written ONLY as a directory event still ends it: that one
# names the administrator in the account column and the account itself only
# inside a distinguished name.
folder12, store12, daemon12 = fresh()
daemon12.read_records([
    line('dcx01', 4740, LOCKED.replace('novak', 'testlock'), 300),
    line('dcx01', 5141, DIR_GONE, 99),
], 'winsec')
daemon12.flush_win_events()
only = store12.win_unlock_after('testlock', NOW - 300)
ok('a deletion written only in the directory still ends it', bool(only), True)
ok('...as a deletion', only['how'] if only else '', 'deleted')
ok('...by the person who did it, not by the account it names',
   only['who'] if only else '', 'mdolezal')
shutil.rmtree(folder12, ignore_errors=True)
shutil.rmtree(folder10, ignore_errors=True)
# Kept in this order on purpose: the block below makes stores of its own,
# and on a server engine every `fresh()` shares one database and empties
# it. Anything with more to ask of `store9` has to ask it before that.
title('...and WHERE each of them was done from, which is on none of them')
# Windows writes no address and no machine name on an account change. What it
# writes is the Logon ID of the session that made it, and the SIGN-IN for
# that session, on the same controller, is where the workstation and the
# address are. Nothing else joins the two.
ok('the session is kept on the change', life[0].get('by_logon'), '0x6DA26C37')
ok('...and on the directory event beside it', life[1].get('by_logon'), '0x6DA26C37')
ok('...and a session that leads nowhere is not kept',
   isemon.win_logon_id({'Subject / Logon ID': '0x3e7'}, 4724), '')
ok('...nor is nobody', isemon.win_logon_id({'Subject / Logon ID': '0x0'}, 4724), '')
# The fields arrive flattened, so a value may have the next heading stuck to
# the end of it. That is how 4720 writes it.
ok('...and the next heading is not read as part of it',
   isemon.win_logon_id({'Subject / Logon ID': '0x6DA26C37  New Account:'}, 4720),
   '0x6DA26C37')
# On a sign-in it is the session being CREATED that everything points back
# to, not the subject that asked for it - which on a controller is the
# machine itself.
ok('...and a sign-in is known by the session it opened',
   isemon.win_logon_id({'Subject / Logon ID': '0x3E7',
                        'New Logon / Logon ID': '0x6DA26C37'}, 4624),
   '0x6DA26C37')
# Nothing joins until the sign-in is there to join to.
ok('with no sign-in, nothing is invented', life[0].get('from_ip'), None)

SIGNED = (
    'An account was successfully logged on.  Subject:  Security ID:  S-1-0-0  '
    'Account Name:  -  Account Domain:  -  Logon ID:  0x0  Logon Information:  '
    'Logon Type:  3  New Logon:  Security ID:  S-1-5-21-1-2-3-16480  '
    'Account Name:  mdolezal  Account Domain:  CORP-EXAMPLE  Logon ID:  0x6DA26C37  '
    'Linked Logon ID:  0x0  Process Information:  Process ID:  0x0  '
    'Process Name:  -  Network Information:  Workstation Name: NB-MDOLEZAL  '
    'Source Network Address: 172.29.6.100  Source Port:  52492')
folder11, store11, daemon11 = fresh()
daemon11.read_records([
    line('dcx01', 4624, SIGNED, 500),
    line('dcx01', 4720, MADE, 400),
    line('dcx01', 5137, DIR_MADE, 399),
    # ...and one made from a session nothing here ever saw signed in.
    line('dcx01', 4726, DELETED, 100),
], 'winsec')
daemon11.flush_win_events()
told = store11.win_life('testlock')
ok('the change knows where it was made from',
   [one.get('from_ip') for one in told if int(one['event']) == 4720], ['172.29.6.100'])
ok('...by name as well', [one.get('from_machine') for one in told
                          if int(one['event']) == 4720], ['NB-MDOLEZAL'])
ok('...and so does every other change in the same session',
   [one.get('from_ip') for one in told if int(one['event']) == 5137], ['172.29.6.100'])
ok('...and one from a session nothing saw says nothing',
   [one.get('from_ip') for one in told if int(one['event']) == 4726], [None])
where = daemon11.win_story('testlock')
ok('the story says where it was all done from',
   [w for w in where['reads'] if w.startswith('Done from NB-MDOLEZAL (172.29.6.100)')] != [],
   True)
# A sign-in from a week ago is not the session an account change today was
# made in, whatever the id says: Windows reuses them.
folder13, store13, daemon13 = fresh()
daemon13.read_records([
    line('dcx01', 4624, SIGNED, 86400 * 9),
    line('dcx01', 4720, MADE, 400),
], 'winsec')
daemon13.flush_win_events()
ok('a sign-in too old to be that session is not used',
   store13.win_life('testlock')[0].get('from_ip'), None)
shutil.rmtree(folder13, ignore_errors=True)
shutil.rmtree(folder11, ignore_errors=True)


shutil.rmtree(folder9, ignore_errors=True)

# ---------------------------------------------------------------------------
title('A refusal is a refusal, whatever number Windows wrote it under')
# 4768, 4769 and 4776 are written whether the answer was yes or no, and the
# number alone does not say which - the code inside does. Filed by the number,
# a wrong password over NTLM was counted as somebody getting in and was
# invisible to every card about what keeps trying an old password, which is
# the one question a lockout leaves behind.
NTLM_NO = ('The computer attempted to validate the credentials for an account.  '
           'Authentication Package: MICROSOFT_AUTHENTICATION_PACKAGE_V1_0 '
           'Logon Account: svc_scan Source Workstation: PVEXC05 Error Code: 0xC000006A')
NTLM_YES = NTLM_NO.replace('0xC000006A', '0x0')
KRB_NO = (
    'A Kerberos authentication ticket (TGT) was requested.  Account Information:  '
    'Account Name:  jan  Supplied Realm Name: KR  Service Information:  '
    'Service Name:  krbtgt  Network Information:  Client Address:  ::ffff:10.1.1.9  '
    'Additional Information:  Result Code:  0x18  Ticket Options:  0x40810010')
KRB_YES = KRB_NO.replace('Result Code:  0x18', 'Result Code:  0x0')
for words, said, want in (('an NTLM check that failed', NTLM_NO, 'ntlm-failed'),
                          ('...and one that worked', NTLM_YES, 'ntlm'),
                          ('a ticket that was refused', KRB_NO, 'kerberos-failed'),
                          ('...and one that was given', KRB_YES, 'kerberos')):
    got = isemon.win_record_from(line('dc1', {'ntlm': 4776, 'kerberos': 4768}.get(
        want.split('-')[0]), said))
    ok(words, got.facts['kind'] if got else '(not read)', want)
ok('...so a failure is never counted as somebody getting in',
   [k for k in ('ntlm-failed', 'kerberos-failed') if k in isemon.WIN_AS_PASSED], [])
ok('...and an event with no code keeps the kind its number gives it',
   isemon.win_kind_of(4776, {}), 'ntlm')
# ...and the stored rows are put right by the walk that reads them again.
folder14, store14, daemon14 = fresh()
daemon14.read_records([line('dc1', 4776, NTLM_NO, 100)], 'winsec')
daemon14.flush_win_events()
ok('a stored refusal is stored as one',
   store14.win_counts(NOW - 3600).get('ntlm-failed'), 1)
with store14.db_write() as db:
    db.execute("UPDATE win_events SET kind = 'ntlm'")
ok('...and one stored by an older version is put right by the re-read',
   (store14.fill_in_win_marks(again=True, mark=False),
    store14.win_counts(NOW - 3600).get('ntlm-failed')), (1, 1))
shutil.rmtree(folder14, ignore_errors=True)

# ---------------------------------------------------------------------------
title('...and a reboot is not the audit log being emptied')
# Windows starting up, the log service stopping and the clock changing are all
# of the `audit` kind. Patch night on three controllers put up a crimson "The
# audit log was cleared - 6 of them" about three machines rebooting.
for event, words, want in ((1102, 'the log really being cleared', 'audit'),
                           (1100, 'the log service stopping', ''),
                           (4608, 'Windows starting up', ''),
                           (4616, 'the clock being changed', '')):
    ok('%s' % words, isemon.win_marks(event, {}, '', isemon.WIN_EVENTS[event][0]), want)

# ---------------------------------------------------------------------------
title('...and the filters are one walk of the window, not three')
ok('the kinds, the events and the controllers come back together',
   'def win_shape(self, since, machines=None, kinds=(), until=0)' in
   open(HERE.parent / 'isemon.py', encoding='utf-8').read(), True)
folder15, store15, daemon15 = fresh()
daemon15.read_records([
    line('dc1', 4776, NTLM_NO, 100), line('dc2', 4776, NTLM_YES, 90),
    line('dc1', 4768, KRB_YES, 80)], 'winsec')
daemon15.flush_win_events()
shape = store15.win_shape(NOW - 3600)
ok('the kinds add up', shape['counts'].get('ntlm-failed'), 1)
ok('...the events too', shape['events'].get(4776), 2)
ok('...and every controller that wrote anything is there',
   sorted(shape['servers']), ['dc1', 'dc2'])
ok('...and it says the same as counting them one at a time',
   shape['counts'], store15.win_counts(NOW - 3600))
# ...and narrowed to a tab, the filters offer only what is behind it.
narrow = store15.win_shape(NOW - 3600, None, ('ntlm-failed',))
ok('a tab is offered only its own event numbers', sorted(narrow['events']), [4776])
ok('...while the counts stay whole, because the tabs say those',
   narrow['counts'], shape['counts'])
shutil.rmtree(folder15, ignore_errors=True)

# ---------------------------------------------------------------------------
title('Watching what the directory says, and saying so when it moves')
# The one change this page exists to catch is not in any log: it is an
# account that is in the group that runs the domain this morning and was not
# in it last night. Only the directory knows, and only against what it said
# before. Nothing here writes to the directory - what is remembered is
# written into THIS database.
folder16, store16, daemon16 = fresh()
SAID = {
    'directory|counts/no_password': {'words': 'No password needed', 'v': 12},
    'directory|shape/lock_after': {'words': 'Locks after', 'v': 5},
    'directory|group/domain admins': {'words': 'Who is in domain admins',
                                      'v': ['mdolezal', 'novak']},
}
daemon16.directory_snapshot = lambda: {k: dict(v) for k, v in SAID.items()}

isemon.CONFIG['directory_watch'] = 0
ok('switched off, nothing is weighed against anything',
   daemon16.note_directory_drift(), {})
isemon.CONFIG['directory_watch'] = 1
ok('...and switched on with nothing remembered, still nothing',
   daemon16.note_directory_drift(), {})

daemon16.remember_directory(by='a test')
ok('remembering writes down what it says now',
   len((store16.meta_json('directory_memory', None) or {}).get('what') or {}), 3)
ok('...and nothing has changed the moment after', daemon16.note_directory_drift(), {})

# A name put into the group that runs the domain, a rule loosened, and a
# count moved: three shapes of change, and all three are noticed.
SAID['directory|group/domain admins']['v'] = ['mdolezal', 'novak', 'newcomer']
SAID['directory|shape/lock_after']['v'] = 0
SAID['directory|counts/no_password']['v'] = 13
drift = daemon16.note_directory_drift()
ok('a name added to the group that runs the domain is noticed',
   'directory|group/domain admins' in drift, True)
ok('...and it says WHO, rather than that a list changed',
   'newcomer added' in (drift['directory|group/domain admins'].get('says') or ''), True)
ok('...and a rule that was loosened says what it was and what it is',
   drift['directory|shape/lock_after'].get('says'), '5 \u2192 0')
ok('...and a count of accounts made easier to get into is noticed too',
   drift['directory|counts/no_password'].get('says'), '12 \u2192 13')

when = drift['directory|shape/lock_after']['at']
ok('what the directory says is not asked twice for the same answer',
   daemon16.note_directory_drift()['directory|shape/lock_after']['at'], when)
# Sticky on purpose: a value that goes back to what it was is still a value
# that moved, and the page must not quietly forget it.
SAID['directory|shape/lock_after']['v'] = 5
ok('...and a value that changes back is still a value that changed',
   'directory|shape/lock_after' in daemon16.note_directory_drift(), True)

said = daemon16.directory_alarm()
ok('the whole dashboard is told, not only the domain page', said.get('n'), 3)
ok('...and it is told what moved',
   sorted(one['words'] for one in said['rows'])[:2],
   ['Locks after', 'No password needed'])

# Two directories, and one of them slow one morning. Its reading did not
# come back, so it says nothing about its groups - which is not every one of
# its administrators taken away.
daemon16.remember_directory(by='a test')
SAID['directory|answered'] = {'words': 'answered', 'v': True, 'meta': True,
                              'groups': True, 'shape': True}
SAID['directory2|answered'] = {'words': 'answered', 'v': True, 'meta': True,
                               'groups': True, 'shape': True}
SAID['directory2|group/domain admins'] = {'words': 'Who is in domain admins',
                                          'v': ['admin2', 'mdolezal']}
daemon16.remember_directory(by='a test')
gone = SAID.pop('directory2|group/domain admins')
SAID.pop('directory2|answered')
ok('a second directory that did not answer this time has changed nothing',
   daemon16.note_directory_drift(), {})
SAID['directory2|answered'] = {'words': 'answered', 'v': True, 'meta': True,
                               'groups': False, 'shape': True}
ok('...and nor has one that answered without getting as far as its groups',
   daemon16.note_directory_drift(), {})
SAID['directory2|answered']['groups'] = True
ok('...while one that answered, with its groups, and one group gone, has',
   'directory2|group/domain admins' in daemon16.note_directory_drift(), True)
# What an earlier version said about such a morning is taken back once the
# directory answers again with what was remembered.
SAID['directory2|group/domain admins'] = gone
ok('...and a list said to be gone that is back as it was is taken back',
   daemon16.note_directory_drift(), {})
for key in ('directory|answered', 'directory2|answered', 'directory2|group/domain admins'):
    SAID.pop(key, None)

# Two ways to clear it, and only two.
daemon16.remember_directory(by='a test')
ok('remembering again takes the red away', daemon16.directory_alarm(), {})
SAID['directory|counts/no_password']['v'] = 99
daemon16.note_directory_drift()
ok('...and what happens after that is noticed from there',
   daemon16.directory_alarm().get('n'), 1)
# The day's work is not an alarm. A domain gains and loses accounts every
# day, people join groups and leave them, machines are built and retired -
# and a page that goes red for any of that is a page nobody reads by
# Thursday. What IS watched is who can do what, and what protects the domain.
daemon16.what_directory_says = lambda ask=False, force=False: {'where': [{
    'which': 'directory', 'at': 1.0,
    'shape': {'lock_after': 5, 'password_least': 12,
              'controllers': [{'name': 'dc1.example.loc'}],
              'trusts': [{'with': 'other.loc'}]},
    'counts': {'service': 1460, 'disabled': 765, 'was_admin': 115,
               'never_expires': 408, 'no_password': 83, 'nopreauth': 0,
               'delegating': 5, 'delegating_any': 1, 'smartcard': 0},
    'privileged': 38,
    'groups': {'domain admins': ['mdolezal']}}]}
# The real one, not the stub this section has been using.
snap = isemon.Daemon.directory_snapshot(daemon16)
ok('an account made or deleted does not raise anything',
   [k for k in snap if k.endswith('counts/service') or k.endswith('counts/disabled')], [])
ok('...and neither does how MANY people run the domain',
   [k for k in snap if k.endswith('counts/privileged')], [])
ok('...nor a password that was set to expire or not',
   [k for k in snap if k.endswith('counts/never_expires')
    or k.endswith('counts/was_admin')], [])
ok('...while WHO runs the domain is watched by name',
   'directory|group/domain admins' in snap, True)
ok('...and so are its controllers and its trusts',
   ['directory|controllers' in snap, 'directory|trusts' in snap], [True, True])
ok('...and the rules that protect it', 'directory|shape/lock_after' in snap, True)
ok('...and the handful of flags that make an account easier to get into',
   sorted(k.split('/')[-1] for k in snap if '|counts/' in k),
   ['delegating', 'delegating_any', 'no_password', 'nopreauth'])
daemon16.forget_directory(by='a test')
ok('...and switching the watching off takes it away as well',
   daemon16.directory_alarm(), {})
isemon.CONFIG['directory_watch'] = 0
ok('...and off, nothing is said at all', daemon16.directory_alarm(), {})
shutil.rmtree(folder16, ignore_errors=True)

# ---------------------------------------------------------------------------
title('A ticket HANDED OVER without pre-authentication, not one asked for')
# Every Windows client on the domain opens with a pre-authentication-less
# request and is told to do it properly; every request that fails for any
# other reason never gets that far either. Counting those made the alarm the
# ordinary morning. What matters is a ticket the domain actually gave out
# without asking the account to prove anything - that is the one somebody
# takes away and cracks at home.
folder17, store17, daemon17 = fresh()
WHEN17 = time.strftime('%b %d %H:%M:%S', time.localtime(time.time() - 60))
ASREQ = ('A Kerberos authentication ticket (TGT) was requested.  '
         'Account Information:  Account Name:  %s  Supplied Realm Name:  CORPNET  '
         'Service Information:  Service Name:  krbtgt/CORPNET.LOC  '
         'Network Information:  Client Address:  ::ffff:10.0.0.51  Client Port:  50001  '
         'Additional Information:  Ticket Options:  0x40810010  Result Code:  %s  '
         'Ticket Encryption Type:  0x12  Pre-Authentication Type:  %s')
daemon17.read_records([
    # The ordinary first packet of every Kerberos sign-in there has ever
    # been: asked without pre-authentication, told to do it properly.
    '%s dc1 WinSecurity: EventID=4768 | %s' % (WHEN17, ASREQ % ('ordinary', '0x19', '-')),
    # A name nobody has, which never gets as far as pre-authentication.
    '%s dc1 WinSecurity: EventID=4768 | %s' % (WHEN17, ASREQ % ('nice_ok0522', '0x6', '-')),
    # ...and the one that matters: a ticket handed over, with nothing asked.
    '%s dc1 WinSecurity: EventID=4768 | %s' % (WHEN17, ASREQ % ('roastme', '0x0', '0')),
], 'winsec')
daemon17.flush_win_events()
rows17, _n17 = store17.win_rows(limit=20, since=time.time() - 3600)
marked17 = sorted(r['account'] for r in rows17 if 'nopreauth' in (r.get('mark') or ''))
ok('a ticket the domain handed over with nothing asked is the alarm',
   marked17, ['roastme'])
ok('...the ordinary first packet of every sign-in is not',
   'ordinary' in marked17, False)
ok('...and neither is a request that failed for some other reason',
   'nice_ok0522' in marked17, False)
# ...and the same rule for RC4: a ticket that was REFUSED was never handed
# over, so there is nothing to take away and crack.
TICKET17 = ('A Kerberos service ticket was requested.  Account Information:  '
            'Account Name:  %s@CORPNET.LOC  Account Domain:  CORPNET.LOC  '
            'Service Information:  Service Name:  MSSQLSvc/db1  '
            'Network Information:  Client Address:  ::ffff:10.0.0.52  Client Port:  50002  '
            'Additional Information:  Ticket Options:  0x40810000  '
            'Ticket Encryption Type:  0x17  Failure Code:  %s')
daemon17.read_records([
    '%s dc1 WinSecurity: EventID=4769 | %s' % (WHEN17, TICKET17 % ('handed', '0x0')),
    '%s dc1 WinSecurity: EventID=4769 | %s' % (WHEN17, TICKET17 % ('refused', '0x1f')),
], 'winsec')
daemon17.flush_win_events()
rows17b, _n17b = store17.win_rows(limit=20, since=time.time() - 3600)
rc4_17 = sorted(r['account'] for r in rows17b if 'rc4' in (r.get('mark') or ''))
ok('a service ticket handed over in RC4 is the alarm', 'handed@CORPNET.LOC' in rc4_17, True)
ok('...and one the domain refused is not', 'refused@CORPNET.LOC' in rc4_17, False)
shutil.rmtree(folder17, ignore_errors=True)

# ---------------------------------------------------------------------------
title('The stored events are read again once, not on every restart')
# The walk is minutes on a million events and the page crawls while it
# happens. It is worth doing when what a stored row MEANS has changed - a
# controller named, a new version reading them differently - and worth doing
# exactly once for each of those. A row that would not decode is not a reason
# to do the whole thing again tomorrow: it will not decode tomorrow either.
folder18, store18, daemon18 = fresh()
daemon18.read_records([
    '%s dc1 WinSecurity: EventID=4624 | An account was successfully logged on.  '
    'Subject:  Account Name:  someone  Logon Type:  3'
    % time.strftime('%b %d %H:%M:%S', time.localtime(time.time() - 60))], 'winsec')
daemon18.flush_win_events()
store18.fill_in_win_marks(again=True)
ok('...the first pass writes down that it was done',
   bool(store18.get_meta('win_sorted')), True)
ok('...so the next start walks nothing at all', store18.win_marks_plan()[0], {})
# ...and the same after a row that could not be read. It used to leave the
# note unwritten, and the whole table was walked again on every restart for
# ever.
store18.set_meta('win_sorted', '')
with store18.db_write() as db18:
    db18.execute('UPDATE win_events SET detail = ?', (b'not a record at all',))
store18.fill_in_win_marks(again=True)
ok('a row that would not decode still leaves the pass written down',
   bool(store18.get_meta('win_sorted')), True)
ok('...and the next start does not walk the table again', store18.fill_in_win_marks(), 0)
shutil.rmtree(folder18, ignore_errors=True)

# ---------------------------------------------------------------------------
title('Reading the stored events again touches only what can have changed')
# The whole of this: a site with a billion events cannot walk them because
# somebody named a controller. Only the rows ABOUT that machine can change,
# and this proves it end to end rather than in the plan.
folder19, store19, daemon19 = fresh()
WHEN19 = time.strftime('%b %d %H:%M:%S', time.localtime(time.time() - 60))
REPL = ('An operation was performed on an object.  Subject:  Account Name:  %s  '
        'Object:  Object Type:  domainDNS  Object Name:  DC=corpnet,DC=loc  '
        'Operation:  Properties:  Control Access  '
        '{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}  '
        'Accesses:  Control Access')
daemon19.read_records(
    ['%s dc1 WinSecurity: EventID=4662 | %s' % (WHEN19, REPL % 'DC-ONE$'),
     '%s dc1 WinSecurity: EventID=4662 | %s' % (WHEN19, REPL % 'DC-TWO$'),
     '%s dc1 WinSecurity: EventID=4662 | %s' % (WHEN19, REPL % 'somebody')],
    'winsec')
daemon19.flush_win_events()


def marks19():
    return {str(r['account']): str(r['mark'] or '') for r in
            store19.db.execute('SELECT account, mark FROM win_events').fetchall()}


ok('nobody is excused while no machine is named',
   [w for w, m in marks19().items() if 'expected' in m], [])
store19.win_marks_noted()
ok('...and that is written down', store19.win_marks_plan()[0], {})

# One controller named. The rows about the OTHER two accounts must not even
# be looked at, so they are made unreadable first: if the pass touched them
# it would count them as rows it could not read, and it does not.
isemon.CONFIG['winsec_controllers'] = 'DC-ONE'
daemon19.note_controllers(force=True)
plan19, why19 = store19.win_marks_plan()
ok('naming one controller asks for the rows about that one machine',
   plan19, {'accounts': ['dc-one']})
ok('...and says so in words a person can read', 'dc-one' in why19, True)
did = store19.fill_in_win_marks()
ok('...and one row is rewritten, not three', did, 1)
after19 = marks19()
ok('...the machine that was named is excused',
   'expected' in after19.get('DC-ONE$', ''), True)
ok('...and nothing else is', [w for w, m in after19.items() if 'expected' in m],
   ['DC-ONE$'])
ok('...and it is not read again for nothing', store19.win_marks_plan()[0], {})

# A row that reads exactly as it already reads is not written. That is most
# of them on any real upgrade, and it is the difference between ten hours and
# twenty minutes on a site with millions.
was_marks = {str(r['ident']): str(r['mark'] or '') for r in
             store19.db.execute('SELECT ident, mark FROM win_events').fetchall()}
ok('a pass that changes nothing writes nothing',
   store19.fill_in_win_marks(again=True), 0)
ok('...and leaves every row exactly as it was',
   {str(r['ident']): str(r['mark'] or '') for r in
    store19.db.execute('SELECT ident, mark FROM win_events').fetchall()}, was_marks)

# ...and it picks up where it stopped rather than starting again, which on
# seven million rows is the difference between finishing and never finishing.
store19.set_meta('win_reading', '')
store19.set_meta('win_reading_at', json.dumps(
    {'plan': json.dumps({'all': True}, sort_keys=True), 'after': 'zzzz', 'at': time.time()}))
ok('a pass left half done starts from where it stopped',
   (store19.meta_json('win_reading_at', None) or {}).get('after'), 'zzzz')
store19.fill_in_win_marks(again=True)
ok('...and once it is finished, there is nowhere to pick up from',
   store19.get_meta('win_reading_at'), '')

# ...and a version that changed the reading of two event numbers asks for
# those two event numbers and nothing else.
was19 = store19.meta_json('win_reading', None) or {}
store19.set_meta('win_reading', json.dumps(dict(was19, version=3)))
ok('a version that changed two events walks neither of the others',
   store19.fill_in_win_marks(), 0)
ok('...and is written down as done all the same',
   store19.win_marks_plan()[0], {})
isemon.CONFIG['winsec_controllers'] = ''
shutil.rmtree(folder19, ignore_errors=True)

# ---------------------------------------------------------------------------
title('The domain page comes back with what is ready, and says so')
# Twenty walks of a window of a table that on a real site holds millions.
# Asked one after another the page took half a minute to build, and a browser
# gives up long before that - then asks again and sets the twenty going a
# second time, so the tab never filled in at all.
folderS = tempfile.mkdtemp(prefix='isemon-soon-')
isemon.STATE_DIR = Path(folderS)
isemon.DB_FILE = Path(folderS) / 'soon.db'
storeS = isemon.Storage()
daemonS = isemon.Daemon(storeS)
slow = []


def slowly():
    slow.append(1)
    time.sleep(0.4)
    return 'the answer'


ok('the first ask comes back at once, with nothing for that part',
   daemonS.soon('one', 30, slowly, 'not yet'), 'not yet')
ok('...and says the page is not whole', getattr(daemonS._soon_tl, 'all', True), False)
time.sleep(0.8)
daemonS._soon_tl.all = True
ok('...and a moment later the answer is there',
   daemonS.soon('one', 30, slowly, 'not yet'), 'the answer')
ok('...and it was only worked out once', len(slow), 1)
ok('...and the page is whole', getattr(daemonS._soon_tl, 'all', True), True)
# ...and whoever must have the whole of it says so and waits.
ok('somebody who must have it waits for it',
   daemonS.soon('two', 30, slowly, 'not yet', wait=True), 'the answer')
first = daemonS.win_summary(1, wait=True)
ok('the whole answer is never half a page', first.get('working'), False)

# ...and something CHANGING does not empty the page. A lockout - or anything
# else worth waking the page for - throws away what is kept about the domain
# so that the next ask works it out afresh. Thrown away outright, that ask
# got nothing at all: the card was empty and the page said it was still
# working something out. On the domain this was found on, something worth
# waking for arrived every couple of minutes, which is oftener than a card
# of it took to build, so the page said so for ever and the same walks were
# done over and over for nothing.
slow[:] = []
daemonS._soon_tl.all = True
daemonS.forget_held('one')
ok('after a change the page is still drawn, from the answer of a moment ago',
   daemonS.soon('one', 30, slowly, 'not yet'), 'the answer')
ok('...and does not claim to be still working it out', getattr(daemonS._soon_tl, 'all', True), True)
time.sleep(0.8)
ok('...and the fresh answer was set going by that same ask', len(slow), 1)
# ...and a change to something else does not touch it at all.
daemonS._soon_tl.all = True
daemonS.forget_held('somethingelse/')
ok('a change to something else leaves this answer alone',
   (daemonS.soon('one', 30, slowly, 'not yet'), len(slow)), ('the answer', 1))
# ...nor does it discard an answer being worked out at that moment.
slow[:] = []
daemonS._slow.clear()
daemonS._soon_tl.all = True
daemonS.soon('one', 30, slowly, 'not yet')          # sets it going
time.sleep(0.1)
daemonS.forget_held('somethingelse/')
time.sleep(0.6)
daemonS._soon_tl.all = True
ok('an answer worked out across an unrelated change is kept',
   (daemonS.soon('one', 30, slowly, 'not yet'), len(slow)), ('the answer', 1))
shutil.rmtree(folderS, ignore_errors=True)

# ---------------------------------------------------------------------------
title('What is kept at all, on a domain that writes millions a day')
# Measured on a real domain: of 756,000 events in a day, 500,000 were
# successful sign-ins and 241,000 were objects being read out of the
# directory. Everything this page exists for - the refusals, the lockouts,
# the accounts and groups being changed - was 2,083 of them. Three tenths of
# one percent. Keeping the rest costs a gigabyte a day and every question
# the page asks has to walk past all of it.
folderK = tempfile.mkdtemp(prefix='isemon-keep-')
isemon.STATE_DIR = Path(folderK)
isemon.DB_FILE = Path(folderK) / 'keep.db'
isemon.CONFIG.update({'winsec': 1, 'winsec_ignore': '', 'winsec_machines': 1,
                      'winsec_keep_logons': 1, 'winsec_keep_reads': 1,
                      'winsec_controllers': '', 'winsec_expected': ''})
storeK = isemon.Storage()
daemonK = isemon.Daemon(storeK)
WHENK = time.strftime('%b %d %H:%M:%S', time.localtime(time.time() - 60))
LINES = [
    # a sign-in that worked: most of a busy domain
    '%s dc1 WinSecurity: EventID=4624 | An account was successfully logged on.  '
    'Subject:  Account Name:  somebody  Logon Type:  3' % WHENK,
    # an object read out of the directory: most of the rest
    '%s dc1 WinSecurity: EventID=4662 | An operation was performed on an object.  '
    'Subject:  Account Name:  service1  Object:  Object Type:  group  '
    'Object Name:  CN=Staff  Operation:  Properties:  Read Property' % WHENK,
    # ...and the one anybody came here for
    '%s dc1 WinSecurity: EventID=4740 | A user account was locked out.  '
    'Subject:  Account Name:  DC1$  Account That Was Locked Out:  '
    'Account Name:  novak  Additional Information:  Caller Computer Name:  NB-NOVAK'
    % WHENK,
    # ...and a read that IS worth knowing about: a machine asking to
    # replicate every password in the domain.
    '%s dc1 WinSecurity: EventID=4662 | An operation was performed on an object.  '
    'Subject:  Account Name:  MEMBER$  Object:  Object Type:  domainDNS  '
    'Object Name:  DC=corpnet,DC=loc  Operation:  Properties:  Control Access  '
    '{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}' % WHENK,
]


def kept(lines):
    got = isemon.win_parse_lines(lines)
    return sorted(one.facts['kind'] for one in got)


ok('with both on, everything is kept',
   kept(LINES), ['lockout', 'logon', 'read', 'read'])
isemon.CONFIG['winsec_keep_logons'] = 0
ok('...the sign-ins go when they are switched off',
   'logon' in kept(LINES), False)
isemon.CONFIG['winsec_keep_reads'] = 0
ok('...and the reads with them', kept(LINES), ['lockout', 'read'])
ok('...but a read that asked to replicate every password is KEPT',
   [one.facts['mark'] for one in isemon.win_parse_lines(LINES)
    if one.facts['kind'] == 'read'], ['replication'])
ok('...and the lockout is never in question',
   'lockout' in kept(LINES), True)
# ...and what is already stored goes with them, at any age, when the
# clean-up runs. Switching a group off and then waiting thirty days for the
# retention to catch up is not an answer on a domain writing millions a day.
isemon.CONFIG.update({'winsec_keep_logons': 1, 'winsec_keep_reads': 1})
for one in isemon.win_parse_lines(LINES):
    storeK.note_win_event(one.facts)

ok('everything is stored while both are on',
   sorted(r['kind'] for r in
          storeK.db.execute('SELECT kind FROM win_events').fetchall()),
   ['lockout', 'logon', 'read', 'read'])
isemon.CONFIG.update({'winsec_keep_logons': 0, 'winsec_keep_reads': 0,
                      'winsec_keep_days': 0})
daemonK.tidy_old_rows()
ok('...and the clean-up lets go of what is no longer kept, at any age',
   sorted(r['kind'] for r in
          storeK.db.execute('SELECT kind FROM win_events').fetchall()),
   ['lockout', 'read'])
ok('...the read that was kept is the one that asked to replicate',
   [r['mark'] for r in
    storeK.db.execute("SELECT mark FROM win_events WHERE kind='read'").fetchall()],
   ['replication'])
# ...and the SIGN-OUTS with the sign-ins. Found on a real install: the site
# switched the sign-ins off, pressed the button, and half the volume stayed
# exactly where it was - 284,653 sign-outs against 284,395 sign-ins, the
# biggest group in the whole table, under no switch at all. A 4634 exists
# only because a 4624 did; keeping one without the other is nothing anybody
# asked for.
BULK = {key: kinds for key, kinds, _d in isemon.WIN_BULK}
ok('a sign-out is under the same switch as the sign-in it followed',
   'logoff' in BULK['winsec_keep_logons'], True)
ok('...and so is a program being started, for the same reason',
   'process' in BULK['winsec_keep_logons'], True)
OUT = ('%s dc1 WinSecurity: EventID=4634 | An account was logged off.  '
       'Subject:  Account Name:  somebody  Logon Type:  3' % WHENK)
isemon.CONFIG.update({'winsec_keep_logons': 1, 'winsec_keep_reads': 1})
ok('a sign-out is read while the switch is on',
   kept([OUT]), ['logoff'])
isemon.CONFIG['winsec_keep_logons'] = 0
ok('...and goes with the sign-ins when it is off', kept([OUT]), [])
isemon.CONFIG.update({'winsec_keep_logons': 1, 'winsec_keep_reads': 1})
for one in isemon.win_parse_lines([OUT]):
    storeK.note_win_event(one.facts)
ok('...and one already stored is stored',
   [r['kind'] for r in
    storeK.db.execute("SELECT kind FROM win_events WHERE kind='logoff'").fetchall()],
   ['logoff'])
isemon.CONFIG.update({'winsec_keep_logons': 0, 'winsec_keep_reads': 0,
                      'winsec_keep_days': 0})
daemonK.tidy_old_rows()
ok('...and the clean-up lets go of it too',
   [r['kind'] for r in
    storeK.db.execute("SELECT kind FROM win_events WHERE kind='logoff'").fetchall()],
   [])

# A mark spares a row from a switch that has been turned off - but only a
# mark that SAYS something. A site running virtual desktops marks the
# machinery `routine` so that nobody is ever shown it, and that very mark
# was sparing the one thing nobody wanted to keep.
ok('"routine" and "expected" are not finds',
   sorted(isemon.WIN_ROUTINE_MARKS), ['expected', 'routine'])
ok('...so a row marked only "routine" tells nothing',
   isemon.win_tells_something('routine'), False)
ok('...nor one marked "expected,routine"',
   isemon.win_tells_something('expected,routine'), False)
ok('...while one that found something does',
   isemon.win_tells_something('replication,expected'), True)
ok('...and the number says the same', bool(isemon.win_telling_bits()
   & isemon.WIN_MARK_BITS['replication']), True)
ok('...with the machinery left out of it', bool(isemon.win_telling_bits()
   & (isemon.WIN_MARK_BITS['routine'] | isemon.WIN_MARK_BITS['expected'])), False)
isemon.CONFIG.update({'winsec_keep_logons': 1, 'winsec_keep_reads': 1})
for kind, mark in (('logon', 'routine'), ('logon', 'cleartext')):
    storeK.note_win_event({
        'ident': 'mk-%s-%s' % (kind, mark), 'ts': time.time(), 'event': 4624,
        'kind': kind, 'account': 'vdi1$', 'mark': mark, 'server': 'dc1'})
isemon.CONFIG.update({'winsec_keep_logons': 0, 'winsec_keep_reads': 0,
                      'winsec_keep_days': 0})
daemonK.tidy_old_rows()
ok('a row marked only "routine" goes with the rest of its group',
   [r['mark'] for r in storeK.db.execute(
       "SELECT mark FROM win_events WHERE kind='logon'").fetchall()],
   ['cleartext'])

# A group can be KEPT and still not be kept as long as the rest. What this
# page is for - the refusals, the lockouts, the changes - is worth three
# months; every machine in the building signing in is not, and on a busy
# domain it is two thirds of everything. One number for both meant choosing
# which of the two to get wrong.
ok('each group can name its own number of days',
   sorted(d for _k, _n, d in isemon.WIN_BULK),
   ['winsec_logons_days', 'winsec_reads_days'])
isemon.CONFIG.update({'winsec_keep_logons': 1, 'winsec_keep_reads': 1,
                      'winsec_keep_days': 90, 'winsec_logons_days': 0,
                      'winsec_reads_days': 0})
OLD = time.time() - 30 * 86400          # a month back: inside ninety days
for n, kind in enumerate(('logon', 'read', 'lockout', 'kerberos-failed')):
    storeK.note_win_event({'ident': 'few-%d' % n, 'ts': OLD, 'event': 4624,
                           'kind': kind, 'account': 'novak', 'server': 'dc1'})


def kindsLeft():
    return sorted(r['kind'] for r in storeK.db.execute(
        "SELECT kind FROM win_events WHERE ident LIKE 'few-%'").fetchall())


daemonK.tidy_old_rows()
ok('with no number of their own, a month-old row survives ninety days',
   kindsLeft(), ['kerberos-failed', 'lockout', 'logon', 'read'])
isemon.CONFIG['winsec_logons_days'] = 7
daemonK.tidy_old_rows()
ok('...and seven days for the sign-ins takes that one and nothing else',
   kindsLeft(), ['kerberos-failed', 'lockout', 'read'])
isemon.CONFIG['winsec_reads_days'] = 7
daemonK.tidy_old_rows()
ok('...and the same for the reads', kindsLeft(), ['kerberos-failed', 'lockout'])
# ...but never at the cost of an alarm.
storeK.note_win_event({'ident': 'few-mark', 'ts': OLD, 'event': 4662,
                       'kind': 'read', 'account': 'MEMBER$', 'server': 'dc1',
                       'mark': 'replication'})
daemonK.tidy_old_rows()
ok('a marked read is kept for the full time whatever the short number says',
   [r['ident'] for r in storeK.db.execute(
       "SELECT ident FROM win_events WHERE ident = 'few-mark'").fetchall()],
   ['few-mark'])
# A number LONGER than the one everything else is kept for is not a way of
# keeping these longer: nothing outlives that one.
isemon.CONFIG.update({'winsec_keep_days': 10, 'winsec_logons_days': 365,
                      'winsec_reads_days': 0})
storeK.note_win_event({'ident': 'few-long', 'ts': OLD, 'event': 4624,
                       'kind': 'logon', 'account': 'novak', 'server': 'dc1'})
daemonK.tidy_old_rows()
ok('a longer number does not outlive the one everything else is kept for',
   [r['ident'] for r in storeK.db.execute(
       "SELECT ident FROM win_events WHERE ident = 'few-long'").fetchall()], [])
isemon.CONFIG.update({'winsec_keep_days': 0, 'winsec_logons_days': 0,
                      'winsec_reads_days': 0})

# ...and the counted answers go with exactly the rows that went, and not one
# more. Found on a live domain: a site that had given the sign-ins seven days
# had every sign-in bucket there was thrown away on every nightly clean-up,
# at every age, while the events themselves stayed. What was left was
# whatever had arrived since; the counting then read a fifth of the events in
# the table and the page was put aside as untrustworthy - correctly, and for
# a reason that was in the throwing-away rather than in the counting.
isemon.CONFIG.update({'winsec_rollup': 1, 'winsec_keep_logons': 1,
                      'winsec_keep_reads': 1, 'winsec_keep_days': 0,
                      'winsec_logons_days': 0, 'winsec_reads_days': 0})
folderF = tempfile.mkdtemp(prefix='isemon-forget-')
WAS_F, WAS_FDB = isemon.STATE_DIR, isemon.DB_FILE
isemon.STATE_DIR = Path(folderF)
isemon.DB_FILE = Path(folderF) / 'forget.db'
storeF = isemon.Storage()
daemonF = isemon.Daemon(storeF)
NOWF = time.time()
storeF.note_win_events(
    # A fortnight of sign-ins and a fortnight of refusals, a day apart. An
    # hour past the day: the cut is on the hour since 1.10.93, so that what
    # goes and what the buckets count are the same rows, and an event on
    # the very second of the cut would be inside it.
    [{'ident': 'f-%d-%s' % (d, k), 'ts': NOWF - d * 86400 - 3600, 'event': 4624,
      'kind': k, 'account': 'novak%d' % (d % 4), 'machine': 'NB-1',
      'ip': '10.0.0.1', 'said': 'x', 'server': 'dc1'}
     for d in range(14) for k in ('logon', 'logon-failed')])
storeF.roll_build()
ok('a fortnight of each is counted',
   storeF.roll_counts(storeF.roll_floor(NOWF - 30 * 86400)),
   {'logon': 14, 'logon-failed': 14})
# Seven days for the sign-ins, everything else kept for ever.
isemon.CONFIG['winsec_logons_days'] = 7
daemonF.tidy_old_rows()
LEFTF = sorted((r['kind'], r['n']) for r in storeF.db.execute(
    'SELECT kind, COUNT(*) AS n FROM win_events GROUP BY kind').fetchall())
ok('the events older than seven days went, and only the sign-ins',
   LEFTF, [('logon', 7), ('logon-failed', 14)])
ok('...and the counted answers say exactly the same',
   sorted(storeF.roll_counts(storeF.roll_floor(NOWF - 30 * 86400)).items()),
   [('logon', 7), ('logon-failed', 14)])
ok('...with every sum still adding up', storeF.roll_whole(), [])
# ...while a group switched off ENTIRELY does go at every age, buckets and all.
isemon.CONFIG.update({'winsec_logons_days': 0, 'winsec_keep_logons': 0})
daemonF.tidy_old_rows()
ok('a group switched off goes at every age',
   sorted(storeF.roll_counts(storeF.roll_floor(NOWF - 30 * 86400)).items()),
   [('logon-failed', 14)])
ok('...and the sums still add up', storeF.roll_whole(), [])
isemon.CONFIG.update({'winsec_keep_logons': 1, 'winsec_rollup': 1,
                      'winsec_keep_days': 0, 'winsec_logons_days': 0})
isemon.STATE_DIR, isemon.DB_FILE = WAS_F, WAS_FDB
shutil.rmtree(folderF, ignore_errors=True)

# ...and when it takes nothing, it says why. "0 in 0 s" in the log, with
# thousands of rows still on the page, is a clean-up that has either found
# nothing or decided nothing - and those are different faults with different
# cures and looked exactly alike.
isemon.CONFIG.update({'winsec_keep_logons': 1, 'winsec_keep_reads': 1,
                      'retain_failed_days': 0, 'retain_passed_days': 0,
                      'retain_events_days': 0, 'winsec_keep_days': 0})
SAID = daemonK.why_nothing_went()
ok('nothing removed says which rules keep everything',
   'kept for ever' in SAID, True)
ok('...and names the groups the domain is still keeping',
   'the sign-ins and the directory reads' in SAID, True)
isemon.CONFIG.update({'retain_failed_days': 90, 'retain_passed_days': 365,
                      'retain_events_days': 90, 'winsec_keep_days': 30})
ok('...and with every rule set, says the rows are simply not old enough',
   'not older than' in daemonK.why_nothing_went()
   or 'nothing stored is older' in daemonK.why_nothing_went(), True)
isemon.CONFIG['winsec_keep_logons'] = 0
ok('...and stops naming a group once it is switched off',
   'the sign-ins' in daemonK.why_nothing_went(), False)

isemon.CONFIG.update({'winsec_keep_logons': 1, 'winsec_keep_reads': 1, 'winsec': 0,
                      'winsec_machines': 0, 'winsec_keep_days': 30})
shutil.rmtree(folderK, ignore_errors=True)

# ---------------------------------------------------------------------------
title('A line a switch has already decided against is never read')
# Turning a line into an event is the expensive half of the whole write path:
# on a real domain's day it was 53% of the time, more than making the rows
# and giving them to the database put together. On a site that has switched
# the sign-ins off, most of that work is done to decide the answer is to be
# thrown away - so the decision is made off the event number and a look at
# the line, first. What it may never do is drop a line this program would
# have found something in.
isemon.CONFIG.update({'winsec': 1, 'winsec_machines': 1, 'winsec_vdi': 0,
                      'winsec_keep_logons': 1, 'winsec_keep_reads': 1})
WHENB = time.strftime('%b %d %H:%M:%S', time.localtime(time.time() - 60))


def bline(event, rest=''):
    return ('%s dc1 WinSecurity: EventID=%d | Something happened.  '
            'Subject:  Account Name:  novak  %s' % (WHENB, event, rest))


ok('with everything kept, every line is worth reading',
   [isemon.win_worth_reading(e, bline(e)) for e in (4624, 4634, 4776, 4662)],
   [True, True, True, True])
isemon.CONFIG['winsec_keep_logons'] = 0
ok('...and with the sign-ins off, a sign-in and a sign-out are not',
   [isemon.win_worth_reading(e, bline(e)) for e in (4624, 4627, 4634, 4647, 4689)],
   [False, False, False, False, False])
ok('...but a refusal always is', isemon.win_worth_reading(4625, bline(4625)), True)
# The one that was actually got wrong: an event whose KIND depends on how the
# domain answered. A 4776 is an NTLM validation when it worked and a refusal
# when it did not, and a refusal is never one of the kinds a switch reaches.
# Read off its number alone, a day of a real domain lost 1,074 refusals.
ok('...and so is an event whose kind depends on the answer it got',
   [isemon.win_worth_reading(e, bline(e)) for e in sorted(isemon.WIN_EITHER_WAY)],
   [True] * len(isemon.WIN_EITHER_WAY))
ok('...and one whose number alone can earn a mark',
   [isemon.win_worth_reading(e, bline(e)) for e in (4662, 4672, 4728, 4648, 1102)],
   [True] * 5)
# ...and the two marks any event at all can earn are words that have to BE in
# the line, so a line carrying one is read however its group is set.
ok('a sign-in by ANONYMOUS LOGON is read even with the sign-ins off',
   isemon.win_worth_reading(4624, bline(4624, 'Account Name:  ANONYMOUS LOGON')), True)
ok('...and one with the password sent in the clear',
   isemon.win_worth_reading(4624, bline(4624, 'Logon Type:  8')), True)
ok('...while an ordinary logon type is not',
   isemon.win_worth_reading(4624, bline(4624, 'Logon Type:  3')), False)
# ...and end to end: the same lines read both ways come out the same.
LINESB = [bline(e, w) for e, w in (
    (4624, 'Logon Type:  3'), (4624, 'Logon Type:  8'),
    (4624, 'Account Name:  ANONYMOUS LOGON'), (4634, ''), (4627, ''), (4689, ''),
    (4776, 'Error Code:  0xC000006A'), (4776, 'Error Code:  0x0'),
    (4625, 'Sub Status:  0xC000006A'), (4740, ''), (4662, ''))]


def bothB():
    keep = isemon.win_worth_reading
    isemon.win_worth_reading = lambda event, line: True
    slow = [o.facts['ident'] for o in isemon.win_parse_lines(LINESB)]
    isemon.win_worth_reading = keep
    fast = [o.facts['ident'] for o in isemon.win_parse_lines(LINESB)]
    return slow, fast


for onB, offB in ((1, 1), (0, 1), (0, 0)):
    isemon.CONFIG.update({'winsec_keep_logons': onB, 'winsec_keep_reads': offB})
    slowB, fastB = bothB()
    ok('sign-ins %s and reads %s: reading every line and dropping first agree'
       % ('on' if onB else 'off', 'on' if offB else 'off'), slowB, fastB)
isemon.CONFIG.update({'winsec_keep_logons': 1, 'winsec_keep_reads': 1,
                      'winsec': 0, 'winsec_machines': 0})

# ---------------------------------------------------------------------------
title('The engine counts the same way this program does')
# The counting is done twice over: as the events arrive, by `roll_deltas`
# here, and from nothing by seven `INSERT ... SELECT` statements that never
# bring a row out of the database. Everything rests on the two agreeing, so
# they are made to prove it on real rows, on whichever engine this is.
folderR = tempfile.mkdtemp(prefix='isemon-roll-')
WAS_R, WAS_RDB = isemon.STATE_DIR, isemon.DB_FILE
isemon.STATE_DIR = Path(folderR)
isemon.DB_FILE = Path(folderR) / 'roll.db'
isemon.CONFIG.update({'winsec': 1, 'winsec_machines': 1, 'winsec_rollup': 1,
                      'winsec_keep_logons': 1, 'winsec_keep_reads': 1})
storeR = isemon.Storage()
NOWR = time.time()
KINDSR = ['logon-failed', 'kerberos-failed', 'ntlm-failed', 'lockout', 'logon', 'read']
SAIDR = ['the password was wrong', 'no such account', 'it worked', '']
MARKR = ['', '', 'routine', 'expected', 'replication', 'replication,expected']
madeR = []
for i in range(900):
    madeR.append({
        'ident': 'rr-%d' % i, 'ts': NOWR - (i * 17) % (6 * 3600), 'event': 4625,
        'server': 'dc1', 'kind': KINDSR[i % len(KINDSR)],
        # ...including the awkward ones: a name longer than the column, one
        # with spaces at both ends, and one that is nothing but spaces.
        'account': ('n' * 200 if i % 97 == 0 else
                    ('  mezery  ' if i % 53 == 0 else 'novak%d' % (i % 30))),
        'is_machine': 1 if i % 5 == 0 else 0,
        'machine': 'NB-%d' % (i % 11), 'ip': '10.0.0.%d' % (i % 9),
        'said': SAIDR[i % len(SAIDR)],
        'by': 'admin%d' % (i % 3) if i % 4 == 0 else '',
        'object': ('CN=' + 'x' * 400) if i % 61 == 0 else ('CN=Staff' if i % 7 else ''),
        'mark': MARKR[i % len(MARKR)]})
storeR.note_win_events(madeR)


def bucketsR():
    return sorted(tuple(dict(r).values()) for r in storeR.db.execute(
        'SELECT span, at, dim, val, kind, mach, quiet, told, n, newest '
        'FROM win_rollup').fetchall())


asWrittenR = bucketsR()
ok('the counting as the events arrived is not empty', len(asWrittenR) > 100, True)
storeR.roll_build()
ok('...and the engine counting from nothing lands in the same place',
   bucketsR(), asWrittenR)
ok('...every sum adding up', storeR.roll_whole(), [])
ok('...and every hour agreeing line for line',
   [one for at in storeR.roll_hours(done=False) for one in storeR.roll_check(at)], [])
# The same reading asked of the ENGINE rather than done here. It exists
# because of what the other one costs: a site timed `--rollup-check` at
# twenty-five seconds, twenty-two of them this program's own processor,
# because proving a day means reading every event of that day out of the
# database to add them up here. The two must answer the same thing, and the
# only way to know that is to ask both.
ok('...and the engine reading it back says the same',
   [one for at in storeR.roll_hours(done=False) for one in storeR.roll_check_sql(at)],
   [])


def bothWaysR():
    """What each reading found, in one shape, so they can be compared."""
    out = []
    for at in storeR.roll_hours(done=False):
        out.append((sorted((x['dim'], x['val'], x['kind'], x['rows'], x['bucket'])
                           for x in storeR.roll_check(at)),
                    sorted((x['dim'], x['val'], x['kind'], x['rows'], x['bucket'])
                           for x in storeR.roll_check_sql(at))))
    return out


# ...and where something IS wrong, which is the answer that matters: a
# reading that agrees about nothing being wrong and disagrees about what is
# wrong has proved nothing at all.
with storeR.db_write() as dbR:
    dbR.execute("UPDATE win_rollup SET n = n + 3 WHERE dim = 'kind' AND span = 3600")
    dbR.execute("DELETE FROM win_rollup WHERE dim = 'machine' AND span = 3600")
BOTHR = bothWaysR()
ok('a bucket counted wrong is found by both readings, and they say the same',
   [a == b for a, b in BOTHR], [True] * len(BOTHR))
ok('...and what they found is not nothing',
   any(a for a, _b in BOTHR), True)
storeR.roll_build()
ok('...and counting them again mends it, by both readings',
   [a == b == [] for a, b in bothWaysR()], [True] * len(storeR.roll_hours(done=False)))
# ...and the two agree about the awkward values, which is where two ways of
# cutting a string part company.
LONGR = [r['val'] for r in storeR.db.execute(
    "SELECT DISTINCT val FROM win_rollup WHERE dim = 'account'").fetchall()]
ok('a name longer than its column is cut once, not twice',
   sorted({len(v) for v in LONGR if v.startswith('n' * 20)}), [180])
ok('...and the spaces around a name are kept, as the column keeps them',
   '  mezery  ' in LONGR, True)
isemon.STATE_DIR, isemon.DB_FILE = WAS_R, WAS_RDB
isemon.CONFIG.update({'winsec': 0, 'winsec_machines': 0})
shutil.rmtree(folderR, ignore_errors=True)

# ---------------------------------------------------------------------------
title('A lockout is on the page the moment it is written')
# The Domain page’s answers are counted ahead of time, and the answers it
# has already worked out are kept for a few seconds. Neither may stand
# between somebody watching this page and the thing they are watching FOR.
folderN = tempfile.mkdtemp(prefix='isemon-now-')
WAS_N, WAS_NDB = isemon.STATE_DIR, isemon.DB_FILE
isemon.STATE_DIR = Path(folderN)
isemon.DB_FILE = Path(folderN) / 'now.db'
isemon.CONFIG.update({'winsec': 1, 'winsec_machines': 1, 'winsec_rollup': 1,
                      'winsec_keep_logons': 1, 'winsec_keep_reads': 1})
storeN = isemon.Storage()
daemonN = isemon.Daemon(storeN)
NOWN = time.time()
storeN.note_win_events([
    {'ident': 'nq-%d' % i, 'ts': NOWN - 7200 + i, 'event': 4624, 'kind': 'logon',
     'account': 'novak%d' % (i % 5), 'machine': 'NB-1', 'ip': '10.0.0.1',
     'said': 'it worked', 'server': 'dc1'} for i in range(200)])
ok('the counting is built and proved', daemonN._roll_build_now(), True)
ok('...and the page believes it', storeN.roll_ready(), True)
BEFORE = daemonN.win_summary(24, wait=True)
ok('nothing is locked to start with', len(BEFORE['lockouts']), 0)
ok('...and nothing stands out', len(BEFORE['incidents']), 0)
# ...and now it happens, written exactly the way the reader writes it.
ATN = time.time()
daemonN._win_waiting = (
    [{'ident': 'nb-%d' % i, 'ts': ATN - 60 + i, 'event': 4625,
      'kind': 'logon-failed', 'account': 'novakova', 'machine': 'NB-9',
      'ip': '10.0.0.9', 'said': 'the password was wrong', 'server': 'dc1'}
     for i in range(30)]
    + [{'ident': 'nlock', 'ts': ATN, 'event': 4740, 'kind': 'lockout',
        'account': 'novakova', 'machine': 'NB-9', 'ip': '10.0.0.9',
        'server': 'dc1'}])
daemonN.flush_win_events()
SAIDN = daemonN.win_summary(24, wait=True)
ok('the lockout is on the page at once',
   [one['account'] for one in SAIDN['lockouts']], ['novakova'])
ok('...and so is the pattern behind it',
   sorted({one['kind'] for one in SAIDN['incidents']}), ['brute'])
ok('...and what keeps trying the password',
   [r['said'] for v in SAIDN['views'] if v['key'] == 'holding' for r in v['rows']],
   ['novakova'])
ok('the counted answers have the refusals at once',
   storeN.roll_counts(storeN.roll_floor(ATN - 3600)).get('logon-failed'), 30)
ok('...and the events themselves say the same',
   storeN.win_counts(storeN.roll_floor(ATN - 3600)).get('logon-failed'), 30)
ok('...and the two still agree line for line',
   storeN.roll_check(storeN.roll_floor(ATN)), [])
ok('a lockout is one of the things the page is never kept waiting for',
   'lockout' in isemon.Daemon.AT_ONCE_KINDS, True)
ok('...along with an audit log cleared and the groups that run the domain',
   sorted(isemon.Daemon.AT_ONCE_MARKS), ['big-group', 'big-right', 'cleared'])
ok('...and a wrong password is NOT, because a domain writes thousands an hour',
   daemonN.worth_waking_for([{'kind': 'logon-failed', 'mark': ''}]), False)

# A reading counts wherever it was asked from. A site read the counting back
# by hand, was told "every sum adds up", asked what the counting was a second
# later and was told "it has agreed with the events 0 time(s)" - both true,
# about different things, and no use at all read one after the other. Only
# the daemon's own hourly reading was ever written down.
ok('the counting has agreed with the events no times yet',
   int(storeN.roll_state().get('checks') or 0), 0)
ok('...a reading asked for by hand finds nothing wrong',
   storeN.roll_proved(storeN.roll_prove(), 'by hand', full=True), [])
ok('...and THAT is written down, so the next question is answered the same way',
   int(storeN.roll_state().get('checks') or 0), 1)
ok('...and again', (storeN.roll_proved(storeN.roll_prove(), 'by hand', full=True),
                    int(storeN.roll_state().get('checks') or 0))[1], 2)
# Put aside, mended, read back in full: believed again. Otherwise a fault
# fixed in an upgrade leaves every site that met it counting a billion rows
# again before it is allowed to say so.
storeN.roll_said(storeN.ROLL_BAD, 'something was found once')
ok('put aside, the page asks the events themselves', storeN.roll_ready(), False)
ok('...the whole proof passing brings it back',
   (storeN.roll_proved(storeN.roll_prove(), 'by hand', full=True),
    storeN.roll_ready())[1], True)
ok('...counted as the one reading it was',
   int(storeN.roll_state().get('checks') or 0), 1)
# ...but ONE hour is not that proof. It is enough to catch a fault and not
# enough to clear one: a swathe of buckets can be missing with the hour just
# gone perfectly intact, which is exactly the fault 1.10.79 mended.
storeN.roll_said(storeN.ROLL_BAD, 'something was found once')
ok('one finished hour agreeing does NOT bring it back',
   (storeN.roll_proved(storeN.roll_check(), 'the hour just gone'),
    storeN.roll_ready())[1], False)
# ...and a reading taken before anything has been counted is about an empty
# table, so it says nothing and is written down as nothing.
storeN.roll_forget(everything=True)
storeN.roll_said(storeN.ROLL_NEW, '', 0)
storeN.roll_proved(storeN.roll_prove(), 'by hand', full=True)
ok('a reading before the first counting is not a verdict on anything',
   storeN.roll_state().get('state'), storeN.ROLL_NEW)

# Work that was asked for is not a fault, and the writer waiting behind it is
# not one either. A site pressed "count them all again" and was answered with
# "[warn] sql took 5.6 s ... 167 row(s)" - which was 167 rows waiting behind
# the very thing it had just asked for.
SAWLOG = []
WAS_LOG, isemon.log = isemon.log, lambda t, lvl='info', **k: SAWLOG.append((lvl, t))
WAS_SLOW, isemon.Db.SLOW = isemon.Db.SLOW, 0.0
try:
    storeN.db.said_what('SELECT 1', (), time.time() - 3)
    with isemon.Db.patiently('counting the domain events ahead of time',
                             everyone=True):
        SAWLOG.append(('--', 'inside'))
        isemon.Db.PATIENT.what = ''          # the OTHER thread's view of it
        storeN.db.said_what('SELECT 1', (), time.time() - 3)
        isemon.Db.PATIENT.what = 'counting the domain events ahead of time'
        storeN.db.said_what('SELECT 1', (), time.time() - 3)
finally:
    isemon.Db.SLOW, isemon.log = WAS_SLOW, WAS_LOG
SAID = [one for one in SAWLOG if one[0] != '--' and 'SELECT 1 ' in one[1]]
ok('a slow statement on its own is a warning', SAID[0][0], 'warn')
# ...and the counting may be in ANOTHER process: `isemon --rollup-build` at a
# terminal holds the same table the daemon is writing into, and no flag in
# this program's memory can say so.
storeN.roll_busy_now('counting the domain events ahead of time')
ok('a counting says so where every process can see it',
   storeN.roll_busy(), 'counting the domain events ahead of time')
WAS_PID = json.loads(storeN.get_meta(storeN.ROLL_BUSY))
storeN.set_meta(storeN.ROLL_BUSY,
                json.dumps(dict(WAS_PID, pid=0x7FFFFFFF)))   # a pid nobody has
storeN._roll_busy_seen = (0.0, '')
ok('...and a counting whose process has gone is not believed',
   storeN.roll_busy(), '')
storeN.roll_busy_now('')
ok('...nor one that has said it is finished', storeN.roll_busy(), '')


# What `isemon --rollup` PRINTS, run for real rather than read. It is in one
# of three states and it must say exactly one of them: a line about a
# counting running was once put inside that chain and took the last arm's
# `else` with it, so a site in use was told in the same breath that it was
# in use and that it had never been counted. Nothing read the command's own
# words, so nothing noticed.
class SaidIt(object):
    def __init__(self):
        self.lines = []

    def title(self, text):
        self.lines.append(('title', text))

    def note(self, text):
        self.lines.append(('note', text))

    def good(self, text):
        self.lines.append(('good', text))

    def bad(self, text):
        self.lines.append(('bad', text))


class NoArgs(object):
    json = False


def rollupSaid():
    pal = SaidIt()
    isemon.cmd_rollup(NoArgs(), pal, storeN)
    words = [text for _how, text in pal.lines]
    return [one for one in ('In use', 'Not counted yet', 'Put aside')
            if any(one in text for text in words)], words


storeN.roll_said(storeN.ROLL_GOOD, '', 3)
ok('in use, it says it is in use and nothing else', rollupSaid()[0], ['In use'])
ok('...and says how many times it has agreed',
   any('agreed with the events 3 time(s)' in one for one in rollupSaid()[1]), True)
storeN.roll_said(storeN.ROLL_BAD, 'something was found once')
ok('put aside, it says that and nothing else', rollupSaid()[0], ['Put aside'])
storeN.roll_said(storeN.ROLL_NEW, '', 0)
ok('never counted, it says that and nothing else',
   rollupSaid()[0], ['Not counted yet'])
# ...and a counting going on right now is said BESIDE the state, never
# instead of it.
storeN.roll_said(storeN.ROLL_GOOD, '', 1)
storeN.roll_busy_now('counting the domain events ahead of time')
SAIDB = rollupSaid()
ok('a counting running now does not replace what state it is in',
   SAIDB[0], ['In use'])
ok('...it is said as well', any('right now' in one for one in SAIDB[1]), True)
storeN.roll_busy_now('')
ok('...and when nothing is running, nothing is said about it',
   any('right now' in one for one in rollupSaid()[1]), False)
ok('...the writer waiting behind the counting is told what it waited for',
   (SAID[1][0], 'holds every other writer' in SAID[1][1]), ('info', True))
ok('...and the counting itself says it is the work and not a fault',
   (SAID[2][0], 'this is the work and not a fault' in SAID[2][1]), ('info', True))
isemon.STATE_DIR, isemon.DB_FILE = WAS_N, WAS_NDB
isemon.CONFIG.update({'winsec': 0, 'winsec_machines': 0})
shutil.rmtree(folderN, ignore_errors=True)

# ---------------------------------------------------------------------------
title('One lockout is one row, however many controllers wrote it down')
# Seen on a real domain: the same account, the same second, the same machine,
# the same twelve refusals before it - drawn twice, the rows differing only
# in which controller was named. A domain records a lockout on the controller
# that saw the last wrong password AND on the one holding the PDC emulator
# role, because lockouts are its business.
folderL = tempfile.mkdtemp(prefix='isemon-locks-')
WAS_L, WAS_LDB = isemon.STATE_DIR, isemon.DB_FILE
isemon.STATE_DIR = Path(folderL)
isemon.DB_FILE = Path(folderL) / 'locks.db'
storeL = isemon.Storage()
daemonL = isemon.Daemon(storeL)
LOCKED = time.time() - 900
for n, (dc, off, mach) in enumerate((('dcx02', 0.0, 'MANAGEMENT'),
                                     ('bdcx02', 1.0, ''),
                                     ('dcx01', 2.0, ''))):
    storeL.note_win_event({'ident': 'lk-%d' % n, 'ts': LOCKED + off, 'event': 4740,
                           'kind': 'lockout', 'account': 'testlock', 'server': dc,
                           'machine': mach, 'ip': '172.29.6.100' if not n else ''})
ok('three controllers wrote it down', storeL.db.execute(
    "SELECT COUNT(*) AS n FROM win_events WHERE kind='lockout'").fetchone()['n'], 3)
locksL = storeL.win_lockouts(LOCKED - 3600, 12)
ok('...and the card shows one lockout', len(locksL), 1)
ok('...naming every controller that wrote it',
   sorted(locksL[0]['servers']), ['bdcx02', 'dcx01', 'dcx02'])
ok('...at the earliest of the moments they wrote', locksL[0]['ts'], LOCKED)
ok('...and taking the machine off whichever of them named one',
   locksL[0]['machine'], 'MANAGEMENT')
ok('...and the address the same way', locksL[0]['ip'], '172.29.6.100')
# ...and the alarm that means "several accounts at once" counts ACCOUNTS.
ok('one account locked three times over is one account',
   storeL.win_locked_accounts(LOCKED - 3600), 1)
for n, who in enumerate(('druhy', 'treti')):
    for m, dc in enumerate(('dcx02', 'bdcx02')):
        storeL.note_win_event({'ident': 'lk2-%d-%d' % (n, m), 'ts': LOCKED + 60 + m,
                               'event': 4740, 'kind': 'lockout', 'account': who,
                               'server': dc})
ok('three accounts, six events, counted as three',
   storeL.win_locked_accounts(LOCKED - 3600), 3)
ok('...and the card has a row for each of them',
   sorted(one['account'] for one in storeL.win_lockouts(LOCKED - 3600, 12)),
   ['druhy', 'testlock', 'treti'])
# Two lockouts of ONE account far enough apart are two lockouts, not one.
storeL.note_win_event({'ident': 'lk-later', 'ts': LOCKED + 3600, 'event': 4740,
                       'kind': 'lockout', 'account': 'testlock', 'server': 'dcx02'})
ok('...but the same account locked again an hour later is a second lockout',
   len([one for one in storeL.win_lockouts(LOCKED - 3600, 12)
        if one['account'] == 'testlock']), 2)
ok('the page draws every controller on the one row',
   'r.servers && r.servers.length ? r.servers : r.server' in PAGE_SRC, True)
isemon.STATE_DIR, isemon.DB_FILE = WAS_L, WAS_LDB
shutil.rmtree(folderL, ignore_errors=True)

# ---------------------------------------------------------------------------
title('An "account" that is not a name at all')
# Seen on a real domain: 3,104 refusals against
# `@@CyBAAAAUBQYAMHArBwUAMGAoBQZ...` - two at-signs and two hundred and fifty
# characters of base64. It is not an account: something put its
# authentication token in the user name field, the domain refuses every one
# of them for ever, and on a card it was three lines of gibberish with the
# answer pushed off the end.
TOKEN = ('@@CyBAAAAUBQYAMHArBwUAMGAoBQZAQGA1BAbAUGAyBgOAQFAhBwcAsGA6AweAUDA0AwNAEEACBwNA'
         'kDAEBQLAEEAFBQNAADAtAANAkDAyAAOA0CA5AwQAQEA1AQLAcDA2AgQAEEAEBAMAMEAFBAMAkDAwAA')
ok('a token in the name field is recognised', isemon.win_is_token_name(TOKEN), True)
ok('...and an ordinary name is not',
   [isemon.win_is_token_name(w) for w in ('novak', 'pdf', '66934', 'DCX01$', '')],
   [False] * 5)
ok('...nor a long name that is not base64 at all',
   isemon.win_is_token_name('a.very.long.service.principal.name@some.domain.example.org'),
   False)
folderT2 = tempfile.mkdtemp(prefix='isemon-token-')
isemon.STATE_DIR = Path(folderT2)
isemon.DB_FILE = Path(folderT2) / 'token.db'
isemon.CONFIG.update({'winsec': 1, 'winsec_machines': 1, 'winsec_ignore': ''})
storeT2 = isemon.Storage()
daemonT2 = isemon.Daemon(storeT2)
WHENT = time.strftime('%b %d %H:%M:%S', time.localtime(time.time() - 60))
daemonT2.read_records(
    ['%s dc1 WinSecurity: EventID=4776 | The computer attempted to validate the '
     'credentials for an account.  Logon Account:  %s  Source Workstation:  BOX  '
     'Error Code:  0xC000006A' % (WHENT, TOKEN) for _n in range(8)], 'winsec')
daemonT2.flush_win_events()
read = daemonT2.win_verdict({'account': TOKEN, 'ip': '172.16.49.36', 'n': 8},
                            time.time() - 3600)
ok('the reading says what it really is',
   any('not an account name' in one for one in read['reads']), True)
ok('...and sends somebody to the machine rather than after the account',
   any('172.16.49.36' in one for one in read['next']), True)
# ...and says only what it can know. It used to call this "a SPNEGO or NTLM
# blob", which one real domain's logs contradict: the events are 4768,
# answered 0x6 with a user ID of S-1-0-0, and a SPNEGO wrapper does not go in
# a Kerberos client name. What those logs DO say is worth more - one constant
# value per machine, hundreds of times, while that machine's own accounts
# sign in beside it perfectly well.
ok('...without naming a protocol it cannot know',
   any('SPNEGO' in one or 'NTLM blob' in one
       for one in read['reads'] + read['next']), False)
ok('...saying instead that it can never let anybody in',
   any('never let anybody in' in one for one in read['next']), True)
ok('...and that one machine is sending the same value over and over',
   any('same value over and over' in one for one in read['next']), True)

# The three families that were falling through to "other", which is under no
# switch at all. Counted on one real domain's day of 704,456 events: 4627
# beside every sign-in (153,213), 4663 beside every 4662 (88,346), and 4689
# beside every 4688 (8,420). Two fifths of the log, kept whatever anybody
# switched off, and drawn nowhere.
ok('the groups written beside every sign-in are part of the sign-in',
   isemon.WIN_EVENTS[4627][0], 'logon')
ok('...an object being accessed is part of the directory being read',
   [isemon.WIN_EVENTS[e][0] for e in (4656, 4658, 4663)], ['read', 'read', 'read'])
ok('...and a program ending is part of the program starting',
   isemon.WIN_EVENTS[4689][0], 'process')
ok('...so every one of them is under a switch now',
   sorted({isemon.WIN_EVENTS[e][0] for e in (4627, 4656, 4658, 4663, 4689)}
          - {k for _s, ks, _d in isemon.WIN_BULK for k in ks}), [])
isemon.CONFIG.update({'winsec': 0, 'winsec_machines': 0})
shutil.rmtree(folderT2, ignore_errors=True)

title('The front page\u2019s domain band, out of the hourly counting')
folderB = tempfile.mkdtemp(prefix='isemon-band-')
isemon.STATE_DIR = Path(folderB)
isemon.DB_FILE = Path(folderB) / 'band.db'
isemon.CONFIG.update({'winsec_rollup': 1, 'winsec_machines': 0})
storeB = isemon.Storage()
NOWB = time.time()
madeB = []
for h in range(60):
    for n, kind in enumerate(('logon', 'logon-failed', 'kerberos-failed', 'ntlm', 'dir-read')):
        madeB.append({'ident': 'b-%d-%d' % (h, n), 'ts': NOWB - h * 1800 - n * 7,
                      'event': 4624, 'kind': kind, 'account': 'u%d' % (h % 5),
                      'machine': 'NB-%d' % (h % 3), 'ip': '10.0.0.%d' % (h % 9),
                      'said': 'x', 'server': 'dc1', 'is_machine': 1 if h % 4 == 0 else 0})
storeB.note_win_events(madeB)
storeB.roll_build()


def bandB(cut, ask=3600):
    bars = {}
    for slot in range(int(cut // ask) * ask, int(NOWB) + ask, ask):
        bars[slot] = {'failed_domain': 0, 'passed_domain': 0}
    storeB._domain_counts(bars, lambda slot: slot, ask, cut)
    return {k: v for k, v in bars.items() if v['failed_domain'] or v['passed_domain']}


for cutB, words in ((NOWB - 20 * 3600 - 1234, 'a window cut part way through an hour'),
                    (storeB.roll_floor(NOWB - 10 * 3600), 'a window on the hour')):
    storeB.roll_said(storeB.ROLL_BAD, 'counted from the events for this check')
    fromEvents = bandB(cutB)
    storeB.roll_said(storeB.ROLL_GOOD, '', 3)
    ok('(the hourly counting is what is asked)', storeB.roll_ready(), True)
    ok('%s: the hourly counting draws exactly what the events do' % words,
       bandB(cutB), fromEvents)
isemon.CONFIG['winsec_machines'] = 1
storeB.roll_said(storeB.ROLL_BAD, 'x')
allB = bandB(NOWB - 30 * 3600)
storeB.roll_said(storeB.ROLL_GOOD, '', 3)
ok('...machines counted in as well, when the page counts them',
   bandB(NOWB - 30 * 3600), allB)
ok('...and not nothing', sum(v['passed_domain'] for v in allB.values()) > 0, True)
isemon.CONFIG.update({'winsec_rollup': 0, 'winsec_machines': 0})
storeB.db.close()
shutil.rmtree(folderB, ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
