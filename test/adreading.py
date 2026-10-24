#!/usr/bin/env python3
"""What the domain page reads out of the controllers' logs (1.10.100).

Built on the shapes of a real site's two controllers, forwarded by NXLog as
`<date> <dc> WinSecurity: EventID=N | <message>`, with the names and the
addresses made up. Every case here is one the real logs had and the page
read wrongly before this version:

  - a wrong password the second controller wrote first, and the PDC wrote
    again "from" the second controller - counted twice, and read as
    something running on a domain controller;
  - one person as `jnovak` and as `jnovak@example.cz` - two cards with two
    different readings of the same terminal server;
  - a terminal server read as "not where the password is";
  - a computer account refused with a wrong password, and the computer's name
    sent as a user by NTLM straight after - read as "a desk";
  - bursts of tries at uneven times read as a clock;
  - the GUID Azure AD Connect addresses a controller by, taken for a name;
  - `TS01$@EXAMPLE.CZ` counted among the people;
  - refusals NPS asked about, with no machine and no address, read as nothing.

    ./test/adreading.py
"""
import shutil
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import isemon  # noqa: E402

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
    print('\n' + words)


folder = tempfile.mkdtemp(prefix='isemon-adreading-')
isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = Path(folder) / 'ad.db'
isemon.RUN_DIR = Path(folder)
isemon.LOG_DIR = Path(folder)
isemon._LOG_PATH = Path(folder) / 'ad.log'
(Path(folder) / 'dc1').mkdir()
(Path(folder) / 'dc2').mkdir()
isemon.CONFIG.update({'winsec': 1, 'winsec_paths': [folder + '/dc1', folder + '/dc2'],
                      'winsec_machines': 0, 'geo': 0, 'directory': 0, 'directory2': 0,
                      'nps': 1, 'blacklist': 1, 'winsec_controllers': ''})
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
daemon._spare_from = None

T0 = time.time() - 5 * 3600
LINES = []


def at(seconds):
    return T0 + seconds


def stamp(ts):
    return time.strftime('%b %d %H:%M:%S', time.localtime(ts))


def put(ts, dc, event, body):
    LINES.append('%s %s WinSecurity: EventID=%d | %s' % (stamp(ts), dc, event, body))


def logon(ts, dc, account, ip, domain='EXAMPLE.CZ', workstation='-'):
    put(ts, dc, 4624, 'An account was successfully logged on.  Subject:  Security ID:  S-1-0-0  '
        'Account Name:  -  Account Domain:  -  Logon ID:  0x0  Logon Information:  Logon Type:  3  '
        'Restricted Admin Mode: -  Virtual Account:  No  Elevated Token:  Yes  '
        'Impersonation Level:  Impersonation  New Logon:  Security ID:  S-1-5-21-1-2-3-9  '
        'Account Name:  %s  Account Domain:  %s  Logon ID:  0x3E945663  Linked Logon ID:  0x0  '
        'Network Account Name: -  Network Account Domain: -  Logon GUID:  {00000000-0000-0000-'
        '0000-000000000000}  Process Information:  Process ID:  0x0  Process Name:  -  Network '
        'Information:  Workstation Name: %s  Source Network Address: %s  Source Port:  55701  '
        'Detailed Authentication Information:  Logon Process:  Kerberos  Authentication '
        'Package: Kerberos  Transited Services: -  Package Name (NTLM only): -  Key Length:  0'
        % (account, domain, workstation, ip))


def preauth_failed(ts, dc, account, ip):
    put(ts, dc, 4771, 'Kerberos pre-authentication failed.  Account Information:  Security ID:  '
        'S-1-5-21-1-2-3-5200  Account Name:  %s  Service Information:  Service Name:  '
        'krbtgt/EXAMPLE.CZ  Network Information:  Client Address:  ::ffff:%s  Client Port:  '
        '55887  Additional Information:  Ticket Options:  0x40810010  Failure Code:  0x18  '
        'Pre-Authentication Type: 2' % (account, ip))


def ntlm(ts, dc, account, workstation, code):
    put(ts, dc, 4776, 'The computer attempted to validate the credentials for an account.  '
        'Authentication Package: MICROSOFT_AUTHENTICATION_PACKAGE_V1_0 Logon Account: %s '
        'Source Workstation: %s Error Code: %s' % (account, workstation, code))


def ticket(ts, dc, account, service, ip):
    put(ts, dc, 4769, 'A Kerberos service ticket was requested.  Account Information:  Account '
        'Name:  %s  Account Domain:  EXAMPLE.CZ  Logon GUID:  {00000000-0000-0000-0000-'
        '000000000000}  Service Information:  Service Name:  %s  Service ID:  S-1-5-21-1-2-3-6802  '
        'Network Information:  Client Address:  ::ffff:%s  Client Port:  59726  Additional '
        'Information:  Ticket Options:  0x40810000  Ticket Encryption Type: 0x12  Session '
        'Encryption Type: 0x12  Failure Code:  0x0  Transited Services: -'
        % (account, service, ip))


def nps_failed(ts, dc, account, sub):
    put(ts, dc, 4625, 'An account failed to log on.  Subject:  Security ID:  S-1-5-18  Account '
        'Name:  DC1$  Account Domain:  EXAMPLE_NT  Logon ID:  0x3E7  Logon Type:   3  Account '
        'For Which Logon Failed:  Security ID:  S-1-0-0  Account Name:  %s  Account Domain:  '
        'EXAMPLE_NT  Failure Information:  Failure Reason:  Unknown user name or bad password.  '
        'Status:   0xC000006D  Sub Status:  %s  Process Information:  Caller Process ID: 0x113c  '
        'Caller Process Name: C:\\Windows\\System32\\svchost.exe  Network Information:  '
        'Workstation Name: -  Source Network Address: -  Source Port:  -  Detailed '
        'Authentication Information:  Logon Process:  IAS  Authentication Package: '
        'MICROSOFT_AUTHENTICATION_PACKAGE_V1_0  Transited Services: -  Package Name (NTLM '
        'only): -  Key Length:  0' % (account, sub))


def adsync(ts, dc):
    put(ts, dc, 4648, 'A logon was attempted using explicit credentials.  Subject:  Security ID:  '
        'S-1-5-21-1-2-3-8609  Account Name:  ADSyncMSA42991$  Account Domain:  EXAMPLE_NT  Logon '
        'ID:  0x33E98A88  Logon GUID:  {00000000-0000-0000-0000-000000000000}  Account Whose '
        'Credentials Were Used:  Account Name:  MSOL_42991ff41a8a  Account Domain:  EXAMPLE.CZ  '
        'Logon GUID:  {00000000-0000-0000-0000-000000000000}  Target Server:  Target Server '
        'Name: 0f3c2a11-7d44-4b6e-9a1c-5e2b8d0c4f7a  Additional Information: '
        'E3514235-4B06-11D1-AB04-00C04FC2DCD2/0f3c2a11-7d44-4b6e-9a1c-5e2b8d0c4f7a/example.cz  '
        'Process Information:  Process ID:  0x153c  Process Name:  C:\\Program Files\\Microsoft '
        'Azure AD Sync\\Bin\\miiserver.exe  Network Information:  Network Address: 10.0.0.7  '
        'Port:   50216')


# The two controllers, each signing in to the other as itself.
for n in range(6):
    logon(at(100 + n * 600), 'dc1', 'DC2$', '10.0.0.7')
    logon(at(130 + n * 600), 'dc2', 'DC1$', '10.0.0.6')
adsync(at(200), 'dc2')

# A terminal server, TS01, that many people sign in through.
for n in range(8):
    logon(at(300 + n * 60), 'dc1', 'user%d' % n, '10.0.1.34')
    ntlm(at(310 + n * 60), 'dc1', 'user%d' % n, 'TS01', '0x0')
for n in range(4):
    logon(at(900 + n * 900), 'dc2', 'TS01$', '10.0.1.34')
    ticket(at(905 + n * 900), 'dc2', 'TS01$@EXAMPLE.CZ', 'krbtgt', '10.0.1.34')

# jnovak works on TS01 with the current password...
for n in range(20):
    ntlm(at(400 + n * 500), 'dc1', 'jnovak', 'TS01', '0x0')
for n in range(5):
    ticket(at(420 + n * 1500), 'dc2', 'jnovak@EXAMPLE.CZ', 'TS01$', '10.0.1.34')
# ...while something in her session there keeps an old one, written as an
# e-mail address, and refused at uneven times: Kerberos at dc2, the PDC's copy
# at dc1 from dc2's address, and NTLM straight after.
gaps = [0, 170, 410, 530, 900, 1190, 1400, 1850, 2100, 2330, 2800, 3050, 3400, 3700, 4090,
        4300, 4780, 5000, 5390, 5700, 6000, 6350, 6700, 6900, 7300, 7650, 8000, 8200, 8650,
        9000]
for g in gaps:
    preauth_failed(at(1000 + g), 'dc2', 'jnovak', '10.0.1.34')
    preauth_failed(at(1000 + g), 'dc1', 'jnovak', '10.0.0.7')
    ntlm(at(1001 + g), 'dc1', 'jnovak@example.cz', 'TS01', '0xC000006A')

# BROKER: its own account refused with a wrong password in bursts, and the
# computer's name sent as a user by NTLM at the same seconds - while the
# machine itself signs in fine.
for start in (2000, 2780, 3200, 3900, 5500):
    for k in range(6):
        preauth_failed(at(start) + k * 0.1, 'dc2', 'BROKER$', '10.0.1.21')
        ntlm(at(start) + k * 0.1, 'dc2', 'BROKER', 'BROKER', '0xC0000064')
for n in range(4):
    logon(at(2500 + n * 1000), 'dc2', 'BROKER$', '10.0.1.21')

# A scanner with an old password on a real clock: two every five minutes.
for r in range(10):
    for k in range(2):
        ntlm(at(600 + r * 300 + k * 7), 'dc1', 'svc-scan', 'PC7', '0xC000006A')
logon(at(650), 'dc1', 'PC7$', '10.0.2.7')

# NPS: pvlcek's phone with the old Wi-Fi password, and names that do not
# exist from a VPN password spray. The controller writes them with no
# machine and no address; NPS's own rows say the rest.
for n in range(7):
    ts = at(3000 + n * 431)
    nps_failed(ts, 'dc1', 'pvlcek', '0xC000006A')
    ntlm(ts, 'dc1', 'pvlcek', '', '0xC000006A')
    store.add_failed({'session': 'nps/w/%d' % n, 'ts': ts, 'ip': '', 'username': 'pvlcek',
                      'kind': 'nps-dot1x-wifi', 'device': 'AP02', 'mac': '4E-AF-29-BB-9D-A0',
                      'reason': 'wrong password'})
for n in range(14):
    ts = at(4000 + n * 97)
    name = 'guess%02d' % n
    nps_failed(ts, 'dc1', name, '0xC0000064')
    store.add_failed({'session': 'nps/v/%d' % n, 'ts': ts, 'ip': '203.0.113.%d' % (n % 3 + 1),
                      'username': name, 'kind': 'nps-vpn', 'device': 'EXAMPLE-FG',
                      'reason': 'no such account'})
store.block('203.0.113.1', None, 'a test', auto=True)

# A proxy that binds to LDAP with a service account - the controller writes
# its OWN name as the workstation of that - and passes a dozen people's
# passwords on by NTLM, naming itself UNC-style.
for n in range(4):
    logon(at(500 + n * 700), 'dc1', 'svc-ldap', '10.0.4.4', workstation='DC1')
logon(at(520), 'dc1', 'PROXY1$', '10.0.4.4')
logon(at(1520), 'dc1', 'PROXY1$', '10.0.4.4')
for n in range(7):
    ntlm(at(1900 + n * 50), 'dc1', 'person%d' % n, '\\\\PROXY1', '0x0')
for n in range(6):
    ntlm(at(2600 + n * 333), 'dc1', 'person1', '\\\\PROXY1', '0xC000006A')

# ISE checking VPN passwords against the domain from its own node, ISEA:
# the controller writes the node's name, ISE writes the person's address.
logon(at(700), 'dc1', 'ISEA$', '10.0.3.5')
for n in range(8):
    ts = at(6000 + n * 213)
    ntlm(ts, 'dc1', 'pkral', 'ISEA', '0xC000006A')
    store.add_failed({'session': 'ise/v/%d' % n, 'ts': ts + 1, 'ip': '198.51.100.9',
                      'username': 'pkral', 'kind': 'vpn', 'device': 'FTD-VPN',
                      'reason': 'wrong password'})
# ...and a spray through it, of names that do not exist.
for n in range(9):
    ts = at(7000 + n * 61)
    ntlm(ts, 'dc1', 'nobody%02d' % n, 'ISEA', '0xC0000064')
    store.add_failed({'session': 'ise/s/%d' % n, 'ts': ts, 'ip': '198.51.100.%d' % (20 + n % 2),
                      'username': 'nobody%02d' % n, 'kind': 'vpn', 'device': 'FTD-VPN',
                      'reason': 'no such account'})
# ...and an 802.1X laptop through ISE with an old password.
for n in range(6):
    ts = at(8000 + n * 400)
    ntlm(ts, 'dc1', 'mdvorak', 'ISEA', '0xC000006A')
    # ...written by ISE with the domain in front and capitals, which the
    # controller writes as plain `mdvorak`.
    store.add_failed({'session': 'ise/w/%d' % n, 'ts': ts - 2, 'ip': '',
                      'username': 'EXAMPLE\\MDvorak', 'kind': 'dot1x-lan', 'device': 'SW-B1',
                      'mac': '00-30-04-13-A9-55', 'reason': 'wrong password'})

recs = isemon.win_parse_lines(LINES, {}, now=time.time())
for rec in recs:
    daemon.take_record('winsec', rec)
daemon.flush_win_events()
daemon.note_controllers(force=True)
since = T0 - 60

title('The controllers, known from their own sign-ins')
ok('both controllers\u2019 addresses are learned', sorted(isemon.WIN_CONTROLLER_IPS),
   ['10.0.0.6', '10.0.0.7'])
ok('a GUID is not a machine\u2019s name',
   store.name_the_machines([{'ip': '10.0.0.7', 'machine': ''}])[0].get('machine', '') in
   ('', 'DC2'), True)
ok('a ticket\u2019s TS01$@EXAMPLE.CZ is a machine', store.db.execute(
    "SELECT MIN(is_machine) AS m FROM win_events WHERE account = 'TS01$@EXAMPLE.CZ'")
   .fetchone()['m'], 1)

summary = daemon.win_summary(6, wait=True)
cards = summary['incidents']
by_kind = {}
for c in cards:
    by_kind.setdefault(c['kind'], []).append(c)

title('One person, one card, counted once')
brute = [c for c in by_kind.get('brute', []) if c['who'].lower() == 'jnovak']
ok('jnovak and jnovak@example.cz are one card', len(brute), 1)
ok('...and no second card for the e-mail form',
   any(c['who'].lower() == 'jnovak@example.cz' for c in cards), False)
card = brute[0] if brute else {'n': 0, 'reads': [], 'next': [], 'where': {}, 'more': ''}
ok('the PDC\u2019s copies are not counted (30 Kerberos + 30 NTLM, not 90)', card['n'], 60)
ok('the card opens both forms', sorted(card['where'].get('accounts', '').split(',')),
   ['jnovak', 'jnovak@example.cz'])
ok('it says each attempt was refused twice', any('refused twice' in r and 'about 30' in r
                                                  for r in card['reads']), True)
ok('it says the person signs in fine', any('signed in successfully' in r
                                           for r in card['reads']), True)
ok('...so not "a person retrying"', any('what a person retrying looks like' in r
                                        for r in card['reads']), False)
ok('it says TS01 is where she works, a terminal server',
   any('works ON it' in r and 'TS01' in r for r in card['next']), True)
ok('...and not that the password is "almost certainly NOT on it"',
   any('almost certainly NOT on it' in r for r in card['next']), False)
ok('...and not a domain controller', any('domain controllers' in r for r in card['next']),
   False)

title('A computer\u2019s own password refused')
machine = [c for c in by_kind.get('machine-password', []) if c['who'] == 'BROKER$']
ok('BROKER$ has a card of its own', len(machine), 1)
mc = machine[0] if machine else {'reads': [], 'next': [], 'more': '', 'where': {}}
ok('...naming where from', '10.0.1.21' in mc['more'], True)
ok('...with the NTLM half beside it', '"BROKER"' in mc['more'], True)
ok('no separate card for an account called BROKER',
   any(c['kind'] == 'brute' and c['who'].lower() == 'broker' for c in cards), False)
ok('bursts are said as bursts', any('bursts of about 6 tries' in r for r in mc['reads']), True)
ok('...and not as a clock', any('to the second' in r for r in mc['reads']), False)
ok('it says the machine itself signs in fine', any('ALSO signed in successfully' in r
                                                   for r in mc['reads']), True)
ok('the card counts the machine accounts when opened', mc['where'].get('machines'), 1)

title('A clock is still a clock')
scan = store.win_rhythm(['svc-scan'], since)
ok('two tries every five minutes', (scan.get('steady'), scan.get('every'), scan.get('per')),
   (True, 300, 2))
ok('and bursts are not', store.win_rhythm(['BROKER$'], since).get('steady'), None)

title('What keeps trying, row by row')
rows = {r['said'].lower(): r for v in summary['views'] if v['key'] == 'holding'
        for r in v['rows']}
row = rows.get('broker') or {}
ok('the row for BROKER has its address, worked out from its own account',
   ((row.get('newest') or {}).get('ip'), row.get('ip_guessed')), ('10.0.1.21', '10.0.1.21'))
ok('...and is read as the computer\u2019s own name, not as a desk',
   (any('computer\u2019s own name' in r for r in row.get('reads') or []),
    any('looks like one machine' in r for r in row.get('next') or [])), (True, False))
mail = rows.get('jnovak@example.cz') or {}
ok('the e-mail form is pointed at', any('written like an e-mail address' in r
                                        for r in mail.get('reads') or []), True)
phone = rows.get('pvlcek') or {}
ok('a refusal NPS asked about is read out of NPS\u2019s own rows',
   any('Wi-Fi through AP02' in r for r in phone.get('reads') or []), True)
ok('...counted as NPS\u2019s own rows, not twice for the two events on the controller',
   any('Wi-Fi through AP02: %s refusal(s)' % isemon.num_words(7) in r
       for r in phone.get('reads') or []), True)
ok('...and a private MAC is said to be one', any('private (randomised)' in r
                                                 for r in phone.get('next') or []), True)

title('Names that do not exist, through NPS')
spray = by_kind.get('nps-names') or []
ok('a card of its own', len(spray), 1)
sc = spray[0] if spray else {'reads': [], 'next': [], 'n': 0}
ok('counting names', sc['n'], 14)
ok('...every one of them found in NPS\u2019s own log', any(r.startswith('14 of these 14')
                                                           for r in sc['reads']), True)
ok('...with the VPN addresses NPS saw', any('203.0.113.1' in r and '203.0.113.3' in r
                                            for r in sc['reads']), True)
ok('...and how many are kept out', any(r.startswith('1 of 3') for r in sc['next']), True)

title('The lists beside the cards count the same way')
places = {r['said']: r['n'] for v in summary['views'] if v['key'] == 'places'
          for r in v['rows']}
ok('a controller\u2019s address is not "where the requests came from"', '10.0.0.7' in places,
   False)
people = {r['said']: r['n'] for v in summary['views'] if v['key'] == 'people'
          for r in v['rows']}
ok('...and jnovak\u2019s refusals are not counted twice', people.get('jnovak'), 30)

title('Names as a proxy writes them, and as a controller writes itself')
ok('\\\\PROXY1 is kept as PROXY1', store.db.execute(
    "SELECT COUNT(*) AS n FROM win_events WHERE machine LIKE '%PROXY1'").fetchone()['n'] ==
   store.db.execute("SELECT COUNT(*) AS n FROM win_events WHERE machine = 'PROXY1'")
   .fetchone()['n'], True)
ok('an address is not named after the controller that wrote its LDAP bind',
   store.name_the_machines([{'ip': '10.0.4.4', 'machine': ''}])[0].get('machine'), 'PROXY1')
row = rows.get('person1') or {}
ok('...so it is not "one of your own domain controllers"',
   any('domain controllers' in r for r in row.get('next') or []), False)
ok('...and a proxy that seven people pass through by NTLM is a server, not a desk',
   any('is a SERVER' in r and 'PROXY1' in r for r in row.get('next') or []), True)

title('ISE and the domain, one attempt from two sides')
rows = {r['said'].lower(): r for v in summary['views'] if v['key'] == 'holding'
        for r in v['rows']}
vpn = rows.get('pkral') or {}
ok('the refusals the domain wrote for ISE are found in ISE\u2019s own log',
   any(r.startswith('ISEA is ISE checking these passwords') for r in vpn.get('reads') or []),
   True)
ok('...with the address on the internet ISE saw',
   any('198.51.100.9' in r and 'VPN' in r for r in vpn.get('reads') or []), True)
ok('...and not a guess about whether ISEA is a desk',
   any('looks like one machine' in r or 'is a SERVER' in r for r in vpn.get('next') or []),
   False)
wired = rows.get('mdvorak') or {}
ok('an 802.1X laptop through ISE: the switch and the MAC',
   any('SW-B1' in r and '00-30-04-13-A9-55' in r for r in wired.get('reads') or []), True)
spr = [c for c in by_kind.get('spray', []) if c['who'] == 'ISEA']
ok('a spray of names through ISE says it came from outside, and from where',
   bool(spr) and any('198.51.100.20' in r for r in spr[0].get('reads') or []), True)

title('The small things')
ok('a private MAC', isemon.mac_is_private('4E-AF-29-BB-9D-A0'), True)
ok('a maker\u2019s MAC', isemon.mac_is_private('00-30-04-13-A9-01'), False)
ok('"every hour", not "every an hour"', daemon.beat_every(3600), 'every hour')
ok('forms folded', [isemon.win_fold_account(x) for x in
                    ('EXAMPLE\\jnovak', 'jnovak@example.cz', 'JNOVAK', 'TS01$@EXAMPLE.CZ')],
   ['jnovak', 'jnovak', 'jnovak', 'ts01$'])

store.db.close()
shutil.rmtree(folder, ignore_errors=True)

title('Only the controllers\u2019 logs: everything still reads, nothing is claimed')
alone = tempfile.mkdtemp(prefix='isemon-adalone-')
isemon.STATE_DIR = Path(alone)
isemon.DB_FILE = Path(alone) / 'ad.db'
isemon.RUN_DIR = Path(alone)
isemon.LOG_DIR = Path(alone)
isemon._LOG_PATH = Path(alone) / 'ad.log'
(Path(alone) / 'dc1').mkdir()
(Path(alone) / 'dc2').mkdir()
isemon.CONFIG.update({'winsec_paths': [alone + '/dc1', alone + '/dc2'], 'nps': 0, 'ise': 0})
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
for rec in isemon.win_parse_lines(LINES, {}, now=time.time()):
    daemon.take_record('winsec', rec)
daemon.flush_win_events()
daemon.note_controllers(force=True)
ok('nothing from ISE or NPS is in this database', store.rows_in('failed'), 0)
summary = daemon.win_summary(6, wait=True)
cards = summary['incidents']
said = ' '.join(' '.join(c.get('reads') or []) + ' '.join(c.get('next') or []) for c in cards)
rows = {r['said'].lower(): r for v in summary['views'] if v['key'] == 'holding'
        for r in v['rows']}
said += ' '.join(' '.join(r.get('reads') or []) + ' '.join(r.get('next') or [])
                 for r in rows.values())
ok('the cards are there', {'brute', 'machine-password', 'nps-names'} <= {c['kind'] for c in cards},
   True)
ok('...and not one of them claims what ISE or NPS saw', 'own log, at the same moment' in said,
   False)
ok('the names NPS asked about say where to read more',
   any('Read the NPS logs here as well' in n for c in cards if c['kind'] == 'nps-names'
       for n in c.get('next') or []), True)
ok('a refusal NPS asked about says what it is, without NPS\u2019s log',
   any('NPS\u2019s own log says which door' in n for n in (rows.get('pvlcek') or {})
       .get('next') or []), True)
ok('the refusals through ISEA are still read, as the domain sees them',
   bool((rows.get('pkral') or {}).get('next') or (rows.get('pkral') or {}).get('reads')), True)
store.db.close()
shutil.rmtree(alone, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
