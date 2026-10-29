#!/usr/bin/env python3
"""A Windows NPS server's own log, read the way this program reads it.

Network Policy Server is the RADIUS server that comes with Windows. On a site
without ISE it is what answers the switches, the wireless and the VPN, and it
writes every request and every answer down in a file of its own - one packet
to a line, sixty-six columns, "ODBC (Legacy)".

The lines below are real ones, out of ten months of a site's log (21 million
lines on one server), with the people's names changed. That log is the shape
of the difficulty:

  * a request and its answer are two lines, joined only by the Class NPS
    stamps on both - and only the REQUEST says whether it was a socket, a
    radio or the VPN, while only the ANSWER says yes or no;
  * six million of those lines are the switches asking whether the server is
    there (`radius-server test`, as an account that does not exist), and
    none of them is anybody signing in to anything;
  * the site has no VPN behind its NPS at all, so no VPN door may appear.

Nothing here is ever judged and nothing here can earn anybody a ban.

    ./test/nps.py
"""
import gzip
import os
import re
import shutil
import sys
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


def fresh(on=1):
    folder = tempfile.mkdtemp(prefix='isemon-nps-')
    isemon.STATE_DIR = Path(folder)
    isemon.DB_FILE = Path(folder) / 'nps.db'
    isemon.BACKUP_DIR = Path(folder) / 'backups'
    isemon.DUMP_DIR = Path(folder) / 'dumps'
    isemon.RUN_DIR = Path(folder)
    isemon.LOG_DIR = Path(folder)
    isemon._LOG_PATH = Path(folder) / 'nps.log'
    isemon.CONFIG.update({
        'blacklist': 0, 'geo': 0, 'mikrotik_host': '', 'debug': False,
        'ise': 0, 'ise_paths': [str(Path(folder) / 'nothing')],
        'winsec': 0, 'otp': 0, 'eduroam': 0, 'tacplus': 0,
        'nps': on, 'nps_paths': [str(Path(folder) / 'nps02')], 'nps_name': 'IN*.log',
        'nps_ignore': '', 'nps_port_names': 'GigabitEthernet',
        'log_zone': '',
    })
    store = isemon.Storage(isemon.DB_FILE)
    daemon = isemon.Daemon(store)
    return folder, store, daemon


TAIL = ',"Use Windows authentication for all users",1,,,,'
# The switches asking whether the server is there. Every few seconds, from
# every switch, for ever: a Login with no port and no calling station, as an
# account that exists nowhere, refused every time.
PROBE = [
    '"NPS02","IAS",09/01/2026,00:00:01,1,"testaccount","MUZABREH\\testaccount",,,,,,'
    '"192.168.200.24",,9,"192.168.200.24","SW_B2_SW_Optika",,,,,,1,1,,0,'
    '"311 1 172.29.136.9 07/23/2026 07:23:32 810669"' + ',' * 33 + TAIL,
    '"NPS02","IAS",09/01/2026,00:00:01,3,,"MUZABREH\\testaccount",,,,,,,,9,'
    '"192.168.200.24","SW_B2_SW_Optika",,,,,,,1,,16,'
    '"311 1 172.29.136.9 07/23/2026 07:23:32 810669"' + ',' * 33 + TAIL,
]
# ...and the accounting NPS writes beside them, which is not an answer.
ACCT = ['"NPS02","IAS",09/01/2026,00:00:01,4,"testaccount",,,,,,,"192.168.200.24",,9,'
        '"192.168.200.24","SW_B2_SW_Optika",,,,,,2,,,0,,,,,,3,0,,,"00000000",1'
        + ',' * 24 + ',"Use Windows authentication for all users",,,,,']
# A printer on a socket, let on by its MAC, and handed VLAN 5.
MAB_OK = [
    '"NPS02","IAS",09/01/2026,00:01:40,1,"b00cd1e0bf88","MUZABREH\\b00cd1e0bf88",'
    '"00-B1-E3-2E-5D-24","B0-0C-D1-E0-BF-88",,"192.168.5.39",,"192.168.200.3",50436,9,'
    '"192.168.200.3","SW_B1_SW1_STACK",,,15,,,10,1,"802.1x VLAN5 Tiskarny",0,'
    '"311 1 172.29.136.9 07/23/2026 07:23:32 810692"' + ',' * 33 + TAIL,
    '"NPS02","IAS",09/01/2026,00:01:40,2,,"MUZABREH\\b00cd1e0bf88",,,,,,,,9,'
    '"192.168.200.3","SW_B1_SW1_STACK",,,,,,2,1,"802.1x VLAN5 Tiskarny",0,'
    '"311 1 172.29.136.9 07/23/2026 07:23:32 810692",,,,,,,,,,,,,,,,,,13,6,,,,"5"'
    + ',' * 10 + TAIL,
]
# A terminal on a socket, by its certificate, handed VLAN 4...
DOT1X_OK = [
    '"NPS02","IAS",09/01/2026,06:11:50,1,"pc.terminal","MUZABREH\\pc.terminal",'
    '"00-D6-FE-5E-70-85","00-30-04-13-AA-C8",,"192.168.4.21",,"192.168.200.22",50305,9,'
    '"192.168.200.22","SW_B2_SW2_STACK",,,15,,,2,5,"802.1x VLAN4 Terminaly",0,'
    '"311 1 172.29.136.9 07/23/2026 07:23:32 815915",,,,'
    '"Microsoft: Smart Card or other certificate"' + ',' * 29 + TAIL,
    '"NPS02","IAS",09/01/2026,06:11:50,2,,"MUZABREH\\pc.terminal",,,,,,,,9,'
    '"192.168.200.22","SW_B2_SW2_STACK",,,,,,2,5,"802.1x VLAN4 Terminaly",0,'
    '"311 1 172.29.136.9 07/23/2026 07:23:32 815915",,,,'
    '"Microsoft: Smart Card or other certificate",,,,,,,,,,,,,,13,6,,,,"4"'
    + ',' * 10 + TAIL,
]
# ...and another one refused, because the EAP exchange failed (code 23).
DOT1X_BAD = [
    '"NPS02","IAS",09/02/2026,12:13:25,1,"pc.terminal","MUZABREH\\pc.terminal",'
    '"00-D6-FE-5E-6D-9B","00-30-04-13-A9-8D",,"192.168.4.31",,"192.168.200.23",50127,9,'
    '"192.168.200.23","SW_B2_SW3_SOC",,,15,,,2,5,"802.1x VLAN4 Terminaly",0,'
    '"311 1 172.29.136.9 07/23/2026 07:23:32 841893",,,,'
    '"Microsoft: Smart Card or other certificate"' + ',' * 29 + TAIL,
    '"NPS02","IAS",09/02/2026,12:13:25,3,,"MUZABREH\\pc.terminal",,,,,,,,9,'
    '"192.168.200.23","SW_B2_SW3_SOC",,,,,,,5,"802.1x VLAN4 Terminaly",23,'
    '"311 1 172.29.136.9 07/23/2026 07:23:32 841893",,,,'
    '"Microsoft: Smart Card or other certificate"' + ',' * 29 + TAIL,
]
# A MAC nobody has put in the directory (code 16).
MAB_BAD = [
    '"NPS02","IAS",09/01/2026,07:35:39,1,"00300413aabb","MUZABREH\\00300413aabb",'
    '"00-D6-FE-5E-74-8B","00-30-04-13-AA-BB",,"192.168.4.81",,"192.168.200.27",50111,9,'
    '"192.168.200.27","SW_B2_SW_Knihovna",,,15,,,10,1,,0,'
    '"311 1 172.29.136.9 07/23/2026 07:23:32 817310"' + ',' * 33 + TAIL,
    '"NPS02","IAS",09/01/2026,07:35:39,3,,"MUZABREH\\00300413aabb",,,,,,,,9,'
    '"192.168.200.27","SW_B2_SW_Knihovna",,,,,,,1,,16,'
    '"311 1 172.29.136.9 07/23/2026 07:23:32 817310"' + ',' * 33 + TAIL,
]
# Wi-Fi through an Aruba controller, which writes both stations as bare hex.
WIFI_OK = [
    '"NPS02","IAS",01/12/2026,15:51:57,1,"MUZABREH\\pracovnik","MUZABREH\\pracovnik",'
    '"4448c1c8f58e","4485000ed913",,,"AP-MASTER","192.168.215.50",0,0,"192.168.215.50",'
    '"AP-MASTER",,,19,,,2,11,"Secure Wireless Connections",0,'
    '"311 1 172.29.136.9 01/05/2026 13:51:38 148781",,,,'
    '"Microsoft: Secured password (EAP-MSCHAP v2)"' + ',' * 29 + TAIL,
    '"NPS02","IAS",01/12/2026,15:51:57,2,,"MUZABREH\\pracovnik",,,,,,,,0,'
    '"192.168.215.50","AP-MASTER",,,,,1,2,11,"Secure Wireless Connections",0,'
    '"311 1 172.29.136.9 01/05/2026 13:51:38 148781",,,,'
    '"Microsoft: Secured password (EAP-MSCHAP v2)"' + ',' * 27
    + '"0x014D555A4142524548",,' + TAIL,
]
WIFI_BAD = [
    '"NPS02","IAS",03/20/2026,09:15:02,1,"brother.ptouch","MUZABREH\\brother.ptouch",'
    '"4448c1c8f58e","d46a6a4040af",,,"AP-MASTER","192.168.215.50",0,0,"192.168.215.50",'
    '"AP-MASTER",,,19,,,2,11,"Secure Wireless Connections",0,'
    '"311 1 172.29.136.9 03/11/2026 16:21:13 196619"' + ',' * 33 + TAIL,
    '"NPS02","IAS",03/20/2026,09:15:02,3,,"MUZABREH\\brother.ptouch",,,,,,,,0,'
    '"192.168.215.50","AP-MASTER",,,,,,,11,"Secure Wireless Connections",23,'
    '"311 1 172.29.136.9 03/11/2026 16:21:13 196619"' + ',' * 33 + TAIL,
]
# A server asking NPS about an account of its own: no socket, no radio, no VPN.
OTHER_OK = [
    '"NPS02","IAS",09/21/2026,12:08:39,1,"jan.novak@example.net","MUZABREH\\jan.novak",'
    ',,,,,"172.29.136.67",1,0,"172.29.136.67","VIEW_Public2",,,,,,,4,"ViewPublic",0,'
    '"311 1 172.29.136.9 07/23/2026 07:23:32 1231595"' + ',' * 33 + TAIL,
    '"NPS02","IAS",09/21/2026,12:08:39,2,,"MUZABREH\\jan.novak",,,,,,,,0,'
    '"172.29.136.67","VIEW_Public2",,,,,,2,4,"ViewPublic",0,'
    '"311 1 172.29.136.9 07/23/2026 07:23:32 1231595"' + ',' * 30 + '"\\MUZABREH",,'
    + TAIL,
]
# A VPN sign-in (NAS-Port-Type 5, Virtual) - which the site these lines come
# from does not have, so it is made up in the same shape: refused, wrong
# password, from an address on the internet.
VPN_BAD = [
    '"NPS02","IAS",09/03/2026,08:00:00,1,"j.novak","EXAMPLE\\j.novak",'
    '"10.0.0.1","198.51.100.23",,,,"10.0.0.1",7,9,"10.0.0.1","ASA-VPN",,,5,,,2,4,'
    '"VPN users",0,"311 1 10.0.0.9 09/01/2026 07:00:00 5"' + ',' * 33 + TAIL,
    '"NPS02","IAS",09/03/2026,08:00:00,3,,"EXAMPLE\\j.novak",,,,,,,,9,"10.0.0.1",'
    '"ASA-VPN",,,,,,,4,"VPN users",16,"311 1 10.0.0.9 09/01/2026 07:00:00 5"'
    + ',' * 33 + TAIL,
]


# ---------------------------------------------------------------------------
title('Reading a line')
ok('every line has the sixty-six columns NPS writes', len(isemon.NPS_COLUMNS), 66)
for name, pair in (('the probe', PROBE), ('MAB', MAB_OK), ('802.1X', DOT1X_OK),
                   ('Wi-Fi', WIFI_OK), ('the VPN', VPN_BAD), ('something else', OTHER_OK)):
    ok('%s splits into all of them' % name,
       [len(isemon.nps_split(line)[0] or []) for line in pair], [66, 66])
GOT = isemon.nps_parse_lines(PROBE + ACCT, {})
ok('the switches asking whether the server is there are nobody', GOT, [])
GOT = isemon.nps_parse_lines(
    MAB_OK + DOT1X_OK + DOT1X_BAD + MAB_BAD + WIFI_OK + WIFI_BAD + OTHER_OK + VPN_BAD, {})
ok('one record an answer', len(GOT), 8)
ok('each one filed at the door its REQUEST says',
   [r.door for r in GOT],
   ['nps-mab-lan', 'nps-dot1x-lan', 'nps-dot1x-lan', 'nps-mab-lan', 'nps-dot1x-wifi',
    'nps-dot1x-wifi', 'nps-other', 'nps-vpn'])
ok('...and each verdict out of its ANSWER',
   [r.failed for r in GOT], [False, False, True, True, False, True, False, True])
mab, dot1x, dot1x_bad, mab_bad, wifi, wifi_bad, other, vpn = GOT
ok('the name without the domain it was written with', dot1x.user, 'pc.terminal')
ok('...and the domain kept beside it', dot1x.realm, 'MUZABREH')
ok('...a name written as an address loses the address', other.user, 'jan.novak')
ok('a refusal says why in words', mab_bad.message,
   'wrong password, or an account that does not exist')
ok('...and so does a certificate that failed', dot1x_bad.message,
   'the EAP exchange failed (usually the certificate)')
ok('...and a code nobody has named is its number', isemon.nps_reason('999'),
   'reason code 999')
ok('the time is the one on the line', time.strftime('%Y-%m-%d %H:%M:%S',
                                                    time.localtime(dot1x.ts)),
   '2026-09-01 06:11:50')
ok('a machine on a socket has no address that knocked', (mab.ip, dot1x.ip), ('', ''))
ok('...and neither does a machine on a radio', wifi.ip, '')
ok('a VPN sign-in has the address it came from', vpn.ip, '198.51.100.23')
ok('one answer is one id, and the same one every time it is read',
   [r.session for r in isemon.nps_parse_lines(MAB_OK, {})], [mab.session])
ok('...which says where it came from', isemon.is_nps_session(mab.session))
ok('...and is short enough for every engine’s key', len(mab.session) < 80)
ok('a request is answered once: a second answer to it is not another record',
   len(isemon.nps_parse_lines(MAB_OK + [MAB_OK[1].replace(',2,,', ',3,,', 1)], {})), 1)

# A line that came through syslog has a stamp and a host in front of it.
SYSLOGGED = ['2026-09-01T06:11:50+02:00 nps02 IAS: ' + line for line in DOT1X_OK]
ok('a line that came through syslog is read all the same',
   [r.door for r in isemon.nps_parse_lines(SYSLOGGED, {})], ['nps-dot1x-lan'])

title('Accounts somebody said to leave out')
ok('nothing is left out until somebody names it', isemon.nps_ignored('testaccount',
                                                                  ignore=''), False)
ok('a name leaves out that account, with its domain or without it',
   [isemon.nps_ignored(n, ignore='testaccount') for n in (
       'testaccount', 'MUZABREH\\testaccount', 'TestAccount@example.int', 'testaccount2')],
   [True, True, True, False])
ok('...and a name with a domain leaves out that domain’s account only',
   [isemon.nps_ignored(n, ignore='EXAMPLE\\svc') for n in ('EXAMPLE\\svc', 'OTHER\\svc')],
   [True, False])
isemon.CONFIG['nps_ignore'] = 'pc.terminal, printer9'
ok('an account named in the settings is no record at all, on either side',
   [r.door for r in isemon.nps_parse_lines(MAB_OK + DOT1X_OK + DOT1X_BAD, {})],
   ['nps-mab-lan'])
isemon.CONFIG['nps_ignore'] = ''
ok('...and back as it was once the setting is emptied',
   len(isemon.nps_parse_lines(MAB_OK + DOT1X_OK + DOT1X_BAD, {})), 3)
ok('the setting is on the NPS page, greyed out while the module is off',
   "'nps', 'nps_paths', 'nps_name', 'nps_ignore', 'nps_port_names']" in PAGE_SRC
   and "nps_ignore: ['nps', '1']" in PAGE_SRC)

title('Every number in it, in words')
ok('a Cisco port number is the stack member and the port',
   [isemon.nps_port(n) for n in ('50124', '50548', '50101', '50436')],
   ['1/0/24', '5/0/48', '1/0/1', '4/0/36'])
ok('...and anything else is left as it came', [isemon.nps_port(n) for n in ('0', '7',
                                                                             '50100', 'x')],
   ['0', '7', '50100', 'x'])
W = {k: isemon.ise_first(wifi.fields, k) for k in wifi.fields}
ok('the make of the device that asked', isemon.ise_first(mab.fields, 'Make of the device'),
   'Cisco (9)')
ok('...who checked the credentials', isemon.ise_first(mab.fields, 'Checked by'),
   'Windows (Active Directory) (1)')
ok('...what was handed to the switch', (isemon.ise_first(mab.fields, 'Tunnel type'),
                                       isemon.ise_first(mab.fields, 'Tunnel medium')),
   ('VLAN (13)', '802 (Ethernet) (6)'))
ok('...which NPS answered, and since when its service has run',
   (isemon.ise_first(mab.fields, 'Answered by NPS at'),
    isemon.ise_first(mab.fields, 'NPS service running since')),
   ('172.29.136.9', '07/23/2026 07:23:32'))
ok('...the domain MS-CHAP wrote as hex', W.get('Domain (MS-CHAP)'), 'MUZABREH')
ok('...the MAC an Aruba controller writes as bare hex, as a MAC',
   W.get('The machine\u2019s MAC'), '44-85-00-0E-D9-13')
ok('...the packet', isemon.ise_first(mab.fields, 'Packet'), 'Access-Accept (2)')
ok('...and the port on the opened record, named', isemon.ise_first(mab.fields, 'Switch port'),
   'GigabitEthernet4/0/36')
ok('every reason code Microsoft lists has words',
   all(isemon.nps_reason(c) and not isemon.nps_reason(c).startswith('reason code')
       for c in ('9', '19', '36', '49', '73', '117', '265', '268', '302')))
ok('...seconds and bytes read the way somebody says them',
   (isemon.nps_seconds('28800'), isemon.nps_seconds('90'), isemon.nps_bytes('1048576')),
   ('8 h', '90 s', isemon.human_size(1048576)))

title('A request and its answer, wherever the file was cut')
HOLD = {}
FIRST = isemon.nps_parse_lines(DOT1X_OK[:1], HOLD)
ok('a request on its own is nothing yet', FIRST, [])
ok('...and is kept, in the shape a tail’s hold is packed in',
   list(isemon.LogTail.unpack_hold(isemon.LogTail.pack_hold(HOLD)).values())
   == list(HOLD.values()))
PACKED = isemon.LogTail.unpack_hold(isemon.LogTail.pack_hold(HOLD))
AFTER = isemon.nps_parse_lines(DOT1X_OK[1:], PACKED)
ok('...so that its answer, read after a restart, finds it',
   [r.door for r in AFTER], ['nps-dot1x-lan'])
ok('...and it is let go once answered', PACKED, {})
ok('an answer whose request was never seen is not guessed at',
   isemon.nps_parse_lines(DOT1X_OK[1:], {}), [])
MANY = {}
for n in range(400):
    isemon.nps_parse_lines([DOT1X_OK[0].replace('815915', 'x%d' % n)], MANY)
ok('requests never answered are not kept for ever', len(MANY) <= isemon.NPS_WAIT_MOST)
ok('...and what a tail keeps across a restart is the newest of them, never none',
   len(isemon.LogTail.pack_hold(MANY)), min(len(MANY), isemon.LogTail.HOLD_KEPT_MOST))
# A busy server: four hundred requests outstanding at once, and then their
# answers. Up to 1.10.96 only the newest 120 still had a request to be
# joined to; the rest were no row at all, and nothing said so.
BUSY = {}
asks = [DOT1X_OK[0].replace('815915', 'b%d' % n) for n in range(400)]
answers = [DOT1X_OK[1].replace('815915', 'b%d' % n) for n in range(400)]
got = isemon.nps_parse_lines(asks + answers, BUSY)
ok('four hundred requests outstanding at once all find their answers',
   len([r for r in got if isinstance(r, isemon.NpsRecord)]), 400)

# ---------------------------------------------------------------------------
title('Stored')
folder, store, daemon = fresh()
ALL = PROBE + ACCT + MAB_OK + DOT1X_OK + DOT1X_BAD + MAB_BAD + WIFI_OK + WIFI_BAD \
    + OTHER_OK + VPN_BAD
ok('reading it wrote something down', daemon.read_records(ALL, kind='nps'), 8)


def kinds(table):
    return {r['kind']: r['n'] for r in store.db.execute(
        'SELECT kind, COUNT(*) AS n FROM %s GROUP BY kind' % table)}


ok('what NPS let on, at its own doors', kinds('passed'),
   {'nps-mab-lan': 1, 'nps-dot1x-lan': 1, 'nps-dot1x-wifi': 1, 'nps-other': 1})
ok('what NPS refused, at its own doors', kinds('failed'),
   {'nps-dot1x-lan': 1, 'nps-mab-lan': 1, 'nps-dot1x-wifi': 1, 'nps-vpn': 1})
row = dict(store.db.execute("SELECT * FROM passed WHERE kind='nps-mab-lan'").fetchone())
ok('a machine is its MAC, in the one shape this uses', row['mac'], 'B0-0C-D1-E0-BF-88')
ok('...on the switch NPS knows it by', (row['device'], row['nad']),
   ('SW_B1_SW1_STACK', '192.168.200.3'))
ok('...at the port the switch said, written the way ISE writes one',
   row['port'], 'GigabitEthernet4/0/36')
ok('...with the address it had', row['client'], '192.168.5.39')
ok('...the network policy that let it on', row['profile'], '802.1x VLAN5 Tiskarny')
ok('...and the VLAN it was handed', row['tkey'], '5')
ok('...answered by that NPS server', row['server'], 'NPS02')
row = dict(store.db.execute("SELECT * FROM passed WHERE kind='nps-dot1x-wifi'").fetchone())
ok('on a radio, the access point that heard it', row['port'], '44-48-C1-C8-F5-8E')
ok('...the machine, whatever spelling the controller used', row['mac'],
   '44-85-00-0E-D9-13')
ok('...and how it proved itself', row['subtype'], 'Secured password (EAP-MSCHAP v2)')
row = dict(store.db.execute("SELECT * FROM failed WHERE kind='nps-dot1x-lan'").fetchone())
ok('a refusal carries NPS’s own code', row['code'], '23')
ok('...and its reason in words', row['reason'],
   'the EAP exchange failed (usually the certificate)')
ok('...and no address that knocked, so nobody can ban a desk by it', row['ip'] or '', '')
detail = store.unpack_detail(dict(store.db.execute(
    "SELECT detail FROM failed WHERE kind='nps-dot1x-lan'").fetchone())['detail'])
ok('the opened record holds the request and the answer together',
   all(k in detail for k in ('Calling-Station-Id', 'NAS-Port-Type', 'Reason-Code',
                             'EAP-Friendly-Name', 'What it said')))
ok('nothing read from NPS is ever judged, a VPN refusal included',
   store.db.execute('SELECT COUNT(*) AS n FROM blocked').fetchone()['n'], 0)
vpn_row = dict(store.db.execute("SELECT * FROM failed WHERE kind='nps-vpn'").fetchone())
ok('...though the VPN refusal keeps the address it came from', vpn_row['ip'],
   '198.51.100.23')
ok('reading the same lines again adds nothing', daemon.read_records(ALL, kind='nps'), 0)

title('The box at the top finds it all')
said = daemon.find('b00c.d1e0')
ok('a machine by its MAC, however it is typed', [m['said'] for m in said['macs']],
   ['B0-0C-D1-E0-BF-88'])
ok('...with the door it is at', said['macs'][0]['kinds'], ['nps-mab-lan'])
said = daemon.find('192.168.5.3')
ok('an address a machine was given, which is no row\u2019s source address',
   [c['said'] for c in said['clients']], ['192.168.5.39'])
said = daemon.find('sw_b1_sw1')
ok('a switch by its name', [d['said'] for d in said['devices']], ['SW_B1_SW1_STACK'])
said = daemon.find('pc.term')
ok('a name, with the doors it is at', said['names'][0]['doors'],
   {'failed': ['nps-dot1x-lan'], 'passed': ['nps-dot1x-lan']})
ok('the page offers all of them',
   all(w in PAGE_SRC for w in ("group('Machines, by MAC'", "group('Network devices'",
                               "group('Addresses machines were given'",
                               "group('Commands typed on the kit'")))
# ...and what 1.10.88 wrote with the port as a bare number is put right.
with store.db_write() as dbw:
    dbw.execute("UPDATE passed SET port = '50436' WHERE kind = 'nps-mab-lan'")
ok('a port 1.10.88 wrote as a number is written the switch\u2019s way at the next start',
   store.mend_nps_ports(force=True), 1)
ok('...as GigabitEthernet4/0/36', store.db.execute(
    "SELECT port FROM passed WHERE kind = 'nps-mab-lan'").fetchone()['port'],
   'GigabitEthernet4/0/36')
ok('...and a second start finds nothing to do', store.mend_nps_ports(force=True), 0)
ok('...and a start under the same version and setting does not even walk the rows',
   store.mend_nps_ports(), 0)
isemon.CONFIG['nps_port_names'] = 'SW_B1_*=FastEthernet, TenGigabitEthernet'
ok('a different name for the ports renames the ones already stored', store.mend_nps_ports(),
   4)
ok('...each switch by the rule that matches it',
   sorted(r['port'] for r in store.db.execute(
       "SELECT port FROM passed WHERE kind IN ('nps-mab-lan','nps-dot1x-lan')")),
   ['FastEthernet4/0/36', 'TenGigabitEthernet3/0/5'])
isemon.CONFIG['nps_port_names'] = ''
ok('...and no name at all is the number alone', store.mend_nps_ports(), 4)
isemon.CONFIG['nps_port_names'] = 'GigabitEthernet'
store.mend_nps_ports()
# The setting saved in the database, not the default, is what a start goes
# by. 1.10.93 and 1.10.94 mended while the database was being opened, before
# the saved settings were read, and so by the default: a site that had
# emptied the setting got every port renamed GigabitEthernet at each start
# and back again whenever the settings were saved.
# On a file only: on a database server the suites empty the one database at
# every Storage, so there is no opening it again to ask about.
ON_FILE = not getattr(isemon.Storage, 'ENGINE', None)
store.settings_write({'nps_port_names': ''}, by='check')
isemon.CONFIG['nps_port_names'] = ''
store.mend_nps_ports()                    # the mark now says "no name"
isemon.CONFIG['nps_port_names'] = 'GigabitEthernet'   # the default, as at a start
if ON_FILE:
    store.db.close()
    storeP = isemon.Storage(isemon.DB_FILE)
else:
    storeP = store
ok('opening the database renames no port: the saved setting is not read yet'
   + ('' if ON_FILE else ' (asked of the running one here)'),
   sorted(r['port'] for r in storeP.db.execute(
       "SELECT port FROM passed WHERE kind IN ('nps-mab-lan','nps-dot1x-lan')")),
   ['3/0/5', '4/0/36'])
daemonP = isemon.Daemon(storeP)
ok('...and the daemon, with the saved setting in, leaves them as it says',
   sorted(r['port'] for r in storeP.db.execute(
       "SELECT port FROM passed WHERE kind IN ('nps-mab-lan','nps-dot1x-lan')")),
   ['3/0/5', '4/0/36'])
storeP.settings_write({'nps_port_names': 'GigabitEthernet'}, by='check')
daemonP.adopt_settings()
ok('...and names them the moment the saved setting says to',
   sorted(r['port'] for r in storeP.db.execute(
       "SELECT port FROM passed WHERE kind IN ('nps-mab-lan','nps-dot1x-lan')")),
   ['GigabitEthernet3/0/5', 'GigabitEthernet4/0/36'])
store, daemon = storeP, daemonP
ok('the rules: a pattern per switch, first match wins, a bare name for the rest',
   [isemon.nps_port_named(d, '1/0/24', 'sw_old*=FastEthernet, GigabitEthernet')
    for d in ('SW_OLD_2', 'SW_NEW')],
   ['FastEthernet1/0/24', 'GigabitEthernet1/0/24'])
ok('...and a name that is not one is not written into anything',
   isemon.nps_port_named('x', '1/0/2', 'Gigabit Ethernet<>'), 'GigabitEthernet1/0/2')

title('What the accounting says a machine was given')
ACCT_WIFI = ('"NPS02","IAS",09/01/2026,06:20:00,4,"pracovnik",,"4448c1c8f58e",'
             '"4485000ed913",,"10.9.8.7",,"192.168.215.50",0,14823,"192.168.215.50",'
             '"AP-MASTER",09/01/2026 06:20:00,,19,,,2,,,0,,,,,,3,0,1000,2000,"AB12",1'
             + ',' * 12 + ',"77"' + ',' * 10 + ',"Use Windows authentication for all users",,,,,')
got = isemon.nps_parse_lines([ACCT_WIFI, ACCT_WIFI.replace('06:20:00', '06:25:00', 1)], {})
ok('an accounting line with an address is what that machine is doing now',
   [type(g).__name__ for g in got], ['EduSession'])
ok('...only the newest of a machine\u2019s in one piece',
   time.strftime('%H:%M', time.localtime(got[0].ts)), '06:25')
ok('...with the address, the VLAN and the access point', (got[0].facts['client'],
                                                          got[0].facts['vlan'],
                                                          got[0].facts['ap']),
   ('10.9.8.7', '77', '44-48-C1-C8-F5-8E'))
ok('...and one without an address or a MAC is nothing',
   isemon.nps_parse_lines(ACCT, {}), [])
daemon.read_records(WIFI_OK + [ACCT_WIFI.replace('09/01/2026', '01/12/2026', 1)],
                    kind='nps')
seen = store.eduroam_seen(['44-85-00-0E-D9-13'])
ok('...kept for the page to put beside the sign-ins', seen.get('44-85-00-0E-D9-13', {})
   .get('client'), '10.9.8.7')
ok('the page says an address came from the accounting, and why one may be missing',
   'r.client_seen' in PAGE_SRC and 'sends no RADIUS accounting to NPS' in PAGE_SRC)
NX = (HERE.parent / 'docs/nxlog-nps.conf').read_text(encoding='utf-8')
ok('NXLog sends accounting with an address and drops the rest',
   ',4,("[^"]*"|[^,]*)' in NX, True)
ok('...and sends the challenges, which are the abandoned conversations',
   ',11,/ drop();' in NX, False)

title('The drop-downs over the lists')
PICKED = {'port': 'GigabitEthernet4/0/36'}
rows_, total = store.passed_rows(kind='nps-mab-lan', picks=PICKED)
ok('a port picked narrows the list to it', total, 1)
rows_, total = store.passed_rows(kind='nps-mab-lan', picks={'port': 'GigabitEthernet9/0/9'})
ok('...and one nobody is on leaves nothing', total, 0)
rows_, total = store.passed_rows(kind='nps-mab-lan', picks={'vlan': '5'})
ok('a VLAN picked by its number', total, 1)
rows_, total = store.passed_rows(kind='nps-mab-lan', picks={'vlan': '5', 'port':
                                                            'GigabitEthernet4/0/36'})
ok('...and two of them together are both', total, 1)
rows_, total = store.passed_rows(kind='nps-mab-lan', picks={'vlan': '4', 'port':
                                                            'GigabitEthernet4/0/36'})
ok('...which is AND, not OR', total, 0)
rows_, total = store.passed_rows(kind='nps-mab-lan', picks={'vlan': '5'}, text='B0-0C')
ok('...and the search box works over what is left', total, 1)
rows_, total = store.passed_rows(kind='nps-mab-lan', picks={'vlan': '5'}, text='nothing-like')
ok('...narrowing it further', total, 0)
rows_, total = store.passed_rows(kind='nps-mab-lan', picks={'nonsense': 'x'})
ok('a drop-down nobody has is ignored rather than written into a statement', total, 1)
said = store._pick_values_now('passed', 'port', 'port', ('nps-mab-lan', 'nps-dot1x-lan'))
ok('what a drop-down offers is what is behind the door', said,
   [['GigabitEthernet3/0/5', 'GigabitEthernet3/0/5'],
    ['GigabitEthernet4/0/36', 'GigabitEthernet4/0/36']])
said = store._pick_values_now('passed', 'port', 'port', ('nps-mab-lan', 'nps-dot1x-lan'),
                              'SW_B1_SW1_STACK')
ok('...and a port list out of the switch already chosen', [p[0] for p in said],
   ['GigabitEthernet4/0/36'])
said = store._pick_values_now('passed', 'vlan', 'tkey', ('nps-mab-lan', 'nps-dot1x-lan'))
ok('VLANs offered by number, in order', said, [['4', 'VLAN 4'], ['5', 'VLAN 5']])
# ISE writes a VLAN three ways, and groups several to a row.
for n, (tkey, groups) in enumerate((('607|LAN_Odbor', 'Staff, VPN'), ('607', 'VPN'),
                                    ('LAN_Odbor', 'Staff'), ('608|LAN_Jine', 'Guests'))):
    store.add_passed({'session': 'ise/test/%d' % n, 'ts': time.time() - 60, 'ip': '',
                      'kind': 'dot1x-lan', 'tkey': tkey, 'groups': groups,
                      'device': 'swje%d' % n, 'port': 'GigabitEthernet1/0/%d' % (n + 2)})
store.note_vlan_name('607', 'LAN_Odbor')
rows_, total = store.passed_rows(kind='dot1x-lan', picks={'vlan': '607'})
ok('a VLAN written as a number, a name or both is one VLAN', total, 3)
said = store._pick_values_now('passed', 'vlan', 'tkey', ('dot1x-lan',))
ok('...and offered once, with its name', said,
   [['607', 'VLAN 607 \u00b7 LAN_Odbor'], ['608', 'VLAN 608 \u00b7 LAN_Jine']])
rows_, total = store.passed_rows(kind='dot1x-lan', picks={'group': 'Staff'})
ok('a group picked finds every row that has it among its groups', total, 2)
rows_, total = store.passed_rows(kind='dot1x-lan', picks={'group': 'VPN'})
ok('...wherever it stands in the list', total, 2)
rows_, total = store.passed_rows(kind='dot1x-lan', picks={'group': 'Sta'})
ok('...and never half a name', total, 0)
ok('...offered one by one, not as the lists rows carry',
   [g[0] for g in store._pick_values_now('passed', 'group', 'groups', ('dot1x-lan',))],
   ['Guests', 'Staff', 'VPN'])
ok('a VLAN drop-down is never offered where tkey is not a VLAN',
   store.pick_values('passed', 'vlan', 'tacacs'), [])
ok('the page draws them per door and sends them ANDed',
   'function drawPicks(prefix, kind) {' in PAGE_SRC and "'pick_' + box.dataset.pick" in PAGE_SRC
   and "concat(pickArgs('f'))" in PAGE_SRC and "concat(pickArgs('p'))" in PAGE_SRC)
ok('...and Clear lets go of them', "clearPicks('f');" in PAGE_SRC
   and "clearPicks('p');" in PAGE_SRC)
with store.db_write() as dbw:
    dbw.execute("DELETE FROM passed WHERE session LIKE 'ise/test/%'")

title('Counted, and offered only where there is something')
ok('the counted doors know about each of them',
   all(k in isemon.LOGIN_KINDS for k in isemon.NPS_KINDS))
ok('...kept apart from ISE’s own everywhere',
   store.failed_counts(0).get('mab-lan', 0) + store.passed_counts(0).get('mab-lan', 0), 0)
ok('...and each counted at its own', store.failed_counts(0)['nps-mab-lan'], 1)
ok('"everything else" is not where they went', store.failed_counts(0).get('other', 0), 0)
ok('the doors NPS has answered through are named for the page', daemon.nps_doors(),
   ['nps-vpn', 'nps-dot1x-lan', 'nps-dot1x-wifi', 'nps-mab-lan', 'nps-other'])
ok('...and MAB on Wi-Fi, which it never has, is not among them',
   'nps-mab-wifi' in daemon.nps_doors(), False)
rows_, total = store.failed_rows(kind='nps-network')
ok('a list asked for NPS’s network has its three refusals', total, 3)
rows_, total = store.failed_rows(kind='nps-network', text='00-30-04-13-AA-BB')
ok('...and a MAC typed into the box finds its machine', total, 1)
rows_, total = store.failed_rows(kind='mab-lan')
ok('...while ISE’s own MAB door has nothing of NPS’s', total, 0)
BARS = store.auth_counts(24 * 400)
ok('the chart draws them as bands of their own',
   (sum(b['failed_npsnet'] for b in BARS), sum(b['failed_npsvpn'] for b in BARS),
    sum(b['passed_npsnet'] for b in BARS)), (3, 1, 4))
ok('...and not as ISE’s VPN',
   sum(b['failed'] - b['failed_npsnet'] - b['failed_npsvpn'] for b in BARS)
   + sum(b['passed'] - b['passed_npsnet'] for b in BARS), 0)
said = daemon.door_summary('nps-network', 24 * 400)
ok('the front page has a door for its network', said['name'], '802.1X / MAB · NPS')
ok('...with cards on it', [v['key'] for v in said['views']], ['machines', 'places',
                                                              'reasons'])
ok('...and says which refused machines got on anyway', 'settled' in said)
ok('...and one for its VPN', daemon.door_summary('nps-vpn', 24 * 400)['totals']
   ['failed']['n'], 1)
ok('the status says whether it is read at all', daemon.nps_on())

title('The database page')
said = store.inside(('nps',))
ok('says how much of it there is', (said['nps']['parts']['accepted'],
                                    said['nps']['parts']['refused']), (4, 4))
ok('...and it has a group of its own to erase', 'nps' in store.ERASABLE)
ok('...which forgets where the files were read up to',
   store.ERASABLE['nps']['reread'], ('nps',))
gone = store.erase(['nps'])
ok('erasing it takes every one of them',
   store.db.execute("SELECT COUNT(*) AS n FROM failed").fetchone()['n']
   + store.db.execute("SELECT COUNT(*) AS n FROM passed").fetchone()['n'], 0)
ok('...and says how many that was', gone['nps'], 8)

# ---------------------------------------------------------------------------
title('Which files are read')
base = Path(folder) / 'nps02'
base.mkdir()
for n, name in enumerate(('IN2607.log', 'IN2608.log', 'IN2609.log', 'IN2609.log.gz',
                          'notes.txt')):
    if name.endswith('.gz'):
        # A copy logrotate made of it: packed, and holding a pair of its own.
        with gzip.open(base / name, 'wt', encoding='utf-8') as packed:
            packed.write('\n'.join(MAB_OK) + '\n')
    else:
        (base / name).write_text('\n'.join(DOT1X_OK) + '\n', encoding='utf-8')
    os.utime(base / name, (1_700_000_000 + n * 1000,) * 2)
ok('the newest two are followed',
   [Path(p).name for p in isemon.nps_newest(str(base))], ['IN2608.log', 'IN2609.log'])
ok('...and every month there is is what going back over NPS means',
   [Path(p).name for p in isemon.nps_matching(str(base))],
   ['IN2607.log', 'IN2608.log', 'IN2609.log'])
ok('a folder with nothing in it yet names the file it is waiting for',
   Path(isemon.nps_newest(str(Path(folder) / 'empty'))[0]).name.startswith('IN'))
ok('the daemon follows them', [(k, Path(p).name, s) for k, p, s in daemon.log_files()],
   [('nps', 'IN2608.log', 'nps'), ('nps', 'IN2609.log', 'nps')])
ok('the logs can be named on their own', isemon.log_modules_named('nps'), ['nps'])
ok('...and they are read in the zone the setting says', 'nps' in isemon.ZONELESS_LOGS)
ok('...from the folders the erase group forgets', isemon.log_folders('nps'),
   [str(base)])
said = daemon.rescan(logs=('nps',))
ok('going back over NPS reads every month there is, and the copies rotated out of them',
   said['seen'], 4)
ok('...and writes each answer down once', said['added'], 2)
ok('...and weighs nothing, because nothing in it is judged', said['weighed'], 0)
isemon.CONFIG['nps'] = 0
ok('switched off, not one of its files is opened', daemon.log_files(), [])
ok('...and it offers no door', daemon.nps_on(), False)
isemon.CONFIG['nps'] = 1

# ---------------------------------------------------------------------------
title('The page it is drawn on')
ok('a door of its own for each of the four ISE has, and the VPN',
   all("{kind: '%s', words: '%s'" % pair in PAGE_SRC for pair in (
       ('nps-vpn', 'NPS VPN'), ('nps-dot1x-lan', 'NPS 802.1X LAN'),
       ('nps-dot1x-wifi', 'NPS 802.1X Wi-Fi'), ('nps-mab-lan', 'NPS MAB LAN'),
       ('nps-mab-wifi', 'NPS MAB Wi-Fi'))))
ok('...offered only while its logs are read', 'if (isNpsKind(kind)) return !s.nps_on;'
   in PAGE_SRC)
ok('...and drawn as the network rows ISE’s are, naming NPS where they name ISE',
   "'nps-dot1x-lan', 'nps-dot1x-wifi', 'nps-mab-lan', 'nps-mab-wifi'," in PAGE_SRC
   and "var SYS = isNpsKind(kind) ? 'NPS' : (isRadiusKind(kind) ? 'FreeRADIUS' : 'ISE');"
   in PAGE_SRC)
ok('the front page offers its doors only where NPS has answered through them',
   "if (npsHas(['nps-vpn'])) {" in PAGE_SRC and "door: 'nps-network'" in PAGE_SRC)
ok('...with bands and a legend of their own',
   "['npsvpn', '#a40e26'], ['npsnet', '#6e40c9']" in PAGE_SRC
   and 'id="leg-nps-vpn-bad"' in PAGE_SRC)
ok('the settings have a page of their own',
   'id="pane-nps"' in PAGE_SRC and "nps:     ['nps', 'nps_paths', 'nps_name', 'nps_ignore', 'nps_port_names']" in PAGE_SRC)
ok('...each greyed out while the module is off', "nps_paths: ['nps', '1']" in PAGE_SRC)
ok('the database page names it', "nps:     {words: 'from a Windows NPS server'"
   in PAGE_SRC)
ok('how to get the files here is shipped', (HERE.parent / 'docs/nps-logs.md').exists())
ok('...with the NXLog configuration for the NPS servers, as the domain\u2019s has',
   (HERE.parent / 'docs/nxlog-nps.conf').exists())
NXLOG = (HERE.parent / 'docs/nxlog-nps.conf').read_text(encoding='utf-8')
ok('...which reads NPS\u2019s own files and sends every line as it is',
   "File            '%NPSLOGS%\\IN*.log'" in NXLOG and '$Message = $raw_event;' in NXLOG)
ok('...over TCP, because a lost line is a lost pair', 'Module      om_tcp' in NXLOG)
ok('...tagged the way the receiving rule files it',
   "$SourceName = 'nps';" in NXLOG
   and "if $programname == 'nps' then {" in (
       HERE.parent / 'deploy/nps/06-nps-store.conf').read_text(encoding='utf-8'))
ok('...into a file the default pattern finds', isemon.fnmatch.fnmatch('IN.log', 'IN*.log')
   and '/IN.log")' in (HERE.parent / 'deploy/nps/06-nps-store.conf').read_text(
       encoding='utf-8'))
ok('...and no comment inside an Exec, which NXLog would read as the end of it',
   [line for line in NXLOG.splitlines()
    if line.rstrip().endswith('\\') and '#' in line and not line.lstrip().startswith('#')],
   [])
ok('...and no address of anybody\u2019s real network in either',
   sorted({a for f in ('docs/nxlog-nps.conf', 'deploy/nps/06-nps-store.conf')
           for a in re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                               (HERE.parent / f).read_text(encoding='utf-8'))
           if not a.startswith('192.0.2.')}), [])
# A line as rsyslog stores it on this side: a full stamp, the host, the tag.
STORED = ['2026-09-01T06:11:50.123456+02:00 nps01 nps: ' + line for line in DOT1X_OK]
ok('a line as the receiving rule stores it is read as it stands',
   [r.door for r in isemon.nps_parse_lines(STORED, {})], ['nps-dot1x-lan'])
ok('...and names no site’s machine',
   __import__('base64').b64decode('Zm5vbA==').decode() not in (HERE.parent / 'docs/nps-logs.md').read_text(encoding='utf-8').lower())

title('eduroam, answered by NPS')


def nps_line(**cols):
    """One line of NPS's log, with the columns named rather than counted."""
    row = [''] * 66
    for name, value in cols.items():
        row[isemon.NPS_COL[name.replace('_', '-')]] = value
    quoted = {'Computer-Name', 'Service-Name', 'User-Name', 'Fully-Qualified-User-Name',
              'Called-Station-Id', 'Calling-Station-Id', 'Framed-IP-Address',
              'NAS-Identifier', 'NAS-IP-Address', 'Client-IP-Address',
              'Client-Friendly-Name', 'Policy-Name', 'Class', 'EAP-Friendly-Name',
              'Proxy-Policy-Name', 'Remote-Server-Address', 'Tunnel-Pvt-Group-ID'}
    return ','.join(('"%s"' % v if v and isemon.NPS_COLUMNS[i] in quoted else v)
                    for i, v in enumerate(row))


def pair(when, klass, answer, reason='0', **req):
    common = dict(Computer_Name='NPS01', Service_Name='IAS', Record_Date='09/02/2026',
                  Record_Time=when, Client_IP_Address='10.1.1.5',
                  Client_Friendly_Name='WLC-1', Class=klass)
    ask = dict(common, Packet_Type='1', NAS_Port_Type='19', Service_Type='2',
               Authentication_Type='11', **req)
    got = dict(common, Packet_Type=answer, Reason_Code=reason,
               Fully_Qualified_User_Name=req.get('Fully_Qualified_User_Name', ''),
               Proxy_Policy_Name=req.get('Proxy_Policy_Name', ''),
               Provider_Type=req.get('Provider_Type', '1'),
               Remote_Server_Address=req.get('Remote_Server_Address', ''))
    return [nps_line(**ask), nps_line(**got)]


EDU = (pair('08:00:00', '311 1 10.1.1.9 09/01/2026 07:00:00 1', '2',
            User_Name='jan@example.cz', Fully_Qualified_User_Name='EXAMPLE\\jan',
            Calling_Station_Id='AA-BB-CC-00-00-01',
            Called_Station_Id='00-11-22-33-44-55:eduroam',
            Proxy_Policy_Name='eduroam - our realm', Provider_Type='1')
       + pair('08:01:00', '311 1 10.1.1.9 09/01/2026 07:00:00 2', '2',
              User_Name='anonymous@cvut.cz', Calling_Station_Id='AA-BB-CC-00-00-02',
              Called_Station_Id='00-11-22-33-44-66:eduroam',
              Proxy_Policy_Name='eduroam - to the national servers', Provider_Type='2',
              Remote_Server_Address='78.128.248.10')
       + pair('08:02:00', '311 1 10.1.1.9 09/01/2026 07:00:00 3', '3', '16',
              User_Name='eva@example.cz', Fully_Qualified_User_Name='EXAMPLE\\eva',
              Calling_Station_Id='AA-BB-CC-00-00-03',
              Proxy_Policy_Name='eduroam - our realm', Provider_Type='1')
       # ...and a switch's 802.1X on the same NPS, which is not eduroam's.
       + pair('08:03:00', '311 1 10.1.1.9 09/01/2026 07:00:00 4', '2',
              User_Name='pc01', Calling_Station_Id='AA-BB-CC-00-00-04', NAS_Port='50101',
              Proxy_Policy_Name='Use Windows authentication for all users')
       + [nps_line(Computer_Name='NPS01', Service_Name='IAS', Record_Date='09/02/2026',
                   Record_Time='08:05:00', Packet_Type='4', User_Name='jan@example.cz',
                   Calling_Station_Id='AA-BB-CC-00-00-01',
                   Called_Station_Id='00-11-22-33-44-55:eduroam',
                   Framed_IP_Address='10.20.30.40', NAS_Port_Type='19',
                   Client_Friendly_Name='WLC-1', Acct_Status_Type='3')])
ok('every one of those lines is NPS\u2019s own shape',
   {len(isemon.nps_split(line)[0] or []) for line in EDU}, {66})
folderE, storeE, daemonE = fresh(on=0)
isemon.CONFIG.update({'eduroam': 1, 'eduroam_format': 'nps',
                      'eduroam_paths': [str(Path(folderE) / 'eduroam')],
                      'eduroam_nps_name': 'IN*.log', 'eduroam_nps_policy': 'eduroam*',
                      'eduroam_ignore': ''})
ok('with NPS chosen, its newest files are what the eduroam module follows',
   [(k, s_) for k, _p, s_ in daemonE.log_files()], [('eduroam', 'eduroam-nps')])
daemonE.read_records(EDU, kind='eduroam-nps')
got = {r['username']: dict(r) for r in storeE.db.execute(
    "SELECT * FROM passed WHERE kind='eduroam'")}
ok('the eduroam sign-ins become eduroam rows', sorted(got), ['anonymous@cvut.cz',
                                                            'jan@example.cz'])
ok('...one of ours by the name the directory resolved, with our institution',
   (got['jan@example.cz']['realm'], got['jan@example.cz']['mac']),
   ('example.cz', 'AA-BB-CC-00-00-01'))
ok('...and a visitor by the institution they came from', got['anonymous@cvut.cz']['realm'],
   'cvut.cz')
detail = storeE.unpack_detail(got['anonymous@cvut.cz']['detail'])
ok('...who the national servers vouched for, and the record says so',
   'the national eduroam servers' in detail and '78.128.248.10' in detail)
bad = [dict(r) for r in storeE.db.execute("SELECT * FROM failed WHERE kind='eduroam'")]
ok('a refusal is an eduroam refusal, with the reason in words',
   [(r['username'], r['reason']) for r in bad],
   [('eva@example.cz', 'wrong password, or an account that does not exist')])
ok('the switch\u2019s 802.1X on the same NPS is not eduroam\u2019s',
   storeE.db.execute("SELECT COUNT(*) AS n FROM passed WHERE username='pc01'")
   .fetchone()['n'], 0)
seen = storeE.eduroam_seen(['AA-BB-CC-00-00-01'])
ok('the accounting says what the machine was given, as eduroam\u2019s detail files do',
   (seen.get('AA-BB-CC-00-00-01') or {}).get('client'), '10.20.30.40')
ok('...and nothing is judged', storeE.db.execute(
    'SELECT COUNT(*) AS n FROM blocked').fetchone()['n'], 0)
isemon.CONFIG['eduroam_nps_policy'] = ''
ok('with no policy named, everything in those files is eduroam',
   len(isemon.edu_nps_parse_lines(EDU, {})), 5)
isemon.CONFIG['eduroam_format'] = 'freeradius'
ok('FreeRADIUS chosen, it is read exactly as it always was',
   [s_ for _k, _p, s_ in daemonE.log_files()], ['eduroam', 'eduroam-detail'])
ok('the eduroam module can be read again whichever it is',
   isemon.log_modules_named('eduroam'), ['eduroam', 'eduroam-detail', 'eduroam-nps'])
isemon.CONFIG.update({'eduroam': 0})
shutil.rmtree(folderE, ignore_errors=True)

# Last, because on a server engine every fresh store is the one shared
# database emptied, and the rest above would lose its rows under it.
title('MAB first, then 802.1X: the ordinary way a PC joins, as on ISE')
folderM, storeM, daemonM = fresh()
# The terminal that got on by its certificate, refused by MAB a second
# before - the switch always asks by MAC first - and a printer nobody has
# enrolled, refused and never let on.
PC_MAB_FIRST = [
    '"NPS02","IAS",09/01/2026,06:11:49,1,"00300413aac8","MUZABREH\\00300413aac8",'
    '"00-D6-FE-5E-70-85","00-30-04-13-AA-C8",,"192.168.4.21",,"192.168.200.22",50305,9,'
    '"192.168.200.22","SW_B2_SW2_STACK",,,15,,,10,1,,0,'
    '"311 1 172.29.136.9 07/23/2026 07:23:32 815900"' + ',' * 33 + TAIL,
    '"NPS02","IAS",09/01/2026,06:11:49,3,,"MUZABREH\\00300413aac8",,,,,,,,9,'
    '"192.168.200.22","SW_B2_SW2_STACK",,,,,,,1,,16,'
    '"311 1 172.29.136.9 07/23/2026 07:23:32 815900"' + ',' * 33 + TAIL,
]
daemonM.read_records(PC_MAB_FIRST + DOT1X_OK + MAB_BAD, kind='nps')
said = daemonM.door_summary('nps-network', 24 * 400)
cards = {v['key']: [r['said'] for r in v['rows']] for v in said['views']}
ok('the PC refused by MAB and let on by 802.1X is on no card',
   '00-30-04-13-AA-C8' in str(cards), False)
ok('...while the printer that never got on is', '00-30-04-13-AA-BB' in cards.get('machines', []))
ok('...and the reasons are the printer\u2019s alone, not the PC\u2019s as well',
   [(r['said'], r['failed']) for r in [v for v in said['views']
                                       if v['key'] == 'reasons'][0]['rows']],
   [('wrong password, or an account that does not exist', 1)])
ok('...and the line under the door says one of the two got on anyway',
   (said['settled']['settled'], said['settled']['machines']), (1, 2))
places = [v for v in said['views'] if v['key'] == 'places'][0]['rows']
rows_, total = storeM.failed_rows(kind='nps-network', device=places[0]['said'],
                                  settled='mac')
ok('pressing a switch on that card opens the refusals it counted, and no others',
   (total, places[0]['failed']), (places[0]['failed'], places[0]['failed']))
rows_, total = storeM.failed_rows(kind='nps-network', settled='mac')
ok('...which leaves out the PC that got on by 802.1X', {r['mac'] for r in rows_},
   {'00-30-04-13-AA-BB'})
rows_, total = storeM.failed_rows(kind='drawn')
ok('what one bar of the chart stands for is a door of its own', total, 2)
PAGE_NOW = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')
ok('the page opens those, and the tiles their own 24 hours',
   "where += '&settled=' + encodeURIComponent(view.settled);" in PAGE_NOW
   and "kind=drawn&from=" in PAGE_NOW and "peek('Refused \\u2014 the last 24 hours'"
   in PAGE_NOW)
ok('...and a name on the front page by the name exactly, at the card\u2019s own door',
   "'&limit=250&username=' + encodeURIComponent(name)" in PAGE_NOW
   and "peekName(Object.assign({kind: 'vpn'}, r))" in PAGE_NOW)
ok('...and the domain\u2019s cards on the front page in the front page\u2019s window',
   "var front = TAB === 'overview';" in PAGE_NOW)
ok('nothing in it is judged, as on ISE', storeM.db.execute(
    'SELECT COUNT(*) AS n FROM blocked').fetchone()['n'], 0)
shutil.rmtree(folderM, ignore_errors=True)

title('An EAP conversation the machine walked away from, as ISE\u2019s 5440')
folderA, storeA, daemonA = fresh()


def walked_away(when, klass, user, mac, finished=None):
    """A request NPS answered with a challenge - and, if `finished`, the
    answer the conversation went on to."""
    ask = ('"NPS02","IAS",09/01/2026,%s,1,"%s","MUZABREH\\%s","00-D6-FE-5E-70-85","%s",,'
           '"192.168.4.21",,"192.168.200.22",50305,9,"192.168.200.22","SW_B2_SW2_STACK",,,'
           '15,,,2,5,"802.1x VLAN4 Terminaly",0,"%s"' % (when, user, user, mac, klass)
           + ',' * 33 + TAIL)
    challenge = ('"NPS02","IAS",09/01/2026,%s,11,,"MUZABREH\\%s",,,,,,,,9,'
                 '"192.168.200.22","SW_B2_SW2_STACK",,,,,,,5,"802.1x VLAN4 Terminaly",0,'
                 '"%s",30' % (when, user, klass) + ',' * 32 + TAIL)
    lines = [ask, challenge]
    if finished:
        lines.append('"NPS02","IAS",09/01/2026,%s,2,,"MUZABREH\\%s",,,,,,,,9,'
                     '"192.168.200.22","SW_B2_SW2_STACK",,,,,,2,5,"802.1x VLAN4 Terminaly",0,'
                     '"%s"' % (finished, user, klass) + ',' * 33 + TAIL)
    return lines


# A zero client that gave up half way and got on six minutes later by its
# certificate (DOT1X_OK is the same MAC), a machine that gave up and never
# got on, and a conversation that was challenged and then did finish.
AWAY = (walked_away('06:05:40', '311 1 172.29.136.9 07/23/2026 07:23:32 900001',
                    'pc.terminal', '00-30-04-13-AA-C8')
        + walked_away('06:05:45', '311 1 172.29.136.9 07/23/2026 07:23:32 900002',
                      'zero.client', '00-30-04-13-A9-97')
        + walked_away('06:05:50', '311 1 172.29.136.9 07/23/2026 07:23:32 900003',
                      'pc.other', '00-30-04-13-A9-01', finished='06:05:51'))
holdA = {}
early = isemon.nps_parse_lines(AWAY, holdA)
ok('a challenge is not a refusal the moment it is read: the conversation may go on',
   [r for r in early if isinstance(r, isemon.NpsRecord) and not r.ok], [])
ok('...and one that did go on is simply its answer', [(r.user, r.ok) for r in early
                                                     if isinstance(r, isemon.NpsRecord)],
   [('pc.other', True)])
later = isemon.nps_parse_lines(DOT1X_OK, holdA)
gone = sorted((r.user, r.door, r.ok, r.abandoned) for r in later
              if isinstance(r, isemon.NpsRecord) and r.abandoned)
ok('a few minutes on with no answer, it is a refusal at its door',
   gone, [('pc.terminal', 'nps-dot1x-lan', False, True),
          ('zero.client', 'nps-dot1x-lan', False, True)])
ok('...saying what happened, since NPS gave no reason code for it',
   {isemon.ise_first(r.fields, 'What it said') for r in later if r.abandoned},
   {isemon.NPS_ABANDONED})
ok('...and the 30 s on the challenge as the wait it was, not a session limit',
   [(isemon.ise_first(r.fields, 'Waited for the next answer'), 'Session limit' in r.fields)
    for r in later if r.abandoned][:1], [('30 s', False)])
ok('...under an id of its own, never the one a real answer to it would have',
   all('/11/' in r.ident for r in later if r.abandoned), True)
ok('...and nothing is left waiting', len(holdA), 0)
# Through the daemon, the way a file is read.
daemonA.read_records(AWAY + DOT1X_OK, kind='nps')
got = storeA.db.execute("SELECT username, code, reason, kind, mac FROM failed "
                        "WHERE code = 'abandoned' ORDER BY username").fetchall()
ok('stored as refusals, with the machine',
   [(r['username'], r['kind'], r['mac']) for r in got],
   [('pc.terminal', 'nps-dot1x-lan', '00-30-04-13-AA-C8'),
    ('zero.client', 'nps-dot1x-lan', '00-30-04-13-A9-97')])
said = daemonA.door_summary('nps-network', 24 * 400)
cards = {v['key']: [r['said'] for r in v['rows']] for v in said['views']}
ok('the one that got on a minute later raises no card, as a PC refused by MAB does not',
   '00-30-04-13-AA-C8' in str(cards), False)
ok('...while the one that never got on is on the card of machines',
   '00-30-04-13-A9-97' in cards.get('machines', []), True)
ok('the eduroam page never counts them: FreeRADIUS does not write them either',
   [r for r in isemon.edu_nps_parse_lines(AWAY + DOT1X_OK, {})
    if getattr(r, 'abandoned', False)], [])
ok('a probe is never one', isemon.nps_abandoned(
    {'parts': {0: isemon.NPS_PROBE_MARK, 2: AWAY[1]}}), None)
ok('nothing in it is judged', storeA.db.execute(
    'SELECT COUNT(*) AS n FROM blocked').fetchone()['n'], 0)
shutil.rmtree(folderA, ignore_errors=True)

shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
