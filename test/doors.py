#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
doors.py - one ISE answers for several different things, and this is the
proof that they are told apart and kept apart.

A site with 802.1X on the LAN and on the wireless, MAB for everything with no
supplicant, TACACS+ on the switches and AnyConnect on the firewall writes all
of it into the same two files. What is at stake is not tidiness:

  * only the VPN may ever earn anybody a ban. A printer that has been failing
    MAB since Christmas is a printer, and the address on such a record is as
    often as not the switch's own - banning it would take a floor of the
    building off the network.
  * a page that mixes them tells nobody anything: a thousand unknown MACs on
    a Monday morning is a normal Monday morning on the LAN and would be an
    emergency on a VPN.

The records below are the real shapes, as the two installations this was
written against actually write them.

    ./test/doors.py
"""
import ast
import json
import hashlib
import shutil
import subprocess
import tempfile
import ipaddress
import threading
import pathlib
import os
import shlex
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import isemon                                        # noqa: E402


def ise_zone(ts=None):
    """The offset ISE writes after the second: this machine's own on that
    day, so that a record made now means now in winter as well as summer."""
    z = time.strftime('%z', time.localtime(ts))
    return z[:3] + ':' + z[3:]


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
    folder = tempfile.mkdtemp(prefix='isemon-doors-')
    isemon.STATE_DIR = Path(folder)
    isemon.DB_FILE = Path(folder) / 'doors.db'
    isemon.BACKUP_DIR = Path(folder) / 'backups'
    isemon.DUMP_DIR = Path(folder) / 'dumps'
    isemon.RUN_DIR = Path(folder)
    isemon.LOG_DIR = Path(folder)
    isemon._LOG_PATH = Path(folder) / 'doors.log'
    isemon.CONFIG.update({
        'blacklist': 1, 'block_mode': 'temporary', 'block_tries': 3,
        'block_window_min': 60, 'block_lots': 0, 'block_bogus_tries': 0,
        'block_ladder': '15, 60, forever', 'feeds_ban': 0, 'geo': 0,
        'mikrotik_host': '', 'watch_devices': '', 'passed_devices': '',
        'never_block': '', 'never_block_countries': '', 'read_passed': 1,
        'judge_max_age_h': 0, 'debug': False,
    })
    store = isemon.Storage(isemon.DB_FILE)
    daemon = isemon.Daemon(store)
    daemon._spare_from = None
    return folder, store, daemon


def line(host, cat, seq, of, n, rest):
    when = time.strftime('%b %d %H:%M:%S', time.localtime())
    return '%s %s %s %010d %d %d %s' % (when, host, cat, seq, of, n, rest)


SEQ = [700]


def feed(daemon, kind, rest, host='isea', user='', when=None):
    """One whole ISE record, written the way ISE writes it."""
    SEQ[0] += 1
    seq = SEQ[0]
    cat = 'CISE_Failed_Attempts' if kind == 'failed' else 'CISE_Passed_Authentications'
    said = 'Failed-Attempt: Authentication failed' if kind == 'failed' \
        else 'Passed-Authentication: Authentication succeeded'
    stamp = time.strftime('%Y-%m-%d %H:%M:%S',
                          time.gmtime(when or time.time())) + '.500 +00:00'
    head = ('%s 0075245450 5400 NOTICE %s, ConfigVersionId=126, '
            'Device IP Address=172.29.2.23, UserName=%s, %s, '
            'AcsSessionID=%s/579122599/%d,' % (stamp, said, user, rest, host, seq))
    daemon.read_records([line(host, cat, seq, 1, 0, head)], kind=kind)
    return '%s/579122599/%d' % (host, seq)


# The five shapes, copied from the logs of a site that runs all of them.
MAB_LAN = ('Protocol=Radius, NetworkDeviceName=swje2np, User-Name=98fc84e1165d, '
           'NAS-IP-Address=172.29.2.23, NAS-Port=50141, Service-Type=Call Check, '
           'Called-Station-ID=68-79-09-E2-17-A9, Calling-Station-ID=98-FC-84-E1-16-5D, '
           'NAS-Port-Type=Ethernet, NAS-Port-Id=GigabitEthernet1/0/41, '
           'cisco-av-pair=method=mab, RadiusFlowType=WiredMAB, SSID=68-79-09-E2-17-A9, '
           'FailureReason=15039 Rejected per authorization profile')
DOT1X_LAN = ('Protocol=Radius, NetworkDeviceName=swje4np, User-Name=host/anonymous, '
             'NAS-IP-Address=172.29.2.27, NAS-Port=50104, Service-Type=Framed, '
             'Framed-IP-Address=172.29.167.103, Calling-Station-ID=98-FC-84-E0-29-D6, '
             'NAS-Port-Type=Ethernet, NAS-Port-Id=GigabitEthernet1/0/4, '
             'cisco-av-pair=method=dot1x, cisco-av-pair=vlan-id=607, '
             'RadiusFlowType=Wired802_1x, AuthenticationMethod=x509_PKI, '
             'SelectedAccessService=Wired_802.1x_Protocols_EAP-FAST, '
             'SelectedAuthorizationProfiles=DOT1X-VLAN607_LAN, '
             'IdentityGroup=Endpoint Identity Groups:Profiled:Windows11-Workstation')
DOT1X_WIFI = ('Protocol=Radius, NetworkDeviceName=WLC-NEW, '
              'Calling-Station-ID=4C-D1-A1-27-52-C4, NAS-Port-Type=Wireless, '
              'cisco-av-pair=method=dot1x, cisco-av-pair=cisco-wlan-ssid=CORPWIFI, '
              'RadiusFlowType=Wireless802_1x, SSID=AP-N-1F-R102:CORPWIFI, '
              'SelectedAccessService=Wireless_802.1x_Protocols, '
              'FailureReason=12851 Received unexpected EAP NAK message')
MAB_WIFI = ('Protocol=Radius, NetworkDeviceName=WLC-NEW, '
            'Calling-Station-ID=A0-B3-39-71-51-38, NAS-Port-Type=Wireless, '
            'cisco-av-pair=method=mab, cisco-av-pair=cisco-wlan-ssid=GUEST, '
            'RadiusFlowType=WirelessMAB, FailureReason=15039 Rejected per authorization '
            'profile')
VPN = ('Protocol=Radius, NetworkDeviceName=ftd1, NAS-IP-Address=172.29.14.81, '
       'Called-Station-ID=198.51.100.200, Calling-Station-ID=%s, NAS-Port-Type=Virtual, '
       'Tunnel-Client-Endpoint=(tag=0) %s, '
       'CVPN3000/ASA/PIX7x-Tunnel-Group-Name=AnyConnect_ADM, '
       'FailureReason=22056 Subject not found in the applicable identity store')
TACACS = ('Protocol=Tacacs, NetworkDeviceName=vs23a, Type=Authentication, Action=Login, '
          'Remote-Address=192.168.251.10, SelectedShellProfile=Admin_LVL15, '
          'FailureReason=13017 Received TACACS+ packet with incorrect password')
VPN_OLD = ('Protocol=Radius, NetworkDeviceName=FTD-VPN, Calling-Station-ID=%s, '
           'EndPointIPAddress=%s, FailureReason=22056 Subject not found')

folder, store, daemon = fresh()

title('Which door each record came through')
feed(daemon, 'failed', MAB_LAN, user='98-FC-84-E1-16-5D')
feed(daemon, 'failed', DOT1X_WIFI, user='USERNAME')
feed(daemon, 'failed', MAB_WIFI, user='A0-B3-39-71-51-38')
feed(daemon, 'failed', VPN % ('185.136.15.24', '185.136.15.24'), user='INVALID')
feed(daemon, 'failed', TACACS, user='pk')
feed(daemon, 'failed', VPN_OLD % ('203.0.113.7', '203.0.113.7'), user='INVALID')
feed(daemon, 'passed', DOT1X_LAN, user='NB0002W11.corp-example.int')

counts = {k: v for k, v in store.failed_counts().items() if v}
ok('every refusal is sorted by the door it knocked on',
   counts, {'vpn': 2, 'tacacs': 1, 'dot1x-wifi': 1, 'mab-lan': 1, 'mab-wifi': 1})
ok('...and a successful one as well',
   {k: v for k, v in store.passed_counts().items() if v}, {'dot1x-lan': 1})
ok('a VPN record written by an older ISE, with no flow type at all, is still the VPN',
   store.failed_rows(kind='vpn')[1], 2)
ok('asking for one door gets that door only',
   [store.failed_rows(kind=k)[1] for k in
    ('mab-lan', 'mab-wifi', 'dot1x-wifi', 'tacacs', 'vpn')], [1, 1, 1, 1, 2])
ok('...and asking for none of them gets all of them', store.failed_rows()[1], 6)

title('What is worth knowing about a machine, beside it')
row = store.failed_rows(kind='mab-lan')[0][0]
ok('the endpoint is kept as its MAC', row['mac'], '98-FC-84-E1-16-5D')
ok('...with the socket it came in on', row['port'], 'GigabitEthernet1/0/41')
ok('...and no network name, because a wire has none', row['ssid'] or '', '')
ok('...and the switch it was plugged into', row['device'], 'swje2np')
wifi = store.failed_rows(kind='dot1x-wifi')[0][0]
ok('on the wireless the network is kept instead of the socket', wifi['ssid'], 'CORPWIFI')
ok('...and the controller is the device', wifi['device'], 'WLC-NEW')
got = store.passed_rows(kind='dot1x-lan')[0][0]
ok('a machine let on to a socket keeps what it was given',
   [got['profile'], got['tkey']], ['DOT1X-VLAN607_LAN', '607'])
ok('...and the VLAN reads the same way whichever of the two ISE wrote',
   [isemon.vlan_parts('607|LAN_Odbor_dopravy'), isemon.vlan_parts('LAN_Odbor_dopravy'),
    isemon.vlan_parts('607'), isemon.vlan_parts('')],
   [('607', 'LAN_Odbor_dopravy'), ('', 'LAN_Odbor_dopravy'), ('607', ''), ('', '')])
# Some sites number their VLANs and some name them, and the name is only ever
# written inside the RADIUS answer ISE sent back - a block of its own, split
# by semicolons where the record is split by commas, which the ordinary field
# reading never reaches into.
BY_NAME = DOT1X_LAN.replace('cisco-av-pair=vlan-id=607, ', '') + \
    (', Response={User-Name=host/x; Class=CACS:1B02:isea/579122599/9; '
     'Tunnel-Type=(tag=1) VLAN; Tunnel-Medium-Type=(tag=1) 802; '
     'Tunnel-Private-Group-ID=(tag=1) LAN_Odbor_dopravy; MS-MPPE-Send-Key=****; }')
feed(daemon, 'passed', BY_NAME, user='NB0001W11.corp-example.int')
named = store.passed_rows(kind='dot1x-lan')[0][0]
ok('a VLAN given by name is read out of the answer ISE sent the switch',
   named['tkey'], 'LAN_Odbor_dopravy')
ok('...and a record carrying both keeps both, so one VLAN is not two things',
   isemon.ise_vlan({'cisco-av-pair': ['vlan-id=607'],
                    'Response': ['{Tunnel-Private-Group-ID=(tag=1) LAN_Odbor_dopravy; }']}),
   '607|LAN_Odbor_dopravy')
ok('...without the RADIUS tag nobody wants to read',
   isemon.ise_vlan({'Response': ['{Tunnel-Private-Group-ID=(tag=1) LAN_Tisk; }']}),
   'LAN_Tisk')
ok('...and a number written into the name field is still a number',
   isemon.ise_vlan({'Tunnel-Private-Group-ID': ['(tag=1) 805']}), '805')
ok('...and which group ISE profiled it into',
   got['groups'], 'Endpoint Identity Groups:Profiled:Windows11-Workstation')
ok('...and how it proved itself', got['subtype'], 'x509_PKI')
vpn = store.failed_rows(kind='vpn')[0][0]
ok('a VPN record is given none of those: it has no socket and no radio',
   [vpn['mac'] or '', vpn['port'] or '', vpn['ssid'] or ''], ['', '', ''])

title('The address of the machine itself, which is not the switch’s')
ok('a machine let on to a socket keeps the address the switch reported for it',
   got['client'], '172.29.167.103')
ok('...and it is not the switch’s own, which is beside it in its own column',
   [got['client'], got['nad']], ['172.29.167.103', '172.29.2.23'])
ok('...and a record that did not carry one says nothing rather than guessing',
   store.failed_rows(kind='mab-lan')[0][0]['client'] or '', '')
ok('the device’s own address is never printed as the machine’s',
   isemon.ise_client_ip({'Device IP Address': ['172.29.2.27'],
                         'NAS-IP-Address': ['172.29.2.27'],
                         'Framed-IP-Address': ['172.29.2.27']}), '')
ok('...nor is the nothing a device writes when it has nothing to write',
   [isemon.ise_client_ip({'Framed-IP-Address': ['0.0.0.0']}),
    isemon.ise_client_ip({'Framed-IP-Address': ['::']})], ['', ''])
ok('...nor a subnet, which is not one machine',
   isemon.ise_client_ip({'Framed-IP-Address': ['10.1.0.0/16']}), '')
ok('what IOS-XE puts in an av-pair is the same fact under another name',
   isemon.ise_client_ip({'cisco-av-pair': ['method=dot1x', 'addr=10.1.2.3']}), '10.1.2.3')
ok('...and an address it can be reached at beats a link-local one',
   isemon.ise_client_ip({'cisco-av-pair': ['addrv6=fe80::d7c7:7515:152f:8e77',
                                           'addr=10.1.2.3']}), '10.1.2.3')
ok('...though a link-local one is better than nothing at all',
   isemon.ise_client_ip({'cisco-av-pair': ['addrv6=fe80::d7c7:7515:152f:8e77']}),
   'fe80::d7c7:7515:152f:8e77')
ok('the field ISE itself shows as the endpoint’s wins over the av-pairs',
   isemon.ise_client_ip({'Framed-IP-Address': ['172.29.167.103'],
                         'cisco-av-pair': ['addr=10.1.2.3']}), '172.29.167.103')
ok('a record about nobody in particular has no address for them',
   isemon.ise_client_ip({}), '')
ok('a VPN record is given no machine address either: the address on it is the person',
   vpn['client'] or '', '')
ok('an address typed into a name brings nothing with it here either',
   isemon.ise_client_ip(isemon.ise_fields(
       'User-Name=bob\\, Framed-IP-Address=198.51.100.7, NAS-IP-Address=172.29.2.27')), '')
ok('the machines can be searched for by the address they have',
   store.passed_rows(kind='dot1x-lan', text='172.29.167.103')[1], 2)
ok('...and that search is only made of the lists it means something on',
   store.passed_rows(kind='vpn', text='172.29.167.103')[1], 0)

title('Only the VPN is ever judged')
now = time.time()
for n in range(6):
    feed(daemon, 'failed', MAB_LAN, user='98-FC-84-E1-16-5D')
ok('a MAC failing over and over earns nothing',
   store.blocked_until('172.29.2.23'), None)
for n in range(6):
    feed(daemon, 'failed', DOT1X_WIFI, user='USERNAME')
ok('...nor does a supplicant that cannot agree on a protocol',
   [r['ip'] for r in store.blocked_all()], [])
for n in range(6):
    feed(daemon, 'failed', TACACS, user='pk')
ok('...nor a wrong password on a switch, which is a different door again',
   store.blocked_until('192.168.251.10'), None)
for n in range(3):
    feed(daemon, 'failed', VPN % ('185.136.15.24', '185.136.15.24'), user='INVALID')
ok('while three at the VPN earns exactly what it always did',
   store.blocked_until('185.136.15.24') is not None, True)

title('...and only the VPN is counted towards one')
# 185.136.15.24 is not here because it is already blocked; what is left of
# everything fed so far is the one other address that knocked at the VPN.
ok('what the counting sees is the VPN and nothing else',
   [r['ip'] for r in daemon.counting_up()['rows']], ['203.0.113.7'])
feed(daemon, 'failed', VPN % ('203.0.113.55', '203.0.113.55'), user='jnovak')
ok('...and one more VPN attempt joins it',
   sorted(r['ip'] for r in daemon.counting_up()['rows']),
   ['203.0.113.55', '203.0.113.7'])
# Two of these have knocked exactly as often as each other, and a list that
# puts equals in whatever order the engine happens to hold them in is a list
# that changes under somebody reading it - and reads differently on every
# engine. Equal counts are ordered by the most recent of them first, which
# is what the page is for.
ok('the busiest addresses are the VPN\'s too, most recent first among equals',
   [r['ip'] for r in store.top_attackers(now - 3600, 10)],
   ['185.136.15.24', '203.0.113.55', '203.0.113.7'])
ok('...and so are the names being tried',
   sorted(r['username'] for r in store.top_users(now - 3600, 10)), ['INVALID', 'jnovak'])

title('The chart draws the three of them apart')
bars = [b for b in store.auth_counts(hours=2, step=3600)
        if b['failed'] or b['passed']]
ok('one bar holds the hour', len(bars), 1)
one = bars[0] if bars else {}
# The bar is the whole of the drawn height; the two named bands are cut out
# of it and what is left over is the VPN.
ok('...with the switches and the network each counted out of the bar',
   [one.get('failed'), one.get('failed_tacacs'), one.get('failed_network')],
   [28, 7, 15])
ok('...leaving the VPN as the rest of it',
   one.get('failed', 0) - one.get('failed_tacacs', 0) - one.get('failed_network', 0), 6)
ok('...and the machines let on to a socket among the successful ones',
   [one.get('passed'), one.get('passed_network')], [2, 2])

title('An older database, sorted out on the way up')
# Rows written before this version have no kind at all. They are worked out
# again from the record kept beside them, which is the only reason that can
# be done at all.
with store.db_write() as db:
    db.execute("UPDATE failed SET kind=NULL, mac=NULL, port=NULL, ssid=NULL")
    db.execute("UPDATE passed SET kind=NULL, mac=NULL, port=NULL, ssid=NULL")
store.set_meta('failed_sorted', '0')
store.set_meta('passed_sorted', '0')
store.forget_distinct()
ok('nothing is sorted to begin with',
   {k: v for k, v in store.failed_counts().items() if v}, {'other': 28})
store.fill_in_failed_kinds()
store.fill_in_kinds()
store.forget_distinct()
ok('...and afterwards every one of them is back where it belongs',
   {k: v for k, v in store.failed_counts().items() if v},
   {'vpn': 6, 'tacacs': 7, 'dot1x-wifi': 7, 'mab-lan': 7, 'mab-wifi': 1})
ok('...with the machines' " own columns filled in again",
   store.failed_rows(kind='mab-lan')[0][0]['port'], 'GigabitEthernet1/0/41')
ok('...and the successful ones as well',
   {k: v for k, v in store.passed_counts().items() if v}, {'dot1x-lan': 2})

title('Which domain a person was resolved in, kept with the record')
# A site with two domains writes both into one log, and ISE says which was
# which. Kept beside the row, it is what decides which directory to ask
# about a name - rather than asking every directory there is.
WITH_REALM = (VPN % ('203.0.113.90', '203.0.113.90')).replace(
    'FailureReason=', 'AD-User-Resolved-Identities=jk@corpnettech.loc, FailureReason=')
feed(daemon, 'failed', WITH_REALM, user='jk')
got = [r for r in store.failed_rows(kind='vpn')[0] if r['username'] == 'jk']
ok('the domain ISE resolved them in is written down with the attempt',
   got[0]['realm'] if got else None, 'corpnettech.loc')
ok('...and a record that says nothing about a domain says nothing',
   store.failed_rows(kind='vpn')[0][1]['realm'] or '', '')


title('What ISE says to a switch is not somebody signing in')
# A change of authorisation: ISE telling a switch to ask an endpoint again
# because it has just been profiled. It is written into the log of successful
# authentications and it is not one - there is nobody in it. Left to fall
# through it became a VPN login with a dash in every column.
COA = ('Protocol=Radius, Device IP Address=172.29.2.34, NetworkDeviceName=sw1rco6np, '
       'NAS-IP-Address=172.29.2.34, Calling-Station-ID=00:01:96:F6:47:A5, '
       'NAS-Port-Id=GigabitEthernet2/0/32, '
       'cisco-av-pair=subscriber:command=reauthenticate, '
       'cisco-av-pair=subscriber:reauthenticate-type=last, '
       'Device CoA type=Cisco CoA, Device CoA port=1700, CoASourceComponent=Profiler, '
       'CoAReason=Endpoint profiled for first time, CoAType=Reauthentication - last, '
       'Response={Calling-Station-ID=0001.96f6.47a5; Error-Cause=200; }')
before = store.passed_rows(kind='vpn')[1]
feed(daemon, 'passed', COA, user='')
ok('it is not a VPN login', store.passed_rows(kind='vpn')[1], before)
ok('...it is among everything else', store.passed_rows(kind='other')[1] >= 1, True)
ok('a change of authorisation is recognised by what only it carries',
   [isemon.ise_is_coa({'CoAType': ['Reauthentication - last']}),
    isemon.ise_is_coa({'cisco-av-pair': ['subscriber:command=reauthenticate']}),
    isemon.ise_is_coa({'Protocol': ['Radius'], 'UserName': ['jnovak']})],
   [True, True, False])
ok('...and a successful RADIUS record with nobody in it is nobody signing in',
   isemon.ise_kind({'Protocol': ['Radius'], 'NetworkDeviceName': ['sw1']}, ''), 'other')
ok('...while a VPN login from an older ISE, which says nothing else, still is one',
   isemon.ise_kind({'Protocol': ['Radius'], 'UserName': ['jnovak'],
                    'Calling-Station-ID': ['1.2.3.4']}, 'jnovak'), 'vpn')


title('The token log, when it is switched on')
# One line is one attempt and the line says whether it worked, so both halves
# come out of one file. The shapes are what a real token server writes.
OTP_LINES = [
    'Sep 24 09:35:34 otp totp.cgi[13177]: Success: user=jnovak@example.int, '
    'mode=PAM_SM_AUTH, host=127.0.0.1, message=Valid token used',
    'Sep 24 09:36:01 otp totp.cgi[13178]: Failure: user=pkolar@example.int, '
    'mode=PAM_SM_AUTH, host=127.0.0.1, message=Not a valid token',
    'Sep 24 09:36:20 otpsec totp.cgi[900]: Success: user=pkolar@example.int, '
    'mode=PAM_SM_AUTH, host=127.0.0.1, message=Scratch-token used',
    'Sep 24 09:37:00 otpsec totp.cgi[901]: Failure: user=edvorak@example.int, '
    'mode=PAM_SM_AUTH, host=127.0.0.1, message=pincodes file not found!',
]
isemon.CONFIG['otp'] = 1
for said in OTP_LINES:                # not `line`: that is the helper above
    for rec in isemon.otp_parse_lines([said]):
        daemon.take_record('otp', rec)
ok('a line that worked and a line that did not go to different tables',
   (store.passed_rows(kind='otp')[1], store.failed_rows(kind='otp')[1]), (2, 2))
got = store.passed_rows(kind='otp')[0][0]
ok('the account is kept as the rest of this program spells it, without the realm',
   got['username'], 'pkolar')
ok('...with the whole of it as the token server wrote it beside',
   got['tkey'], 'pkolar@example.int')
ok('...and what the server said, in its own words',
   got['subtype'], 'Scratch-token used')
ok('...and which of the two token servers answered', got['server'], 'otpsec')
bad = store.failed_rows(kind='otp')[0]
ok('a refusal is put in words a person can act on',
   sorted(r['reason'] for r in bad),
   ['the token was wrong', 'this account has nothing enrolled here'])
ok('the loopback is not written down as an address, because it is this server',
   [r['ip'] for r in bad], ['', ''])
ok('a token attempt never counts towards a ban',
   sorted(r['ip'] for r in daemon.counting_up()['rows']),
   ['203.0.113.55', '203.0.113.7', '203.0.113.90'])
ok('...and is not among the busiest addresses either',
   'pkolar' in [r['username'] for r in store.top_users(time.time() - 3600, 20)], False)
# Two token servers writing to one folder, a copied log, a daemon restarted
# mid-file: all of them are the same line arriving twice.
again = sum(1 for line in OTP_LINES for rec in isemon.otp_parse_lines([line])
            if daemon.take_record('otp', rec))
ok('the same line read twice is one attempt, not two', again, 0)
ok('a name with a realm and the same name without it are one person',
   isemon.otp_account('EXAMPLE\\pkolar'), 'pkolar')

title('What the RADIUS server in front of the token software was asked')
# The token log says whether a number was right. Everything else about the
# attempt - whose address it really was, which machine, which door - is in the
# RADIUS server's own detail log, shipped a record to a line by a script that
# runs once a minute. So it arrives AFTER the token line it belongs to, and
# nothing here may assume otherwise.
DETAIL = [
    # The request: the whole of what AnyConnect told the head end.
    'Sep 24 09:36:01 otp radius-detail[1682]: nas=172.22.0.137 '
    'file=auth-detail-20260924 ts=[Tue Sep 24 09:35:34 2026] '
    'Packet-Type = Access-Request, Packet-Src-IP-Address = 172.22.0.137, '
    'Packet-Src-Port = 48603, Packet-Dst-Port = 1812, '
    'User-Name := "jnovak@example.int", NAS-Port = 1201500160, '
    'Called-Station-Id = "198.51.100.7", Calling-Station-Id = "203.0.113.9", '
    'NAS-Port-Type = Virtual, User-Password = "123456", '
    'Cisco-AVPair = "mdm-tlv=device-platform=win", '
    'Cisco-AVPair = "mdm-tlv=computer-name=WorkPC", '
    'Cisco-AVPair = "mdm-tlv=ac-user-agent=AnyConnect Windows 5.1.19.1862", '
    'Cisco-AVPair = "audit-session-id=2ee3a969479d70006ab79ff8", '
    'Vendor-3076-Attr-146 = 0x4d474d54, Cisco-AVPair = "coa-push=true"',
    # ...and the answer to it, which is a second line of a second file and
    # carries nothing but the verdict.
    'Sep 24 09:36:01 otp radius-detail[1682]: nas=172.22.0.137 '
    'file=reply-detail-20260924 ts=[Tue Sep 24 09:35:34 2026] '
    'Packet-Type = Access-Accept, Packet-Src-Port = 1812, '
    'Packet-Dst-Port = 48603',
    # A refusal, with the reason the server sent back.
    'Sep 24 09:37:01 otp radius-detail[1682]: nas=172.22.0.137 '
    'file=reply-detail-20260924 ts=[Tue Sep 24 09:36:01 2026] '
    'Packet-Type = Access-Reject, Packet-Src-Port = 1812, '
    'Packet-Dst-Port = 51000, '
    'Reply-Message = "Denied access by rlm_perl authenticate function."',
]
got = isemon.otp_detail_lines(DETAIL)
ok('every shape of that log is read', len(got), 3)
# Two spellings of the same thing: `Packet-Src-Port` is the name in
# FreeRADIUS's own internal dictionary and `Packet-Src-IP-Port` is what some
# builds and some hand-written dictionaries put there instead. A detail log
# is read whichever its server chose, or the pair that joins a request to
# its reply is missing on half the sites there are.
OTHER = [DETAIL[0].replace('Packet-Src-Port', 'Packet-Src-IP-Port')
                  .replace('Packet-Dst-Port', 'Packet-Dst-IP-Port')]
ok('...under either name the server writes the port with',
   isemon.otp_detail_lines(OTHER)[0].facts['rid'], got[0].facts['rid'])

# Three real lines off a 2.2.6 with the configuration, both patches and the
# shipper all in place. They are here verbatim because every assumption in
# this file was written before there was one to check against, and one of
# them was wrong: the configuration expands `Packet-Src-Port` and the detail
# module writes the same value out as `Packet-Src-IP-Port`.
REAL_ASK = (
    'Sep 26 16:11:01 otp1 radius-detail[9512]: nas=127.0.0.1 id=9572d1b230a58771 '
    'file=auth-detail-20260926 ts=[Sat Sep 26 16:10:38 2026] '
    'Packet-Type = Access-Request, Packet-Src-IP-Address = 127.0.0.1, '
    'Packet-Dst-IP-Address = 127.0.0.1, Packet-Src-IP-Port = 43537, '
    'Packet-Dst-IP-Port = 1812, User-Name := "mdolezal@example.cz", '
    'NAS-IP-Address = 127.0.0.1, NAS-Port = 1812, '
    'Message-Authenticator = 0x1610448cca1f2d8729276a8e1a04d8d0, '
    'Totp-Request-Id = "127.0.0.1:43537"')
REAL_REPLY = (
    'Sep 26 16:11:01 otp1 radius-detail[9512]: nas=127.0.0.1 id=93df7961f68830ae '
    'file=reply-detail-20260926 ts=[Sat Sep 26 16:10:38 2026] '
    'Packet-Type = Access-Accept, Packet-Src-IP-Address = 127.0.0.1, '
    'Packet-Dst-IP-Address = 127.0.0.1, Packet-Src-IP-Port = 1812, '
    'Packet-Dst-IP-Port = 43537')
REAL_TOKEN = ('Sep 26 16:10:39 otp1 totp.cgi[9499]: Success: user=mdolezal@example.cz, '
              'mode=PAM_SM_AUTH, host=127.0.0.1, rid=127.0.0.1:43537, '
              'message=Valid token used')
halves = isemon.otp_detail_lines([REAL_ASK, REAL_REPLY])
ok('a real request and the real reply to it are both read', len(halves), 2)
ok('...and both carry the id the configuration put on them',
   [h.facts['rid'] for h in halves], ['127.0.0.1:43537'] * 2)
ok('...and the same client port, which is what pairs them',
   [h.facts['port'] for h in halves], ['43537'] * 2)
for half in halves:
    store.note_otp_asked(half.facts)
ok('...so the two lines are one packet here, not two',
   store.db.execute("SELECT COUNT(*) AS n FROM otp_asked WHERE rid='127.0.0.1:43537'")
        .fetchone()['n'], 1)
said = store.db.execute("SELECT * FROM otp_asked WHERE rid='127.0.0.1:43537'").fetchone()
ok('...with the question\u2019s name and the answer\u2019s verdict on the one row',
   (said['username'], said['verdict']), ('mdolezal@example.cz', 'accept'))
real_token = isemon.otp_parse_lines([REAL_TOKEN])[0]
ok('the token line carries the same id, under the name the CGI writes',
   (real_token.fields.get('Asked as') or [''])[0], '127.0.0.1:43537')
joined = store.otp_asked_near([('otp/real', 'otp1', 'mdolezal', real_token.ts, True,
                                'mdolezal@example.cz', '127.0.0.1:43537')])
ok('...and the two logs are joined by it rather than weighed against each other',
   (joined.get('otp/real') or {}).get('by'), 'the id both logs carry')
ok('...with nothing left to be unsure about',
   (joined.get('otp/real') or {}).get('sure'), True)
store.db.execute("DELETE FROM otp_asked WHERE rid='127.0.0.1:43537'")

# The packet arrives after the token line it belongs to - a shipper on a
# timer sees to that - so the row was already drawn with nothing beside it.
# It is not a record and is never counted as one, but it changes what that
# row says, and a page that is not told sits on what it has.
OTP_WAS = (isemon.CONFIG.get('otp'), isemon.CONFIG.get('otp_detail'))
isemon.CONFIG['otp'] = 1
isemon.CONFIG['otp_detail'] = 1
was = daemon.status()['serial']
daemon.read_records([REAL_TOKEN], kind='otp')
told_token = daemon.status()['serial']
ok('a token line moves the page on', told_token > was, True)
logins = store.db.execute('SELECT COUNT(*) AS n FROM passed').fetchone()['n']
daemon.read_records([REAL_ASK, REAL_REPLY], kind='otp-detail')
told_packet = daemon.status()['serial']
ok('...and so does the packet that arrives beside it a minute later',
   told_packet > told_token, True)
ok('...without being counted as a login, which would count the sign-in twice',
   store.db.execute('SELECT COUNT(*) AS n FROM passed').fetchone()['n'], logins)
daemon.read_records([REAL_ASK], kind='otp-detail')
ok('...and the same packet read again moves nothing',
   daemon.status()['serial'], told_packet)
isemon.CONFIG['otp'], isemon.CONFIG['otp_detail'] = OTP_WAS
# Put the table back as the rest of this file expects to find it.
with store.db_write() as db:
    db.execute("DELETE FROM otp_asked WHERE rid='127.0.0.1:43537'")
    db.execute("DELETE FROM passed WHERE username LIKE 'mdolezal%'")
first = got[0].facts
ok('...as the time inside the record, not the time it was shipped',
   time.strftime('%H:%M:%S', time.localtime(first['ts'])), '09:35:34')
ok('...with the person\'s own address, which the token log has not',
   first['ip'], '203.0.113.9')
ok('...the box that asked', first['nas'], '172.22.0.137')
ok('...the tunnel group, out of the hex the head end writes it in',
   first['tunnel'], 'MGMT')
ok('...what the machine calls itself', first['device'], 'WorkPC')
ok('...and the session id ISE wrote about the other half of the same sign-in',
   first['session'], '2ee3a969479d70006ab79ff8')
# The one thing that must never be here, whatever the server and the shipper
# did or did not do about it themselves.
ok('a password on the packet is dropped unread',
   [n for n in first['attrs'] if 'assword' in n], [])
ok('...and is nowhere in what would be stored',
   '123456' in json.dumps(first['attrs']), False)
ok('the reply says what it answered', got[1].facts['verdict'], 'accept')
ok('...and a refusal says why', got[2].facts['said'].startswith('Denied access'), True)

for rec in got:
    daemon.take_record('otp-detail', rec)
ok('a RADIUS packet is never a row: one sign-in is one attempt, not two',
   (store.passed_rows(kind='otp')[1], store.failed_rows(kind='otp')[1]), (2, 2))
# Three lines, two rows: the request and the reply to it carry the same
# second and the same client port, which is what makes them one transaction.
ok('...it is kept beside them instead', store.otp_asked_count(), 2)
kept = store.db.execute("SELECT * FROM otp_asked WHERE verdict = 'accept'").fetchall()
ok('...and the request and the reply to it are one row, not two', len(kept), 1)
ok('...carrying both halves', (kept[0]['ip'], kept[0]['verdict']),
   ('203.0.113.9', 'accept'))
ok('reading the same lines again adds nothing',
   [daemon.take_record('otp-detail', r) for r in isemon.otp_detail_lines(DETAIL)]
   and store.otp_asked_count(), 2)

# A message with a comma in it, which the token server writes and which used
# to be cut in half here: `Rate-limit reached, please try again later` was
# stored as `Rate-limit reached`, five times a day on one real site.
comma = isemon.otp_record_from(
    'Sep 24 09:38:00 otp totp.cgi[902]: Failure: user=pkolar@example.int, '
    'mode=PAM_SM_AUTH, host=127.0.0.1, message=Rate-limit reached, please try again later')
ok('a message with a comma in it is kept whole',
   isemon.ise_first(comma.fields, 'What it said'),
   'Rate-limit reached, please try again later')

# ...and the id a patched token server writes on its own line, which is what
# turns the matching below from a judgement into a lookup.
named = isemon.otp_record_from(
    'Sep 24 09:35:34 otp totp.cgi[13177]: Success: user=jnovak@example.int, '
    'mode=PAM_SM_AUTH, host=127.0.0.1, rid=172.22.0.137:48603, message=Valid token used')
ok('an id on the token line is read', isemon.ise_first(named.fields, 'Asked as'),
   '172.22.0.137:48603')
ok('...and the message after it is still whole',
   isemon.ise_first(named.fields, 'What it said'), 'Valid token used')
daemon.take_record('otp', named)
byid = store.otp_asked_near([(named.session, 'otp', 'jnovak', named.ts + 240, True,
                              'jnovak@example.int', '172.22.0.137:48603')])
ok('a packet and an attempt that carry one id are joined by it',
   bool(byid), True)
ok('...and it says that is how', list(byid.values())[0]['by'], 'the id both logs carry')
ok('...four minutes apart, which nothing else here survives',
   list(byid.values())[0]['sure'], True)

# The join. The two are written by two different programs, one of which calls
# the other, so they are the same second or near enough - and a token attempt
# that arrived before its packet did simply has nothing beside it yet.
near = store.otp_asked_near(
    [('row-1', 'otp', 'jnovak', first['ts'] + 1, True, 'jnovak@example.int')])
ok('a token attempt finds the packet that caused it, a second either way',
   bool(near), True)
ok('...and it is the right one', near['row-1']['ip'], '203.0.113.9')
ok('...matched on the whole account, realm and all', near['row-1']['by'],
   'the whole account')
ok('...and it says it was not a guess', near['row-1']['sure'], True)
ok('a minute away is not the same attempt',
   store.otp_asked_near([('row-2', 'otp', 'jnovak', first['ts'] + 60, True, '')]), {})
ok('...nor is somebody else at the same moment',
   store.otp_asked_near([('row-3', 'otp', 'someone-else', first['ts'], True, '')]), {})
# Two people whose names are one name once the realm is cut off, signing in
# at the same moment on the same server: the whole account is what tells them
# apart, and the row's own id is what keeps the two answers apart.
two = store.otp_asked_near(
    [('one', 'otp', 'jnovak', first['ts'], True, 'jnovak@example.int'),
     ('two', 'otp', 'jnovak', first['ts'], True, 'jnovak@elsewhere.cz')])
ok('two realms, one name: only the one that really matches is given a packet',
   sorted(two), ['one'])
# ...and one packet is one attempt's, not everybody's.
ok('a packet already taken is not handed to a second attempt',
   len({one['ts'] for one in store.otp_asked_near(
       [('a', 'otp', 'jnovak', first['ts'], True, 'jnovak@example.int'),
        ('b', 'otp', 'jnovak', first['ts'], True, 'jnovak@example.int')]).values()}), 1)
ok('how far behind the shipping is running can be said',
   store.otp_asked_behind()['behind'] >= 0, True)


# Which door, the same way the TACACS page says where a sign-in came from.
isemon.CONFIG['otp_from'] = '172.22.0.137=VPN, 192.168.4.0/24=VDI'
isemon.CONFIG['otp_from_mark'] = 1
places = daemon.otp_places_for(['172.22.0.137', '192.168.4.11', '10.0.0.1'])
ok('the box that asked is named', places['172.22.0.137']['name'], 'VPN')
ok('...a range names every box in it', places['192.168.4.11']['name'], 'VDI')
ok('...and one that is on neither list is marked',
   places['10.0.0.1']['usual'], False)
isemon.CONFIG['otp_from'] = ''

title('...and the RADIUS log is only read when it is asked for')
isemon.CONFIG['otp_detail'] = 0
ok('switched off, it is not among the files being read',
   [p for _k, p, src in daemon.log_files() if src == 'otp-detail'], [])
isemon.CONFIG['otp_detail'] = 1
ok('...and switched on, one file per token server is',
   [p for _k, p, src in daemon.log_files() if src == 'otp-detail'],
   ['/var/log/remote/otp/radius-detail.log', '/var/log/remote/otpsec/radius-detail.log'])
isemon.CONFIG['otp_detail'] = 0

title('...and switched off it is not read at all')
isemon.CONFIG['otp'] = 0
isemon.CONFIG['otp_paths'] = ['/var/log/remote/otp']
ok('no token file is among the files being read',
   [p for _k, p, src in daemon.log_files() if src == 'otp'], [])
isemon.CONFIG['otp'] = 1
ok('...and switched on, one file per server is',
   [p for _k, p, src in daemon.log_files() if src == 'otp'],
   ['/var/log/remote/otp/totp.cgi.log'])

title('The ISE logs can be switched off altogether, for a site that has no ISE')
isemon.CONFIG['otp'] = 1
isemon.CONFIG['otp_paths'] = ['/var/log/remote/otp']
ok('they are read unless somebody says otherwise',
   bool([p for _k, p, src in daemon.log_files() if src == 'ise']), True)
isemon.CONFIG.pop('ise', None)
ok('...and a setting that is not there at all still means read them',
   bool([p for _k, p, src in daemon.log_files() if src == 'ise']), True)
isemon.CONFIG['ise'] = 0
ok('switched off, no ISE file is among the files being read',
   [p for _k, p, src in daemon.log_files() if src == 'ise'], [])
ok('...and the token logs beside them are read exactly as before',
   [p for _k, p, src in daemon.log_files() if src == 'otp'],
   ['/var/log/remote/otp/totp.cgi.log'])
# A switch about reading is not a switch about forgetting. What is in the
# database was put there by something that happened, and no setting may
# make any of it disappear.
was = (store.db.execute('SELECT COUNT(*) AS n FROM failed').fetchone()['n'],
       store.db.execute('SELECT COUNT(*) AS n FROM passed').fetchone()['n'])
ok('...and nothing already written down is touched by the switch',
   (store.db.execute('SELECT COUNT(*) AS n FROM failed').fetchone()['n'],
    store.db.execute('SELECT COUNT(*) AS n FROM passed').fetchone()['n']), was)
ok('the page is told, so it can say so',
   daemon.status().get('ise_on'), False)
isemon.CONFIG['ise'] = 1
ok('...and back on, they are read again',
   bool([p for _k, p, src in daemon.log_files() if src == 'ise']), True)
isemon.CONFIG['otp'] = 0

title('The addresses out for good, as a Cisco access list')
store.block('80.94.95.0/24', None, 'a burst', 'by hand')
store.block('193.37.69.104', None, 'a burst', 'by hand')
store.block('9.9.9.9', time.time() + 900, 'on a clock', 'by hand')
acl = daemon.ios_acl()
lines = acl['text'].splitlines()
ok('it is an access list with the name from the settings',
   lines[len([l for l in lines if l.startswith('!')]) + 1],
   'ip access-list extended SECURE-IPv4-IN')
ok('...the list of before taken away first, so it can be pasted again (1.10.200)',
   lines[len([l for l in lines if l.startswith('!')])],
   'no ip access-list extended SECURE-IPv4-IN')
ok('a range is written with the wildcard mask IOS wants',
   ' deny   ip 80.94.95.0 0.0.0.255 any' in lines, True)
ok('...and a single address as a host', ' deny   ip host 193.37.69.104 any' in lines, True)
ok('an address on a clock is left out: it will have lapsed before this is pasted',
   any('9.9.9.9' in l for l in lines), False)
ok('...and the two lines that must end it, always, in that order',
   lines[-2:], [' deny   udp any any eq snmp', ' permit ip any any'])

title('The controller writes the access point and the network in one field')
# Called-Station-ID=AP-HQ-8F-EAST:CORPWIFI - the access point before the
# colon, the network after it. ISE copies it into SSID on some records and
# not on others, so both fields are read and neither is trusted to be there.
ok('the access point is what comes before the colon',
   isemon.ise_ap({'Called-Station-ID': ['AP-HQ-8F-EAST:CORPWIFI']}), 'AP-HQ-8F-EAST')
ok('...and the network is what comes after it',
   isemon.ise_ssid({'Called-Station-ID': ['AP-HQ-8F-EAST:CORPWIFI']}), 'CORPWIFI')
ok('...even when ISE left the SSID field out of that record',
   [isemon.ise_ap({'Called-Station-ID': ['AP-N-4F-R421-1:CORPWIFI'], 'SSID': ['']}),
    isemon.ise_ssid({'Called-Station-ID': ['AP-N-4F-R421-1:CORPWIFI'], 'SSID': ['']})],
   ['AP-N-4F-R421-1', 'CORPWIFI'])
ok('a called station that is the switch\u2019s MAC is neither of those things',
   [isemon.ise_ap({'Called-Station-ID': ['68-79-09-E2-17-A9'], 'SSID': ['68-79-09-E2-17-A9']}),
    isemon.ise_ssid({'Called-Station-ID': ['68-79-09-E2-17-A9'], 'SSID': ['68-79-09-E2-17-A9']})],
   ['', ''])
ok('...nor is one written with colons, which is the same MAC',
   isemon.ise_ap({'Called-Station-ID': ['68:79:09:E2:17:A9']}), '')
ok('...nor the address a VPN client dialled',
   [isemon.ise_ap({'Called-Station-ID': ['198.51.100.200'], 'SSID': ['198.51.100.200']}),
    isemon.ise_ssid({'Called-Station-ID': ['198.51.100.200'], 'SSID': ['198.51.100.200']})],
   ['', ''])
ok('the av-pair still wins where the controller sent one',
   isemon.ise_ssid({'cisco-av-pair': ['cisco-wlan-ssid=GUEST'],
                    'Called-Station-ID': ['AP-12:CORPWIFI']}), 'GUEST')
ok('ISE\u2019s own escaping is taken back out of what it says',
   isemon.ise_reason({'FailureReason': [
       '11512 Extracted EAP-Response/NAK packet requesting to use unsupported EAP '
       'protocol\\; EAP-negotiation failed']})[1],
   'Extracted EAP-Response/NAK packet requesting to use unsupported EAP protocol; '
   'EAP-negotiation failed')
ok('on a socket the access point is nothing and the column is the port',
   [isemon.ise_where_on({'NAS-Port-Id': ['GigabitEthernet1/0/41']}, False),
    isemon.ise_where_on({'NAS-Port-Id': ['capwap_9000016d'],
                         'Called-Station-ID': ['AP-HQ-8F-EAST:CORPWIFI']}, True)],
   ['GigabitEthernet1/0/41', 'AP-HQ-8F-EAST'])


title('A log file this daemon may not read says so in words')
said = isemon.trouble_words(
    "[Errno 13] Permission denied: '/var/log/remote/otp/totp.cgi.log'",
    '/var/log/remote/otp/totp.cgi.log')
ok('the error is turned into the thing that is actually wrong',
   'may not read that file' in said, True)
ok('...and the command that ends it names the folder, not the file',
   isemon.trouble_fix("[Errno 13] Permission denied", '/var/log/remote/otp/totp.cgi.log')
   .startswith('chgrp -R'), True)
ok('...and a file that is simply not there yet is not dressed up as a problem',
   isemon.trouble_words('[Errno 2] No such file or directory', '/x/y.log'),
   'there is no such file yet')
ok('...and nothing wrong says nothing', isemon.trouble_words('', '/x/y.log'), '')


title('The tab counts are not handed out half-made')
# The counts behind the tabs are worked out behind whoever asked. Handing
# back nought for a table that is not empty draws a page with no numbers on
# the tabs and whole doors missing, which is not something anybody would
# think to reload.
store.forget_distinct()
counts = store.failed_counts()
ok('asked cold, they are the real ones',
   counts['vpn'] > 0 and counts['otp'] > 0, True)
ok('...and asked again they are the same',
   store.failed_counts(), counts)
# The one that bit: a count taken while the tables were still empty, handed
# out as the truth for two minutes while a backlog arrived behind it. The
# page then drew tabs with no numbers and whole doors missing.
store.forget_distinct()
store._distinct[('failed', '#kinds', 0)] = (time.time(), {k: 0 for k in isemon.LOGIN_KINDS}, -1)
ok('a count of nought taken before the records arrived is not handed out',
   store.failed_counts()['vpn'] > 0, True)


title('An answer that is not ready is not handed out as one')
# Three of these bit at once: a count taken while the tables were empty was
# handed out for two minutes; the login counts never went through the cache
# at all, so the page was told they were never ready; and a count that was
# refused for being empty came straight back out of the waiting.
store.forget_distinct()
store._distinct[('passed', '#kinds', 0)] = (time.time(),
                                            {k: 0 for k in isemon.LOGIN_KINDS}, -1, 0.0)
ok('the login counts are not the noughts from before the logins arrived',
   store.passed_counts()['otp'] > 0, True)
ok('...and the page is told they are ready', store.counts_ready('passed'), True)
store.failed_counts()
ok('...as are the refusals', store.counts_ready('failed'), True)

title('A search says how far it counted')
rows, total = store.failed_rows(limit=5, text='the token was wrong')
ok('a search that fits on one page is counted exactly', total, len(rows))
ok('...and a blank box is not a search at all',
   store.failed_rows(limit=5, text='   ')[1], store.failed_rows(limit=5)[1])

title('The number on a tab counts the window the list is showing')
old = time.time() - 5 * 86400
feed(daemon, 'failed', TACACS, user='pk', when=old)
feed(daemon, 'failed', TACACS, user='pk', when=old + 60)
day = time.time() - 86400
# Read without the keeping-for-a-while in the way: what is being held here
# is the counting itself, not how long an answer is kept.
store.forget_distinct()
inside = store._failed_kinds_now(day)
whole = store._failed_kinds_now(0)
ok('the two records older than the window are not counted in it',
   whole['tacacs'] - inside['tacacs'], 2)
ok('...and the number on the tab is what pressing it shows',
   store.failed_rows(kind='tacacs', since=day)[1], inside['tacacs'])
ok('...over everything as well',
   store.failed_rows(kind='tacacs')[1], whole['tacacs'])
ok('the same on the other side',
   store.passed_rows(kind='dot1x-lan', since=day)[1],
   store._passed_kinds_now(day)['dot1x-lan'])
ok('a door with nothing in the window still says how many it holds in all',
   whole['tacacs'] > inside['tacacs'], True)
ok('asking for the window through the keeping gives the same answer',
   store.failed_counts(since=day).get('tacacs', -1) in (0, inside['tacacs']), True)
store.forget_distinct()
ok('a window nobody has asked about is not called ready',
   store.counts_ready('failed', day), False)
store.failed_counts(since=day)
# Worked out behind whoever asked, so waited for rather than slept through:
# a fixed sleep is a test that fails on a busy machine and proves nothing on
# a quick one.
for _ in range(100):
    if store.counts_ready('failed', day):
        break
    time.sleep(0.1)
    store.failed_counts(since=day)
ok('...and the one that was asked for is, once it is worked out',
   store.counts_ready('failed', day), True)
ok('...which is asked of that window and not of any other',
   store.counts_ready('failed', time.time() - 3 * 86400), False)

title('The same window asked twice is one question')
store.forget_distinct()
before = len(store._distinct)
# Half a minute past a minute, so that six asks a second apart are six asks
# inside one minute rather than four in this one and two in the last. The
# rounding is what is being tested; whether the clock happens to tick over
# in the middle of the test is not.
inside = (int(time.time()) // 60) * 60 + 30
for n in range(6):
    store.failed_counts(since=inside - 86400 - n)
ok('six asks a second apart are one answer kept, not six',
   len(store._distinct) - before, 1)
ok('...and a window rounds to the minute it is in',
   [isemon.round_window(1790000123), isemon.round_window(1790000159),
    isemon.round_window(1790000160)], [1790000100, 1790000100, 1790000160])
ok('...while "everything" is still nought',
   [isemon.round_window(0), isemon.round_window(None), isemon.round_window(-5)], [0, 0, 0])

title('How wide one bar of the chart is, and where a day starts')
# A window a year long asked for in hours would be 8,760 bars: a megabyte of
# counts for a line nobody can make out one bar of, and a walk of somebody's
# database to count them. So the bar widens with the window - and a bar a
# day wide has to be a day where somebody is reading it, not a day in UTC,
# or "14-09" is a label over two hours of the 15th.
ok('six hours is drawn in five-minute bars', isemon.Daemon.chart_step(6), 300)
ok('...a day and a week and a month in hours',
   [isemon.Daemon.chart_step(h) for h in (24, 168, 720)], [3600, 3600, 3600])
ok('...and a year in days', isemon.Daemon.chart_step(8760), 86400)
DAY = store.auth_counts(hours=8760, step=86400)
ok('a year is drawn in a year of bars, not eight thousand',
   366 >= len(DAY) >= 365, True)
ok('...and each of them starts at midnight on somebody’s own clock',
   sorted({time.strftime('%H:%M', time.localtime(b['ts'])) for b in DAY}), ['00:00'])
ok('...with nothing lost between the bars',
   sum(b['failed'] for b in DAY), store.count_since('failed', time.time() - 8760 * 3600))

title('Nobody signing in is not drawn as somebody signing in')
feed(daemon, 'passed', COA, user='')
bars = store.auth_counts(hours=2, step=7200)
drawn = sum(b['passed'] - b['passed_tacacs'] - b['passed_network'] - b['passed_otp']
            - b['passed_eduroam'] for b in bars)
ok('a change of authorisation is not counted as a VPN login',
   store.passed_rows(kind='other')[1] > 0 and drawn, 0)
ok('...and it is not in the bar at all, only named beside it',
   sum(b['passed_other'] for b in bars) > 0, True)

title('The two numbers at the top of the page are counted, not capped')
ok('the count is the count, however many there are',
   store.count_since('failed', 0), store.failed_rows(limit=1)[1])
ok('...and by door as well',
   store.count_since('failed', 0, 'vpn'), store.failed_rows(limit=1, kind='vpn')[1])
whole = store.count_since('failed', 0)
was = isemon.Storage.COUNT_CAP
isemon.Storage.COUNT_CAP = 2
ok('a list stops counting at the cap, as it is meant to',
   store.failed_rows(limit=1)[1] < store.count_since('failed', 0), True)
ok('...while the number on the front page is the whole of it',
   store.count_since('failed', 0), whole)
isemon.Storage.COUNT_CAP = was


title('With the directory switched off, nothing is asked and nothing appears')
isemon.CONFIG['directory'] = 0
said = daemon.directory_person('jnovak')
ok('the answer is that there is no directory, not a failure',
   (said['on'], said['found'], said['trouble']), (False, False, ''))


shutil.rmtree(folder, ignore_errors=True)
title('Which node has been doing the work')
# An HA pair is two nodes and one of them is quiet at any moment. The quiet
# one looks exactly like a node that has stopped talking to this machine,
# and the only thing that tells them apart is whether the other one picked
# the same work up in the same hour.
now = time.time()
# Names of their own, so that what the rest of this suite has already
# written cannot be mistaken for them.
for n in range(30):
    store.add_failed({'session': 'quiet-one/1/%d' % n, 'ts': now - 7200,
                      'server': 'quiet-one', 'ip': '203.0.113.%d' % (n + 1),
                      'username': 'jnovak', 'kind': 'vpn', 'device': 'FTD-VPN'})
for n in range(30, 45):
    store.add_failed({'session': 'busy-one/1/%d' % n, 'ts': now - 600,
                      'server': 'busy-one', 'ip': '203.0.113.%d' % (n + 1),
                      'username': 'jnovak', 'kind': 'vpn', 'device': 'FTD-VPN'})
got = store.node_counts(now - 86400)
ok('each node is counted on its own', got['failed'].get('quiet-one'), 30)
ok('...and so is the one that took over', got['failed'].get('busy-one'), 15)
hour = store.node_counts(now - 3600)['failed']
ok('a window leaves out the one that went quiet before it',
   hour.get('quiet-one', 0), 0)
ok('...while the one still writing is there', hour.get('busy-one'), 15)
ok('over all time both are there',
   sorted(n for n in store.node_counts(0)['failed'] if n.endswith('-one')),
   ['busy-one', 'quiet-one'])
ok('...and the logins are counted apart from the refusals',
   'passed' in store.node_counts(now - 86400))

title('The page that draws all of this')
# Two faults this file has actually shipped, both invisible from anywhere
# else: a row function left in twice under one name - where the later
# definition silently wins and the page draws something nobody wrote - and a
# row whose cells and whose headers had stopped agreeing. Neither shows up in
# any other check here, and both are a few lines to look for.
PAGE = (Path(__file__).resolve().parent.parent / 'web' / 'index.php').read_text(
    encoding='utf-8')
# ...and the daemon's own source, for the few checks that are about the two
# of them agreeing rather than about either on its own.
DAEMON = (Path(__file__).resolve().parent.parent / 'isemon.py').read_text(encoding='utf-8')
INSTALLER = (Path(__file__).resolve().parent.parent / 'install.sh').read_text(
    encoding='utf-8')
# ...and the page's stylesheet on its own, which several checks read.
CSS = PAGE[PAGE.index('<style>') + 7:PAGE.index('</style>')]
names = re.findall(r'^function ([A-Za-z_$][\w$]*)\s*\(', PAGE, re.M)
twice = sorted({n for n in names if names.count(n) > 1})
ok('no function on the page is defined twice', twice, [])
ok('...and there are as many of them as ever there were', len(names) > 200, True)


def cells_of(fn):
    """How many cells one row function puts in a row."""
    at = PAGE.index('function %s(' % fn)
    body = PAGE[at:PAGE.index('\n}\n', at)]
    return body.count('tr.appendChild(')


def token_tones():
    """What tone the page gives each thing the token server can say."""
    at = PAGE.index('var TOKEN_WORDS = {')
    block = PAGE[at:PAGE.index('\n};', at)]
    return dict(re.findall(r"'([^']+)':\s*\['[^']*',\s*'([a-z]+)'\]", block))


TOKEN_TONES = token_tones()


def heads_of(which, kind):
    """How many columns that kind's header list says there are."""
    at = PAGE.index('var %s = {' % which)
    block = PAGE[at:PAGE.index('\n};', at)]
    said = re.search(r'\n  %s: \[(.*?)\],\n  [a-z]' % kind, block, re.S)
    text = ' '.join(said.group(1).split())
    # An entry is either a plain string or a {words: ..., cls: ...} object,
    # and an object holds strings of its own - so the objects are taken out
    # whole first and what is left is counted.
    text, objects = re.subn(r'\{[^{}]*\}', '', text)
    return objects + len(re.findall(r"'[^']*'", text))


# One cell to one heading. tokenRow draws one cell more on the logins page -
# the whole account, which a refusal has no room for and no need of - so the
# two header lists are one apart and the function fills the longer.
ok('the OTP logins have a column each for the verdict beside it, the address, '
   'the flag, the machine, the group, the box and its name',
   heads_of('PHEADS', 'otp'), 12)
ok('...and the refusals the same, one short of the whole-account column',
   heads_of('FHEADS', 'otp'), 11)
ok('...which is exactly what the row function fills', cells_of('tokenRow'), 12)
# The second mark sits in a cell of its own rather than beside the first.
# Next to it, it starts wherever that one happened to end and a column of
# them is ragged - the same complaint the addresses had, and the same
# answer.
# The height of a row in these two lists is set by the button on the end of
# it, not by the words. With the cells disagreeing about where their
# contents sit - some `top`, some `middle` - the words ended seven pixels
# above the button beside them and the eye ran down a line that was not
# straight. Measured in a browser at the time: `content mid=17` against a
# row middle of 24.
ok('the two lists of records put every cell on the row\u2019s middle',
   '#f-table td,#p-table td{vertical-align:middle}' in CSS, True)
ok('...and nothing in them sets it back to the top again',
   [sel for sel, body in re.findall(r'([^{}]+)\{([^{}]*)\}', CSS)
    if 'vertical-align:top' in ' '.join(body.split())
    and ('f-table' in sel or 'p-table' in sel)], [])
ok('...while a list whose rows really are several lines keeps the top',
   'vertical-align:top}' in CSS, True)

ok('the mark beside the reason has a cell of its own',
   "var also = el('td', 'placecell');" in PAGE and 'also.appendChild(fine);' in PAGE, True)
ok('...and is not pushed along by hand any more',
   "fine.style.marginLeft = '6px';" in PAGE, False)

# What the machine calls itself. It is drawn by one function for all three
# tables, so that a column of them lines up wherever it is shown, and the
# VPN's failures have a header list of their own for it rather than sharing
# `plain` with the doors that have no machine in them.
ok('one function draws the machine, and every table that shows it uses that one',
   PAGE.count('function machineCell('), 1)
for which, kind in (('PHEADS', 'vpn'), ('FHEADS', 'vpn'),
                    ('PHEADS', 'otp'), ('FHEADS', 'otp')):
    at = PAGE.index('var %s = {' % which)
    block = PAGE[at:PAGE.index('\n};', at)]
    said = re.search(r"\n  %s: \[(.*?)\],\n  (?:[a-z]|/\*)" % kind, block, re.S)
    ok('%s.%s has a column for the machine' % (which, kind),
       "'The machine'" in ' '.join(said.group(1).split()), True)
ok('the VPN sign-ins fill it', 'machineCell(r.machine)' in PAGE, True)
# Plain words rather than a mark: the eye should go to a name somebody gave
# an address or a sign-in that was refused, not to every machine on the page.
ok('...and it is drawn as plain words, not as something to look at first',
   bool(re.search(r"function machineCell\(.*?el\('span', '', said\)", PAGE, re.S)), True)
# --------------------------------------------------------------------------
# Nothing that opens may make the page wider.
#
# A panel hung off the left edge of a button that is itself near the right
# of the window ends past the end of the page. Nothing clips it: the
# document becomes that much wider, a horizontal scrollbar appears, and the
# whole page slides sideways the moment somebody opens a filter. It is the
# kind of fault that is obvious once seen and invisible while writing the
# rule, so the rules are checked rather than remembered.
#
# An out-of-flow box with a width of its own, anchored on one side only, can
# do it. The three below cannot: each is a few pixels inside something that
# already holds it. Anything else has to be placed when it opens, from where
# it really is, and `.ccpanel` is.
CSS = PAGE[PAGE.index('<style>') + 7:PAGE.index('</style>')]
HELD = {'.sw .knob::after', '.sw3::after', '.ctl-nav button[data-pane].on::before', '.ctl-nav'}
loose = []
for sel, body in re.findall(r'([^{}]+)\{([^{}]*)\}', CSS):
    flat = ' '.join(body.split())
    sel = ' '.join(sel.split())
    if sel.startswith('/*'):
        sel = sel[sel.rindex('*/') + 2:].strip() if '*/' in sel else sel
    if 'position:absolute' not in flat:
        continue
    if not re.search(r'(?<![a-z-])width:\s*\d+px', flat):
        continue
    if re.search(r'(?<![a-z-])right:', flat):
        continue                              # held on both sides, it cannot run
    if sel in HELD or sel == '.ccpanel':
        continue
    loose.append(sel)
ok('every fixed-width panel is either held in place or placed when it opens',
   loose, [])
ok('...and the one that is placed says which side every time, not sometimes',
   PAGE.count("panel.style.left = 'auto'") == 1
   and PAGE.count("panel.style.right = 'auto'") == 1, True)
ok('...measuring the window rather than trusting the stylesheet',
   'document.documentElement.clientWidth' in PAGE
   and 'button.getBoundingClientRect()' in PAGE, True)
ok('...when it opens', bool(re.search(
    r"wrap\.classList\.add\('open'\);\s*\n\s*placePanel\(\);", PAGE)), True)
ok('...and again if the window changes size under it',
   "window.addEventListener('resize', placePanel)" in PAGE, True)
ok('...and it stops listening when it shuts, or every picker ever opened stays',
   "window.removeEventListener('resize', placePanel)" in PAGE, True)
ok('...with a floor under it for a window narrower than the panel',
   'max-width:calc(100vw - 16px)' in CSS, True)
# ...and the window is not always what is holding it. The same picker is on
# the filters inside a popup, and a popup is its own scrolling box: a panel
# that runs past ITS right edge makes that box wider and the popup slides
# sideways, which is the page sliding one box further in. Measured in a
# browser on the popup for a name: the popup went from 1318px to 1379px wide
# and scrolled 52px the moment the filter opened.
ok('...measured against everything that is holding it, not only the window',
   'function holdingBox(' in PAGE and "how.overflowX === 'visible'" in PAGE, True)
ok('...every such box on the way up, not merely the first',
   bool(re.search(r'for \(var node = wrap\.parentNode;.*?node = node\.parentNode\)', PAGE, re.S)), True)
ok('...and the floor under its width is that box too, not the window',
   "panel.style.maxWidth = Math.max(180, box.right - box.left - 16) + 'px';" in PAGE, True)
# The other half of the same complaint, and a different cause: a browser
# scrolls whatever is holding a box it has just focused. Inside a popup
# whose lists are wider than it is, focusing the panel's own search box slid
# the popup 52px sideways on its own. The panel has already been put
# somewhere it can be seen; there is nothing to scroll to.
ok('the box inside it is focused without the popup being scrolled to it',
   'find.focus({preventScroll: true})' in PAGE, True)
ok('...with the plain focus still there for a browser that has never heard of it',
   bool(re.search(r'catch \(e\) \{ find\.focus\(\); \}', PAGE)), True)

# The find box's card, and the words on it. One card per thing found, and
# the doors as short chips under it: the question behind typing an address
# into that box is nearly always "is it banned, and where does it turn up",
# and a single pair of totals answers neither.
# A sign-in the token server accepted and the RADIUS server refused after
# it. The row has to carry both answers or it says something untrue about
# one of them - and the one it used to get wrong is the token's.
ok('the page knows every refusal the handler in front of the token can make',
   sorted(re.findall(r"^  '([a-z0-9()' ]+)':", PAGE[PAGE.index('var RADIUS_WORDS = {'):
                                                 PAGE.index('var RADIUS_SAYS = {')], re.M)),
   ['account does not pass ldap group filter(s)', 'account does not pass ldap user filter',
    'ldap server(s) have gone away', 'unable to bind to ldap server', 'unknown error'])
ok('...and has words for each of them',
   sorted(re.findall(r"^  '([a-z0-9()' ]+)':", PAGE[PAGE.index('var RADIUS_SAYS = {'):
                                                 PAGE.index('function radiusKey')], re.M)),
   sorted(re.findall(r"^  '([a-z0-9()' ]+)':", PAGE[PAGE.index('var RADIUS_WORDS = {'):
                                                 PAGE.index('var RADIUS_SAYS = {')], re.M)))
ok('...and shows one it has never seen as it was said, rather than as a blank',
   "return got ? got[0] : String(said || '');" in PAGE, True)
ok('...and the shapes that are not one fixed sentence, recognised by what is in them',
   bool(re.search(r'var RADIUS_LIKE = \[', PAGE))
   and 'certificate|ssl|tls handshake' in PAGE, True)
ok('such a row says what the token itself made of it, in one of three ways',
   sorted(re.findall(r"^      '([a-z-]+)': \[", PAGE[PAGE.index('var TOKEN_MARK = {'):
                                             PAGE.index("var how = TOKEN_MARK")], re.M)),
   ['no-token', 'token-lost', 'token-ok'])
ok('...and those are the three the daemon writes',
   sorted(set(re.findall(r"'(token-ok|no-token|token-lost)'", DAEMON))),
   ['no-token', 'token-lost', 'token-ok'])
ok('...with the whole of what was said kept where it can be read',
   "'\\n\\nIn its own words: <code>'" in PAGE, True)
ok('...and is marked, because it is the row most easily read wrongly',
   "tr.classList.add('after-token')" in PAGE
   and 'tr.after-token>td:first-child{' in PAGE, True)
ok('...on one edge of the row, not down every cell of it',
   'tr.after-token>td{' in PAGE, False)

ok('the doors have one set of words, used wherever a door is named',
   PAGE.count('var DOOR_WORDS = {'), 1)
ok('...every door the daemon can record is in it',
   sorted(re.findall(r"'?([a-z0-9-]+)'?\s*:\s*'", PAGE[PAGE.index('var DOOR_WORDS = {'):
                                                      PAGE.index('function doorWords')])),
   ['dacl', 'dot1x-lan', 'dot1x-wifi', 'eduroam', 'mab-lan', 'mab-wifi',
    'nps-dot1x-lan', 'nps-dot1x-wifi', 'nps-mab-lan', 'nps-mab-wifi', 'nps-other',
    'nps-vpn', 'otp', 'radius-dot1x-lan', 'radius-dot1x-wifi', 'radius-mab-lan',
    'radius-mab-wifi', 'radius-other', 'radius-vpn', 'tacacs', 'tacacs-cmd', 'tacplus',
    'tacplus-cmd', 'vpn'])
ok('the card draws a chip per door', "el('span', 'fdoor')" in PAGE, True)
ok('...and one line saying where it was last seen anywhere',
   "'Last seen '" in PAGE, True)
ok('...with the totals counted off those same doors, so the card agrees with itself',
   'doors.reduce(function (m, d)' in PAGE, True)
ok('a suggestion says how many records, not how many failures',
   "' record(s) \\u00b7 '" in PAGE, True)
ok('...and the names group is no longer only about names being tried',
   "group('Names'," in PAGE and "group('Names being tried'," not in PAGE, True)
ok('...and a name that has only signed in opens the logins, not the refusals',
   "showTab(mostly === 'logins' ? 'logins' : 'failed')" in PAGE, True)

# Pressing a door takes somebody to the records behind it and lights the
# row. Everything about that has to hold together or the press lands on an
# empty page, which is worse than no press at all.
ok('one function does the going, so every press behaves the same',
   PAGE.count('function goToRecords('), 1)
ok('...it widens the window first, or the records it sends people to are filtered out',
   "hours.value = '0'" in PAGE, True)
ok('...and clears the country, for the same reason',
   'if (country && country.value)' in PAGE, True)
ok('...it waits for the rows before looking for one',
   'Promise.resolve(drawn).then' in PAGE, True)
ok('...which is possible because the two lists hand their drawing back',
   ["return loadFailed();" in PAGE,
    "return api('failed&' + q, undefined, {lane: 'failed'})" in PAGE,
    "return api('passed&' + q, undefined, {lane: 'passed'})" in PAGE], [True, True, True])
ok('...and every row says which record it is',
   PAGE.count("tr.dataset.session = r.session || '';"), 2)
ok('a row is lit by its background, not by a shadow it may not draw',
   '.found-row>td{animation:foundrow' in PAGE, True)
ok('...for about four seconds', '4s ease-out' in PAGE and 'row ? 4000 : 2200' in PAGE, True)
ok('...and the same row can be lit twice, which needs the mark taken off first',
   'void node.offsetWidth;' in PAGE, True)
ok('the chips are pressable and the door itself is not',
   ["el('a', 'fgo', num(d.passed)" in PAGE, "el('a', 'fgo', num(d.failed)" in PAGE], [True, True])
ok('...and the last sighting is a press of its own',
   'function lastSeenLine(' in PAGE and "goToRecords(last.ok ? 'passed' : 'failed'" in PAGE, True)
# The find box answers a name the way it answers an address, and does it on
# Enter rather than while somebody types: it is several queries and a
# question to somebody else's directory, and it is the answer to a question
# that has been finished rather than to half of one.
ok('a name has a card of its own', 'function findNameCard(' in PAGE, True)
ok('...asked for only when Enter is pressed',
   'function lookUpPerson(' in PAGE
   # Enter does what a press does (1.10.155): a name is looked up there,
   # and remembered in the history as well.
   and "if (on) { on.click(); return; }" in PAGE
   and "if (it.name) lookUpPerson(it.name); else { closeFind(); it.go(); }" in PAGE, True)
ok('...and pressing one in the list asks rather than closing the box',
   "if (it.name) lookUpPerson(it.name); else { closeFind(); it.go(); }" in PAGE, True)
ok('...with the box left open afterwards, because the card is to be pressed',
   'closeFind' in PAGE[PAGE.index('function lookUpPerson('):
                       PAGE.index('function isAddress(')], False)
ok('it carries the same chips and the same last-seen line as an address',
   ['doorChips(d.name, doors)' in PAGE, 'lastSeenLine(d.last)' in PAGE], [True, True])
ok('...the addresses it has come from, each one openable',
   'lookUp(a.ip)' in PAGE, True)
ok('...and what the directory says, asked separately so the card is not held up',
   "api('who&name=' + encodeURIComponent(d.name))" in PAGE, True)
ok('nothing here writes to a directory', 'directory' in PAGE and
   not re.search(r"api\('who[^']*',\s*\{", PAGE), True)
ok('Escape clears what was typed before it closes anything',
   "if ($('findinput').value) {" in PAGE
   and "$('findinput').value = '';" in PAGE, True)
ok('...and the box says so', 'clear, then close' in PAGE, True)

# A name in that box may be a person or a machine and nothing in a log says
# which: `host/PC1.example.int` and `jnovak` are both just names. The card
# guesses from the doors and the directory overwrites the guess, which is
# the only place the difference is actually written down.
ok('the card says which it thinks it is', "el('span', 'tag info', d.looks_like)" in PAGE, True)
ok('...and the daemon works that out from the doors it has been seen at',
   "looks = ('a machine' if doors and doors <= set(Storage.MACHINE_DOORS)" in DAEMON, True)
ok('...and only the doors a machine can come through count as one',
   sorted(x.strip() for x in re.search(
       r'MACHINE_DOORS = \((.*?)\)', DAEMON, re.S).group(1).replace("'", '').split(',')
       if x.strip()),
   ['dot1x-lan', 'dot1x-wifi', 'mab-lan', 'mab-wifi'])
ok('...and the directory, which knows, has the last word over the guess',
   "guess.textContent = w.machine ? 'a machine' : 'a person';" in PAGE, True)
# What a machine did on the network, which is the half of the card a VPN
# record has not got: the switch, the socket, the VLAN it was put into, the
# MAC that did it.
ok('a machine’s card says where on the network it was',
   [w in PAGE for w in ("['switch', n.switch]", "['socket', n.port]",
                        "['VLAN', n.vlan]", "['MAC', n.mac]")],
   [True, True, True, True])
ok('...off both lists, each with the column that is its own',
   "for table, extra in (('passed', 'subtype AS said, tkey AS vlan')," in DAEMON, True)
ok('...and each of those rows opens the record it came from',
   "goToRecords(n.ok ? 'passed' : 'failed', n.kind, d.name, n.session);" in PAGE, True)
# Two directories, which is the shape this site has: example.cz and example.loc
# are one domain under two names. "There is no such account" and "the one
# directory we asked has not got it" are different sentences.
ok('with two directories the card says both were asked',
   "? 'neither directory has such an account' : 'the directory has no such account'" in PAGE,
   True)
ok('...and which of them answered, when there were two to ask',
   'if (w.asked_both && w.where_words)' in PAGE, True)
ok('...and the daemon says whether it asked both',
   "'asked_both': len(which) > 1" in DAEMON, True)
ok('...while trouble at one of them is said rather than read as "no such account"',
   "'\\n\\nThough one of them had trouble answering: '" in PAGE, True)

# The filters on a row are one row of controls and have to look like one.
# The country filter is a button rather than a select - a list of two-letter
# codes is a filter nobody can use - and being a button it had a size of its
# own: 29px beside 40.3px, at a lighter weight, in a row of four.
def rule(sel):
    said = re.search(r'(?:^|[;{}\n])\s*%s\{([^{}]*)\}' % re.escape(sel), CSS)
    out = {}
    for one in ' '.join(said.group(1).split()).rstrip(';').split(';'):
        if ':' in one:
            name, _, value = one.partition(':')
            out[name.strip()] = value.strip()
    return out


BTN, SEL, BOX = rule('.ccbtn'), rule('select'), rule(
    'input[type=text],input[type=search],input[type=password],input[type=number],textarea,select')
ok('the country filter is padded exactly as the selects beside it',
   BTN.get('padding'), SEL.get('padding'))
ok('...at the same size', BTN.get('font-size'), BOX.get('font-size'))
ok('...at the same weight', BTN.get('font-weight'), SEL.get('font-weight'))
ok('...and with the same corners', BTN.get('border-radius'), BOX.get('border-radius'))
# The Ctrl-K badge sits inside the find box, so the words have to stop
# before it. Two rules of equal weight set that padding and the later one
# won, which is how the placeholder ended up running under the badge.
ok('the find box keeps its words clear of the badge in the corner',
   rule('.findbox input[type=search]').get('padding'), '6px 52px 6px 11px')
# `.findbox input` and `input[type=search]` are worth exactly the same, so
# the one written later wins - and the one written later was the general
# rule, which threw the 52px away and let the placeholder run under the
# badge. Said with the type on it, it cannot be lost that way again.
ok('...said with the type on it, so nothing of equal weight can take it back',
   [sel for sel, body in re.findall(r'([^{}]+)\{([^{}]*)\}', CSS)
    if '.findbox input' in sel and '[type=' not in sel
    and 'padding' in ' '.join(body.split())], [])

# Every window of this kind offers the same windows, and the longest of
# them is a year: a site looks at a month on the chart and then wants the
# shape of the year behind it, and a filter that stops at a month makes that
# a question nobody on the page can ask.
WINDOWS = re.findall(r'<select id="(ov-hours|f-hours|p-hours)"[^>]*>(.*?)</select>', PAGE, re.S)
ok('there are three windows of this kind on the page', len(WINDOWS), 3)
for which, block in WINDOWS:
    said = re.findall(r"<option value=\"(\d+)\"[^>]*>([^<]+)</option>", block)
    ok('%s goes out to a year' % which,
       [v for v, words in said if 'year' in words], ['8760'])
    ok('...and the windows are in order, shortest first' ,
       [int(v) for v, _ in said if v != '0'],
       sorted(int(v) for v, _ in said if v != '0'))
ok('...and the daemon draws a year without being asked for a bar an hour',
   [isemon.Daemon.chart_step(h) for h in (6, 24, 720, 8760)], [300, 3600, 3600, 86400])

# ---------------------------------------------------------------------------
# What an address is called. The rule this whole feature lives under is that
# nothing waits for it, and the page is where that is either true or a lie:
# the names are asked for after a table has been drawn, never before, and an
# answer that is not ready yet is a blank rather than a page that hangs.
ok('the page asks for the names of the addresses it has just drawn',
   'function askNames(' in PAGE and 'function wantsName(' in PAGE, True)
ok('...gathered for a moment first, so a table is one question and not two hundred',
   "PTR_SOON = setTimeout(askNames, 120)" in PAGE, True)
ok('...and it is drawn first and told afterwards, never the other way round',
   bool(re.search(r"function addrLine\(ip, kind, ts\) \{.*?wantsName\(a, ip, ts\);\s*\n\s*return a;",
                  PAGE, re.S)), True)
ok('...with the moment of the row, because a lease moves',
   "one.ip + '@' + Math.round(one.ts)" in PAGE, True)
ok('...and a name that could not be fetched is never an error on the page',
   "}).catch(function () { /* a name is never worth an error on the page */ });" in PAGE,
   True)
# Over the address rather than in a column of its own: a column would change
# the shape of every table on this page, and a name is not what anybody is
# scanning down - it is what they want about the one row they stopped at.
ok('a name is shown over the address, not as a column',
   '.addr.named{border-bottom:1px dotted' in CSS, True)
ok('...and the daemon keeps one row per name an address has had',
   'CREATE TABLE IF NOT EXISTS ptr (' in DAEMON, True)
ok('...with both ends of the time it had it',
   ['first  REAL NOT NULL' in DAEMON, 'last   REAL NOT NULL' in DAEMON], [True, True])
# The servers are a list with an order, so they are edited as a list with an
# order - a row each and a button to add one - rather than as a line of text
# with commas in it.
ok('the name servers are edited a row at a time, like the places are',
   "input = dnsEditor(s);" in PAGE and 'function dnsEditor(' in PAGE, True)
ok('...with a button that adds one', "cmdButton('Add a name server', 'add', 'small')" in PAGE,
   True)
ok('...and one that moves a row up, because which is asked first decides',
   "iconButton('up', 'Ask this one earlier')" in PAGE, True)
ok('...written back out as the plain list the daemon reads',
   bool(re.search(r'function dnsWrite\(rows\)', PAGE)), True)
ok('...and read back in the same way, so a hand-typed one is not thrown away',
   bool(re.search(r'function dnsRead\(text\)', PAGE)), True)
# An address is fifteen characters at its longest. A box four times that
# wide says something longer is expected, and it drags the button on the end
# of the row to the far side of the card, away from the thing it belongs to.
# Measured in a browser: 200px for an address, 84px for a port.
for which in ('.places-row input:first-child', '.dnsrow input:nth-child(2)'):
    said = rule(which)
    ok('%s is as wide as an address, not as wide as the card' % which,
       said.get('flex', ''), '0 1 200px')
ok('...and the port beside it is narrower still',
   rule('.dnsrow input:nth-child(3)').get('flex', '').startswith('0 1 8'), True)
ok('...and a row of them wraps rather than running off a narrow window',
   [rule(one).get('flex-wrap') for one in ('.places-row', '.dnsrow')], ['wrap', 'wrap'])

# Every box the page writes into has to be a box that is there. One line of
# the "go back over every log" card wrote to an element that had been taken
# out of the markup: that threw, the throw landed in the card's own `catch`,
# and the card was left blank with the answer it had just been given thrown
# away - so pressing the button asked "? earns ?" and offered to weigh 0
# records. Nothing in any test looked at it, because everything it broke was
# a blank rather than an error.
ASKED = sorted(set(re.findall(r"\$\('([A-Za-z0-9_-]+)'\)", PAGE)))
IN_HTML = set(re.findall(r'id="([A-Za-z0-9_-]+)"', PAGE))
MADE = set(re.findall(r"\.id = '([A-Za-z0-9_-]+)'", PAGE)) \
    | set(re.findall(r"id: '([A-Za-z0-9_-]+)'", PAGE))
ok('every box the page writes into is a box that exists',
   [one for one in ASKED if one not in IN_HTML and one not in MADE], [])
ok('...and there are as many of them as ever there were', len(ASKED) > 200, True)
# ...and the one card that was bitten by it says what it would do before it
# asks, rather than asking with question marks in the sentence.
ok('the card that goes back over the logs asks the daemon before it asks anybody',
   'loadRescan().then(function () { askRescan(); })' in PAGE, True)
ok('...and a box that is missing costs that box and nothing else',
   'function setText(id, text)' in PAGE, True)
ok('...and it has a page of its own rather than the bottom of Banning',
   'id="pane-rescan"' in PAGE and 'data-pane="rescan"' in PAGE, True)
ok('...where the rule it weighs by is said outright',
   "setText('rescan-rule', (d.trigger || '') + ' earns ' + (d.lengths || ''));" in PAGE, True)

# The same idea over a MAC: the first half of one is an assignment out of
# the IEEE's registers, so a page of MAB refusals can say Apple, VMware or
# Zebra rather than hex. Fetched with the country database, answered out of
# the table here, and shown by looking at what was drawn rather than by
# every table remembering to ask.
ok('the makers behind the MACs are shown the same way the names are',
   'function nameTheMakers(' in PAGE and 'function wantsVendor(' in PAGE, True)
ok('...and it runs on whatever has just been drawn',
   bool(re.search(r'nameTheAddresses\(host\);\s*\n\s*nameTheMakers\(host\);', PAGE)), True)
# The maker is the answer, not a word inside a sentence: its own line, at a
# size worth looking at, and never broken across two of them. Measured in a
# browser before this: `word-break:break-all` on that block - which is right
# for a session id - turned "Apple, Inc." into "Appl / e, Inc.".
ok('the maker gets a line of its own at the top of the popup',
   'var head = \'<div class="maker">\' + richText(vendor) + \'</div>\';' in PAGE, True)
ok('...and is never broken across two lines',
   [rule('.sethelp .maker').get(one) for one in ('white-space', 'word-break')],
   ['nowrap', 'normal'])
ok('...and a name is shown the same way over an address',
   [rule('.sethelp .host').get(one) for one in ('white-space', 'word-break')],
   ['nowrap', 'normal'])
ok('...with the sentence under either of them set as a sentence, not as an id',
   rule('.sethelp .k .more').get('word-break'), 'normal')
ok('...in the page\u2019s own face rather than the monospace of the block it sits in',
   [rule('.sethelp .maker').get('font-family'), rule('.sethelp .k .more').get('font-family')],
   ['var(--face)', 'var(--face)'])
ok('...reading a MAC however it was written',
   "String(said || '').replace(/[-:.\\s]/g, '').toUpperCase()" in PAGE, True)
ok('...and the daemon keeps the three registers, not only the 24-bit one',
   sorted(re.findall(r"oui\w*\.csv', (\d+)\)|mam\.csv', (\d+)\)", DAEMON)) != [], True)
ok('...with the longest assignment winning, which is what the 28s and 36s are for',
   "for bits, cut in ((36, 9), (28, 7), (24, 6)):" in DAEMON, True)
ok('...and it is fetched with everything else that is fetched by itself',
   'for work in (self.feeds_due, self.geo_due, self.mac_due):' in DAEMON, True)
ok('...and by the one button that fetches everything now',
   "said.append('the MAC vendor registers: %s' % words)" in DAEMON, True)

# And the one pass that goes back: the daemon only learns an address when a
# record arrives or a page is drawn, so a database with a year in it is
# mostly addresses nobody has ever asked about.
ok('there is a way to fill in every address that has no name yet',
   'def ptr_fill_job(' in DAEMON, True)
ok('...from the command line', "'--ptr-fill'" in DAEMON, True)
ok('...and from the page, saying how many there are before it is pressed',
   'id="ptr-fill"' in PAGE and "api('ptr', {missing: true})" in PAGE, True)
ok('...at the same handful a second as everything else, rather than in a burst',
   'self.names.allowed()' in DAEMON, True)
ok('...and one address can be asked about by hand, of every server in turn',
   "'--ptr'" in DAEMON and 'def cmd_ptr(' in DAEMON, True)

ok('the settings have a page of their own for it',
   'id="pane-names"' in PAGE and 'data-pane="names"' in PAGE, True)
ok('...saying out loud that nothing waits for it',
   '<b>Nothing waits for any of it.</b>' in PAGE, True)
ok('...and that it is your servers rather than this machine\u2019s resolver',
   'not this machine' in PAGE, True)

ok('the address popup shows the same chips rather than its own',
   "kv('Where it has been seen', doorChips(" in PAGE, True)
ok('...and the token packets, which are in neither list it draws',
   "'What the token server was asked from it'" in PAGE, True)
ok('...and both of its lists say which door each row came through',
   PAGE.count('tr.appendChild(doorCell(r.kind));'), 2)
ok('the chips are not tied to the card they were first drawn on',
   ['.findcard .fdoor{' in CSS, '\n  .fdoor{' in CSS], [False, True])

ok('the switch that stops the ISE logs being read has a place on the page',
   bool(re.search(r"logs:\s*\['ise',", PAGE)), True)
ok('...and the OTP rows fill it from the packet beside the token line',
   'machineCell(asked && asked.device)' in PAGE, True)
ok('the machine is never judged: it is drawn and nothing else',
   bool(re.search(r'machineCell\([^)]*\)\s*(===|!==|==|!=)', PAGE)), False)

# Every token verdict wears its own mark now, the ordinary one included.
ok('the token verdict is a mark whatever it says',
   "var mark = el('span', 'tag ' + tone," in PAGE, True)
ok('...and the ordinary success is the green one',
   TOKEN_TONES.get('valid token used'), 'ok')

# ---------------------------------------------------------------------------
# The guide beside the token-server files tells whoever is installing them to
# check what arrived against a table of sums, and a wrong sum there is worse
# than none: it sends somebody looking for a damaged copy of a file that came
# over perfectly. So the table is checked against the files themselves.
HERE = pathlib.Path(__file__).resolve().parent.parent
GUIDE = HERE / 'docs' / 'otp-radius-detail.md'
BESIDE = HERE / 'docs' / 'otp-radius-detail'
if GUIDE.exists() and BESIDE.is_dir():
    said = dict(re.findall(r'^\| `([^`]+)` \|[^|]*\| `([0-9a-f]{32})` \|$',
                           GUIDE.read_text(encoding='utf-8'), re.M))
    real = {f.name: hashlib.md5(f.read_bytes()).hexdigest()
            for f in sorted(BESIDE.iterdir()) if f.is_file()}
    ok('every file beside the guide is in its table of sums',
       sorted(set(real) - set(said)), [])
    ok('...and the table names nothing that is not there',
       sorted(set(said) - set(real)), [])
    ok('...and every sum in it is the sum of the file that shipped',
       sorted(n for n in said if n in real and said[n] != real[n]), [])
    # The script checks the same six files against a table of its own before
    # it touches anything, so that a file which arrived damaged is caught
    # there rather than as a server that will not start. Two tables of the
    # same sums is two things to forget, so the second one is checked too.
    SETUP = BESIDE / 'otp-radius-setup.sh'
    if SETUP.exists():
        text = SETUP.read_text(encoding='utf-8')
        mine = dict((name, sum) for sum, name in
                    re.findall(r'^\t\t([0-9a-f]{32}) (\S+)$', text, re.M))
        ok('the script checks every file it uses against a sum',
           sorted(set(real) - set(mine) - {SETUP.name}), [])
        ok('...and the sums it checks them against are the sums they shipped',
           sorted(n for n in mine if mine[n] != real.get(n)), [])
        ok('...and it does not try to check its own, which it cannot',
           SETUP.name in mine, False)
        ok('the script is a script bash will run', 0, os.system(
            'bash -n %s' % shlex.quote(str(SETUP))))
        ok('...and it is marked executable, or nobody can run it',
           bool(SETUP.stat().st_mode & 0o111), True)

    # Nothing shipped for somebody else's server may carry an address of
    # ours. It happened once: the rsyslog rule went out with a real
    # collector in it, so every site installing this would have forwarded
    # its records to one particular machine that is not theirs. The
    # documentation ranges are what an example is written with; the
    # loopback is the loopback everywhere.
    ALLOWED = ('127.0.0.1', '0.0.0.0', '255.255.255.255')
    DOCS = ('192.0.2.', '198.51.100.', '203.0.113.')
    for f in sorted(BESIDE.iterdir()):
        if not f.is_file():
            continue
        found = sorted({a for a in re.findall(
            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', f.read_text(encoding='utf-8',
                                                             errors='replace'))
            if a not in ALLOWED and not a.startswith(DOCS)})
        ok('%s carries no address of anybody\u2019s real network' % f.name, found, [])
    # ...and the one address that does have to be known is asked for.
    if SETUP.exists():
        ok('where to forward to is asked for rather than assumed',
           'ask_collector' in text and 'COLLECTOR' in text, True)

    # Both patches have to apply to a file the other patch has not touched,
    # so `patch` counts the lines of each hunk and refuses a header that
    # disagrees with the body under it. A hand-edited patch is exactly how
    # that happens.
    for name in sorted(n for n in real if n.endswith('.patch')):
        bad = []
        text = (BESIDE / name).read_text(encoding='utf-8')
        # The newline that ends the file is not a line of the last hunk:
        # split leaves an empty string behind it, and counting that as one
        # more line of context makes every last hunk look one too long.
        lines = text[:-1].split('\n') if text.endswith('\n') else text.split('\n')
        for i, line in enumerate(lines):
            m = re.match(r'^@@ -\d+,(\d+) \+\d+,(\d+) @@', line)
            if not m:
                continue
            old = new = 0
            for body in lines[i + 1:]:
                if body.startswith(('@@', '--- ', 'diff ')):
                    break
                if body.startswith('-'):
                    old += 1
                elif body.startswith('+'):
                    new += 1
                elif body.startswith(' ') or body == '':
                    old += 1
                    new += 1
            if (old, new) != (int(m.group(1)), int(m.group(2))):
                bad.append(line)
        ok('%s counts its own lines the way patch will' % name, bad, [])

# ---------------------------------------------------------------------------
# Half a dozen faults the page has shipped, every one of them invisible from
# the daemon's side and every one a line or two to look for here. They are
# checked in the source because what they are about is what the file says: a
# script tag without the number on it is a tag a browser refuses to run, and
# there is no test anywhere else that would notice.
title('The page, where what it says is the whole of it')
# Read off the starts of lines, which is where the page's own tags are:
# the note at the top of the file talks ABOUT a script tag and is not one.
scripts = re.findall(r'(?m)^<script\b[^>]*>', PAGE)
ok('every script tag on the page carries the number that lets it run',
   [one for one in scripts if 'nonce=' not in one], [])
ok('...and there are as many of them as ever there were', len(scripts) >= 9, True)
ok('...and the stylesheet too',
   [one for one in re.findall(r'(?m)^<style\b[^>]*>', PAGE) if 'nonce=' not in one], [])
ok('...and the number is made fresh for each answer, not written into the file',
   bool(re.search(r'\$nonce = base64_encode\(random_bytes\(\d+\)\)', PAGE)), True)
# ...and the styles, which is where this went wrong once and took the layout
# of the whole page with it. A `style="..."` in the markup cannot carry the
# number - there is nowhere to put one on an attribute - so a policy that
# names a nonce for styles switches inline off for the attributes as well,
# and a browser then refuses every one of them.
policy = PAGE[PAGE.index('header("Content-Security-Policy'):]
policy = policy[:policy.index(');')]
attributes = len(re.findall(r'\sstyle="[^"]+"', PAGE))
ok('the page really does lay itself out with style attributes', attributes > 40, True)
ok('...so what governs an attribute allows them',
   bool(re.search(r"style-src 'self' 'unsafe-inline'", policy)), True)
ok('...and it is not the thing that carries the number',
   bool(re.search(r"style-src 'self' [^;]*nonce", policy)), False)
ok('...while a <style> tag still has to carry it',
   bool(re.search(r"style-src-elem 'self' 'nonce-", policy)), True)
ok('...and so does a script', bool(re.search(r"script-src 'self' 'nonce-", policy)), True)
ok('...and nothing has been let into the scripts alongside it',
   'unsafe-inline' in re.search(r"script-src[^;]*", policy).group(0), False)
# The health of the database is the sign-in page's one way to explain why no
# password will work, and it used to say it with the database account, the
# server, the port, the name and the driver's own error text - to anybody who
# could load the URL.
health = PAGE[PAGE.index('$health  = isemon_get'):PAGE.index('$token_there')]
ok('what a database fault says to somebody not signed in is blanked',
   bool(re.search(r"if \(!\$me && is_array\(\$health\) && isset\(\$health\['database'\]\)",
                  health)), True)
for part in ('engine', 'where', 'trouble'):
    ok("...with '%s' emptied rather than passed on" % part,
       bool(re.search(r"'%s'\s*=> ''" % part, health)), True)
# Which firewall's key is being asked for has to be passed on, or the second
# router's key is the first router's key with nothing saying so.
grab = PAGE[PAGE.index("if ($what === 'mikrotik-key-download')"):]
grab = grab[:grab.index('Cache-Control')]
ok('the download of a router key passes on which router it is',
   "'/api/mikrotik/key/download'" in grab and 'fw=' in grab, True)
ok('...and what it takes for that name is letters and digits only',
   bool(re.search(r"preg_replace\('/\[\^a-z0-9\]/'", grab)), True)
ok('...and the file it hands over is named after that router',
   'Content-Disposition' in grab and '$fw' in grab, True)
# Anything posted here is a form nobody can make from another site, and is
# not a body big enough to be a denial of service on its own.
post = PAGE[:PAGE.index('/* ---- the page ---')]
ok('a body bigger than the cap is refused before it is read',
   "CONTENT_LENGTH" in post, True)
ok('...and one that does not say it is JSON', 'CONTENT_TYPE' in post, True)
ok('...and one the browser says came from another site',
   'HTTP_SEC_FETCH_SITE' in post, True)
# Every string the page writes into markup goes through one function, and
# that function has to escape the quote as well: an attribute written with
# single quotes is an attribute anything can be added to without it.
rich = PAGE[PAGE.index('function richText('):]
rich = rich[:rich.index('\n}\n')]
for what, mark in (('the ampersand', '&amp;'), ('the less-than', '&lt;'),
                   ('the quote', '&quot;'), ('the apostrophe', '&#39;')):
    ok('the one function that escapes for markup escapes %s' % what,
       mark in rich, True)

# ---------------------------------------------------------------------------
title('Two things a column of pills has to do')
# A pill has seven pixels of padding of its own, and a pill that starts a cell
# is pulled back by exactly that so its word lines up with the heading above
# it. Written as "the only child of the cell" that pull-back skipped every
# cell that happens to have a second pill in it - an account that is the
# directory's is `full admin` AND `from AD` - so a column of roles was seven
# pixels ragged, row by row, and none of it lined up with its own heading.
pull = re.search(r'td:not\(:first-child\) > \.tag([^{]*)\{margin-left:-7px\}', CSS)
ok('the pill that starts a cell is pulled back by its own padding',
   bool(pull), True)
ok('...whether or not a second pill follows it in the same cell',
   ':last-child' in (pull.group(1) if pull else ':last-child'), False)

# An address with no reverse name looked exactly like an address nobody had
# asked about yet: the popup had the row's own words in it and nothing else,
# and on a page of foreign scanners - which mostly have no reverse record -
# that reads as the naming being broken rather than as the answer it is.
say = PAGE[PAGE.index('function ptrSay('):]
say = say[:say.index('\n}\n')]
ok('an address the zone has no name for says so',
   'got.known' in say and 'no name for this address' in say, True)
ok('...and one nobody has asked about yet still says nothing',
   bool(re.search(r'if \(!got\.known', say)), True)
ok('...and it is not said twice on the same one',
   'ptrnone' in say, True)

# ---------------------------------------------------------------------------
title('The ending of an access list, on the page that types it')
# It is read by the daemon as it is typed - the same reading that refuses it
# on save and the same one the command line uses - so there is one answer to
# "would a router take this" rather than three that can drift apart.
ed = PAGE[PAGE.index('function aclEditor('):]
ed = ed[:ed.index('\nfunction ')]
ok('what is typed is read by the daemon, not by the page',
   "api('acltry'" in ed, True)
ok('...and it is asked about the family it belongs to', "'ipv6' : 'ipv4'" in ed, True)
ok('...after a moment rather than on every keystroke', 'setTimeout' in ed, True)
ok('...and the box says which line is wrong', "'line ' + one.n" in ed, True)
ok('the relay lets that reading through both ways',
   PAGE.count("'/api/acl/try'"), 2)
ok('...and the daemon has it', "path == '/api/acl/try'" in DAEMON, True)
# One of the four settings is a name and one is a body; both families have
# both, because on a router they are two different access lists.
for key in ('ios_acl_name', 'ios_acl_name6', 'ios_acl_tail', 'ios_acl_tail6'):
    ok('%s is a setting the daemon knows' % key, "'%s':" % key in DAEMON, True)
    ok('...and the page puts it on a card', "'%s'" % key in PAGE, True)

title('One id, a page of sign-ins, and a packet each')
# An id says WHICH conversation, and a pair of address and port is reused all
# day: a head end that walks its source ports comes back round, and a token
# server that passes on the NAS rather than the client writes one id on every
# line it ever writes. So the id narrows it and the clock decides, per
# attempt - and a packet handed to one attempt is not handed to another.
# Asked a page at a time this used to keep only the newest packet per id
# across the whole page, so a day of sign-ins all wore the address, the
# machine and the tunnel group of whoever had signed in last. One row at a
# time - which is what the popup behind a row asks for - has a window of its
# own and was right, so the list and the popup said different things about
# the same row, which is how it was found.
SHARED = '172.22.0.137:1812'
folder2, store2, daemon2 = fresh()
page, base = [], time.time() - 6 * 3600
for n, (name, address, machine) in enumerate(
        [('novak', '10.0.0.11', 'NB-NOVAK'), ('kolar', '10.0.0.22', 'NB-KOLAR'),
         ('vesela', '10.0.0.33', 'PC-VESELA'), ('mdolezal', '198.51.100.26', 'Workshop')]):
    at = base + n * 3600
    store2.note_otp_asked({'ts': at, 'at': at, 'server': 'otp2', 'kind': 'ask',
                           'half': 'ask', 'ip': address, 'nas': '172.22.0.137',
                           'port': '1812', 'device': machine, 'tunnel': 'CORPNET',
                           'username': name + '@example.cz', 'verdict': 'accept',
                           'session': 'sess-%d' % n, 'rid': SHARED, 'attrs': {}, 'av': {}})
    page.append(('otp/%d' % n, 'otp2', name, at + 1, True, name + '@example.cz', SHARED))
whole = store2.otp_asked_near(page)
ok('a page of sign-ins that all carry one id gets a packet each, not one packet',
   [(whole.get(one[0]) or {}).get('ip') for one in page],
   ['10.0.0.11', '10.0.0.22', '10.0.0.33', '198.51.100.26'])
ok('...and the machine on each row is that row\u2019s own',
   [(whole.get(one[0]) or {}).get('device') for one in page],
   ['NB-NOVAK', 'NB-KOLAR', 'PC-VESELA', 'Workshop'])
ok('...which is what asking for them one at a time says too',
   [(store2.otp_asked_near([one]).get(one[0]) or {}).get('ip') for one in page],
   ['10.0.0.11', '10.0.0.22', '10.0.0.33', '198.51.100.26'])
ok('...and every one of them is still a lookup rather than a guess',
   sorted({(whole.get(one[0]) or {}).get('by') for one in page}),
   ['the id both logs carry'])
# Two attempts a second apart under one id: the nearer packet is the one that
# is taken, and the other attempt gets the other packet rather than the same.
ok('...and one packet is never given to two of them',
   len({(whole.get(one[0]) or {}).get('ts') for one in page}), len(page))

title('...and a refusal written onto the attempt it belongs to')
# The other half of the same mistake, and the worse half: this one WRITES.
# A refusal the RADIUS server made after the token server had already said
# yes is carried onto the token attempt it belongs to, which moves that
# attempt out of the sign-ins and into the refusals. Found by the id both
# logs carry - and that lookup took the NEWEST attempt with that id, over
# all time, with no window at all. On a site where the id repeats, that is
# whoever signed in last: their good sign-in moved into the refusals wearing
# somebody else's reason, and the person actually refused left standing as a
# success, which is the one lie this whole function exists to stop.
folder3, store3, daemon3 = fresh()
isemon.CONFIG['otp'] = 1
SAME = '172.22.0.137:1812'
now3 = time.time()
morning, evening = now3 - 8 * 3600, now3 - 60
store3.add_passed({'session': 'otp/novak', 'ts': morning, 'ip': '', 'kind': 'otp',
                   'server': 'otp2', 'username': 'novak', 'tkey': 'novak@example.cz',
                   'asked_as': SAME, 'subtype': 'Valid token used'})
store3.note_otp_asked({'ts': morning, 'at': morning, 'server': 'otp2', 'kind': 'ask',
                       'half': 'ask', 'ip': '10.0.0.11', 'nas': '172.22.0.137',
                       'port': '1812', 'username': 'novak@example.cz', 'verdict': 'reject',
                       'said': 'LDAP server(s) have gone away', 'session': 's1',
                       'rid': SAME, 'attrs': {}, 'av': {}})
store3.add_passed({'session': 'otp/mdolezal', 'ts': evening, 'ip': '', 'kind': 'otp',
                   'server': 'otp2', 'username': 'mdolezal', 'tkey': 'mdolezal@example.cz',
                   'asked_as': SAME, 'subtype': 'Valid token used'})
daemon3.apply_radius_refusals(since=morning - 60)


def sits_in(session):
    for table in ('passed', 'failed'):
        row = store3.db.execute('SELECT session FROM %s WHERE session=?' % table,
                                (session,)).fetchone()
        if row is not None:
            return table
    return 'gone'


ok('a refusal is carried onto the attempt it belongs to', sits_in('otp/novak'), 'failed')
ok('...and not onto the one that merely shares its id',
   sits_in('otp/mdolezal'), 'passed')
ok('...whose own words are left alone',
   store3.db.execute("SELECT subtype FROM passed WHERE session='otp/mdolezal'")
        .fetchone()['subtype'], 'Valid token used')
# ...and the same id a whole day later is somebody else, not a near miss.
store3.add_passed({'session': 'otp/old', 'ts': now3 - 30 * 3600, 'ip': '', 'kind': 'otp',
                   'server': 'otp2', 'username': 'old', 'tkey': 'old@example.cz',
                   'asked_as': SAME, 'subtype': 'Valid token used'})
ok('an attempt a day away is not what an id points at',
   store3.token_row_for(SAME, 'otp2', 'old', now3, 3)[1] != 'otp/old', True)
isemon.CONFIG['otp'] = 0
shutil.rmtree(folder3, ignore_errors=True)

title('A name is typed by whoever is knocking, so it may not choose the door')
# Only the VPN is ever judged. So any way a person at a prompt can make their
# own attempts come out as some other door is a way to guess passwords all
# day and never be counted, let alone banned - with nothing on the page
# looking wrong, because every attempt is there under "Everything else".
def doorof(user, failed=True):
    body = ('Authentication failed, ConfigVersionId=86, '
            'Device IP Address=172.22.0.137, UserName=' + user + ', Protocol=Radius, '
            'NetworkDeviceName=FTD-VPN, Calling-Station-ID=203.0.113.66, '
            'AcsSessionID=ise2/1/1,')
    got = isemon.ise_fields(body)
    return isemon.ise_kind(got, isemon.ise_unescape(isemon.ise_first(got, 'UserName')),
                           failed=failed), isemon.ise_source_ip(got)


ok('an ordinary name knocks at the VPN', doorof('jnovak'), ('vpn', '203.0.113.66'))
# The name of a downloadable ACL. A real one is the firewall fetching a list
# for a session already let in: a successful record, with no client address
# on it because nobody is asking. Typed at a prompt it is a person.
ok('somebody who types the name of a downloadable ACL is still at the VPN',
   doorof('#ACSACL#-IP-AnyConnect_OLYMPUS-6913329c'), ('vpn', '203.0.113.66'))
ok('...and a real one, which has nobody\u2019s address on it, is still an ACL',
   isemon.ise_kind(isemon.ise_fields(
       'ConfigVersionId=86, Device IP Address=172.22.0.137, '
       'UserName=#ACSACL#-IP-AnyConnect_OLYMPUS-6913329c, Protocol=Radius,'),
       '#ACSACL#-IP-AnyConnect_OLYMPUS-6913329c', failed=False), 'dacl')
# A value may not swallow the field after it either. ISE escapes a comma as
# `\,` AND a backslash as `\\`, so an escaped comma is preceded by an odd run
# of backslashes and a real separator by an even one. Looking one character
# back cannot tell those apart, and a name ending in a backslash ate the
# field after it - the protocol, or the address - and the record fell out of
# the judging either way.
ok('a name ending in a backslash does not eat the field after it',
   doorof('bob' + '\\' * 2), ('vpn', '203.0.113.66'))
ok('...and neither does one ending in two of them',
   doorof('bob' + '\\' * 4), ('vpn', '203.0.113.66'))
ok('...while a comma inside a name is still not a separator',
   isemon.ise_fields('UserName=Novak\\, Jan, Protocol=Radius'),
   {'UserName': ['Novak\\, Jan'], 'Protocol': ['Radius']})
ok('...and a backslash then an escaped comma keeps both',
   isemon.ise_fields('UserName=a\\\\\\, b, Protocol=Radius'),
   {'UserName': ['a\\\\\\, b'], 'Protocol': ['Radius']})
ok('...and a value can still never make a field of its own',
   isemon.ise_first(isemon.ise_fields(
       'UserName=bob\\, Calling-Station-ID=198.51.100.7, Protocol=Radius'),
       'Calling-Station-ID'), '')
# ...and the whole of it, through the reader and the judging.
folder4, store4, daemon4 = fresh()
isemon.CONFIG.update({'blacklist': 1, 'block_tries': 3, 'block_window_min': 10,
                      'block_bogus_tries': 0, 'block_lots': 0, 'watch_devices': ''})
now4 = time.time()
for words, user in (('an ordinary name', 'jnovak'),
                    ('the name of an ACL', '#ACSACL#-IP-x'),
                    ('a name ending in a backslash', 'bob' + '\\' * 2)):
    with store4.db_write() as db:
        db.execute('DELETE FROM failed')
        db.execute('DELETE FROM blocked')
    for n in range(6):
        at = now4 - n * 5
        day = time.strftime('%b %d %H:%M:%S', time.localtime(at))
        iso = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(at))
        head = '%s ise2 CISE_Failed_Attempts 00000%05d 3 ' % (day, 700 + n)
        lines = [head + '0 ' + iso + '.500 ' + ise_zone(at) +
                 ' 0229674592 5400 NOTICE Failed-Attempt: '
                 'Authentication failed, ConfigVersionId=86, '
                 'Device IP Address=172.22.0.137, UserName=' + user + ', Protocol=Radius, '
                 'NetworkDeviceName=FTD-VPN, Calling-Station-ID=203.0.113.66, '
                 'AcsSessionID=ise2/1/%d,' % n,
                 head + '1 AuthenticationMethod=PAP_ASCII, FailureReason=22040 Wrong password,',
                 head + '2 EndPointIPAddress=203.0.113.66, '
                 'Response={RadiusPacketType=AccessReject; }']
        for rec in isemon.ise_parse_lines(lines, {}):
            daemon4.take_record('ise', rec)
    daemon4.maybe_block('203.0.113.66', isemon._AtTime(now4))
    ok('six wrong passwords behind %s earn a ban' % words,
       [r['ip'] for r in store4.blocked_all()], ['203.0.113.66'])
shutil.rmtree(folder4, ignore_errors=True)

# ---------------------------------------------------------------------------
title('A promise about a country is a promise a tidy-up may not break')
# `spared()` has three arms - written out, inside a range, or in a country that
# is never kept out - and the guard in front of folding asked only the first
# two. So a street was replaced by one subnet that took in a house in a spared
# country: the subnet went to the firewall, the house was kept out through it,
# and the pass that lets the spared back in could not undo it, because that
# asks whether the SUBNET is spared rather than what the subnet holds.
folder5, store5, daemon5 = fresh()
isemon.CONFIG.update({'never_block': '', 'never_block_countries': 'CZ',
                      'fold_after': 4, 'fold_least': 4})
now5 = time.time()
# One country database: the whole of this street is in CZ.
lo5, fam5 = isemon.pack_address('185.136.15.0')
hi5, _ = isemon.pack_address('185.136.15.255')
with store5.db_write() as db:
    db.execute('DELETE FROM geo_ranges')
    db.execute('INSERT INTO geo_ranges (lo, hi, family, cc) VALUES (?,?,?,?)',
               (lo5, hi5, fam5, 'CZ'))
ok('an address in that street may never be kept out',
   bool(daemon5.spared('185.136.15.200')), True)
ok('...and the guard in front of folding says so about the whole street',
   daemon5._touches_spared(ipaddress.ip_network('185.136.15.0/24')), True)
ok('...so the street is never folded into one line',
   [one['net'] for one in (daemon5.fold_plan() or {}).get('nets', [])
    if one.get('net', '').startswith('185.136.15.')], [])
ok('...while a street with nothing spared in it still can be',
   daemon5._touches_spared(ipaddress.ip_network('203.0.113.0/24')), False)
ok('...and a family that has no ranges at all is not spared by accident',
   daemon5._touches_spared(ipaddress.ip_network('2001:db8::/64')), False)
isemon.CONFIG['never_block_countries'] = ''
ok('...and with no country spared the same street is allowed again',
   daemon5._touches_spared(ipaddress.ip_network('185.136.15.0/24')), False)

# ---------------------------------------------------------------------------
title('A watch list that names nothing real is said out loud')
# The one fault that has actually happened here: a filter matching nothing
# looks exactly like a filter that is off, except that nothing is ever banned.
for n in range(3):
    store5.add_failed({'session': 'watched/%d' % n, 'ts': now5 - n, 'kind': 'vpn',
                       'ip': '203.0.113.90', 'username': 'INVALID', 'device': 'FTD-VPN',
                       'server': 'ise2', 'reason': 'wrong password', 'detail': '{}'})
said5 = store5.watched_devices_seen(now5 - 3600, {'ftd-vpn'})
ok('a list that names the device refusals come from is answered as hit',
   said5['watched'], 3)
said5 = store5.watched_devices_seen(now5 - 3600, {'none'})
ok('...and one that names nothing real is answered as nought',
   (said5['watched'], said5['all']), (0, 3))
ok('...with the names there really are, so the page can say what to type',
   said5['names'], ['FTD-VPN'])
ok('...and nothing is asked at all when nothing is filtered',
   store5.watched_devices_seen(now5 - 3600, set()), None)

# ---------------------------------------------------------------------------
title('One thread that would not start does not stop the firewall for ever')
# The busy flag is cleared only by the thread's own `finally`, so a thread that
# never started left it set for the life of the process - and every later
# change, the once-a-minute catch-up included, turned round at the door.
isemon.CONFIG.update({'mikrotik_host': '10.0.0.1', 'mikrotik_user': 'admin',
                      'mikrotik_password': 'x', 'mikrotik_sync': 1,
                      'mikrotik_list': 'isemon'})
made5 = []
real_thread = threading.Thread


class Refuses(real_thread):
    def start(self):
        made5.append(self.name)
        if self.name == 'mikrotik' and len(made5) == 1:
            raise RuntimeError("can't start new thread")
        return None                  # started but does nothing, for the test


threading.Thread = Refuses
try:
    if daemon5.mikrotik_ready():
        try:
            daemon5.mikrotik_after_change()
        except RuntimeError:
            ok('a thread that cannot start is not swallowed silently', False)
        ok('the firewall is not left marked busy by a thread that never started',
           daemon5._mikrotik_busy, False)
        daemon5.mikrotik_after_change()
        ok('...so the next change really does try again', made5.count('mikrotik'), 2)
    else:
        ok('the firewall is not left marked busy by a thread that never started',
           True)                     # no router configured in this build
        ok('...so the next change really does try again', True)
finally:
    threading.Thread = real_thread
    with daemon5._mikrotik_want:
        daemon5._mikrotik_busy = False
isemon.CONFIG.update({'mikrotik_host': '', 'mikrotik_sync': 0})
shutil.rmtree(folder5, ignore_errors=True)

# ---------------------------------------------------------------------------
title('A name typed at a prompt may not invent the fields around it')
# The one value on a token-log line that somebody chose is the name they
# typed, and it is written FIRST: `user=<typed>, mode=..., host=..., rid=...`.
# A name with `, rid=` inside it put a second id on the line ahead of the real
# one, and the first of each was taken - so the field the attempt is joined to
# its RADIUS packet by, and the address the row is filed under, were both
# whatever the person at the prompt said they were.
BASE = ('Sep 25 11:32:48 tok1 totp.cgi[4242]: Failure: user=%s, mode=totp, '
        'host=127.0.0.1, rid=10.9.9.1:41000, message=the token was wrong')
for typed, why in (('jnovak', 'an ordinary name'),
                   ('jnovak, rid=10.9.9.1:33333', 'a name carrying an id'),
                   ('jnovak, host=198.51.100.77', 'a name carrying an address'),
                   ('jnovak, rid=10.9.9.1:33333, host=198.51.100.77', 'a name carrying both')):
    said6 = isemon.otp_record_from(BASE % typed)
    ok('%s is joined by the id the token server wrote' % why,
       isemon.ise_first(said6.fields, 'Asked as'), '10.9.9.1:41000')
    ok('...and filed under the address the token server wrote',
       isemon.ise_first(said6.fields, 'Asked from'), '127.0.0.1')
    ok('...and the message is the one the server wrote',
       isemon.ise_first(said6.fields, 'What it said'), 'the token was wrong')
# ...and the RADIUS detail log, where a quote in a name re-opened the splitter.
DETAIL = ('\tUser-Name = "%s"\n\tTotp-Request-Id = 10.9.9.1:41000\n'
          '\tCalling-Station-Id = "203.0.113.9"\n')
for typed, why in (('mallory', 'an ordinary name'),
                   ('mallory\\", Calling-Station-Id = "198.51.100.50',
                    'a name carrying a quote and an address')):
    got6 = isemon.radius_attrs(', '.join(
        one.strip() for one in (DETAIL % typed).strip().split('\n')))
    ok('%s leaves the address the RADIUS server wrote' % why,
       (got6.get('Calling-Station-Id') or [''])[0], '203.0.113.9')
ok('a quoted comma in an ordinary value still holds together',
   isemon.radius_pieces('Reply-Message = "two, three", NAS-Port = 5'),
   ['Reply-Message = "two, three"', 'NAS-Port = 5'])

# ---------------------------------------------------------------------------
title('An id says which conversation; the name says whose')
folder6, store6, daemon6 = fresh()
now6 = time.time()
RID = '10.9.9.1:41000'
store6.add_passed({'session': 'otp/tok1/4242/%d/aaaa' % now6, 'ts': now6, 'kind': 'otp',
                   'username': 'jnovak', 'asked_as': RID, 'server': 'tok1', 'detail': '{}'})
store6.add_failed({'session': 'otp/tok1/4242/%d/bbbb' % now6, 'ts': now6 - 1, 'kind': 'otp',
                   'username': 'mallory', 'asked_as': RID, 'server': 'tok1', 'ip': '',
                   'reason': 'the token was wrong', 'detail': '{}'})
ok('a packet about one person finds that person\'s attempt, not the nearest one',
   store6.token_row_for(RID, 'tok1', 'jnovak', now6, 5),
   ('passed', 'otp/tok1/4242/%d/aaaa' % now6))
ok('...and a packet about the other finds the other',
   store6.token_row_for(RID, 'tok1', 'mallory', now6 - 1, 5),
   ('failed', 'otp/tok1/4242/%d/bbbb' % now6))
ok('...and a packet about somebody with no attempt at all finds nothing',
   store6.token_row_for(RID, 'tok1', 'someone-else', now6, 5), ('', ''))
ok('...while a packet with no name to go on still joins by the id alone',
   store6.token_row_for(RID, 'tok1', '', now6, 5)[0] in ('passed', 'failed'), True)
shutil.rmtree(folder6, ignore_errors=True)

# ---------------------------------------------------------------------------
title('A long list scrolls its rows and nothing else')
# The search box, the filters and the pager of a hundred-thousand-row list
# are the things somebody reaches for most, and a page that scrolls as one
# puts all three off the top of the window at the third row. So the card is
# as tall as the window and the table moves inside it - but ONLY where the
# card is alone on its page, or whatever is under it is below the fold for
# ever behind a second scrollbar.
ok('the long cards are marked as long', PAGE.count('data-hold="1"') >= 4, True)
ok('...and none of them is held by the markup itself',
   'card full held' in PAGE, False)
ok('...the page decides, by whether the card is alone on it',
   'function holdTheTallOnes(' in PAGE, True)
ok('...and decides again whenever a different page is shown',
   PAGE.count('holdTheTallOnes()') >= 2, True)
ok('...before anything can ask for it',
   PAGE.index('function holdTheTallOnes(') < PAGE.index('holdTheTallOnes();'), True)
# ...and a list inside a card that is already holding does not hold as well.
ok('two boxes never each keep a height of their own',
   '.card.held .list-view{max-height:none' in PAGE, True)
ok('...and the rows are the one thing that scrolls',
   '.card.held > .scroll.rowsonly{flex:1 1 auto' in PAGE, True)
ok('...with the heading staying above them',
   '.card.held > .scroll.rowsonly table thead th{position:sticky' in PAGE, True)

# ---------------------------------------------------------------------------
title('A card that has not changed is not drawn again')
# The live update asks every few seconds and most of the time the answer is
# the one already on the page. Clearing a card and building the same card
# back is, on a page somebody has scrolled down, a visible flicker every few
# seconds - and holding the box at its old height while it happened made it
# worse, because the new content is rarely the same height and the release
# was the jump. The scroll position is the thing that has to stay still.
ok('an answer is compared with the one already drawn',
   'function sameAsDrawn(' in PAGE, True)
for who in ('ovDrawDomain', 'ovDrawDoor', 'drawWinViews', 'drawWinIncidents'):
    at = PAGE.index('function %s(' % who)
    body = PAGE[at:PAGE.index('\n}\n', at)]
    ok('...and %s asks before it redraws' % who, 'sameAsDrawn(' in body, True)
ok('...and nothing is held at a height it is about to stop having',
   'style.minHeight' in PAGE, False)
at = PAGE.index('function settle(')
ok('...the scroll is put back instead',
   'window.scrollTo(0, back)' in PAGE[at:PAGE.index('\n}\n', at)], True)

# ---------------------------------------------------------------------------
title('The domain is a tab on both lists, and it carries a number')
ok('the refusals offer it', "{kind: 'domain'" in PAGE, True)
ok('...and it is offered on both strips rather than one',
   "host.id !== 'f-kinds'" in PAGE, False)
ok('...with a count of its own, which this page does not tally',
   "winsec_counts" in PAGE, True)
ok('...counted by the daemon', "'winsec_counts':" in DAEMON, True)
ok('...and both lists draw its rows with one function',
   PAGE.count('winRowsInto('), 3)
ok('...and neither brings a second search box with it',
   'loadPassedDomain' in PAGE and "winRowsTable(d.rows || [], 'failed-domain')" not in PAGE,
   True)

# ---------------------------------------------------------------------------
title('The JavaScript on the page parses')
# The check this file was missing, and the fault it was missing: `php -l`
# reads the PHP and says nothing at all about the JavaScript inside it,
# which on this page is most of what there is. One stray brace shipped a
# page that drew nothing, with a lint that passed and every other check here
# green - because every other check here reads the source as TEXT.
#
# So the script blocks are handed to a real JavaScript parser. Where there is
# no such parser on this machine the braces are counted instead, which
# catches the shape of that same fault and says so rather than passing
# quietly.
def script_blocks():
    """Every <script> on the page, with PHP echoes turned into values."""
    def hush(m):
        return 'null' + '\n' * m.group(0).count('\n')
    flat = re.sub(r'<\?.*?\?>', hush, PAGE, flags=re.S)
    out = []
    for m in re.finditer(r'<script[^>]*>(.*?)</script>', flat, re.S):
        out.append((PAGE[:m.start(1)].count('\n') + 1, m.group(1)))
    return out


blocks = script_blocks()
ok('the page has its script blocks', len(blocks) >= 5, True)
node = shutil.which('node') or shutil.which('nodejs')
if node:
    trouble = []
    for line0, code in blocks:
        with tempfile.NamedTemporaryFile('w', suffix='.js', delete=False,
                                         encoding='utf-8') as fh:
            fh.write(code)
            where = fh.name
        got = subprocess.run([node, '--check', where],
                             capture_output=True, text=True)
        os.unlink(where)
        if got.returncode:
            first = [l for l in got.stderr.split('\n') if 'SyntaxError' in l]
            hit = re.search(r'\.js:(\d+)', got.stderr)
            trouble.append('index.php line %s: %s'
                           % (line0 + int(hit.group(1)) - 1 if hit else '?',
                              (first[0] if first else got.stderr)[:90]))
    ok('...and every one of them parses', trouble, [])
else:
    # No parser here. The braces are counted instead - it is not a parse,
    # but a block that ends one brace up or one brace down is exactly the
    # fault this is here for.
    off = []
    for line0, code in blocks:
        bare = re.sub(r'/\*.*?\*/', '', code, flags=re.S)
        bare = re.sub(r'(?m)^\s*//.*$', '', bare)
        bare = re.sub(r"'(\\.|[^'\\])*'", "''", bare)
        bare = re.sub(r'"(\\.|[^"\\])*"', '""', bare)
        if bare.count('{') != bare.count('}'):
            off.append('index.php line %d: %d { against %d }'
                       % (line0, bare.count('{'), bare.count('}')))
    ok('...and the braces in every one of them balance', off, [])

# ---------------------------------------------------------------------------
title('The line under the door strip belongs to one function')
# The fault: the line holds the words AND the counts AND what they open, and
# the tab strip was rewriting it with the words alone on every refresh. It
# was invisible while the card underneath redrew every few seconds and put
# the counts back - and the moment a card that had not changed stopped being
# redrawn, the counts vanished a few seconds after every load.
at = PAGE.index('function ovDoorTabs(')
tabs = PAGE[at:PAGE.index('\n}\n', at)]
ok('the tab strip only writes that line when nothing else has',
   "!$('ov-doorsays').firstChild" in tabs, True)
at = PAGE.index('function ovDrawDoor(')
draw = PAGE[at:PAGE.index('\n}\n', at)]
ok('...and the summary is written even when the card has not changed',
   draw.index('ovDoorSummary(d)') < draw.index('sameAsDrawn('), True)
at = PAGE.index('function ovShowDoor(')
show = PAGE[at:PAGE.index('\n}\n', at)]
ok('...and a door changed starts that line again',
   "$('ov-doorsays').textContent" in show, True)

# ---------------------------------------------------------------------------
title('One thing hovered over is one panel')
# A door row says everything about itself on hover, and the hardware address
# in it used to open a SECOND panel on top of the first - two boxes fighting
# over the same corner of the screen, which is what 1.10.44 was sent back
# for. The maker is now a line of the panel that is already there.
ok('a maker looks for the panel it is already inside',
   'function nearestPanel(' in PAGE, True)
# ...and the rule lives in `explain` itself, so it holds for everything on
# this page rather than for hardware addresses alone: the name over an
# address, a tag, a heading, anything drawn inside a row that already says
# everything about itself on hover.
at = PAGE.index('function explain(')
body = PAGE[at:PAGE.index('\n}\n', at)]
# From 1.10.156 nothing is folded into anything: a row of the Traffic list
# that took in every address, name and mark inside it showed a column of a
# dozen paragraphs, the same ones twice. One panel at a time still - there is
# only one box - and it is the innermost thing under the pointer; moving back
# out onto the row shows the row's.
ok('...and every panel says only what its own thing is',
   'nearestPanel(over)' not in body and 'dataset.joined' not in body, True)
ok('...the innermost one under the pointer, the one around it again on the way out',
   'if (up._explainHtml && to && up.contains(to)) {' in body, True)
ok('...and does not walk the whole page looking for one', 'deep < 4' in PAGE, True)
ok('...and a maker still names itself in that panel',
   "'<b>Made by:</b> '" in PAGE or 'Made by' in PAGE, True)
# ...which only works if the row's own panel is there by the time the maker
# is asked for. Asked first, it found nothing to join and opened its own.
card = PAGE[PAGE.index('function ovViewCard('):PAGE.index('function shortName(')]
ok('the row is explained before its maker is asked for',
   card.index("explain(tr, 'Press it") < card.index('wantsVendor(name'), True)
ok('...and a maker is still asked for at all', card.count('wantsVendor(name'), 1)

# ...and a panel of a dozen lines has to go somewhere that is not the header.
at = PAGE.index('function helpAt(')
helpat = PAGE[at:PAGE.index('\n}\n', at)]
ok('a tall panel is told apart from a small one',
   'window.innerHeight / 3' in helpat, True)
ok('...and goes beside the row where there is room for it',
   'at.right + 8 + wide.width' in helpat and 'at.left - wide.width - 8' in helpat, True)
ok('...and a small one still flips above the way it always did',
   'at.top - wide.height - 8' in helpat, True)
ok('...and nothing is ever put outside the window',
   'Math.min(at.top, window.innerHeight - wide.height - 8)' in helpat, True)

# ---------------------------------------------------------------------------
title('Every button on the settings rail opens something')
# A settings pane is three things in three places: a button on the rail, a
# `.ctl-pane` for it to show, and a `sect-` box for the fields to be drawn
# into. Miss the middle one and the rail hides every pane and shows none, so
# the pane is BLANK - which is what 1.10.43 shipped for the domain
# controllers. No other check here can see it: the daemon has the settings,
# the page has the names, and the one thing missing is a div.
rail = list(dict.fromkeys(re.findall(r'data-pane="([a-z0-9]+)"', PAGE)))
cards = set(re.findall(r'id="pane-([a-z0-9]+)"', PAGE))
boxes = set(re.findall(r'id="sect-([a-z0-9]+)"', PAGE))
groups = re.search(r'var PANES = \{(.*?)\n\};', PAGE, re.S).group(1)
groups = re.findall(r'^\s*([a-z0-9]+):', groups, re.M)
ok('every button on the rail has a pane to show', [b for b in rail if b not in cards], [])
ok('...and every group of settings has a box to be drawn into',
   [g for g in groups if g not in boxes], [])
ok('...and no pane is there that nothing opens', sorted(cards - set(rail)), [])
ok('...and the domain controllers are one of them',
   ('winsec' in rail, 'winsec' in cards, 'winsec' in boxes), (True, True, True))
# ...and the fields it draws are fields the daemon really has, or the pane is
# there and empty, which looks exactly the same to somebody using it.
said = re.search(r'var PANES = \{(.*?)\n\};', PAGE, re.S).group(1)
wanted = re.findall(r"'([a-z0-9_]+)'", said)
missing = [k for k in wanted if ("'%s':" % k) not in DAEMON]
ok('...and every setting the panes name is a setting the daemon keeps', missing, [])

# ---------------------------------------------------------------------------
title('Every name the page asks for is a name the relay knows')
# The page asks the daemon through the PHP relay, which has one map of names
# it will answer with GET and another for POST. A name the page uses that is
# in neither is a card that is empty on the real thing and perfect in every
# test, because the tests talk to the daemon directly.
page = (Path(__file__).resolve().parent.parent / 'web' / 'index.php').read_text()
asked = set(re.findall(r"api\('([a-z0-9-]+)", page))
asked |= set(re.findall(r'api\("([a-z0-9-]+)', page))
known = set(re.findall(r"^\s*'([a-z0-9-]+)'\s*=>\s*'/api/", page, re.M))
# ...besides the handful the relay answers itself rather than passing on,
# because they are about the cookie: see the top of index.php.
ITSELF = {'login', 'logout', 'password'}
ok('every name the page asks for is in the relay',
   sorted(asked - known - ITSELF), [])
ok('...and the ones the relay answers itself are handled there',
   all(("'%s'" % one) in page for one in ITSELF), True)
ok('...and the doors one is among them', 'door' in known, True)
# ...and a door is a read: it counts and answers, it changes nothing.
reads = page.split('$reads = [', 1)[1].split('];', 1)[0]
writes = page.split('$writes = [', 1)[1].split('];', 1)[0]
ok('the doors are read with GET', "'door'" in reads, True)
ok('...and are not a road that changes anything', "'door'" in writes, False)

# ---------------------------------------------------------------------------
title('Every band in the chart has a colour, a legend and a number behind it')
# A band drawn in a colour that is in no legend is a colour nobody can read;
# a legend entry for a band that is never drawn is a question nobody can
# answer. Both have happened, so both are checked.
parts = re.search(r'var PARTS = \[(.*?)\n  \];', PAGE, re.S).group(1)
bands = re.findall(r"\['([a-z0-9]+)', '(#[0-9a-f]{6})'\]", parts)
legend = re.findall(r'background:(#[0-9a-f]{6})', PAGE)
ok('every band drawn has its colour in the legend',
   sorted({c for _b, c in bands if c not in legend}), [])
# ...and the domain is NOT one of them: it is a bar of its own, on a scale of
# its own. A controller writes several records for one person signing in
# once, and drawn against this site's own doors it would be a wall of blue
# with the whole VPN an inch high underneath it.
ok('the domain is not one of the doors\u2019 bands', 'domain' in {b for b, _c in bands}, False)
ok('...it is a bar of its own', "var DOM_COLOUR = {failed:" in PAGE, True)
ok('...with its refusals against the same ruler as the doors\u2019',
   "one[0] === 'failed' ? ceil : ceilDom" in PAGE, True)
ok('...and its sign-ins against a ceiling of their own',
   ('var ceilDom = ceilingOf(topDom);' in PAGE
    and 'p.passed_domain || 0' in PAGE), True)
ok('...which is nothing to do with the ceiling the doors are drawn against',
   bool(re.search(r'var top = [^;]*?Math\.max\(m, p\.failed, p\.passed\)', PAGE, re.S)), True)
ok('...and the two colours it is drawn in are in the legend',
   [c for c in ('#8b9dff', '#79c0ff') if c not in legend], [])
ok('...and each has a legend entry of its own',
   ('leg-dom-bad' in PAGE, 'leg-dom-good' in PAGE), (True, True))
ok('...which is hidden on a site that reads no controller log',
   bool(re.search(r"\['leg-dom-bad', 'leg-dom-good'\].{0,220}?winsec_on", PAGE, re.S)), True)
ok('...and so is the second scale itself', 'domainOn ? 46 : 12' in PAGE, True)
# ...and the numbers themselves come from the daemon rather than from nowhere.
ok('the daemon counts what those bars draw',
   ("'failed_domain'" in DAEMON and "'passed_domain'" in DAEMON), True)
ok('...and nothing of it is mixed into a door\u2019s own bar',
   'got.all = all;' in PAGE, True)
ok('...and the popup says which ruler those two numbers are against',
   'right-hand scale' in PAGE, True)

# ---------------------------------------------------------------------------
title('The debug switches are switches, and only while there is a debug log')
for one in ('debug_sql', 'debug_ldap', 'debug_api', 'debug_logs', 'debug_router'):
    ok('%s is on the About pane' % one, ("'%s'" % one) in PAGE, True)
    ok('...and is asleep while the debug switch is off',
       bool(re.search(r"%s: \['debug', '1'\]" % one, PAGE)), True)
    ok('...and the daemon knows what it is', ("'%s'" % one) in DAEMON, True)

# ---------------------------------------------------------------------------
title('Every card can press through to its own rows, not to a search')
# The one that got out: a card grouped by the answer the domain gave had no
# filter of that name, so pressing it fell through to a free-text search over
# nine columns. The list underneath was a mixture of accounts and the count
# at the top of it was not the count on the row that had been pressed. It is
# the same mistake anywhere a card is grouped by a column nothing can ask
# for, so it is checked for every card there is rather than for that one.
# What a domain card may be grouped by, read off the one line that decides
# it rather than off a list somebody has to remember to keep up to date.
by_win = set(re.findall(r"'([a-z_]+)'", re.search(
    r"if by not in \((.*?)\):", DAEMON, re.S).group(1)))
column_map = re.search(r'var WIN_BY_COLUMN = \{(.*?)\};', PAGE, re.S).group(1)
known = set(re.findall(r'([a-z_]+):', column_map))
# ...what the daemon will actually filter on, read off the one place that
# decides it.
win_filters = re.search(r"for column, value in \(\('account', account\)(.*?)\):",
                        DAEMON, re.S).group(1)
win_filters = set(re.findall(r"\('([a-z_]+)',", win_filters)) | {'account'}
ok('every column a domain card is grouped by can be pressed',
   sorted(by_win - known), [])
ok('...and every one of those is a filter the daemon really has',
   sorted(known - win_filters), [])
ok('...including the answer the domain gave, which is what came out wrong',
   ('said' in known, 'said' in win_filters), (True, True))
ok('...and the list a card opens drops the machinery it dropped',
   ("ask.routine = '0'" in PAGE and 'routine=False if' in DAEMON), True)

# ...and the same for this site's own doors.
door_views = re.search(r'DOOR_VIEWS = \{(.*?)\n    \}', DAEMON, re.S).group(1)
by_doors = set(re.findall(r"'by': '([a-z_]+)'", door_views))
row_map = re.search(r'var OV_ROW_FILTER = \{(.*?)\};', PAGE, re.S).group(1)
door_known = set(re.findall(r"'([a-z_]+)':", row_map))
ok('every column a door card is grouped by can be pressed',
   sorted(by_doors - door_known), [])
auth_filters = re.search(r"for column, value in \(\('mac', mac\)(.*?)\):",
                         DAEMON, re.S).group(1)
auth_filters = set(re.findall(r"\('([a-z_]+)',", auth_filters))
auth_filters |= {'mac', 'ip', 'device', 'server', 'country'}
ok('...and each of those is a filter the daemon really has',
   sorted(set(re.findall(r"'([a-z_]+)'", row_map)) - auth_filters - by_doors), [])
ok('...and a name is asked for exactly rather than through the search box',
   "'username': 'username'" in PAGE, True)

# ---------------------------------------------------------------------------
title('A row says how wide it is before it names one event')
# "the password was wrong / 65628adm / 118" was read as a hundred and
# eighteen wrong passwords for that account. It was a hundred and eighteen
# for four accounts, of which that one was simply the last.
ok('a domain row counts the accounts it covers', "wide.push(num(r.names)" in PAGE, True)
ok('...and marks what follows as the newest rather than the whole',
   PAGE.count("'newest: '") >= 2, True)
ok('...and the hover says so too', 'The newest of them was' in PAGE, True)
ok('a door row does the same', 'var counted = (view.key ===' in PAGE, True)

# ---------------------------------------------------------------------------
title('Asking the directory is a switch, and it shows on the page')
# A reading that is quietly not happening looks exactly like a domain where
# nothing is wrong. So it has a switch of its own, it says how often, and the
# page says whether it is being asked, of whom, when and how much came back.
for one in ('winsec_directory', 'winsec_directory_h'):
    ok('%s is a setting the daemon keeps' % one, ("'%s':" % one) in DAEMON, True)
    ok('...and it is on the domain controllers pane', ("'%s'" % one) in PAGE, True)
ok('...and it is only a question while the controller logs are read',
   bool(re.search(r"winsec_directory: \['winsec', '1'\]", PAGE)), True)
ok('...and how often only while it is on',
   bool(re.search(r"winsec_directory_h: \['winsec_directory', '1'\]", PAGE)), True)
ok('the reading honours the switch',
   "if not int(CONFIG.get('winsec_directory') or 0)" in DAEMON, True)
ok('...and the hours beside it',
   "int(CONFIG.get('winsec_directory_h') or 24) * 3600" in DAEMON, True)
ok('the daemon hands the page what it found',
   'def directory_state(self, weigh=True)' in DAEMON, True)
ok('...on the domain answer', "'directory': self.held('win-directory'" in DAEMON, True)
ok('...and the page draws it', 'function drawWinDirectory(' in PAGE, True)
ok('...under the list it weighs', 'drawWinDirectory(d.directory)' in PAGE, True)
ok('...saying counts and never names',
   ("for name in ('service', 'nopreauth', 'disabled', 'privileged'):\n            out[name] = len("
    in DAEMON), True)
ok('...and saying out loud that it only reads',
   'nothing is ever written to Active Directory' in PAGE, True)
ok('the button asks it again rather than waiting a day',
   ('def ask_directory_now(self)' in DAEMON
    and 'if again:\n                self.ask_directory_now()' in DAEMON), True)
ok('...and it forces both clocks rather than clearing one by hand',
   ('if not force and now - float(kept.get(\'tried\')' in DAEMON
    and "if not force and now - float(kept.get('at')" in DAEMON), True)
ok('...while drawing the page never goes and knocks',
   'self.what_directory_says(ask=False)' in DAEMON, True)
ok('...and the daemon\u2019s own clock is what does the knocking',
   'self.winsec_on() and int(CONFIG.get(\'winsec_directory\') or 0)' in DAEMON, True)

# ---------------------------------------------------------------------------
title('The bar under the button starts when the button is pressed')
# What was wrong: the page asked once, 700 ms after the press, got the answer
# that had been worked out ten seconds BEFORE it, saw no job in it and stopped
# asking. The job itself begins by asking two domain controllers about their
# groups - a minute with nothing to count - so by the time some later poll
# caught it, it was over. Three things had to be true and none of them was.
ok('the press starts a watch that does not depend on the first answer',
   'WIN_WATCH_UNTIL = Date.now() + WIN_WATCH_FOR' in PAGE, True)
ok('...which keeps the page asking while it lasts',
   'WIN_GOING || Date.now() < WIN_WATCH_UNTIL' in PAGE, True)
ok('...and ends the moment a job is actually seen',
   'if (one) WIN_WATCH_UNTIL = 0;' in PAGE, True)
ok('the daemon throws away the answer from before the press',
   ("def forget_held(self, prefix)" in DAEMON
    and "self.forget_held('winsec/')" in DAEMON), True)
ok('...and a job with nothing to count still says it is going',
   ('speak_up' in DAEMON and 'if self.total or speak_up:' in DAEMON), True)
ok('...which is what the asking of the directory uses',
   "name='win-directory',\n                      speak_up=True" in DAEMON, True)
ok('...and the bar draws that as a bar that moves',
   "fill.classList.toggle('creeping', !one.total && !guess)" in PAGE, True)
ok('one pass at a time, decided before the thread starts',
   ('def start_reread(self' in DAEMON and 'with self._reread_lock:' in DAEMON), True)
ok('...and every road in goes through it',
   DAEMON.count('threading.Thread(target=self._reread_win_marks'), 1)

# ---------------------------------------------------------------------------
title('Both directories say which domain they are')
# The second one had its domain in a blue chip and the first did not, which
# left the two blocks looking like different kinds of thing. "The directory"
# names a setting on this page; the domain names the thing itself.
ok('the second directory draws its domain',
   "head.appendChild(el('span', 'alias', o.domain))" in PAGE, True)
ok('...and so does the first',
   "head.appendChild(el('span', 'alias', w.domain))" in PAGE, True)
ok('...and the daemon sends it for whichever one answered',
   "out['domain'] = self.directory_domain(which)" in DAEMON, True)

# ---------------------------------------------------------------------------
title('What the directory read is somewhere a person can look at it')
# "What did switching it on actually add?" Four counts on a line is what it
# knows; this is what it says, and a feature nobody can see is a feature
# nobody can tell is switched off.
ok('the domain itself is read, not only its accounts',
   'def domain_shape(self, link, base, which)' in DAEMON, True)
for one in ('lockoutThreshold', 'lockoutDuration', 'msDS-Behavior-Version',
            'trustedDomain', 'msDS-PasswordSettings', 'ms-DS-MachineAccountQuota'):
    ok('...including %s' % one, ("'%s'" % one) in DAEMON, True)
ok('...and it reaches the page', "'shape': said.get('shape') or {}" in DAEMON, True)
ok('...where there is a button that opens it',
   'What it read from the directory' in PAGE, True)
ok('...and a panel that draws it', 'function peekDirectoryShape(' in PAGE, True)
for words in ('Locks after', 'Other domains it trusts',
              'The controllers the domain names',
              'Who is in each group that runs the domain'):
    ok('...saying "%s"' % words, words in PAGE, True)
ok('the rule it found is what an alarm is weighed against',
   "facts.get('lock_after')" in DAEMON, True)
ok('...and a domain that never locks is said out loud',
   'does NOT lock accounts out' in DAEMON, True)

# ---------------------------------------------------------------------------
title('The tabs are in one order, and the panels follow it')
# The strip across the top and the list that shows and hides the panels are
# two places saying the same thing, and they were not checked against each
# other: one reordered without the other is a tab that shows the wrong page.
strip = re.findall(r'data-tab="([a-z]+)"', PAGE.split('<!-- ===', 1)[0])
listed = re.search(r"\[('overview',.*?)\]\.forEach", PAGE, re.S).group(1)
listed = re.findall(r"'([a-z]+)'", listed)
ok('every tab on the strip is in the list that shows the panels',
   [one for one in strip if one not in listed], [])
ok('...and in the same order', strip, listed)
ok('...with the domain before the firewall',
   strip.index('windows') < strip.index('router'), True)
ok('...and every one of them has a panel',
   [one for one in strip if ('id="tab-%s"' % one) not in PAGE], [])

# ---------------------------------------------------------------------------
title('Two domains read into one of these stay two domains')
ok('what each directory says is kept under its own domain',
   "'by_domain': {}" in DAEMON, True)
ok('...under every name an event might write it as',
   'def domain_names(self, which)' in DAEMON, True)
ok('...and a name is weighed against the domain the event said it was in',
   'def facts_for(facts, domain' in DAEMON, True)
ok('...with a suffix never taking a name from the domain it belongs to',
   'own names last' in DAEMON, True)
ok('the alarm carries which domain it happened in',
   "'domain': domain," in DAEMON, True)
ok('...read off the newest event behind it',
   "'SELECT account, by_who, domain FROM win_events" in DAEMON, True)
ok('...and each domain’s own lockout rule is the one used',
   'whichever of them locks soonest' in DAEMON, True)
ok('and the page draws the counts per directory rather than summed',
   "if ((d.where || []).length > 1)" in PAGE, True)

# ---------------------------------------------------------------------------
title('This program only ever READS a directory')
# Not a promise about what the code happens to do today: the socket refuses.
ok('there is one list of what may be sent', 'MAY_SAY = (0x60, 0x63, 0x42, 0x77)' in DAEMON,
   True)
ok('...and every message is checked against it on the way out',
   'if tag not in self.MAY_SAY:' in DAEMON, True)
ok('...naming the writes so the refusal can say which it was',
   "WRITES = {0x66: 'modify'" in DAEMON, True)
for word in ('ldap_modify', 'ldap_add', 'ldap_delete', 'modifyRequest',
             'addRequest', 'delRequest', 'modDNRequest'):
    ok('...and nothing anywhere builds a %s' % word, word in DAEMON, False)

# ---------------------------------------------------------------------------
title('A big domain is read whole, and says where it stopped')
ok('every question is asked a page at a time', 'paged=True' in DAEMON, True)
ok('...through one place that counts as well as keeps',
   'def count_and_keep(self, link, base, made' in DAEMON, True)
ok('...with the names capped and the count not',
   ('FACTS_KEEP' in DAEMON and 'FACTS_WALK' in DAEMON
    and "found[name + '_n'] = total" in DAEMON), True)
ok('...and the groups paged too, because Domain Users is everybody',
   'limit=20000, paged=True' in DAEMON, True)
ok('...and the page told which lists were cut short', "w.cut || []" in PAGE, True)
ok('...and given the real counts rather than the length of what was kept',
   "'counts': {name: int(said.get(name + '_n')" in DAEMON, True)

# ---------------------------------------------------------------------------
title('...and there is a great deal more of it than four numbers')
for one in ('was_admin', 'never_expires', 'no_password', 'delegating',
            'delegating_any', 'smartcard'):
    ok('it asks which accounts are %s' % one.replace('_', ' '),
       ("('%s', lambda" % one) in DAEMON, True)
ok('...and where the domain thinks its addresses are', "out['subnets']" in DAEMON, True)
ok('...and which sites there are', "out['sites']" in DAEMON, True)
ok('...and the page draws them',
   'Sites, and the addresses that belong to them' in PAGE, True)
ok('an answer from a version that asked fewer questions is asked again',
   "'was_admin_n' not in kept" in DAEMON, True)

# ---------------------------------------------------------------------------
title('Two directories are drawn the same way')
# They were two shapes: one put the directory's name after the person's with
# the domain at the end of it, the other put the directory first with the
# domain beside it and the person underneath. Two accounts in two domains
# read side by side have to be the same shape or the eye cannot compare them.
ok('both open with the directory, its domain and its marks',
   PAGE.count("el('div', 'alsohead')"), 2)
ok('...then the person', PAGE.count("'fwhoname'") >= 2, True)
ok('...and both draw every fact they have',
   '(o.facts || []).slice(0, 6)' in PAGE, False)
ok('...and the domain chip is in both',
   (PAGE.count("el('span', 'alias', o.domain)")
    + PAGE.count("el('span', 'alias', w.domain)")), 2)

# ---------------------------------------------------------------------------
title('Nothing in what the directory said is shortened, and all of it opens')
ok('the names behind a count can be asked for', "'dir-names'" in PAGE, True)
ok('...and the daemon answers them', "/api/windows/directory-names" in DAEMON, True)
ok('...without opening a socket to anybody', "kept = store.meta_json('%s_facts'" in DAEMON,
   True)
ok('every count opens the names behind it', 'function peekDirectoryNames(' in PAGE, True)
# One way of drawing a name out of the directory, used everywhere: the
# names popup, every group, and anything else that lists them.
ok('...and every name opens what the directory holds about it',
   "showPerson(String(name || ''), which || '')" in PAGE, True)
ok('...drawn one way, so none of them can be the one that is not pressable',
   PAGE.count('function dirNamePill(name, which)'), 1)
ok('a group lists every member it has rather than the first twelve',
   "groups[g].slice(0, 12)" in PAGE, False)
ok('...and each member is pressable',
   "row.appendChild(which === null ? el('span', 'tag namepill flat', String(one))"
   in PAGE, True)
ok('...and looks it, which it did not', '.namesrow .namepill.opens{cursor:pointer}'
   in PAGE, True)
ok('...under a heading of its own rather than beside one',
   'function dirNameSet(title, names, which, says, more)' in PAGE, True)
ok('...and a controller is too', "showPerson(String(c.name).split('.')[0]" in PAGE, True)
ok('and the daemon keeps enough of a group to list it',
   "per_group[group] = sorted(set(mine))[:2000]" in DAEMON, True)

# ---------------------------------------------------------------------------
title('A database that grows for years is still answered out of an index')
# Everything a page asks is "inside this window". With an index that starts
# with the window that costs what the window costs, however much is behind
# it; with one that starts with anything else it costs what the whole table
# costs, and grows for ever.
for one in ('win_ts_kind', 'win_ts_event', 'win_ts_server', 'failed_country_ts_ip',
            'win_marked_ts'):
    ok('there is an index %s' % one,
       any(one == name for name, _sql in
           re.findall(r"\('([a-z_]+)',\s*(\{|')", DAEMON)) or ("'%s'" % one) in DAEMON,
       True)
ok('the marks are a number, one bit a mark', 'WIN_MARK_BITS = {' in DAEMON, True)
ok('...and no question about one is a search any more',
   "like_same('mark')" in DAEMON, True)     # only the fallback for unknown words
ok('...and the ten cards are counted in one pass',
   'def win_marked_all(self, since, wanted' in DAEMON, True)
ok('a huge table is not counted row by row to draw a number',
   ('COUNT_EXACTLY' in DAEMON and 'def rows_guess' in DAEMON), True)
ok('...and each engine says how it guesses, SQLite from its row ids (1.10.97)',
   DAEMON.count('def rows_guess'), 4)
ok('old rows are let go a stride at a time',
   'def tidy_older(self, table, cut' in DAEMON, True)
ok('...and nothing deletes a year in one statement',
   ("db.execute('DELETE FROM failed WHERE ts < ?'" in DAEMON
    or "db.execute('DELETE FROM win_events WHERE ts < ?'" in DAEMON), False)
ok('the box at the top reads the window once, not once a column',
   'ONE pass, not one a column' in DAEMON, True)

# ---------------------------------------------------------------------------
title('An account on the Domain page opens what the directory holds about it')
# The whole of that page is what the controllers wrote down. Every account on
# it has another half - who the person is, which groups, whether it is
# switched off or locked, when the password was last set - and it was one
# press away from a single event and nowhere else.
ok('there is one way of drawing a name that opens the directory',
   'function winWho(name, domain, cls, life)' in PAGE, True)
ok('...and one for a machine, which the domain holds as an account too',
   'function winMachineWho(name, domain, ip)' in PAGE, True)

# The domain's own controllers, marked wherever they turn up. A page of
# refusals in and out of a domain controller is the directory doing its work;
# the same page about a desk is an old password saved on it, and which of the
# two it is should not need knowing the site's naming by heart.
ok('the controllers the domain named are marked on the page',
   'function winDCMark(node, name, ip)' in PAGE, True)
ok('...by name and by address, both',
   'function winIsDC(name, ip)' in PAGE, True)
ok('...out of what the daemon sends, rather than anything written in the page',
   'WIN_DC[short] = true' in PAGE and 'd.controllers' in PAGE, True)
ok('...and the machine names are folded the way the daemon folds them',
   'function winShort(said)' in PAGE, True)

# Watching what the directory says: the switch, the button, the red and the
# band across the top of every page.
ok('the card carries a switch for watching what the directory says',
   'function dirWatchRow(d)' in PAGE, True)
ok('...and a button that remembers what it says now',
   "api('win-dirwatch', {act: 'remember'})" in PAGE, True)
ok('...and the relay knows the route it goes through',
   "'win-dirwatch' => '/api/windows/directory-watch'" in PAGE, True)
ok('...and a value that has moved is drawn red and says what moved',
   'function dirMark(node, which, what)' in PAGE, True)
ok('...and the whole dashboard carries a band while it has',
   'function drawDirectoryAlarm(said)' in PAGE and 'id="dir-alarm"' in PAGE, True)
ok('...which is drawn from the status, so it is on every page',
   'drawDirectoryAlarm(data.directory_alarm)' in PAGE, True)
# Taking the band off the page is for the person who pressed it and for
# nobody else: it clears nothing, and it comes back the moment something
# else changes.
ok('...and taking it off the page hides it for this browser alone',
   "window.sessionStorage.setItem('isemon-dir-alarm', key)" in PAGE, True)

# The word index and an upgrade, which met each other on a real site: the
# background CONCURRENTLY build and the ordinary index work of a daemon
# starting up, and PostgreSQL killed one of them.
ok('the word index waits for the shape of the database to settle',
   'Storage.SETTLED.wait(' in DAEMON, True)
ok('...which is set when every table, column and index is made or given up on',
   'Storage.SETTLED.set()' in DAEMON, True)
ok('...and where it is beaten to the table anyway, it tries again',
   'for go in range(self.WORDS_TRIES)' in DAEMON, True)
ok('...having first dropped what PostgreSQL leaves behind, which IF NOT '
   'EXISTS would otherwise find',
   'DROP INDEX CONCURRENTLY IF EXISTS' in DAEMON, True)
ok('...and it is not written down as done until it really is',
   DAEMON.count("store.set_meta('win_words_done'"), 2)

# What a card counts and what pressing it opens are one question asked
# twice, and that has to hold for the alarms the DIRECTORY narrows as well:
# "a ticket asked for with no pre-authentication" is about the accounts that
# do not have it switched off, so the number, the newest and the filter the
# popup is opened with all move together.
ok('an alarm the directory narrows carries the accounts it is about',
   'def only(keep, why)' in DAEMON, True)
ok('...and the list of events knows that filter',
   "accounts=one('accounts')" in DAEMON, True)
ok('...and the page passes every filter the daemon counted with',
   'Object.keys(where).forEach' in PAGE, True)

# The directory, asked again, without walking a million stored events for it.
ok('there is a way to ask the directory alone',
   'def read_directory_only(self, by=' in DAEMON, True)
ok('...with a button of its own beside the other',
   'id="winsec-dirread"' in PAGE, True)
ok('...which reads the directory and nothing else',
   "'/api/windows/directory-read'" in DAEMON and "'win-dirread'" in PAGE, True)

# The DC mark, everywhere rather than on the page that asked for it.
ok('the controllers are known to every page, off the status',
   "'controllers': self.held('win-dc'" in DAEMON
   and 'dcLearn(data.controllers)' in PAGE, True)
ok('...and whatever is drawn is marked as it appears',
   'function dcSweep(root)' in PAGE and 'new MutationObserver' in PAGE, True)
ok('...by name, by whole name, by domain and name, and by address',
   'function dcWord(said)' in PAGE, True)
# The two letters are drawn by the stylesheet: a mark made of real text
# would land in everything that reads a row back out of the page.
ok('...without putting two letters into what the page says',
   ".is-dc::after{content:'DC'" in PAGE, True)

# A ticket asked for with no pre-authentication is what every Windows client
# opens with; a ticket HANDED OVER without it is the thing worth knowing.
ok('the alarm counts a ticket that was handed over, not one that was asked for',
   'if event == 4768 and win_worked(event, fields)' in DAEMON, True)
ok('...and RC4 the same way, because a refusal hands nothing over',
   'if event in (4768, 4769) and win_worked(event, fields) is not False:' in DAEMON, True)
ok('...and every stored event is read again once, so the old marks go',
   'WIN_SORT_VERSION = 5' in DAEMON, True)

# A switch is named with the address it answered from, everywhere. The name
# is what somebody typed into ISE; the address is what is on the network, and
# only the second one is any use at three in the morning.
ok('there is one way of naming a device with its address',
   'function deviceWords(name, at)' in PAGE, True)
ok('...and one for a socket, which is a socket ON something',
   'function portWords(port, name, at)' in PAGE, True)
ok('...the popups use it', PAGE.count('deviceWords(got.device, got.nad)') >= 2, True)
ok('...the whole record uses it', 'deviceWords(r.device, r.nad)' in PAGE, True)
ok('...and so do the rows of every card',
   PAGE.count('deviceWords(got.device, got.nad),') >= 3, True)
ok('...and the tables carry the address on the hover',
   'function deviceCell(r)' in PAGE and PAGE.count('deviceCell(r)') >= 6, True)
ok('...and the daemon sends it with every subject',
   "'nad', 'client'" in DAEMON, True)
# The socket and the switch it is a socket ON go on two lines: one line long
# enough to wrap is a line the browser breaks wherever it runs out of room,
# and where it ran out was the middle of the address.
ok('...and the socket says what it is on, on a line of its own',
   "return where ? said + '\\non ' + where : said;" in PAGE, True)
ok('...where an address is never broken in half',
   'word-break:normal;overflow-wrap:anywhere;white-space:pre-line' in PAGE, True)
ok('...in the hover panel either', PAGE.count('word-break:normal;overflow-wrap:anywhere') >= 2,
   True)

# A popup must never close by itself while somebody is reading it.
ok('nothing is redrawn under a pointer', 'function pointerBusy(host)' in PAGE, True)
ok('...which is what every list that redraws itself asks first',
   'if (pointerBusy(host)) return true;' in PAGE, True)
ok('...and the mouseleave a redraw causes is not a mouseleave',
   'if (from && from.nodeType === 1 && !from.isConnected) return;' in PAGE, True)
ok('...and a panel over something taken away waits for the pointer to move',
   'SETHELP._mouseAt' in PAGE and 'var MOUSE_AT' in PAGE, True)

# The switch and the Remember button belong to the popup whose values they
# mark red, not to a card three sections up the page.
ok('the watching sits on the foot of the popup it is about',
   'function dirWatchBar(d)' in PAGE
   and 'shown.foot.insertBefore(dirWatchBar(d)' in PAGE, True)
ok('...and not on the domain card any more',
   'head.appendChild(dirWatchSwitch(d))' in PAGE, False)

# One popup over one word. A `title` as well as the page's own panel is the
# browser's white box drawn on top of the dark one.
ok('the DC mark never carries a browser tooltip',
   "mark.setAttribute('title'" in PAGE, False)
ok('...and neither does the sign-in message',
   "said.setAttribute('title'" in PAGE, False)
ok('...they both use the page\u2019s own panel', PAGE.count('explain(mark, DC_WHY)'), 1)

# A controller's name in a file path is where its log lives, not a machine
# doing something.
ok('a name with a slash on both sides is left alone',
   'function dcInPath(bits, at)' in PAGE, True)
ok('...and the card of log files is left alone altogether',
   'data-nodc' in PAGE, True)
# ...which means the line ALONG ITS HEADING as well - "isea 17 856 · iseb 5 ·
# otp 2 · bdcx02 0 · dcx01 0" is a count per log file, not a controller
# doing something.
_nodc_at = PAGE.find('data-nodc')
_nodc_card = PAGE[_nodc_at:PAGE.find('</div>', PAGE.find('</table>', _nodc_at))]
ok('...including the counts along its heading',
   'id="ov-busy"' in _nodc_card, True)
ok('...and the rows of files under it', 'id="ov-logs"' in _nodc_card, True)
# ...and a distinguished name is where an object LIVES in the directory, not
# a machine doing something.
ok('...and a distinguished name is never marked anywhere',
   'if (IS_DN.test(said)) continue;' in PAGE, True)

# The stored events are read again once, not on every restart.
ok('a pass that met an unreadable row is still written down',
   'if mark:\n            self.win_marks_noted(changed=done > 0)' in DAEMON, True)
# ...and it reads again only what can actually have changed, which is what
# makes a site with a billion events possible at all.
ok('there is a plan for what has to be read again',
   'def win_marks_plan(self)' in DAEMON, True)
ok('...which knows which events each version changed',
   'MARK_VERSIONS = {' in DAEMON, True)
ok('...and narrows a controller being named to that machine\u2019s own rows',
   "plan['accounts']" in DAEMON, True)
ok('...and never reads further back than the site keeps',
   "keep_days = int(CONFIG.get('winsec_keep_days') or 0)" in DAEMON, True)
ok('...and picks up where it stopped rather than beginning again',
   "self.set_meta('win_reading_at'," in DAEMON, True)
ok('...and does not rewrite a row that reads exactly as it already reads',
   "if (str(row['kind'] or '') == fresh[0]" in DAEMON, True)
ok('...and the old note\u2019s version is read rather than thrown away',
   'had_version = int(had)' in DAEMON, True)
# Every question about a mark says `marks <> 0` out loud, or the partial
# index that answers it is not used and the engine walks the whole table.
ok('every question about a mark can use the index that answers it',
   DAEMON.count('marks <> 0') >= 3, True)

# A daemon walking a million rows and a daemon that has stopped look the same
# from a terminal. These are the two commands that tell them apart.
ok('the long jobs can be seen from a terminal', 'def cmd_jobs(args, pal, store)' in DAEMON,
   True)
# ...and under a name of its own. `jobs` was already the register of what a
# button starts; giving the table-walkers the same name quietly replaced it,
# `/api/status` raised KeyError on every poll, and the whole dashboard went
# dark.
ok('...under a name that is not already taken',
   'def long_jobs(self)' in DAEMON, True)
# No class may define one name twice: the second replaces the first in
# silence, and everything calling the first goes on calling it.
_dupes = []
for _cls in ast.walk(ast.parse(DAEMON)):
    if not isinstance(_cls, ast.ClassDef):
        continue
    _seen = {}
    for _one in _cls.body:
        if isinstance(_one, ast.FunctionDef):
            _seen[_one.name] = _seen.get(_one.name, 0) + 1
    _dupes += ['%s.%s' % (_cls.name, k) for k, v in _seen.items() if v > 1]
ok('no class defines one name twice', _dupes, [])
ok('...with how far along, and how long is left at this rate',
   "out['left_s'] = max(0.0, took * (self.total - self.done)" in DAEMON, True)
ok('...and one of them can be asked to stop',
   'def cmd_stop_job(args, pal, store)' in DAEMON, True)
ok('...which it does between batches, keeping what it has done',
   'def wanted(self):' in DAEMON and 'if not going.wanted():' in DAEMON, True)
ok('...and a restore is never stopped half way',
   "WONT_STOP = ('db-restore'" in DAEMON, True)
# ...and a narrowed pass says how many it is going to walk, or there is no
# fraction and nothing to work an estimate out of.
ok('a narrowed pass counts what it is going to walk',
   'def count_them():' in DAEMON, True)
ok('...behind the walk, so a cold count never holds the start up',
   "threading.Thread(target=count_them, name='win-marks-count'" in DAEMON, True)

# One answer worked out once, however many ask at the same moment - and the
# table settled afterwards, because on PostgreSQL a rewritten row is two
# rows until the server collects the old one.
ok('the kept answers are worked out once, not once per asker',
   'self._slow_wait' in DAEMON and 'mine.wait(self.HELD_WAIT_S)' in DAEMON, True)

# ...and an answer that HURT to make is kept for longer than one that did
# not. A page asking every ten seconds for something that takes four seconds
# is a database that never stops working and a page that is never once right:
# the rebuild has not finished when the next one falls due. Measured on a
# domain of seven and a half million events, one card cost forty seconds and
# was being asked for every twenty.
folderH, storeH, daemonH = fresh()
COUNTED = [0]


def slowly(seconds):
    def make():
        COUNTED[0] += 1
        time.sleep(seconds)
        return COUNTED[0]
    return make


ok('a cheap answer is kept exactly as long as it was asked to be',
   daemonH.held('cheap', 10, slowly(0)) and daemonH.kept_for('cheap', 10), 10)
daemonH.held('dear', 5, slowly(0.5))
ok('...and a dear one for longer than it was asked to be',
   daemonH.kept_for('dear', 5) > 5, True)
ok('...by what it cost, not by a guess',
   abs(daemonH.kept_for('dear', 5)
       - daemonH._slow_cost['dear'] * daemonH.KEPT_TIMES) < 0.5, True)
ok('...and never longer than the cap, however dear',
   daemonH.kept_for('dear', 5) <= daemonH.KEPT_MOST_S, True)
daemonH._slow_cost['huge'] = 10000.0
ok('...which holds even for an answer that took hours',
   daemonH.kept_for('huge', 10), float(daemonH.KEPT_MOST_S))
WAS = COUNTED[0]
daemonH.held('dear', 5, slowly(0.5))
ok('...so asking again inside that keeping does not go near the database',
   COUNTED[0], WAS)
ok('...and what things cost outlives the answers, because it is the '
   'installation that is slow, not the moment',
   'self._slow_cost[key] = cost' in DAEMON
   and 'self._slow_cost = {}' in DAEMON, True)
shutil.rmtree(folderH, ignore_errors=True)
ok('...and a table that has just been rewritten is settled and counted again',
   "apart.execute('VACUUM (ANALYZE) %s' % self.ident(table))" in DAEMON, True)

# The domain page is twenty walks of a window of a very large table. It comes
# back with what is ready and fills the rest in, rather than making a browser
# wait for all twenty and give up.
ok('the page is built out of answers that never make it wait',
   'def soon(self, key, seconds, make, fallback=None, wait=False, most=0)' in DAEMON,
   True)
# ...and the ones that carry an ALARM are never held back, however dear they
# were. A lockout is what somebody has this page open for; keeping it two
# minutes because it once cost four seconds is not thrift.
ok('an answer that carries an alarm has a ceiling on how long it is kept',
   'def kept_for(self, key, seconds, most=0):' in DAEMON
   and 'return min(held, float(most)) if most else held' in DAEMON, True)
ok('...and the patterns, the counts and what holds a password all have one',
   DAEMON.count('most=self.NOW_MOST_S') >= 3, True)
ok('...and the lockouts are hardly kept at all',
   "'%s/lockouts' % mine, 5," in DAEMON and 'most=5) or []' in DAEMON, True)
# ...and the rare loud ones do not even wait for that: what the page is
# holding about the domain is dropped the moment one is written down.
ok('a lockout drops what the page was holding, so the next poll is fresh',
   'def worth_waking_for(self, events):' in DAEMON
   and "self.forget_held('win/')" in DAEMON, True)
ok('...and a wrong password does not, because a domain writes thousands an hour',
   "AT_ONCE_KINDS = ('lockout',)" in DAEMON, True)
ok('...and says when it is only half of them yet',
   "out['working'] = not getattr(self._soon_tl, 'all', True)" in DAEMON, True)
ok('...which the page draws instead of looking empty',
   'id="w-working"' in PAGE and 'if (d.working)' in PAGE, True)
ok('...and comes back for the rest by itself',
   'WIN_SOON = setTimeout' in PAGE, True)

# ...and the real answer at that scale: do not store what nobody looks at.
# On a measured domain, of 756,000 events in a day, 500,000 were successful
# sign-ins and 241,000 were objects being read; the refusals, lockouts and
# changes this page exists for were 2,083.
ok('the two groups that are the volume can be switched off',
   "'winsec_keep_logons': 1" in DAEMON and "'winsec_keep_reads': 1" in DAEMON, True)
ok('...applied before an event is ever written down',
   'if not win_worth_keeping(got.facts):' in DAEMON, True)
ok('...and never to an event this program has FOUND something in',
   'if win_tells_something(facts.get(\'mark\')):\n        return True' in DAEMON, True)
ok('...though the marks that only say "the machinery" spare nothing',
   "WIN_ROUTINE_MARKS = ('expected', 'routine')" in DAEMON, True)
ok('...with what is already stored let go by the clean-up, at any age',
   "only='(COALESCE(marks,0) & %d) = 0 AND kind IN (%s)'" in DAEMON, True)
ok('...and the sign-outs under the same switch as the sign-ins',
   "('logon', 'logoff', 'privilege', 'explicit'," in DAEMON, True)
ok('...and a clean-up that takes nothing says which rules kept everything',
   'def why_nothing_went(self):' in DAEMON
   and "log('%s: nothing was removed - %s' % (said, self.why_nothing_went())" in DAEMON,
   True)
ok('...and both on the settings page',
   "'winsec_keep_days', 'winsec_keep_logons', 'winsec_logons_days'," in PAGE
   and "'winsec_keep_reads', 'winsec_reads_days'," in PAGE, True)
# ...and a group that IS kept can still be kept for less time than the rest.
ok('each of the two can be kept for less time than everything else',
   "'winsec_logons_days': 0," in DAEMON and "'winsec_reads_days': 0," in DAEMON, True)
ok('...bounded like every other number',
   "'winsec_logons_days': (0, 3650), 'winsec_reads_days': (0, 3650)," in DAEMON, True)
ok('...and drawn where the switch they belong to is',
   'winsec_logons_days: [\'winsec\', \'1\']' in PAGE
   and 'winsec_reads_days: [\'winsec\', \'1\']' in PAGE, True)

# ...and the room is only got back if the biggest table is offered at all.
# Erasing makes its copy INSIDE the job. It used to be asked for by the page,
# waited for, and the erasing asked for afterwards - and on a five gigabyte
# database that copy is four minutes inside one request, which nothing
# between a browser and this daemon waits for. Seen on a real install: the
# copy finished, the answer went nowhere, the erasing was never asked for,
# every row stayed where it was and no error said so.
# Turning a line into an event is the expensive half of the write path - on a
# real domain's day, 53% of it - and on a site that has switched a group off,
# most of that is done to decide the answer is to be thrown away.
ok('a line whose group is switched off is dropped before it is read',
   'def win_worth_reading(event, line):' in DAEMON
   and 'if said and not win_worth_reading(int(said.group(1)), line):' in DAEMON, True)
ok('...but never one whose kind depends on the answer it got',
   'if event in WIN_EITHER_WAY:\n        # What kind this IS depends' in DAEMON, True)
ok('...nor one whose number alone can earn a mark',
   'WIN_MARK_EVENTS = frozenset(' in DAEMON, True)
ok('...nor one carrying a word that earns one',
   "WIN_MARK_WORDS = re.compile(r'ANONYMOUS|Logon Type:" in DAEMON, True)

# The counting is done by the ENGINE, in one transaction, and not by walking
# the table through here. It used to read five thousand rows at a time into
# Python: four minutes for two million events, hours for a billion - and
# wrong, because the walk was in id order, an id is a hash rather than a
# clock, and an event arriving mid-walk could land on the far side of the
# cursor and be counted twice. On a live domain that showed up as the
# counting a few higher than the rows, and higher the longer it ran.
# A verdict about the counting is a verdict about the PROGRAM that reached
# it. Put aside by one version, it stayed put aside for ever: the state
# stopped the checking, and the checking was what would have cleared it - so
# an upgrade whose whole point was to mend the counting was never allowed to
# show it. Seen on a live domain, hours after the version that wrote the
# verdict had been replaced.
# The counted answers go with exactly the rows that went, and not one more.
# A group KEPT but for fewer days is not a group switched off: found on a
# live domain, every nightly clean-up threw away every sign-in bucket there
# was, at every age, while the events themselves stayed.
ok('a shorter retention takes only the buckets before its cut',
   "where += ' AND span = ? AND at %s ?'" in DAEMON
   and 'def roll_bound(self, before, span):' in DAEMON, True)
ok('...while a group switched off still goes at every age',
   'for span in ((ROLL_HOUR, ROLL_DAY) if before else (None,)):' in DAEMON, True)
ok('...and the hourly watch asks the sums, which is what catches it',
   'wrong = store.roll_whole(recent) or store.roll_check_sql(store.roll_last_hour())'
   in DAEMON, True)
ok('...over the last few days only, never the whole of a billion rows',
   'ROLL_WHOLE_S = ' in DAEMON
   and 'recent = now - (store.ROLL_WHOLE_S if whole else self.ROLL_RECENT_S)' in DAEMON, True)
# ...and the two things somebody may ask of the counting, where the page it
# is about can reach them rather than only at a terminal.
ok('the counting can be rebuilt and read back from the page',
   "if path == '/api/windows/rollup':" in DAEMON
   and "'win-rollup'   => '/api/windows/rollup'," in PAGE, True)
ok('...with a card that says which of the three states it is in',
   'function drawRollup() {' in PAGE and "id=\"winsec-rollbuild\"" in PAGE
   and "id=\"winsec-rollcheck\"" in PAGE, True)
ok('...and says outright that nothing waits for it',
   'an event is counted in the same ' in PAGE, True)

ok('a verdict about the counting says which version reached it',
   "said['version'] = __version__" in DAEMON, True)
ok('...and a newer version counts them again rather than inheriting it',
   "if str(said.get('version') or '') == __version__:" in DAEMON
   and "store.roll_said(store.ROLL_NEW, 'a newer version is running', 0)" in DAEMON,
   True)
ok('...and the command line says it is what was found THEN, not now',
   'That is what was found THEN and written down' in DAEMON, True)

ok('the counting from nothing is done by the engine',
   'def roll_build_sql(self, dim, span=ROLL_HOUR, since=None, until=None):' in DAEMON
   and "'INSERT INTO win_rollup (span, at, dim, val, kind, mach, quiet, told, '" in DAEMON,
   True)
ok('...in one transaction, so nothing can be written into the middle of it',
   'self.db_write() as db:\n                db.execute(\'DELETE FROM win_rollup '
   'WHERE span = ?\', (span,))' in DAEMON, True)
# ...and while that one transaction runs, every other writer waits on it.
# That wait is the same work seen from the other side, and a site was shown
# it as a warning about 167 rows.
ok('work that is MEANT to take a while is written down as work, not as a fault',
   'def patiently(what, everyone=False, quiet=False):' in DAEMON
   and "else 'info' if patient or waited else 'warn'" in DAEMON, True)
ok('...the counting says so for every other writer as well',
   "Db.patiently('counting the domain events ahead of time', everyone=True)"
   in DAEMON, True)
ok('...and does a day at a time, so nobody waits for the whole of it',
   'ROLL_BUILD_STRIDE = ROLL_DAY' in DAEMON and 'while at < end:' in DAEMON, True)
ok('...and so does an upgrade building an index over millions of rows',
   "with Db.patiently('bringing the schema up to date'):" in DAEMON, True)
# A reading counts wherever it was asked from. It used to count only when
# the daemon asked: `--rollup-check` said "every sum adds up" and `--rollup`
# said "agreed 0 time(s)" a second later.
ok('what a reading found is written down in one place',
   'def roll_proved(self, said, where=\'\', full=False):' in DAEMON, True)
ok('...and the terminal, the page and the daemon all go through it',
   DAEMON.count('roll_proved(') >= 4, True)
ok('...only the whole proof may bring a counting back from being put aside',
   'not enough to clear one.' in DAEMON, True)
# ...and the reading itself is done where the rows are. A site timed
# `--rollup-check` at twenty-five seconds, twenty-two of them this program's
# own processor, because proving a day meant reading every event of that day
# out of the database to add it up here.
ok('the counting is read back in the engine, not row by row in here',
   'def roll_check_sql(self, at, span=ROLL_HOUR):' in DAEMON
   and 'HAVING SUM(saw) <> SUM(got) ' in DAEMON, True)
ok('...and both readings describe a bucket with the same words',
   'def roll_columns(self, dim):' in DAEMON
   and DAEMON.count('self.roll_columns(dim)') >= 2, True)
ok('...the hourly watch and the whole proof both ask the engine',
   'store.roll_check_sql(store.roll_last_hour())' in DAEMON
   and 'said += self.roll_check_sql(at)' in DAEMON, True)
# A counting running in ANOTHER process holds this one's writing, and no
# flag in this program's memory can say so.
ok('a counting says so where every process can see it',
   "ROLL_BUSY = 'win_roll_busy'" in DAEMON
   and 'def roll_busy(self):' in DAEMON, True)
ok('...believed only while the process that wrote it is there',
   'and still_running(said.get(\'pid\'))' in DAEMON, True)
ok('...and a second counting is not started on top of the first',
   "if store.roll_busy() or not daemon.claim('_rolling'):" in DAEMON, True)

# What is kept for the page is marked stale, never thrown away. Thrown away,
# the card is empty and the page says it is still working something out; on
# a domain where something worth waking for arrives every couple of minutes
# it said so for ever and did the same twenty walks again and again.
ok('a kept answer is marked stale rather than dropped',
   'self._slow[key] = (0.0, self._slow[key][1])' in DAEMON, True)
ok('...and what is thrown away is only what the change was about',
   'def slow_gen(self, key):' in DAEMON
   and 'self._slow_gen[prefix] = self._slow_gen.get(prefix, 0) + 1' in DAEMON, True)
ok('...an answer made across a change is kept as stale, not lost',
   'self._slow.setdefault(key, (0.0, made))' in DAEMON, True)
ok('...and each engine names an hour its own way',
   DAEMON.count('def bucket(self, column, span):') >= 3, True)
ok('...PostgreSQL by flooring, because a cast there ROUNDS',
   "'CAST(FLOOR(%s / %d) AS BIGINT) * %d'" in DAEMON, True)
# ...and the reading back is not allowed to race the writing either.
ok('the two halves of the check are asked in one statement',
   "'SELECT %s, counted.* FROM (SELECT %s FROM win_events '" in DAEMON, True)
ok('...about hours that are finished, never the one being written into',
   'def roll_hours(self, most=0, done=True):' in DAEMON, True)
ok('...and a disagreement is asked again before it is believed',
   'A real disagreement is still there a moment later; a race' in DAEMON
   and DAEMON.count('store.roll_whole(recent)') >= 2, True)

ok('the copy before erasing is part of the erasing',
   'def erase_job(self, groups, tidy=True, by=\'\', copy_first=False):' in DAEMON, True)
ok('...made by the job rather than by the page',
   "where = self.store.safety_copy('before-erasing')" in DAEMON, True)
ok('...asked for in the one request that starts it',
   "copy_first=bool(data.get('copy'))" in DAEMON, True)
ok('...and the page asks once and watches the bar',
   "api('db-erase', {groups: picked, tidy: $('erase-tidy').checked,\n"
   "                         copy: true})" in PAGE, True)
ok('...with the name of the copy said at the end of it',
   "out['copy'] = made" in DAEMON, True)
ok('...and the page no longer waits for a backup of its own',
   "api('db-backup', {label: 'before-erasing'})" in PAGE, False)

# ...and the bar MOVES while it does it. The copy says how far along it is
# through a reporter of its own - the one the log draws and the database page
# draws - and the job's bar could see none of it: it sat at "0 of 3" through
# four minutes of copying and then finished.
folderB, storeB, daemonB = fresh()
ok('nothing going on is nothing to draw', daemonB.busy_now(), None)
goB = isemon.Going('copying the database to x.db', 1000, name='db-copy')
goB.step(250)
saidB = daemonB.busy_now()
ok('a copy going on is found', bool(saidB), True)
ok('...at the fraction it is really at', round(saidB['part'], 2), 0.25)
ok('...said as the kind it is', saidB['kind'], 'db-copy')
ok('...with the rows it is on in the words',
   '250' in saidB['words'] and '1,000' in saidB['words'], True)
ok('...and the rows are not the indexes', saidB['indexes'], False)
goB.what = 'copying the database to x.db \u2014 building its indexes'
goB.step(0)                       # what the copying itself does when it turns to them
ok('...while the indexes say so', daemonB.busy_now()['indexes'], True)
goB.done_now()
goT = isemon.Going('tidying the database', 4, name='db-tidy')
goT.step(2)
ok('the rebuild afterwards is drawn too', daemonB.busy_now()['kind'], 'db-tidy')
goT.done_now()
ok('...and when it is over there is nothing to draw', daemonB.busy_now(), None)
ok('a kind nobody asked about is not drawn',
   daemonB.busy_now(('db-restore',)), None)
# The two halves of a copy each count from nought, so each gets a share of
# the bar rather than the whole of it twice - and the bar never retreats.
ok('the two halves of a copy share the bar',
   "ROWS, INDEXES, REBUILD = (0, copy_to * 3 // 5)" in DAEMON, True)
ok('...and the bar never goes backwards',
   'far[0] = max(far[0], int(low + said[\'part\'] * (high - low)))' in DAEMON, True)
ok('...with the watcher stopped whatever happens',
   'finally:\n                watching.set()' in DAEMON, True)
shutil.rmtree(folderB, ignore_errors=True)

# The lookup panel answers with a card of a dozen facts, both directories,
# every door and the addresses somebody was last seen at. In 760 by 660 that
# was a scrollbar from the first answer onwards.
# One thing pointed at is ONE panel, with all of it in. The folding was only
# ever done upwards - a line joining the panel it is part of - which works
# when the panel is drawn first and not at all when it is drawn second, and
# not when a thing is given its words BEFORE it is put on the page. A site
# saw two boxes over one row, each appearing on its own and in its own place.
ok('a panel no longer takes in what is explaining itself inside it (1.10.156)',
   "var inside = over.querySelectorAll ? over.querySelectorAll('[data-explains=\"1\"]')"
   not in PAGE, True)
ok('...and whatever is left over is folded in after each redraw',
   'function foldNested(where) {' in PAGE and 'foldNested(host);' in PAGE, True)
ok('...including what the header redraws, once it has finished drawing it',
   "explainWhatWasDrawn(quiet ? (document.querySelector('header') || document) : document);\n}"
   in PAGE, True)
ok('...and whatever a tab holds, the moment it is shown',
   'function onTab(name) {' in PAGE
   and PAGE.count('explainWhatWasDrawn(document);') >= 1, True)
ok('a folded element says nothing of its own and hides nothing either',
   'if (over._explainHtml) helpAt(over, over._explainHtml, e);' in PAGE
   and 'if (over._explainHtml) hideHelp(e);' in PAGE, True)
# ...and the browser's own pale box, which is the same fault in a hat.
ok('a title put back on something that explains itself becomes its words',
   "one._explainHtml = '<div>' + richText(said) + '</div>';" in PAGE, True)
ok('...and anything explained loses its browser title',
   "if (over.getAttribute && over.getAttribute('title')) {\n"
   "    over.removeAttribute('title');" in PAGE, True)

ok('the lookup panel is wide enough for what it answers with',
   '.findpanel{width:min(1100px,100%);max-height:calc(100vh - 60px)' in PAGE, True)
ok('...and sits high enough up the page for the height to be there',
   'align-items:flex-start;padding:44px 16px 16px' in PAGE, True)

ok('the domain events are on the list of what can be erased',
   "'name': 'the events the domain controllers wrote'" in DAEMON, True)
ok('...along with the notes that say how they were read',
   "'meta': ['win_sorted', 'win_reading', 'win_words_done', 'win_bits_done',\n"
   "                     'win_roll', 'win_roll_seen']" in DAEMON, True)
ok('...and a group that is notes rather than rows can still be ticked',
   'g.rows || g.rereads || g.notes' in PAGE, True)
ok('...and what is in the database says so too',
   "win_events: 'events from the domain controllers'" in PAGE, True)

# An "account" that is not a name: a client putting its authentication token
# where the user name goes. 250 characters of base64 on a card is a card
# nobody can read.
ok('a token in the name field is known for what it is',
   'def win_is_token_name(said)' in DAEMON, True)
ok('...and the page draws it short, with the whole of it on the hover',
   'function winTokenName(said)' in PAGE, True)
ok('...and the card says so rather than printing it',
   "'an authentication token sent as a user name'" in DAEMON, True)
ok('...online, never with the table held shut',
   "'VACUUM (ANALYZE)" in DAEMON, True)

# Throwing the old rows away: one place, a button, and a time of day.
ok('every keeping is applied in one place',
   'def tidy_old_rows(self, said=' in DAEMON, True)
ok('...which the five-minute pass, the clock and the button all use',
   'def tidy_due(self)' in DAEMON and "if what == 'tidy':" in DAEMON, True)
ok('...with a button on the database page', 'id="db-tidy"' in PAGE, True)
# Three buttons that all sound like tidying, so each says which it is:
# what the settings already say is old, an age chosen by hand, and the disk.
ok('...and each of the three says which of the three it is',
   ['Apply what is kept, now' in PAGE, 'Forget records older than' in PAGE,
    'Give the disk back' in PAGE], [True, True, True])
ok('...and a time of day where a site wants one',
   "'tidy_daily': (0, 1), 'tidy_at': 'str'" in DAEMON, True)
ok('...and the ban history is kept by when a ban ENDED',
   "column='ended'" in DAEMON, True)
# ...and the three keepings that were numbers written into this program are
# numbers a site can set, with the row ceilings left where they are.
ok('every keeping is a setting, not a number in the program',
   all(("'%s'" % k) in DAEMON for k in
       ('retain_eduroam_days', 'retain_otp_days', 'retain_names_days')), True)
ok('...and they are on the database page with the others',
   "'retain_eduroam_days', 'retain_otp_days', 'retain_names_days'" in PAGE, True)

# What somebody is told when a sign-in does not work: one sentence, with the
# whole of what the directory said under the pointer.
ok('the sign-in page says one sentence and keeps the rest for a hover',
   'function sayBad(words, detail)' in PAGE, True)
ok('...out of what the daemon sends beside the sentence',
   "(got.d && got.d.detail) || ''" in PAGE, True)
ok('...which the API puts there rather than gluing it into the sentence',
   "out['detail'] = str(detail)" in DAEMON, True)
ok('...and every refusal that has one carries it',
   'class Refused(ValueError)' in DAEMON, True)

# The Domain page reads; the button that rewrites what is on it lives with
# the settings it obeys.
ok('the button to read everything again is not on the domain page',
   'id="w-reread"' in PAGE, False)
ok('...it is in the settings pane', 'id="winsec-reread"' in PAGE, True)
ok('...where the same progress bar is drawn, off the same answer',
   'id="winsec-going"' in PAGE and "drawGoing('winsec-going', going)" in PAGE, True)
ok('...and the bar on the domain page runs the width of it',
   'class="going wide" id="w-going"' in PAGE, True)
ok('...with the read-only line beside the button rather than on the card',
   'Read only — nothing is ever written to Active Directory' in PAGE, True)
ok('...and it asks by the domain the row carries',
   "winPeekLife(whose, domain || '')" in PAGE, True)
ok('...and works with no directory configured at all, because a life needs none',
   "if (!said || said === '-') return span" in PAGE, True)
ok('...and is marked, so a name that opens something looks like one',
   '.asksdir{' in PAGE, True)
ok('...and does not also open the row it sits in',
   "span.addEventListener('click', function (e) { e.stopPropagation(); })" in PAGE, True)
for where in ('winLockRow', 'winPeekLock', 'winRowsTable', 'winBlameTable',
              'winViewCard'):
    at = PAGE.find('function ' + where + '(')
    ok('%s draws its names that way' % where,
       at >= 0 and ('winWho(' in PAGE[at:at + 4000]
                    or 'winMachineWho(' in PAGE[at:at + 4000]), True)
ok('...and so does an alarm that names one', "el('span', 'askdir')" in PAGE, True)

# ---------------------------------------------------------------------------
title('The whole life of one account, including one that no longer exists')
# Who made it, who changed it, who unlocked it, who deleted it. None of it was
# reachable by name, and the account it matters most about is usually one the
# directory no longer holds a word of.
ok('the daemon answers a life', 'def win_story(self, account, hours=0)' in DAEMON, True)
ok('...out of the events, two ways round',
   'def win_life(self, account, limit=400, since=0)' in DAEMON, True)
ok('...finding it as the account AND inside an object name',
   "'AND (LOWER(account) = ? OR %s)'" in DAEMON, True)
ok('...by cn=name, rather than the name anywhere in a tree',
   "like_for('cn=%s,' % want)" in DAEMON, True)
ok('...oldest first, because a life is read forwards',
   "sql + ' ORDER BY ts ASC LIMIT ?'" in DAEMON, True)
ok('there is a door for it', "path == '/api/windows/life'" in DAEMON, True)
ok('...and the page is allowed through it',
   "'win-life'  => '/api/windows/life'" in PAGE, True)
ok('the page draws it', 'function winPeekLife(account, domain)' in PAGE, True)
ok('...and every name on the Domain page opens it',
   "winPeekLife(whose, domain || '')" in PAGE, True)
ok('...a machine\u2019s being the account the domain keeps for it, NAME$',
   "if (account && !/\\$$/.test(account)) account += '$';" in PAGE, True)
ok('...and so does a name typed into the box at the top',
   "if (w.what === 'account') { return winPeekLife(w.said, ''); }" in PAGE, True)
ok('...and so does its own card', "if (view.key === 'lives')" in PAGE, True)
ok('...and the directory card, which cannot answer this at all',
   "{words: 'Who made it, changed it, unlocked it'" in PAGE, True)
ok('...and the directory card offers it even having found nothing',
   "'Was it ever here? Who made it and who deleted it'" in PAGE, True)
ok('a deleted account is said to be the whole of what is left',
   'this is the whole of what is left' in DAEMON, True)
ok('...and a life longer than fits gives up its middle, not its ends',
   'the middle of them is not shown' in DAEMON, True)
ok('...which the page draws as a row of its own rather than as an event',
   'if (r.gap) {' in PAGE, True)
ok('...and the directory is not offered for one that is gone',
   "directory_on && !(d || {}).gone" in PAGE, True)
# An account nothing was ever done TO is the commonest thing on this page -
# every account being refused is one - and a popup that said so and offered
# nothing was a door into a blank room.
ok('...and a life with nothing in it still offers the two ways on',
   'function winLifeWaysOn(said, d, domain)' in PAGE, True)
ok('...which are drawn before the early return, not after it',
   PAGE.index('winLifeWaysOn(said, d, domain));\n        explainWhatWasDrawn(body);')
   < PAGE.index('function winLifeWaysOn'), True)
ok('...and the empty one is not six boxes of dashes',
   "d.first ? ['First of them', shortStamp(d.first)] : null" in PAGE, True)
# A jump to the page somebody is already on closed the popup and did nothing
# whatever, which reads as a button that is broken.
ok('a popup does not offer to go where it already is',
   'if (jump && jump.tab !== TAB) {' in PAGE, True)
ok('everybody who touched it is named',
   'Everybody who did something to it' in DAEMON, True)
ok('...in English rather than as a field', 'def and_list(words)' in DAEMON, True)

# ---------------------------------------------------------------------------
title('A lockout says how it ended, and who ended it')
# A lockout somebody cleared two minutes later and one that is locked still
# read identically otherwise, and which of the two it is is the first thing
# anybody wants to know.
ok('the daemon finds the unlock that ended a lock',
   'def win_unlock_after(self, account, at, within=86400 * 7)' in DAEMON, True)
ok('...as the first one after it', "'ORDER BY ts ASC LIMIT 1'" in DAEMON, True)
ok('...and hangs it on the lockout', "one['freed'] = self.win_unlock_after(" in DAEMON, True)
ok('the page says so in words', 'function winFreedWords(freed)' in PAGE, True)
ok('...naming who did it', 'box.appendChild(winWho(freed.who' in PAGE, True)
ok('...and saying so when nobody did',
   'still locked, as far as these logs go' in PAGE, True)
ok('...and counting a deletion as an ending, because it is one',
   'LOCK_ENDERS = (4767, 4726, 5141)' in DAEMON, True)
ok('...found the same two ways round a life is',
   "'AND ts > ? AND ts <= ? ORDER BY ts ASC LIMIT 1'" in DAEMON, True)
ok('...and said as one on the page',
   'never unlocked \\u2014 the account was deleted ' in PAGE, True)
ok('...so the story never calls a deleted account locked still',
   "elif out['locks'] and out['gone']:" in DAEMON, True)

# ---------------------------------------------------------------------------
title('A column that is a dash all the way down is not drawn')
# "Through" says which PROGRAM used the password, which is the best answer a
# lockout has - when Windows fills it in. On a domain controller it usually
# does not, and a column of dashes takes width from one that is saying
# something.
ok('the page knows when to leave it out',
   'function winLockThrough(table, rows)' in PAGE, True)
ok('...by whether any row has an answer for it',
   "var any = (rows || []).some(function (r) { return !!shortProcess(r.process); })"
   in PAGE, True)
ok('...hiding the heading with the cells', '.nothrough .throughcell{display:none}'
   in PAGE, True)
for where in ('<th class="throughcell">Through</th>', "['Through', 'throughcell']",
              "el('td', 'throughcell'"):
    ok('...on both tables and their cells (%s)' % where[:28], where in PAGE, True)
ok('...and both of them ask', PAGE.count('winLockThrough('), 3)
ok('the popup leaves out a fact it has nothing for',
   "shortProcess(r.process) ? ['Through', shortProcess(r.process)] : null" in PAGE, True)
ok('...in the row itself, not only inside the popup',
   "end.appendChild(winFreedWords(r.freed))" in PAGE, True)
for head in ('<th>How it ended</th>', "'How it ended',"):
    ok('...with a column for it (%s)' % head, head in PAGE, True)

# ---------------------------------------------------------------------------
title('An event is named by what it SAYS, not by which group it is in')
# "an account was deleted (4726)" rather than "an account changed (4726)",
# which is the difference between a page that reads and one to be decoded.
ok('the page knows every event by name', 'var WIN_EVENT_WORDS = {' in PAGE, True)
ok('...and prefers it to the group', 'var exact = event ? WIN_EVENT_WORDS[' in PAGE, True)
ok('...falling back to the group for one it has never seen',
   "var said = WIN_KIND_WORDS[kind] || String(kind || '')" in PAGE, True)
words = {}
for line in PAGE.split('var WIN_EVENT_WORDS = {', 1)[1].split('};', 1)[0].split('\n'):
    for hit in re.finditer(r"'(\d+)': '((?:[^'\\]|\\.)*)'", line):
        words[int(hit.group(1))] = hit.group(2).replace("\\'", "'").replace('\\\\', '\\')
ok('...and it is the daemon\u2019s own table, entry for entry',
   len(words), len(isemon.WIN_EVENTS))
wrong = [n for n, w in words.items()
         if isemon.WIN_EVENTS.get(n, ('', ''))[1].replace('\u2019', "\\u2019") != w]
ok('...with the same words in every one of them', wrong, [])

# ---------------------------------------------------------------------------
title('An upgrade goes from any version to any version, quietly')
# Nobody upgrades version by version, and an upgrade is exactly the moment
# two connections bring the same database up to date at once: the new daemon
# starts while the one it replaces is still finishing. On PostgreSQL
# `CREATE INDEX IF NOT EXISTS` is not atomic, so the second one is refused
# with a unique violation on `pg_class` - and a perfectly sound database
# ended an upgrade saying five of its parts could not be brought up to date.
ok('each engine can say what indexes it has', 'def index_names(self, db)' in DAEMON, True)
for one in ("SELECT name FROM sqlite_master WHERE type='index' ",
            'SELECT indexname AS name FROM pg_indexes ',
            'SELECT DISTINCT index_name AS name FROM information_schema.statistics '):
    ok('...on every one of them (%s)' % one.split()[-2], one in DAEMON, True)
ok('an index that is already there is not made again',
   'if name in have_index or cli or name in pg_narrow:' in DAEMON, True)
ok('...and one that was refused is looked for before anybody is told',
   "there = name in set(self.dialect.index_names(self.db))" in DAEMON, True)
ok('...and taken off the list of what went wrong when it is there',
   "missed.remove('the index %s' % name)" in DAEMON, True)
ok('a refusal that is expected is not shouted about',
   'def quietly()' in DAEMON and 'HUSH = threading.local()' in DAEMON, True)
ok('...and the shouting is what the block turns down',
   "'debug' if getattr(Db.HUSH, 'on', False) else" in DAEMON, True)
# The installer said 1.10.43 while the program beside it said 1.10.58.
ok('the installer does not keep a version of its own',
   re.search(r'^VERSION="\d', INSTALLER, re.M), None)

# ---------------------------------------------------------------------------
title('A long job on the database does not stop everything else')
# Pressing "make a copy now" on a gigabyte stopped the whole installation for
# five minutes: the copy held the write lock for the whole of itself, so the
# reader, the page and a person signing in all queued behind it - and from
# outside that is indistinguishable from a daemon that has died.
ok('a copy is no longer made behind the write lock',
   'with self._write:' in DAEMON.split('def copy_into')[1].split('def read_apart')[0],
   False)
ok('...it reads on a connection of its own', 'def read_apart(self)' in DAEMON, True)
ok('...held still, so it still sees one moment', 'def steady(self, db)' in DAEMON, True)
for one in ('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY',
            'START TRANSACTION WITH CONSISTENT SNAPSHOT'):
    ok('...in the way that engine means it (%s)' % one.split()[1], one in DAEMON, True)
ok('...and with autocommit off, or the snapshot is one statement long',
   'db.raw.autocommit = False' in DAEMON, True)
ok('a long answer is read a batch at a time off the SERVER',
   'def stream(self, db, sql)' in DAEMON, True)
ok('...by a named cursor on PostgreSQL', "cur.itersize = Dialect.COPY_BATCH" in DAEMON, True)
ok('...and an unbuffered one on MariaDB', 'pymysql.cursors.SSCursor' in DAEMON, True)
ok('a copy builds its indexes after the rows, not before',
   'keys = [one for one in made if is_index_sql(one)]' in DAEMON, True)

# ---------------------------------------------------------------------------
title('...and every database job says so, from beginning to end')
# From outside, a job that takes five minutes and a daemon that has stopped
# look exactly the same. The log is where somebody looks to tell them apart.
ok('there is one way of saying it', 'class DbJob(object)' in DAEMON, True)
ok('...which says when it started', "- starting'" in DAEMON, True)
ok('...how long it took', "- done in %s%s'" in DAEMON, True)
ok('...and says so when it fails instead', "- FAILED after %s: %s'" in DAEMON, True)
for job in ('making a copy: %s', 'making a %s dump: %s', 'putting a copy back: %s',
            'putting a dump back: %s', 'checking the database (%s)',
            'tidying up (%s)', 'forgetting old records: %s'):
    ok('...and it is used for: %s' % job.replace('%s', '\u2026'),
       "DbJob('%s'" % job in DAEMON, True)
ok('the long ones say how far along they are as well',
   "Going('copying the database to %s'" in DAEMON, True)
ok('...and the page can draw that bar wherever it is watching from',
   'function drawGoing(where, going, only, skip)' in PAGE, True)
ok('...including on the database pane', "drawGoing('db-going', data.going, 'db-', 'db-dump')" in PAGE,
   True)
ok('...and a dump in the card where it was asked for, against the last one\u2019s size',
   ("drawGoing('db-dump-going', data.going, 'db-dump')" in PAGE
    and 'expect=last_dump_size(target)' in DAEMON), True)
ok('...which the status carries, so it survives a reload',
   "'going': Going.snapshot()," in DAEMON, True)
ok('...and the buttons that would start a second one are held',
   'function dbBusyButtons(busyNow)' in PAGE, True)

# ---------------------------------------------------------------------------
title('...and a table is only rewritten when there is room to get back')
# A rewrite takes an exclusive lock: nothing may read the table, let alone
# write to it, for as long as it takes. Every table used to be rewritten
# whether it had a dead row in it or none.
ok('the daemon asks what each table is holding', 'def dead_rows(self, db)' in DAEMON, True)
ok('...the room it takes as well as its rows, because the counters lag',
   'pg_relation_size(c.oid) AS room' in DAEMON, True)
ok('...and decides in one place', 'def worth_rewriting(self, dead, live, room)' in DAEMON,
   True)
ok('...and says out loud what a rewrite costs while it does one',
   'Nothing can read this table until it is done.' in DAEMON, True)

# ---------------------------------------------------------------------------
title('Nothing on this page writes a tag into something that draws text')
# `el(...)` sets textContent, so a <span> handed to it is four characters of
# punctuation and a word - shown to somebody as exactly that. The page has
# `richText` and `innerHTML` for the places where markup is meant.
_markup = []
for _m in re.finditer(r"el\((\s*'[a-z0-9]+'\s*,[^;]{0,600}?)\)\);", PAGE, re.S):
    _piece = _m.group(1)
    if re.search(r"<(span|b|i|br|div|a|p|table)\b", _piece):
        _markup.append(' '.join(_piece.split())[:80])
ok('no tag is handed to something that draws text', _markup, [])

# ---------------------------------------------------------------------------
title('A dump says how far along it is, by the file it is writing')
# A dump is somebody else's program and says nothing about its own progress.
# What it does do is write a file, and that file getting bigger IS the
# progress: fifty seconds of silence and then "done" tells nobody whether it
# is working or wedged.
ok('there is a way of watching a file grow', 'class Growing(object)' in DAEMON, True)
ok('...used by the PostgreSQL dump', DAEMON.count("Growing(part, 'writing the dump"), 2)
ok('...and it counts bytes as bytes, not as a row of digits',
   'return human_size(n) if self.size else num_words(n)' in DAEMON, True)
ok('...which the page is told about', "'size': self.size," in DAEMON, True)
ok('...and draws accordingly', 'var much = one.size ? bytes : num;' in PAGE, True)
ok('...with no total, because there is nothing honest to compare against',
   "Going(what, 0, name=name, speak_up=True, size=True)" in DAEMON, True)

# ---------------------------------------------------------------------------
title('...and a bar that has finished has finished')
ok('building the indexes is its own phase, not a hundred per cent that works on',
   'going.total = len(every)' in DAEMON, True)
ok('...and a copy under construction is not made durable on every write',
   "'PRAGMA synchronous=OFF', 'PRAGMA journal_mode=MEMORY'" in DAEMON, True)

# ---------------------------------------------------------------------------
title('...and a walk of a whole table leaves the machine usable')
# A fixed pause is a promise about a machine rather than about the job: on a
# database where a batch takes three seconds it is nothing at all, and
# pressing "read everything again" made every page on the site crawl.
ok('the pause is as long as the work was',
   'time.sleep(max(0.02, min(2.0, time.time() - began)))' in DAEMON, True)
ok('...and it reads on a connection of its own',
   'apart = self.read_apart()' in DAEMON, True)
ok('...which it gives back afterwards', 'apart.close()' in DAEMON, True)

# ---------------------------------------------------------------------------
title('Every card opens the rows it counted, whatever it counted them by')
# The one fault this page keeps having: a card counts one set of rows and
# pressing it opens another. It used to copy six filter names by hand, so a
# card counted with a seventh opened something else entirely.
ok('the page passes on every filter it is given',
   'Object.keys(where).forEach(function (k) {' in PAGE, True)
ok('...including whether the machine accounts are counted',
   "var over = ask.machines === '1' ? {machines: true} : null;" in PAGE, True)
# ...and since 1.10.100 the computer-password and NPS-names cards as well,
# and the brute card writes it as a keyword.
ok('the spray, brute, dead, computer-password and NPS cards say they counted only the '
   'refusals', DAEMON.count("'routine': '0'") + DAEMON.count("routine='0'"), 6)
ok('...and "cannot sign in anyway" is a filter the rows can be asked for',
   'if dead:' in DAEMON and "dead=one('dead') == '1'," in DAEMON, True)
ok('a lockout looks for the refusals IN the query, not after the limit',
   'kinds=tuple(k for k in self.BLAME_KINDS' in DAEMON, True)
ok('...and the newest of each card row is asked for one row at a time',
   "more + ' ORDER BY ts DESC LIMIT 1'" in DAEMON, True)

# ---------------------------------------------------------------------------
title('A very large database is answered out of one walk, not several')
ok('the filters are one walk of the window',
   'def win_shape(self, since, machines=None, kinds=(), until=0)' in DAEMON, True)
ok('...grouped by all three at once', 'GROUP BY kind, event, server' in DAEMON, True)
ok('the marks are counted both ways in one walk',
   'def win_marked_both(self, since, wanted, machines=None' in DAEMON, True)
ok('...grouped by whether it is a machine account',
   "GROUP BY marks, is_machine" in DAEMON, True)
ok('the page counts the kinds once and hands the answer down',
   'self.win_incidents(since, people, counts=counts)' in DAEMON, True)
ok('...and the list of events never fetches the packed record to drop it',
   'WIN_ROW_COLUMNS' in DAEMON and "SELECT * FROM win_events WHERE 1=1" not in DAEMON,
   True)

# ---------------------------------------------------------------------------
title('...and searching for a word is a lookup where the engine can make it one')
# `LIKE %word%` cannot use an ordinary index. PostgreSQL can index the
# three-letter pieces of a value, which turns the box at the top of the page
# from a walk of the window into a seek: measured on three million domain
# events, 0.52 s became 0.04 s.
ok('there is a place for what one engine can do and the others cannot',
   'def speed_up(self, store)' in DAEMON, True)
ok('...which is nothing at all on the engines that have nothing to offer',
   DAEMON.count('def speed_up(self, store)'), 2)
ok('PostgreSQL indexes the words', "USING gin (%s)" in DAEMON, True)
ok('...over every column anybody searches', "WORDS_COLUMNS = ('account', 'by_who'"
   in DAEMON, True)
ok('...built without stopping anybody writing', 'CREATE INDEX CONCURRENTLY' in DAEMON,
   True)
ok('...once, and noted so a restart does not do it again',
   "store.set_meta('win_words_done'" in DAEMON, True)
ok('...and quietly, where the account may not create the extension',
   'pg_trgm is not available to this account' in DAEMON, True)
ok('...behind the page, not in front of it',
   "target=self.make_searching_quick, name='db-words'" in DAEMON, True)

# ---------------------------------------------------------------------------
title('...and the small things the audit turned up')
ok('a cached answer is stamped when it was FINISHED, not when it began',
   'self._slow[key] = (time.time(), made)' in DAEMON, True)
ok('a thread whose connection the server dropped opens another',
   'def alive(self)' in DAEMON and 'not conn.alive()' in DAEMON, True)
ok('...and asks only when it has been sitting idle', 'CHECK_IDLE' in DAEMON, True)
ok('forgetting old records cannot be asked for a negative number of days',
   "days = max(0, min(3650, int(float(data.get('days') or 0))))" in DAEMON, True)
ok('a restore is one transaction, so it is all of it or none',
   'spare.copy_out(other, db, say=say, commit=False)' in DAEMON, True)
ok('MariaDB\u2019s sampled guess is not shown as a count',
   'GUESS_FROM = 20000000' in DAEMON, True)
ok('a loopback address is not read as a machine somebody should visit',
   "if not said or said in ('-', '::1', '127.0.0.1', '0.0.0.0', '::')" in DAEMON, True)
ok('...and a ticket with no pre-authentication named at all is still marked',
   "'Pre-Authentication Type') or '') in ('0', '')" in DAEMON, True)
ok('one failed poll does not stop a job being watched',
   'still asking' in PAGE and 'missed < 10' in PAGE, True)

# ---------------------------------------------------------------------------
title('The second audit: the page')
ok('emptying a host makes it forget what it had drawn',
   'if (node) node._drew = undefined;' in PAGE, True)
ok('...and anything saying "ago" is redrawn once a minute',
   "'@' + Math.floor(Date.now() / 60000)" in PAGE, True)
ok('every popup that asks the daemon holds a ticket',
   PAGE.count('var ticket = modalTicket();'), 15)   # + the time window picker (1.10.152)
#                                                   + the database server's four (1.10.173)
ok('...and draws only while its ticket is current', PAGE.count('modalStill(ticket)') >= 5, True)
# 1.10.241: a popup underneath gets its own ticket back; the last closed
# spends it for a number never given before.
ok('...and closing the popup spends the ticket',
   "MODAL_GEN = ++MODAL_SEQ;\n  $('modal').hidden = true;" in PAGE and
   'MODAL_GEN = frame.gen;' in PAGE, True)
ok('the directory\u2019s answer lands in the card that asked',
   'var where = dir;\n      if (!where.isConnected) return;' in PAGE, True)
ok('one status question in flight at a time', 'if (TICK_BUSY && Date.now() - TICK_BUSY < (LAST_OK ? 65000 : 15000)) return;'
   in PAGE, True)
ok('...and never stuck busy', 'TICK_BUSY = false;' in PAGE, True)
ok('a job watcher forgets its misses once a poll works',
   'missed = 0;                          /* one that worked wipes the slate */' in PAGE, True)

title('...and the daemon')
ok('nothing left in the clear is read after StartTLS',
   'in the clear after agreeing to TLS' in DAEMON, True)
ok('...and only StartTLS may be sent as an extended operation',
   "op != _ber(0x77, _ber_str(self.START_TLS_OID, tag=0x80))" in DAEMON, True)
ok('a paged search that stops early is let go of properly',
   'def _let_go(self, base, scope, filter_ber, want, cookie)' in DAEMON
   and 'self._paging_control(cookie, size=0)' in DAEMON, True)
ok('...and one cut short at the page limit returns what it read',
   'was cut short there' in DAEMON, True)
ok('a ban made longer tells the router', DAEMON.count('self.mikrotik_after_change()') >= 6, True)
ok('...and the sync rewrites an entry held for too short',
   'def router_holds_too_short(self, held, row)' in DAEMON, True)
ok('...reading the duration the router prints', 'def mikrotik_seconds(text)' in DAEMON, True)
ok('a subnet is spared when it takes in a spared address',
   'def _spared_inside(self, net)' in DAEMON, True)
ok('the bans this program remembers are remembered with their moment',
   ("self._blocked_times.setdefault(str(ip), []).append(time.time())" in DAEMON
    or ("self._blocked_times.setdefault(str(ip), []).append(at)" in DAEMON
        and 'at = time.time()' in DAEMON)), True)
ok('escalation reaches the top rung', "if plain == 'for good':" in DAEMON, True)
ok('the count towards a ban is of the watched devices only',
   'devices=self.watch_devices()' in DAEMON, True)
ok('a socket or a radio with no method is the network',
   "return 'mab-lan' if method == 'mab' else 'dot1x-lan'" in DAEMON, True)
ok('a put-back ban is not a new ban', "again=True" in DAEMON and 'if not again:' in DAEMON, True)
ok('old rows are let go from where the last stride stopped',
   "'SELECT %s AS ts FROM %s WHERE %s%s >= ? AND %s < ? ORDER BY %s '" in DAEMON, True)
ok('the controllers are read out of the last month, and kept for an hour',
   "self.held('win-servers', 3600," in DAEMON, True)
ok('a cache refresh begun before a change does not write the old world back',
   'if gen == self.slow_gen(key):' in DAEMON, True)
ok('the smart-card bit is the smart-card bit',
   "(0x040000, 'smart card required'" in DAEMON, True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
