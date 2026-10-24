#!/usr/bin/env python3
"""1.10.207: the review of MikroTik, NAT, DHCP and FreeRADIUS - searching
them on every page, what their cards count, a rescan that kept leaving
FreeRADIUS out, and the popup said in the page's language.

    ./test/fixes207.py
"""
import re
import sys
import tempfile
import time
from datetime import datetime
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


page = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')
src = (HERE.parent / 'isemon.py').read_text(encoding='utf-8')
folder = Path(tempfile.mkdtemp(prefix='isemon-207-'))
isemon.STATE_DIR = folder
isemon.DB_FILE = folder / 'c.db'
isemon.LOG_DIR = folder
isemon._LOG_PATH = folder / 'c.log'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'geo': 0, 'mikrotik1': 0, 'mikrotik_sync': 0})
NOW = time.time()
STAMP = (lambda d: d.strftime('%b ') + '%2d' % d.day + d.strftime(' %H:%M:%S'))(datetime.fromtimestamp(NOW - 120))
H = '%s gw.example.net ' % STAMP


def one(msg):
    got = isemon.ros_record_from(H + msg, NOW, {}, {})
    return got.facts if got else None


print('\nMikroTik: who changed what')
for line, user, ip in (
        ('system,info filter rule changed by winbox-3.43/tcp-msg(winbox):admin@10.0.0.2/action:42 '
         '(/ip firewall filter set *5 log=yes)', 'admin', '10.0.0.2'),
        ('system,info filter rule changed by ssh:admin@10.0.0.1/action:5 (/ip firewall filter set '
         '*5)', 'admin', '10.0.0.1'),
        ('system,info device changed by winbox-3.43/tcp-msg(winbox):Admin@2001:db8::5/action:1 '
         '(/x)', 'Admin', '2001:db8::5')):
    f = one(line)
    ok('a change with the step RouterOS 7 numbers says who and from where (%s)' % ip,
       (f['user'], f['srcip'], bool(f['fields'].get('cmd'))), (user, ip, True))
f = one('system,info nat rule changed by winbox-3.43/tcp-msg(winbox):Admin@192.168.40.12/script:'
        'LOG-ENABLE-NAT/action:966 (/ip firewall nat set *AC log=yes)')
ok('...and a script\'s, which script', (f['user'], f['fields'].get('script')),
   ('Admin', 'LOG-ENABLE-NAT'))

print('\nMikroTik: what each event is called on the cards')
for line, said in (
        ('dhcp,info DHCP_LAN assigned 192.168.40.115 for 98:E2:55:F8:0C:23 Temp',
         'DHCP lease given out'),
        ('dhcp,info DHCP_LAN deassigned 192.168.40.115 for 98:E2:55:F8:0C:23',
         'DHCP lease given back'),
        ('system,info,account user Admin logged in from 192.168.40.12 via winbox', 'signed in'),
        ('system,error,critical login failure for user admin from 1.2.3.4 via ssh',
         'sign-in refused'),
        ('l2tp,ppp,error user bob authentication failed', 'VPN sign-in refused'),
        ('ssh,info publickey accepted for user: zigmon, fingerprint: SHA256:x', 'SSH key accepted'),
        ('system,info filter rule changed by ssh:admin@10.0.0.1 (/ip firewall filter set *5)',
         'configuration changed')):
    f = one(line)
    ok('%s' % said, f['fields'].get('logdesc'), said)
dims = dict(isemon.Storage.fw_dims(one('dhcp,info DHCP_LAN assigned 192.168.40.115 for '
                                       '98:E2:55:F8:0C:23 Temp')))
ok('...so a lease is counted by those words, not by its address and MAC', dims.get('event'),
   'DHCP lease given out')

print('\nMikroTik: what is counted where')
nat = one('firewall,info nat-masquerade srcnat: in:LAN out:VLAN108, connection-state:new '
          'src-mac 00:11:32:E6:94:43, proto UDP, 192.168.40.253:58007->52.46.184.236:53, len 103')
names = {d for d, _v in isemon.Storage.fw_dims(nat)}
ok('a NAT rule\'s line is counted on its page and in the hours, not under the sessions\' '
   'addresses, ports, rules and interfaces',
   (('area', 'nat') in isemon.Storage.fw_dims(nat), names & {'src', 'dst', 'port', 'service',
                                                            'policy', 'intf'}),
   (True, set()))
f = one('firewall,info prerouting: in:LAN out:(unknown 0), connection-state:new proto TCP (SYN), '
        '192.168.40.12:50000->1.1.1.1:443, len 60')
ok('a mangle line with no verdict in its prefix is only said', f['verdict'], 'info')

print('\nThe Traffic search')
row = {'_detail': {'connectionstate': 'established,snat', 'srcmac': 'BC:FC:E7:D7:86:70'},
       'msg': '', 'usr': ''}


def finds(q, r=None):
    return isemon.FwQuery(q).match(dict(r if r is not None else row))


ok('a MAC typed on its own is a MAC, however it is written, and not the field `bc`',
   (finds('BC:FC:E7:D7:86:70'), finds('bc-fc-e7-d7-86-70'), finds('bcfc.e7d7.8670'),
    'bc is' in isemon.FwQuery('bc:fc:e7:d7:86:70').says()), (True, True, True, False))
ok('...and as the value of a MAC field', finds('srcmac:bc-fc-e7-d7-86-70'), True)
ok('an IPv6 address typed on its own is a word, not the field `fe80`',
   isemon.FwQuery('fe80::1').says(), 'anything says “fe80::1”')
ok('one state of several: established,snat is snat, and established',
   (finds('connectionstate:snat'), finds('connectionstate:established'),
    finds('connectionstate:new')), (True, True, False))
ok('...quoted with commas, all of them', (finds('connectionstate:"established,snat"'),
                                           finds('connectionstate:"established,dnat"')),
   (True, False))
q = isemon.FwQuery('user:*')
ok('`user:*` is a line that names somebody, not every line',
   ("<> ''" in q.sql()[0], finds('user:*', {'usr': ''}), finds('user:*', {'usr': 'novak'})),
   (True, False, True))

print('\nThe sign-in lists\' search')
lq = isemon.ListQuery('passed', 'country:*', columns=['country', 'mac', 'ssid'])
ok('`country:*` is a row that has one', "COALESCE(country, '') <> ''" in lq.sql, True)
lq = isemon.ListQuery('passed', 'vlan:*', columns=['tkey', 'mac'], door='radius-dot1x-wifi')
ok('...and so is `vlan:*`', "<> ''" in lq.sql, True)
lq = isemon.ListQuery('passed', 'ssid:x jan 3c:52:82:44:55:66',
                      columns=['mac', 'ssid', 'username'], word_columns=['mac', 'username'],
                      door='radius-dot1x-lan')
ok('a MAC beside a field is found however it is written', '3C-52-82-44-55-66' in lq.args, True)
ok('...and on its own, by the list\'s own word search',
   "if mac_key(text) and 'mac' in columns:" in src)

print('\nFreeRADIUS: going back over it, and its clock')
isemon.CONFIG.update({'radius': 1, 'radius_zone': '', 'log_zone': ''})
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
isemon.FRAD_LEARNED['offset'].clear()
key = daemon.zone_key('radius')
isemon.FRAD_LEARNED['offset']['/a'] = 7200
isemon.FRAD_LEARNED['offset']['/b'] = 3600
ok('the key is the settings alone: an offset learned since does not move it',
   daemon.zone_key('radius'), key)
store.set_meta('zone_read_radius', '|/a=7200|')
ok('...and a key written by 1.10.204-206 still reads as the same zone',
   daemon.zone_moved('radius'), False)
store.set_meta('zone_read_radius', 'Europe/Prague||')
ok('...while a zone really changed since is still said', daemon.zone_moved('radius'), True)
here = int(datetime.fromtimestamp(NOW).astimezone().utcoffset().total_seconds())
isemon.FRAD_LEARNED['offset']['/c'] = here
isemon.FRAD_LEARNED['offset']['/d'] = here + 3600 if here < 12 * 3600 else here - 3600
ok('a server on this machine\'s own clock is read in its zone, which knows summer time',
   isemon.frad_zone_for('/c', NOW), '')
ok('...one elsewhere by the offset it showed',
   isemon.frad_zone_for('/d', NOW), isemon.frad_zone_words(isemon.FRAD_LEARNED['offset']['/d']))
isemon.CONFIG['radius_zone'] = 'Europe/Prague'
ok('...and the zone set wins over both', isemon.frad_zone_for('/d', NOW), 'Europe/Prague')
isemon.CONFIG['radius_zone'] = ''
ok('a machine put on its door has its values filed under it',
   'self.seen_note(table, dict(got))' in src)
ok('a VPN refusal behind FreeRADIUS is said as the VPN\'s',
   "('vpn', 'nps-vpn', 'radius-vpn')" in src)

print('\nGoing back over the logs, with a firewall whose sessions are not kept')
isemon.CONFIG.update({'fwlog': 1, 'fwlog_keep_allowed': 0,
                      'fwlog_sources': [{'name': 'gw', 'type': 'routeros',
                                         'path': str(folder), 'files': '*.log'}]})
said = [one_log for one_log in daemon.rescan_logs() if one_log['log'] == 'fwlog']
ok('the firewall is listed but not offered, saying why', bool(said and said[0].get('off')), True)
ok('...the page cannot tick it, and leaves it out of "all of them"',
   'if (one.off) { box.checked = false; box.disabled = true;' in page
   and '.filter(function (b) { return !b.disabled; });' in page)
isemon.CONFIG.update({'fwlog': 0, 'fwlog_keep_allowed': 1})

print('\nWhat the search box offers, page by page')
lot = [dict(isemon.ros_record_from(H + line, NOW, {}, {}).facts, fw='gw') for line in (
    'dhcp,info DHCP_LAN assigned 192.168.40.115 for 98:E2:55:F8:0C:23 Temp',
    'firewall,info accept forward: in:LAN out:SRV, connection-state:new src-mac '
    'BC:FC:E7:D7:86:70, proto TCP (SYN), 192.168.40.12:54997->192.168.42.31:22, len 52')]
store.note_fw_events(lot)
ok('the values of a field come from the page\'s own lines',
   ([v['val'] for v in store.fw_suggest('mac', '', NOW - 3600, area='dhcp')],
    [v['val'] for v in store.fw_suggest('mac', '', NOW - 3600, area='session')]),
   (['98:E2:55:F8:0C:23'], []))
ok('...and so do the names inside the lines',
   ('mac' in [f['name'] for f in store.fw_inside_fields(NOW - 3600, 'dhcp')],
    'mac' in [f['name'] for f in store.fw_inside_fields(NOW - 3600, 'session')]),
   (True, False))
ok('the page asks for its own', "tFwArg() + tAreaArg()" in page
   and "'fw-suggest&field=&hours=' + tHours() + tFwArg() + tAreaArg()" in page)
ok('the NAT and DHCP pages offer their own fields first',
   "nat: ['srcip', 'srcintf', 'dstip', 'dstintf', 'natkind', 'natsrc', 'natto', 'natdst'" in page
   and "dhcp: ['action', 'dstip', 'mac', 'host', 'server', 'fw']" in page
   and 'T_QKNOWN[n] || T_PAGE_INSIDE[n]' in page)
ok('a kind of line no longer offered where the page never holds it',
   "kinds: /^traffic(?!\\/nat$)/" in page and "kinds: /^event(?!\\/dhcp$)/" in page)
ok('the administrators\' "changes" are MikroTik\'s too',
   "config-save,added,changed,removed,'" in page)

print('\nThe popup of a line')
ok('a capitalised label is translated as the words it was made of',
   "hit = I18N.exact.get(key.charAt(0).toLowerCase() + key.slice(1));" in page)
ok('...never a single word, which may be a name', "key.indexOf(' ') > 0" in page)
ok('words and a number together: the words said, the number kept',
   'var withNum = ' in page)
ok('the title in the page\'s language', 'var title = qShown(' in page)
ok('what the firewall wrote is shown as written',
   "line.appendChild(one[2] in (r.fields || {}) ? noI18n(v) : v);" in page
   and "noI18n(el('td', 'mono t-val'" in page)
ok('a MikroTik line shows no policy number, bytes or length it never wrote',
   "(r.type !== 'traffic' || 'topics' in (r.fields || {}))" in page)
ok('the translation and a DHCP lease each a part of the popup',
   "['Translated', ['trandisp', 'natkind', 'natsrc', 'natdst'" in page
   and "['The DHCP lease', ['leased', 'leasemac', 'leasename', 'server']]" in page)
ok('which firewall wrote a NAT or DHCP line, under its time',
   "tr.firstChild.appendChild(vt.lastChild);" in page)
ok('the MikroTik choice is said in words', "'fwlog_ros_plain': {'allow': 'Let through (allow)'"
   in src)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
