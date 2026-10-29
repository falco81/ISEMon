#!/usr/bin/env python3
"""A FortiGate's own log, read the way this program reads it.

FortiOS writes one line per thing that happened, `key=value` pairs after the
syslog header: a session it let through or refused (type=traffic), what its
web filter and its SSL inspection did (type=utm), and what it says about
itself - the VPN, its administrators, its own health (type=event).

The lines below have the shape of a real site's log, with every address,
name, serial and user changed. Nothing here is ever judged and nothing here
can earn anybody a ban: the Traffic page shows what crossed the firewall.

    ./test/fortigate.py
"""
import calendar
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


def fresh(**more):
    folder = tempfile.mkdtemp(prefix='isemon-fg-')
    isemon.STATE_DIR = Path(folder)
    isemon.DB_FILE = Path(folder) / 'fg.db'
    isemon.BACKUP_DIR = Path(folder) / 'backups'
    isemon.DUMP_DIR = Path(folder) / 'dumps'
    isemon.RUN_DIR = Path(folder)
    isemon.LOG_DIR = Path(folder)
    isemon._LOG_PATH = Path(folder) / 'fg.log'
    isemon.CONFIG.update({
        'blacklist': 0, 'geo': 0, 'mikrotik_host': '', 'debug': False,
        'ise': 0, 'ise_paths': [str(Path(folder) / 'nothing')],
        'winsec': 0, 'otp': 0, 'eduroam': 0, 'tacplus': 0, 'nps': 0,
        'fwlog': 1, 'fwlog_type': 'fortigate', 'fwlog_paths': [str(Path(folder) / 'fw')],
        'fwlog_name': '*.log', 'fwlog_keep_days': 7, 'fwlog_allowed_days': 1,
        'fwlog_keep_allowed': 1, 'log_zone': '',
    })
    isemon.CONFIG.update(more)
    store = isemon.Storage(isemon.DB_FILE)
    return folder, store


NOW = int(time.time()) - 600
HEAD = 'Oct  1 07:56:02 fw.example.cz '


def line(rest, at=None, ns=1):
    at = NOW if at is None else at
    return (HEAD + 'date=2026-10-01 time=07:56:02 devname="FG-EXAMPLE" '
            'devid="FGT00EXAMPLE0001" eventtime=%d%09d tz="+0200" ' % (at, ns * 1000000) + rest)


ALLOWED = line(
    'logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" '
    'srcip=10.1.2.3 srcport=63693 srcintf="LAN" srcintfrole="lan" dstip=198.51.100.7 '
    'dstport=443 dstintf="wan1" dstintfrole="wan" srccountry="Reserved" '
    'dstcountry="Denmark" sessionid=1001 proto=6 action="client-rst" policyid=6 '
    'policytype="policy" policyname="LAN-WAN - Internet" service="HTTPS" trandisp="snat" '
    'transip=203.0.113.1 transport=41000 duration=12 sentbyte=1500 rcvdbyte=64000 '
    'sentpkt=10 rcvdpkt=50 appcat="unscanned"', ns=1)
REFUSED = line(
    'logid="0001000014" type="traffic" subtype="local" level="notice" vd="root" '
    'srcip=192.0.2.66 srcport=48383 srcintf="wan1" srcintfrole="wan" dstip=203.0.113.1 '
    'dstport=9793 dstintf="root" dstintfrole="undefined" srccountry="Canada" '
    'dstcountry="Czech Republic" sessionid=1002 proto=6 action="deny" policyid=0 '
    'policytype="local-in-policy" service="tcp/9793" trandisp="noop" app="tcp/9793" '
    'duration=0 sentbyte=0 rcvdbyte=0 crscore=5 craction=262144 crlevel="low"', ns=2)
BLOCKED = line(
    'logid="0315012547" type="utm" subtype="webfilter" eventtype="urlfilter" '
    'level="notice" vd="root" proto=6 httpmethod="GET" policyid=6 sessionid=1003 '
    'srcip=10.1.2.4 srcport=64413 srccountry="Reserved" srcintf="LAN" dstip=198.51.100.9 '
    'dstport=80 dstcountry="Czech Republic" dstintf="wan1" service="HTTP" '
    'profile="EXAMPLE-WEB" hostname="noproxy.example.org" '
    'agent="WinHttp-Autoproxy-Service/5.1" action="blocked" reqtype="direct" '
    'msg="The HTTP request contained an invalid domain name." sentbyte=144 rcvdbyte=0 '
    'url="/wpad.dat" catdesc="Unrated"', ns=3)
WEBPASS = line(
    'logid="0316013056" type="utm" subtype="webfilter" eventtype="ftgd_allow" '
    'level="notice" vd="root" policyid=6 sessionid=1001 srcip=10.1.2.3 srcport=63693 '
    'srcintf="LAN" dstip=198.51.100.7 dstport=443 dstintf="wan1" service="HTTPS" '
    'hostname="update.example.com" profile="EXAMPLE-WEB" action="passthrough" '
    'url="https://update.example.com/" catdesc="Information Technology"', ns=4)
VPNFAIL = line(
    'logid="0101039426" type="event" subtype="vpn" level="alert" vd="root" '
    'logdesc="SSL VPN login fail" action="ssl-login-fail" tunneltype="ssl-web" '
    'tunnelid=0 remip=192.0.2.77 user="someone" group="N/A" dst_host="N/A" '
    'reason="sslvpn_login_permission_denied" msg="SSL user failed to logged in"', ns=5)
ADMIN = line(
    'logid="0100044546" type="event" subtype="system" level="information" vd="root" '
    'logdesc="Attribute configured" user="fwadmin" ui="GUI(10.1.2.9)" action="Edit" '
    'cfgtid=104988740 cfgpath="log.syslogd.setting" '
    'cfgattr="server[198.51.100.1->10.1.2.252]" msg="Edit log.syslogd.setting "', ns=6)
QUOTED = line(
    'logid="0100032001" type="event" subtype="system" level="information" vd="root" '
    'user="fwadmin" srcip=10.1.2.9 action="login" status="success" '
    'msg="Administrator \\"fwadmin\\" logged in = ok"', ns=7)


title('One line read')
one = isemon.fg_record_from(ALLOWED)
f = one.facts
ok('a session let through is let through', f['verdict'], 'allow')
ok('...when it was is the firewall\'s own clock, to the second at least',
   int(f['ts']), NOW)
ok('...from where, to where', (f['srcip'], f['srcport'], f['dstip'], f['dstport']),
   ('10.1.2.3', 63693, '198.51.100.7', 443))
ok('...on which interfaces', (f['srcintf'], f['dstintf']), ('LAN', 'wan1'))
ok('...by which policy', (f['policy'], f['policyname']), (6, 'LAN-WAN - Internet'))
ok('...and how much it carried', (f['sent'], f['rcvd'], f['duration']), (1500, 64000, 12))
ok('the device is the name it gives itself, not the syslog header', f['dev'], 'FG-EXAMPLE')
ok('what the columns do not take is kept beside the row',
   (f['fields'].get('transip'), f['fields'].get('srcintfrole')), ('203.0.113.1', 'lan'))
ok('...but not the columns twice', 'srcip' in f['fields'], False)
ok('the ident is the device, its clock, the log id, the session and the port',
   f['ident'], 'fw/FGT00EXAMPLE0001/%d001000000/0000000013/1001/63693' % NOW)

ok('a policy refusing it is refused', isemon.fg_record_from(REFUSED).facts['verdict'], 'deny')
ok('the web filter blocking it is blocked',
   isemon.fg_record_from(BLOCKED).facts['verdict'], 'block')
ok('...the name asked for is the host', isemon.fg_record_from(BLOCKED).facts['host'],
   'noproxy.example.org')
ok('...and the web filter letting it pass is let through',
   isemon.fg_record_from(WEBPASS).facts['verdict'], 'allow')
vpn = isemon.fg_record_from(VPNFAIL).facts
ok('a VPN sign-in that did not work failed', vpn['verdict'], 'fail')
ok('...from the address it came from', vpn['srcip'], '192.0.2.77')
ok('...and "N/A" is nobody, not a name', vpn['host'], '')
ok('an administrator changing a setting is said, not judged',
   isemon.fg_record_from(ADMIN).facts['verdict'], 'info')
q = isemon.fg_record_from(QUOTED).facts
ok('a quoted value keeps its spaces, its equals and its own quotes',
   q['msg'], 'Administrator "fwadmin" logged in = ok')
ok('a line that is not FortiGate\'s is nothing',
   isemon.fg_record_from('Oct  1 07:56:02 host sshd[1]: Accepted password for x'), None)
ok('...and neither is half of one', isemon.fg_record_from(HEAD + 'date=2026-10-01'), None)
ok('the parser picked by the setting reads them all',
   len(isemon.fw_parse_lines([ALLOWED, REFUSED, BLOCKED, 'junk', VPNFAIL])), 4)
ok('...and it is the reader the firewall log is given',
   isemon.LOG_PARSERS.get('fwlog') is not None, True)
ok('an eventtime to the second is understood as well as one to the nanosecond',
   int(isemon.fg_when({'eventtime': str(NOW)})), NOW)
ok('...and with no eventtime at all the date, time and zone are used',
   int(isemon.fg_when({'date': '2026-10-01', 'time': '07:56:02', 'tz': '+0200'})),
   calendar.timegm((2026, 10, 1, 5, 56, 2, 0, 0, 0)))

title('Written down and counted')
folder, store = fresh()
lines = [ALLOWED, REFUSED, BLOCKED, WEBPASS, VPNFAIL, ADMIN, QUOTED]
events = [e.facts for e in isemon.fw_parse_lines(lines)]
ok('every line is written', store.note_fw_events(events + [events[0]]), 7)
ok('...and a line written twice by the syslog server is one row',
   store.rows_in('fw_events'), 7)
ok('...and read again, nothing is written twice', store.note_fw_events(events), 0)
s = store.fw_summary(time.time() - 3600)
ok('the cards are counted: let through', s['totals']['allow']['n'], 2)
ok('...refused', s['totals']['deny']['n'], 1)
ok('...blocked', s['totals']['block']['n'], 1)
ok('...failed', s['totals']['fail']['n'], 1)
ok('...and what was carried', s['totals']['allow']['rcvd'], 64000)
refused_from = [r['val'] for r in s['tops']['src']['refused']]
ok('who was refused is on the card of the refused', '192.0.2.66' in refused_from, True)
ok('...and who was not, is not', '10.1.2.3' in refused_from, False)
ok('the port it knocked on is counted with its protocol',
   [r['val'] for r in s['tops']['port']['refused']], ['9793/tcp'])

rows, total = store.fw_rows(since=time.time() - 3600)
ok('the list has every line, newest first', (total, rows[0]['ident']),
   (7, events[-1]['ident']))
ok('...only the refused and blocked',
   sorted(r['verdict'] for r in store.fw_rows(since=0, verdict='deny,block')[0]),
   ['block', 'deny'])
ok('...only the web filter', store.fw_rows(since=0, kind='utm/webfilter')[1], 2)
ok('...only what the firewall said about itself', store.fw_rows(since=0, kind='event')[1], 3)
ok('...from one address', store.fw_rows(since=0, src='10.1.2.3')[1], 2)
ok('...to one port', store.fw_rows(since=0, port=9793)[1], 1)
ok('...by one policy, as the card names it', store.fw_rows(since=0, policy='6 LAN-WAN')[1], 3)
ok('...by one way through', store.fw_rows(since=0, intf='wan1 → root')[1], 1)
ok('...one session', store.fw_rows(since=0, session=1001)[1], 2)
ok('...by level, any of several', store.fw_rows(
   since=0, kind='event', query='level:warning,error,critical,alert,emergency')[1], 1)
ok('...and ordered by a heading at the same time', store.fw_rows(
   since=0, kind='event', query='level:alert', sort='user', desc=False)[1], 1)
ok('...any word', store.fw_rows(since=0, text='noproxy')[1], 1)
ok('...and one stretch of time',
   store.fw_rows(since=NOW - 1, until=NOW + 1)[1], 7)
ok('...and nothing outside it', store.fw_rows(since=NOW + 5)[1], 0)
ok('the list can be ordered by how much a session carried, most first',
   [r['ident'] for r in store.fw_rows(since=0, sort='bytes', limit=2)[0]][:1], [events[0]['ident']])
ok('...or least first', store.fw_rows(since=0, sort='port', desc=False,
                                      query='type:traffic')[0][0]['dstport'], 443)
ok('...and a heading it does not know orders it by the time',
   store.fw_rows(since=0, sort='nonsense; DROP TABLE x')[0][0]['ident'], events[-1]['ident'])

got = store.fw_get(events[0]['ident'])
ok('one line comes back with every field', got['fields'].get('transport'), '41000')
ok('...and the other lines of the same session',
   [m['ident'] for m in got['mates']], [events[3]['ident']])
ok('...and nobody\'s name column under the database\'s word for it', 'usr' in got, False)
ok('a line that is not there is None', store.fw_get('fw/none'), None)
shutil.rmtree(folder, ignore_errors=True)


title('Keeping only what was refused')
folder, store = fresh(fwlog_keep_allowed=0)
events = [e.facts for e in isemon.fw_parse_lines(lines)]
store.note_fw_events(events)
ok('the sessions it let through are not kept as rows',
   store.fw_rows(since=0, verdict='allow')[1], 0)
ok('...but what it said about itself is', store.fw_rows(since=0, kind='event')[1], 3)
ok('...and the let-through sessions are still counted on the cards',
   store.fw_summary(time.time() - 3600)['totals']['allow']['n'], 2)
shutil.rmtree(folder, ignore_errors=True)


title('Growing old')
folder, store = fresh(fwlog_keep_days=3, fwlog_allowed_days=1)
old = [e.facts for e in isemon.fw_parse_lines(
    [line('logid="0000000013" type="traffic" subtype="forward" srcip=10.9.9.9 dstip=198.51.100.1 '
          'sessionid=7 proto=6 action="close" policyid=6', at=NOW - 2 * 86400, ns=11),
     line('logid="0001000014" type="traffic" subtype="local" srcip=192.0.2.9 dstip=203.0.113.1 '
          'sessionid=8 proto=6 action="deny" policyid=0', at=NOW - 2 * 86400, ns=12),
     line('logid="0001000014" type="traffic" subtype="local" srcip=192.0.2.10 dstip=203.0.113.1 '
          'sessionid=9 proto=6 action="deny" policyid=0', at=NOW - 5 * 86400, ns=13)])]
store.note_fw_events(old)
ok('three old lines', store.rows_in('fw_events'), 3)
store.tidy_fw()
left = sorted(r['srcip'] for r in store.fw_rows(since=0)[0])
ok('a let-through session goes after a day, a refused one after the days kept',
   left, ['192.0.2.9'])
shutil.rmtree(folder, ignore_errors=True)


title('The search box')
folder, store = fresh()
events = [e.facts for e in isemon.fw_parse_lines(lines)]
store.note_fw_events(events)


def found(query, **more):
    said = {}
    rows, total = store.fw_rows(since=0, query=query, said=said, **more)
    return sorted(r['ident'] for r in rows), total, said


def idents(*which):
    return sorted(e['ident'] for e in events if e['ident'] in which)


A, R, B, W, V, D, Q = [e['ident'] for e in events]
ok('a word on its own is looked for anywhere', found('noproxy')[0], [B])
ok('...and case does not matter', found('NOPROXY')[0], [B])
ok('a field is that field, exactly', found('srcip:10.1.2.3')[0], sorted([A, W]))
ok('...under FortiOS\'s own name for it as well', found('sessionid:1002')[0], [R])
ok('a comma is any of these', found('verdict:deny,block')[0], sorted([R, B]))
ok('...and the page\'s words for a verdict are understood', found('verdict:refused')[0], [R])
ok('two terms side by side must both hold', found('srcip:10.1.2.3 kind:traffic')[0], [A])
ok('OR is either', found('dstport:9793 OR user:someone')[0], sorted([R, V]))
ok('- turns a term round', found('srcip:10.1.2.3 -kind:traffic')[0], [W])
ok('...and so do ! and NOT', (found('srcip:10.1.2.3 !kind:traffic')[0],
                              found('srcip:10.1.2.3 NOT kind:traffic')[0]), ([W], [W]))
ok('!= is "is not"', found('srcip:10.1.2.3 type!=traffic')[0], [W])
ok('brackets group', found('(dstport:9793 OR dstport:80) type:traffic')[0], [R])
ok('* is anything', found('host:*.example.org')[0], [B])
ok('the category by its name', found('category:unrated')[0], [B])
ok('...while cat is FortiOS\'s own field, its number', found('cat:52')[1], 0)
ok('~ is "contains"', found('msg~"invalid domain"')[0], [B])
ok('a range of numbers', found('dstport:1-100')[0], [B])
ok('more than, with a unit', found('rcvd>10k')[0], [A])
ok('a range of addresses', found('ip:192.0.2.0/24')[0], sorted([R, V]))
# A /8 or narrower is said to the database exactly since 1.10.175; one
# wider still is read back.
ok('...said to the database exactly, nothing read back',
   found('ip:192.0.2.0/24')[2].get('scanned', 0), 0)
ok('a range wider than /8, read back', (found('ip:192.0.0.0/7')[0],
                                        found('ip:192.0.0.0/7')[2]['scanned'] > 0),
   (sorted([R, V]), True))
ok('a field from inside the stored line', found('crlevel:low')[0], [R])
ok('...with contains', found('agent~autoproxy')[0], [B])
ok('...and with more than', found('crscore>1')[0], [R])
ok('...and turned round beside a column', found('type:utm -profile:EXAMPLE-WEB')[0], [])
ok('...and it says which fields it read out', found('crlevel:low')[2]['inside'], ['crlevel'])
ok('the drop-downs still narrow it', found('srcip:10.1.2.3', kind='utm')[0], [W])
ok('what it was understood to mean is said back',
   found('srcip:10.1.2.3 -dstport:443')[2]['says'],
   'source address is 10.1.2.3 and not destination port is 443')
for bad in ('srcip:', '(srcip:1', 'a OR', 'NOT', 'sent>lots', 'host>3'):
    try:
        isemon.FwQuery(bad)
        ok('%r is not a search' % bad, 'read', 'refused')
    except isemon.FwQueryError:
        ok('%r is not a search, and says why' % bad, True)
got = store.fw_suggest('srcip', '10.1', since=0)
ok('the box offers the values a field holds, busiest first',
   [v['val'] for v in got], ['10.1.2.3', '10.1.2.4', '10.1.2.9'][:len(got)])
ok('...a policy with its name beside it',
   store.fw_suggest('policy', '', since=0)[0], {'val': '6', 'n': 1,
                                               'label': 'LAN-WAN - Internet'})
ok('...a field from inside the lines as well',
   [v['val'] for v in store.fw_suggest('crlevel', '', since=0)], ['low'])
ok('...and the names of those fields',
   'crlevel' in [f['name'] for f in store.fw_inside_fields(0)], True)
ok('a private address is one of the site\'s own', (isemon.fw_private('10.1.2.3'),
                                                  isemon.fw_private('192.0.2.66'),
                                                  isemon.fw_private('8.8.8.8')),
   (True, True, False))
shutil.rmtree(folder, ignore_errors=True)


title('More of what FortiOS writes')
DNSQ = line(
    'logid="1501054802" type="utm" subtype="dns" eventtype="dns-response" level="notice" '
    'vd="root" policyid=7 sessionid=2001 srcip=10.1.2.5 srcport=58792 srccountry="Reserved" '
    'srcintf="LAN" dstip=10.1.2.6 dstport=53 dstcountry="Reserved" dstintf="SRV" proto=17 '
    'profile="EXAMPLE-DNS" xid=31682 qname="cdn.example.org" qtype="A" qtypeval=1 qclass="IN" '
    'ipaddr="198.51.100.20, 198.51.100.21" msg="Domain is monitored" action="pass" cat=0 '
    'catdesc="Unrated"', ns=21)
d = isemon.fg_record_from(DNSQ).facts
ok('a DNS filter line is let through, and the name asked is the host',
   (d['verdict'], d['host']), ('allow', 'cdn.example.org'))
ok('...and what DNS answered is kept', d['fields'].get('ipaddr'), '198.51.100.20, 198.51.100.21')
IKE = line(
    'logid="0101037124" type="event" subtype="vpn" level="error" vd="root" '
    'logdesc="IPsec phase 1 error" msg="IPsec phase 1 error" action="negotiate" '
    'remip=192.0.2.88 locip=203.0.113.1 remport=35366 locport=500 outintf="wan1" '
    'user="N/A" group="N/A" vpntunnel="N/A" status="negotiate_error" '
    'reason="peer SA proposal not match local policy"', ns=22)
k = isemon.fg_record_from(IKE).facts
ok('an IPsec negotiation from outside that failed is a failed attempt',
   (k['verdict'], k['srcip'], k['user']), ('fail', '192.0.2.88', ''))
CLOUD = line(
    'logid="0100053401" type="event" subtype="system" level="warning" vd="root" '
    'logdesc="Central Management connectivity is inactive" action="connect" status="failure" '
    'msg="Failed to connect FortiGate Cloud 198.51.100.60"', ns=23)
ok('...while the firewall failing to reach its own cloud is not somebody refused',
   isemon.fg_record_from(CLOUD).facts['verdict'], 'info')
LONG = line(
    'logid="0000000020" type="traffic" subtype="forward" level="notice" vd="root" '
    'srcip=10.1.2.7 srcport=60398 srcintf="LAN" dstip=198.51.100.30 dstport=443 '
    'dstintf="wan1" sessionid=3001 proto=6 action="accept" policyid=6 service="HTTPS" '
    'duration=300 sentbyte=5000000 rcvdbyte=90000000 sentdelta=1000000 rcvddelta=30000000 '
    'user="someone" group="STAFF" authserver="DC-RADIUS"', ns=24)
END = line(
    'logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" '
    'srcip=10.1.2.7 srcport=60398 srcintf="LAN" dstip=198.51.100.30 dstport=443 '
    'dstintf="wan1" sessionid=3001 proto=6 action="close" policyid=6 service="HTTPS" '
    'duration=420 sentbyte=6000000 rcvdbyte=100000000 sentdelta=1000000 rcvddelta=10000000 '
    'user="someone" group="STAFF"', ns=25)
folder, store = fresh()
more = [e.facts for e in isemon.fw_parse_lines([DNSQ, IKE, CLOUD, LONG, END])]
store.note_fw_events(more)
s2 = store.fw_summary(time.time() - 3600)
ok('a session written twice as it lasted is one session', s2['totals']['allow']['n'], 2)
ok('...and carried what its deltas say, not its running total added up',
   (s2['totals']['allow']['sent'], s2['totals']['allow']['rcvd']), (2000000, 40000000))
ok('...and the web filter\'s and the DNS filter\'s lines add no bytes of their own',
   isemon.fw_carried(isemon.fg_record_from(WEBPASS.replace('catdesc=', 'sentbyte=900 rcvdbyte=9000 catdesc=')).facts)[:2],
   (0, 0))
ok('the person on a session is counted', [r['val'] for r in s2['tops']['user']['busiest']],
   ['someone'])
ok('...and so is their group', [r['val'] for r in s2['tops']['group']['busiest']], ['STAFF'])
ok('what the firewall said about itself is counted by what it is',
   sorted(r['val'] for r in s2['tops']['event']['busiest']),
   ['Central Management connectivity is inactive', 'IPsec phase 1 error'])
ok('a search for a group reads only lines that name somebody',
   isemon.FwQuery('group:STAFF').narrowing(), ("usr <> ''", []))
said = {}
ok('...and finds them', store.fw_rows(since=0, query='group:STAFF', said=said)[1], 2)
ok('the DNS filter\'s name is searched as the host', store.fw_rows(
   since=0, query='host:cdn.example.org kind:utm/dns')[1], 1)
shutil.rmtree(folder, ignore_errors=True)


title('Reading it again')
ok('the firewall\'s log can be named to be read again', 'fwlog' in isemon.LOG_MODULE_NAMES, True)
ok('...and a pass back over every log leaves it alone, since nothing in it is judged',
   'fwlog' in isemon.ZONELESS_LOGS, True)
ok('the live reader and a pass back over the files write one at a time',
   'with FW_WRITING:' in DAEMON_SRC, True)


title('The box at the top')
folder, store = fresh()
daemon = isemon.Daemon(store)
NOWISH = int(time.time()) - 60
store.note_fw_events([e.facts for e in isemon.fw_parse_lines(
    [line(ALLOWED.split('tz="+0200" ', 1)[1], at=NOWISH, ns=31),
     line(BLOCKED.split('tz="+0200" ', 1)[1], at=NOWISH, ns=32)])])
said = daemon.fw_find('10.1.2.3')
ok('an address typed into the box is found on the firewall',
   [(f['what'], f['src']) for f in said], [('address', {'allow': 1})])
ok('...and so is a name asked through it',
   [f['val'] for f in daemon.fw_find('noproxy') if f['what'] == 'name asked for'],
   ['noproxy.example.org'])
ok('...and the address\'s own popup says what the firewall saw of it',
   daemon.fw_about_address('10.1.2.3')['src'], {'allow': 1})
shutil.rmtree(folder, ignore_errors=True)


title('More than one firewall')
folder, store = fresh()
daemon = isemon.Daemon(store)
ok('with no list, the older settings are one firewall named after its folder',
   [(f['name'], f['type'], f['files']) for f in isemon.fw_sources()],
   [('fw', 'fortigate', '*.log')])
hq = Path(folder) / 'hq'
br = Path(folder) / 'branch.example.cz'
hq.mkdir()
br.mkdir()
isemon.CONFIG['fwlog_sources'] = isemon.check_setting('fwlog_sources', [
    {'name': 'hq', 'type': 'fortigate', 'path': str(hq), 'files': 'fw-*.log'},
    {'name': '', 'type': 'fortigate', 'path': str(br) + '/', 'files': ''},
    {'name': '', 'path': ''}])
ok('a list of firewalls is read, each with its own name, kind and files',
   [(f['name'], f['files']) for f in isemon.fw_sources()],
   [('hq', 'fw-*.log'), ('branch.example.cz', '*.log')])
for bad, why in (([{'name': 'a@b', 'path': '/x'}], 'a name with @'),
                 ([{'name': 'x', 'path': '/a'}, {'name': 'X', 'path': '/b'}], 'two of one name'),
                 ([{'name': 'x', 'type': 'pix', 'path': '/a'}], 'a kind it cannot read'),
                 ([{'name': 'x', 'path': ''}], 'a firewall with nowhere to read')):
    try:
        isemon.check_setting('fwlog_sources', bad)
        ok('%s is refused' % why, False)
    except ValueError:
        ok('%s is refused' % why, True)
ok('...and the command line may write it as JSON',
   isemon.check_setting('fwlog_sources', '[{"name": "x", "path": "/var/log/x"}]')[0]['name'],
   'x')
(hq / 'fw-1.log').write_text(line(ALLOWED.split('tz="+0200" ', 1)[1], ns=41) + '\n'
                             + line(REFUSED.split('tz="+0200" ', 1)[1], ns=42) + '\n')
(hq / 'other.log').write_text('not this one\n')
(br / 'x.log').write_text(line(BLOCKED.split('tz="+0200" ', 1)[1], ns=43)
                          .replace('FGT00EXAMPLE0001', 'FGT00EXAMPLE0002') + '\n')
files = [p for _k, p, src in daemon.log_files() if src == 'fwlog']
ok('each firewall\'s files are followed by its own pattern',
   sorted(Path(p).name for p in files), ['fw-1.log', 'x.log'])
# Read the way the daemon reads them, by its own loop: a reader that tagged
# the lines in a test and lost the tag in the loop would pass here otherwise.
for p in files:
    daemon._tails[daemon.tail_key(p, 'fwlog')] = isemon.LogTail(p, 0)
daemon.read_logs()
daemon.flush_fw_events()
ok('every line carries the name of the firewall it came from',
   sorted((r['fw'], r['verdict']) for r in store.fw_rows(since=0)[0]),
   [('branch.example.cz', 'block'), ('hq', 'allow'), ('hq', 'deny')])
ok('the list can be asked for one firewall', store.fw_rows(since=0, fw='hq')[1], 2)
ok('...and searched for one', store.fw_rows(since=0, query='fw:branch*')[1], 1)
whole = store.fw_summary(time.time() - 3600)
one = store.fw_summary(time.time() - 3600, fw='hq')
other = store.fw_summary(time.time() - 3600, fw='branch.example.cz')
ok('the cards add every firewall up',
   sorted((v, t['n']) for v, t in whole['totals'].items()),
   [('allow', 1), ('block', 1), ('deny', 1)])
ok('...or count one of them', sorted((v, t['n']) for v, t in one['totals'].items()),
   [('allow', 1), ('deny', 1)])
ok('...and the other', sorted((v, t['n']) for v, t in other['totals'].items()), [('block', 1)])
ok('...the busiest of a card are that firewall\'s too',
   [r['val'] for r in one['tops']['src']['busiest']], ['10.1.2.3', '192.0.2.66'])
ok('the page is told the firewalls to switch between',
   [f['name'] for f in daemon.fw_summary(1)['firewalls']], ['hq', 'branch.example.cz'])
ok('...and which one it was answered for', daemon.fw_summary(1, 'hq')['fw'], 'hq')
ok('...and a name it does not know is answered for all of them',
   daemon.fw_summary(1, 'gone')['fw'], '')
ok('what the search box offers for the field is the firewalls',
   [v['val'] for v in store.fw_suggest('firewall')], ['branch.example.cz', 'hq'])
ok('the settings page is given the editor for the list, with the kinds',
   [(s['kind'], sorted(s['types'])) for s in daemon.settings_state()
    if s['key'] == 'fwlog_sources'], [('fwsources', ['fortigate', 'ftd', 'routeros'])])
ok('...and the page draws one row per firewall',
   'function fwSourcesEditor(s)' in PAGE_SRC and "s.kind === 'fwsources'" in PAGE_SRC, True)
ok('...and the Traffic tab switches between them, asking for one everywhere',
   'function drawTFws(list)' in PAGE_SRC and "api('fw&' + tWindowArgs() + tFwArg()"
   in PAGE_SRC and "ask.push('fw=' + encodeURIComponent(TFW))" in PAGE_SRC, True)
isemon.CONFIG['fwlog_sources'] = []
shutil.rmtree(folder, ignore_errors=True)


title('Settings and the page')
ok('it is off until somebody turns it on', isemon.DEFAULTS.get('fwlog'), 0)
ok('...and the kinds of firewall are a choice', 'fortigate' in isemon.FW_TYPES, True)
ok('everything it keeps can be erased as one', 'firewall' in isemon.Storage.ERASABLE, True)
ok('...and its tables are in that, the overview worked out ahead (1.10.154) too',
   sorted(isemon.Storage.ERASABLE['firewall']['tables']), ['fw_events', 'fw_ready', 'fw_roll'])
ok('the tab sits between Logins and the Domain',
   PAGE_SRC.index('data-tab="logins"') < PAGE_SRC.index('data-tab="traffic"')
   < PAGE_SRC.index('data-tab="windows"'), True)
ok('...and is hidden until the setting is on', 'trafficTab.hidden = !s.fwlog_on' in PAGE_SRC,
   True)
ok('...with a pane of its own in Settings', 'id="pane-fwlog"' in PAGE_SRC, True)
ok('nothing on the page bans anybody',
   "api('ban" in PAGE_SRC[PAGE_SRC.index('var TRAFFIC = null;'):
                          PAGE_SRC.index('function drawFwLine')], False)
neg = isemon.fg_record_from(
    'date=2026-10-01 time=10:08:36 devname="FG-1" devid="FGT0000000000000" '
    'eventtime=1790842116114784417 tz="+0200" logid="0101037124" type="event" subtype="vpn" '
    'level="error" vd="root" logdesc="IPsec phase 1 error" msg="IPsec phase 1 error" '
    'action="negotiate" remip=198.51.100.4 locip=192.0.2.5 remport=35366 locport=500 '
    'outintf="wan1" cookies="a90dcd7334082455/0000000000000000" user="N/A" group="N/A" '
    'useralt="N/A" xauthuser="N/A" xauthgroup="N/A" assignip=N/A vpntunnel="N/A" '
    'status="negotiate_error" reason="peer SA proposal not match local policy" '
    'peer_notif="NOT-APPLICABLE" advpnsc=0').facts
negd = dict(isemon.Storage.fw_dims(neg))
ok('a FortiGate tunnel that failed counts on the peers and why tunnels fail, with its meaning',
   (isemon.fw_area(neg), negd.get('peer'), negd.get('s2swhy')),
   ('s2s-vpn', '198.51.100.4',
    'peer SA proposal not match local policy \u2014 no encryption both sides accept'))
ok('the cards of a row are as tall as each other',
   '.t-tops{display:grid' in PAGE_SRC and 'margin-top:14px;align-items:stretch}' in PAGE_SRC, True)
ok('...and the small cards are on the overview only, not on the pages',
   'drawPageCards' not in PAGE_SRC, True)
ok('the API answers only somebody signed in',
   DAEMON_SRC.count("if path == '/api/fw") == 6
   and DAEMON_SRC.split("if path == '/api/fw/vpn':", 1)[1][:120].count('need_login') == 1
   and DAEMON_SRC.split("if path == '/api/fw/router':", 1)[1][:500].count('need_login') == 1
   and DAEMON_SRC.split("if path == '/api/fw/suggest':", 1)[1][:120].count('need_login') == 1
   and DAEMON_SRC.split("if path == '/api/fw/row':", 1)[1][:120].count('need_login') == 1,
   True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
