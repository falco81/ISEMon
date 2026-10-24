#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
names.py - turning an address back into the machine it is, and every way
that can go wrong.

An address in a log is a fact about a machine that nobody can read. The
reverse zone turns it back into `nb-novak.example.loc`, which is the thing
whoever is reading the page actually wanted. What is at stake:

  * nothing waits for it. Not the page, not the reading of a log, not the
    judging. A name server that has gone away may leave a name blank and may
    do nothing else at all.
  * the servers are asked in the order written and the first one with a NAME
    wins. A site keeps its offices in one set of servers and its DMZ in
    another: a server saying it has never heard of an address is not an
    answer about that address, it is an answer about that server.
  * an answer is written down with its time, because a lease moves. The same
    address is one machine this morning and another this afternoon, and a
    list of yesterday's refusals labelled with today's names is a page
    lying about every row on it.
  * the same address is not asked about twice, and an address nobody has a
    name for is asked about once rather than once a page.
  * switched off, not one packet is sent.

Everything here runs against `mockdns.py`, which answers the way a name
server does - including the ways that are not answers: quiet, refused, "no
such name", and a reply cut short so it has to be asked again over TCP.

    ./test/names.py
"""
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))
import isemon                                        # noqa: E402
import mockdns                                       # noqa: E402

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
    folder = tempfile.mkdtemp(prefix='isemon-names-')
    isemon.STATE_DIR = Path(folder)
    isemon.DB_FILE = Path(folder) / 'names.db'
    isemon.BACKUP_DIR = Path(folder) / 'backups'
    isemon.DUMP_DIR = Path(folder) / 'dumps'
    isemon.RUN_DIR = Path(folder)
    isemon.LOG_DIR = Path(folder)
    isemon._LOG_PATH = Path(folder) / 'names.log'
    isemon.CONFIG.update(isemon.DEFAULTS)
    store = isemon.Storage()
    return store, isemon.Daemon(store)


def waited(how, ends=6.0):
    """Wait for something the threads are doing, or give up and say so."""
    until = time.time() + ends
    while time.time() < until:
        if how():
            return True
        time.sleep(0.05)
    return False


store, daemon = fresh()

# Two servers with two different zones, which is the shape this was built
# for: the offices are in one and the DMZ is in the other, and neither of
# them has ever heard of the other's addresses.
OFFICES = {'10.0.0.5': 'nb-novak.example.loc', '10.0.0.6': 'pc-podatelna.example.loc',
           '10.0.0.7': 'pc-sklad.example.loc'}
DMZ = {'203.0.113.9': 'www.example.cz'}
office_port, office_stop, offices = mockdns.serve(OFFICES)
dmz_port, dmz_stop, dmz = mockdns.serve(DMZ)
BOTH = '127.0.0.1:%d, 127.0.0.1:%d' % (office_port, dmz_port)

# ---------------------------------------------------------------------------
title('The question, written the way a name server expects it')
ok('an address becomes the name its reverse zone answers to',
   isemon.dns_reverse_name('203.0.113.9'), '9.113.0.203.in-addr.arpa')
ok('...and an IPv6 address becomes its nibbles',
   isemon.dns_reverse_name('2001:db8::1').endswith('.ip6.arpa'), True)
ok('...while something that is not an address is not a question at all',
   isemon.dns_reverse_name('nonsense'), '')
ident, packet = isemon.dns_question('9.113.0.203.in-addr.arpa')
ok('the packet carries the question it was asked', b'in-addr' in packet, True)
ok('...and asks for a name rather than an address', packet[-4:], b'\x00\x0c\x00\x01')
ok('...and says who is asking, so an answer to somebody else is not read as ours',
   packet[0:2], ident.to_bytes(2, 'big'))

# ---------------------------------------------------------------------------
title('Which servers to ask, out of what somebody typed')
ok('one to a line or several to a comma, both',
   isemon.dns_servers('10.0.0.1\n10.0.0.2, 10.0.0.3'),
   [('10.0.0.1', 53), ('10.0.0.2', 53), ('10.0.0.3', 53)])
ok('...with a port where one is written', isemon.dns_servers('10.0.0.1:5353'),
   [('10.0.0.1', 5353)])
ok('...and an IPv6 address, in the brackets that let it carry one',
   isemon.dns_servers('[2001:db8::1]:5353, 2001:db8::2'),
   [('2001:db8::1', 5353), ('2001:db8::2', 53)])
ok('...while anything that is not an address is left out rather than asked',
   isemon.dns_servers('dns.example.com, 10.0.0.1, , rubbish'), [('10.0.0.1', 53)])

# ---------------------------------------------------------------------------
title('The first server with a name is the answer')
both = isemon.dns_servers(BOTH)
ok('an address the first one knows is answered by the first one',
   isemon.dns_ptr('10.0.0.5', both)[0], 'nb-novak.example.loc')
ok('...and the second one is never asked about it',
   [q for q in dmz.asked if q.startswith('5.0.0.10')], [])
ok('an address only the second one knows is answered by the second one',
   isemon.dns_ptr('203.0.113.9', both)[0], 'www.example.cz')
ok('...which means the first was asked and passed over, rather than believed',
   [q for q in offices.asked if q.startswith('9.113.0.203')],
   ['9.113.0.203.in-addr.arpa'])
ok('...and the answer says which server had it',
   isemon.dns_ptr('203.0.113.9', both)[1], '127.0.0.1:%d' % dmz_port)
ok('an address nobody has a name for is nothing, and nothing went wrong',
   isemon.dns_ptr('198.51.100.7', both), ('', '', ''))

title('...and a server that is not answering is passed over, not believed')
offices.how = 'quiet'
began = time.time()
got = isemon.dns_ptr('203.0.113.9', both, timeout=0.4)
ok('a server that says nothing at all does not stop the next one being asked',
   got[0], 'www.example.cz')
ok('...and it is given the time it was allowed and no more',
   0.3 < time.time() - began < 2.0, True)
offices.how = 'refused'
ok('a server that refuses is passed over too',
   isemon.dns_ptr('203.0.113.9', both, timeout=0.5)[0], 'www.example.cz')
offices.how = 'answer'
dmz.how = 'quiet'
said = isemon.dns_ptr('198.51.100.9', both, timeout=0.4)
ok('one server saying it has no such name is an answer even where another '
   'could not be reached', said, ('', '', ''))
offices.how = 'quiet'
said = isemon.dns_ptr('198.51.100.9', both, timeout=0.4)
ok('when every server has failed, that is said rather than left as "no name"',
   bool(said[2]), True)
ok('...and no name is invented', said[0], '')
offices.how = 'answer'
dmz.how = 'answer'

title('...and a reply that was cut short is asked for again over TCP')
offices.how = 'cut'
ok('the whole answer still arrives', isemon.dns_ptr('10.0.0.5', both)[0], 'nb-novak.example.loc')
offices.how = 'answer'

# ---------------------------------------------------------------------------
title('What came back, written down with its time')
now = time.time()
store.ptr_note('10.0.0.5', 'nb-novak.example.loc', at=now - 7200, server='dc1')
ok('an address has a name', store.ptr_now(['10.0.0.5'])['10.0.0.5']['name'],
   'nb-novak.example.loc')
store.ptr_note('10.0.0.5', 'nb-novak.example.loc', at=now - 3600, server='dc1')
ok('the same answer again is the same lease, not a second one',
   len(store.ptr_history('10.0.0.5')), 1)
ok('...counted, so a name that keeps coming back says so',
   store.ptr_history('10.0.0.5')[0]['tries'], 2)
store.ptr_note('10.0.0.5', 'nb-kolar.example.loc', at=now, server='dc1')
ok('a different answer is a new lease, because the address has moved on',
   [h['name'] for h in store.ptr_history('10.0.0.5')],
   ['nb-kolar.example.loc', 'nb-novak.example.loc'])
# The whole reason the history is kept: a record from two hours ago belongs
# to the machine that had the address two hours ago.
then = store.ptr_at([('10.0.0.5', now - 5400), ('10.0.0.5', now)])
ok('a record is shown the name its address had at the time',
   then['10.0.0.5|%d' % int(now - 5400)]['name'], 'nb-novak.example.loc')
ok('...and a record from now is shown the name it has now',
   then['10.0.0.5|%d' % int(now)]['name'], 'nb-kolar.example.loc')
ok('...and a moment before anything was ever looked up is said to be a guess',
   store.ptr_at([('10.0.0.5', now - 400000)])['10.0.0.5|%d' % int(now - 400000)]['then'],
   False)
store.ptr_note('198.51.100.7', '', at=now)
ok('an address nobody has a name for is written down as having none',
   store.ptr_now(['198.51.100.7'])['198.51.100.7'], {'name': '', 'at': now, 'since': now,
                                                     'known': True})
ok('...which is what stops it being asked about again every time anybody looks',
   store.ptr_stale(['198.51.100.7'], now - 3600), [])
ok('...while an address nobody has asked about at all is worth asking about',
   store.ptr_stale(['192.0.2.55'], now - 3600), ['192.0.2.55'])
ok('...and so is one whose answer has gone stale',
   store.ptr_stale(['198.51.100.7'], now + 1), ['198.51.100.7'])

# ---------------------------------------------------------------------------
title('A machine can be found by what it is called')
ok('the addresses that have ever been called that',
   [a['ip'] for a in store.ptr_addresses('novak')], ['10.0.0.5'])
# Part of a name, which is how anybody types one - and an address that has
# had two names matching it is two machines, so it is two rows.
ok('...by part of the name, which is how anybody types one',
   sorted(a['name'] for a in store.ptr_addresses('nb-')),
   ['nb-kolar.example.loc', 'nb-novak.example.loc'])
ok('...and one letter is not a search, it is everything',
   store.ptr_addresses('n'), [])
store.add_failed({'session': 'name/1', 'ts': now - 60, 'ip': '10.0.0.5',
                  'username': 'jnovak', 'kind': 'vpn', 'server': 'ise1'})
store.add_failed({'session': 'name/2', 'ts': now - 60, 'ip': '198.51.100.7',
                  'username': 'somebody', 'kind': 'vpn', 'server': 'ise1'})
rows, total = store.failed_rows(text='nb-kolar', limit=10)
ok('a search of the records for a machine’s name finds its address’s records',
   (total, [r['ip'] for r in rows]), (1, ['10.0.0.5']))
ok('...and a name nothing has ever been called finds nothing rather than everything',
   store.failed_rows(text='nb-nobody', limit=10)[1], 0)

# ---------------------------------------------------------------------------
title('Nothing waits for any of it')
isemon.CONFIG['ptr'] = 1
isemon.CONFIG['ptr_servers'] = BOTH
isemon.CONFIG['ptr_timeout_s'] = 1
isemon.CONFIG['ptr_every_min'] = 60
ok('with servers written down and the switch on, it is on', daemon.names.on(), True)
began = time.time()
added = daemon.names.ask(['10.0.0.6', '203.0.113.9', '192.0.2.77'])
ok('asking about three addresses queues three', added, 3)
ok('...and takes no time at all, because it opens no socket',
   time.time() - began < 0.25, True)
ok('...and the same three again while they are still in the queue queues nothing',
   daemon.names.ask(['10.0.0.6', '203.0.113.9', '192.0.2.77']), 0)
ok('the answers arrive on their own',
   waited(lambda: store.ptr_now(['10.0.0.6']).get('10.0.0.6', {}).get('name')), True)
ok('...each from the server that has that zone',
   (store.ptr_now(['10.0.0.6'])['10.0.0.6']['name'],
    waited(lambda: store.ptr_now(['203.0.113.9']).get('203.0.113.9', {}).get('name'))
    and store.ptr_now(['203.0.113.9'])['203.0.113.9']['name']),
   ('pc-podatelna.example.loc', 'www.example.cz'))
ok('...and an address nobody has a name for is written down as having none',
   waited(lambda: '192.0.2.77' in store.ptr_now(['192.0.2.77'])), True)
ok('an address just answered is not asked about again',
   daemon.names.ask(['10.0.0.6']), 0)

title('...and a log is read without one packet being sent')
offices.asked = []
dmz.asked = []


def failed_record(ts, ip, user='INVALID', host='ise2', seq=1):
    """One refusal, written the way ISE writes it: three lines to a record."""
    when = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts)) + '.500 +02:00'
    head = ('%s 0229674592 5400 NOTICE Failed-Attempt: Authentication failed, '
            'ConfigVersionId=86, Device IP Address=172.22.0.137, UserName=%s, '
            'Protocol=Radius, NetworkDeviceName=FTD-VPN, Called-Station-ID=46.227.169.105, '
            'Calling-Station-ID=%s, NAS-Port-Type=Virtual, '
            'Tunnel-Client-Endpoint=(tag=0) %s, '
            'CVPN3000/ASA/PIX7x-Tunnel-Group-Name=CORPNET, AcsSessionID=%s/569337134/%d,'
            % (when, user, ip, ip, host, seq))
    two = (' AuthenticationMethod=PAP_ASCII, SelectedAccessService=AnyConnect_VPN, '
           'FailureReason=22056 Subject not found in the applicable identity store(s), '
           'Step=11001,')
    three = (' EndPointIPAddress=%s, Response={RadiusPacketType=AccessReject; }' % ip)
    head_line = 'Sep 23 13:27:47 %s CISE_Failed_Attempts %010d 3 0 %s' % (host, seq, head)
    two_line = 'Sep 23 13:27:47 %s CISE_Failed_Attempts %010d 3 1 %s' % (host, seq, two)
    three_line = 'Sep 23 13:27:47 %s CISE_Failed_Attempts %010d 3 2 %s' % (host, seq, three)
    return [head_line, two_line, three_line]


# An address nothing has asked about before, so that what is being watched
# here is the reading asking about it and not an answer left over from a
# check above.
ok('nobody has asked what this one is called yet', store.ptr_now(['10.0.0.7']), {})
began = time.time()
daemon.read_records(failed_record(time.time(), '10.0.0.7', seq=9001), kind='failed')
ok('reading a record takes no longer for this being switched on',
   time.time() - began < 0.3, True)
ok('...and the address it came from is asked about afterwards, not during it',
   waited(lambda: store.ptr_now(['10.0.0.7']).get('10.0.0.7', {}).get('name')
          == 'pc-sklad.example.loc'), True)

title('...and switched off, not one packet is sent')
isemon.CONFIG['ptr'] = 0
offices.asked = []
dmz.asked = []
ok('nothing is queued', daemon.names.ask(['10.0.0.5', '198.51.100.1']), 0)
ok('...and it says it is not looking', daemon.names.on(), False)
daemon.read_records(failed_record(time.time(), '198.51.100.31', seq=9002), kind='failed')
time.sleep(0.5)
ok('...and reading a record sends nothing either',
   offices.asked + dmz.asked, [])
isemon.CONFIG['ptr'] = 1
isemon.CONFIG['ptr_servers'] = ''
ok('nor does the switch on its own, with nowhere written down to ask',
   daemon.names.on(), False)
isemon.CONFIG['ptr_servers'] = BOTH

# ---------------------------------------------------------------------------
title('Going back over the addresses that were never asked about')
# The daemon asks about an address when a record arrives and when a page is
# drawn, so everything since it was switched on has an answer and nothing
# from before it does. A database with a year in it is mostly addresses
# nobody has ever asked about, and this is the pass that fills them in.
store.add_failed({'session': 'old/1', 'ts': now - 200 * 86400, 'ip': '10.0.0.6',
                  'username': 'somebody', 'kind': 'vpn', 'server': 'ise1'})
store.add_passed({'session': 'old/2', 'ts': now - 200 * 86400, 'ip': '10.0.0.7',
                  'username': 'somebody', 'kind': 'vpn', 'server': 'ise1'})
store.add_failed({'session': 'old/3', 'ts': now - 3600, 'ip': '192.0.2.99',
                  'username': 'somebody', 'kind': 'vpn', 'server': 'ise1'})
ok('an address already answered is not in the list to fill in',
   '10.0.0.6' in store.ptr_missing(), False)
ok('...while one nobody has asked about is', '192.0.2.99' in store.ptr_missing(), True)
ok('...and the list can be cut to what happened recently',
   '192.0.2.99' in store.ptr_missing(since=now - 7200), True)
MISSING = list(store.ptr_missing())
got = daemon.ptr_fill_job(by='a test')
waited(lambda: daemon.job(got['id'])['done'], 20)
said = daemon.job(got['id'])
ok('the pass runs as a job that can be watched or left alone',
   (said['done'], said['ok']), (True, True))
ok('...and every address that had no answer has one now',
   [ip for ip in MISSING if ip not in store.ptr_now(MISSING)], [])
ok('...including the ones nobody has a name for, so they are not asked again',
   store.ptr_now(['192.0.2.99'])['192.0.2.99']['name'], '')
ok('...and it says what it did',
   'address(es) asked' in str((said.get('result') or {}).get('message')), True)
ok('a second pass has nothing left to do', store.ptr_missing(), [])
isemon.CONFIG['ptr'] = 0
again = daemon.ptr_fill_job(by='a test')
waited(lambda: daemon.job(again['id'])['done'], 10)
ok('...and with the whole thing switched off it asks nothing and says so',
   'switched off' in str((daemon.job(again['id']).get('result') or {}).get('message')), True)
isemon.CONFIG['ptr'] = 1

# ---------------------------------------------------------------------------
title('The button on the settings page asks every server, not the first')
offices.asked = []
dmz.asked = []
said = daemon.ptr_try('203.0.113.9')
ok('the name is found', said['name'], 'www.example.cz')
ok('...and both servers were asked, which is the point of the button',
   len(said['asked']), 2)
ok('...with the one that has never heard of it saying so in words',
   said['asked'][0]['says'], 'it has never heard of that address')
ok('...and the one that has it answering with the name',
   said['asked'][1]['name'], 'www.example.cz')
ok('something that is not an address is refused before anything is asked',
   daemon.ptr_try('not-an-address')['trouble'], 'that is not an address')
isemon.CONFIG['ptr_servers'] = ''
ok('...and so is a lookup with nowhere to ask',
   daemon.ptr_try('203.0.113.9')['trouble'],
   'no name server is written down to ask')
isemon.CONFIG['ptr_servers'] = BOTH

# ---------------------------------------------------------------------------
title('What the pages are handed')
story = daemon.address_story('10.0.0.5')
ok('the popup about an address carries every name it has had',
   [h['name'] for h in story['ptr']], ['nb-kolar.example.loc', 'nb-novak.example.loc'])
found = daemon.find('nb-kolar')
ok('the box that finds anything finds a machine by its name',
   [m['ip'] for m in found['machines']], ['10.0.0.5'])
ok('...and an address typed in comes back with what it is called',
   (daemon.find('10.0.0.5')['address'] or {}).get('ptr', {}).get('name'),
   'nb-kolar.example.loc')
ok('...and knows there were more names before it',
   (daemon.find('10.0.0.5')['address'] or {}).get('ptr_all'), 2)
ok('the addresses on offer carry their names too',
   isinstance(found.get('ptr'), dict), True)

# ---------------------------------------------------------------------------
title('Old names are let go with the records they belong to')
store.ptr_note('192.0.2.200', 'long-gone.example.loc', at=time.time() - 500 * 86400)
ok('a name older than anything kept is there until it is tidied',
   bool(store.ptr_history('192.0.2.200')), True)
store.tidy_ptr(30)
ok('...and then it is not', store.ptr_history('192.0.2.200'), [])
ok('...while the ones still worth showing are left alone',
   bool(store.ptr_history('10.0.0.5')), True)

# ---------------------------------------------------------------------------
title('A password is never a name, and a name is never a password')
# The one rule this file shares with every other: nothing that arrives from
# outside is written anywhere near a row without being cut to size first.
store.ptr_note('192.0.2.201', 'x' * 900)
ok('a name longer than any name is cut rather than kept',
   len(store.ptr_history('192.0.2.201')[0]['name']) <= 255, True)
ok('...and an answer with nothing in it is not a name',
   store.ptr_note('', 'nothing.example'), False)

# ---------------------------------------------------------------------------
title('Who made the machine behind a MAC')
# The first half of a MAC is an assignment out of the IEEE's own registers.
# Three of them, because a block is 24, 28 or 36 bits wide - and the longer
# ones are the point: a small maker is given a slice of a block somebody
# else administers, so reading only the first three bytes names the
# administrator rather than the maker.
import http.server                                   # noqa: E402
import threading                                     # noqa: E402

REGISTERS = {
    '/oui.csv': 'Registry,Assignment,Organization Name,Organization Address\n'
                'MA-L,BCFCE7,"Apple, Inc.",One Apple Park Way\n'
                'MA-L,005056,"VMware, Inc.",Palo Alto\n'
                'MA-L,8C1F64,IEEE Registration Authority,Piscataway\n'
                'MA-L,001122,Private,\n',
    '/mam.csv': 'Registry,Assignment,Organization Name,Organization Address\n'
                'MA-M,8C1F64A,Mala firma s.r.o.,Hometown\n',
    '/oui36.csv': 'Registry,Assignment,Organization Name,Organization Address\n'
                  'MA-S,8C1F64A1B,Jeste mensi s.r.o.,Hometown\n',
}


class _Registers(http.server.BaseHTTPRequestHandler):
    def do_GET(self):                                # noqa: N802
        body = REGISTERS.get(self.path)
        if body is None:
            self.send_response(404)
            self.end_headers()
            return
        raw = body.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/csv')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):                    # quiet
        return


REG = http.server.ThreadingHTTPServer(('127.0.0.1', 0), _Registers)
threading.Thread(target=REG.serve_forever, daemon=True).start()
WHERE = 'http://127.0.0.1:%d' % REG.server_address[1]
isemon.Daemon.MAC_REGISTERS = ((WHERE + '/oui.csv', 24), (WHERE + '/mam.csv', 28),
                               (WHERE + '/oui36.csv', 36))
isemon.CONFIG['mac_vendors'] = 1
got, words = daemon.mac_fetch()
ok('the registers are fetched and written down', got, 5)
ok('...and a block marked private is not a maker', 'Private' in str(
    [r for r in [store.mac_vendor_of('00-11-22-33-44-55')]]), False)
ok('a MAC out of a plain 24-bit block is named',
   store.mac_vendor_of('BC-FC-E7-D7-86-70'), 'Apple, Inc.')
ok('...however it was written', store.mac_vendor_of('bcfc.e7d7.8670'), 'Apple, Inc.')
ok('...and by the colons a controller writes', store.mac_vendor_of('00:50:56:aa:bb:cc'),
   'VMware, Inc.')
# The whole reason the longer registers are read at all.
ok('a MAC out of a 28-bit slice is the maker, not the administrator of the block',
   store.mac_vendor_of('8C-1F-64-A2-00-01'), 'Mala firma s.r.o.')
ok('...and a 36-bit slice inside that one is the maker inside it',
   store.mac_vendor_of('8C-1F-64-A1-B2-34'), 'Jeste mensi s.r.o.')
ok('...while the rest of the block is still whoever administers it',
   store.mac_vendor_of('8C-1F-64-00-00-01'), 'IEEE Registration Authority')
ok('a MAC nobody has registered is nobody rather than a guess',
   store.mac_vendor_of('02-00-00-00-00-01'), '')
ok('something that is not a MAC is not asked about at all',
   store.mac_vendor_of('not-a-mac'), '')
ok('a page of them is one question',
   sorted(daemon.mac_vendor_says(['BC-FC-E7-D7-86-70', '00:50:56:aa:bb:cc',
                                  'rubbish']).values()),
   ['Apple, Inc.', 'VMware, Inc.'])
ok('how many assignments are known is said without counting them again',
   store.mac_vendors_size(), 5)
# A fetch that falls over leaves what was there rather than half of it.
isemon.Daemon.MAC_REGISTERS = ((WHERE + '/oui.csv', 24), (WHERE + '/nothing.csv', 28))
got, words = daemon.mac_fetch()
ok('a register that cannot be fetched is said, not swallowed', got, 0)
ok('...and what was already known is still known',
   store.mac_vendor_of('8C-1F-64-A1-B2-34'), 'Jeste mensi s.r.o.')
ok('...and the trouble is kept where the page can say it',
   bool(store.get_meta('mac_vendors_error')), True)
REG.shutdown()

# ---------------------------------------------------------------------------
title('The other way round: a name, and the address behind it')
# The domain says which machines are its controllers by NAME, and the page in
# front of somebody is as often an address as a name. This is the one honest
# way from one to the other, and it asks a name server rather than the
# directory - which is never asked to do anything but read.
offices.how = 'answer'
dmz.how = 'answer'
servers = isemon.dns_servers('127.0.0.1:%d' % office_port)
ok('a name the zone knows comes back as its address',
   isemon.dns_address('nb-novak.example.loc', servers, 2.0), ['10.0.0.5'])
ok('...and a name nobody has is no address rather than a wrong one',
   isemon.dns_address('nothing-here.example.loc', servers, 2.0), [])
ok('...and an address handed in is itself, without a question being asked',
   isemon.dns_address('10.0.0.5', servers, 2.0), ['10.0.0.5'])
ok('...and nothing at all is nothing',
   isemon.dns_address('', servers, 2.0), [])
# The DMZ server has never heard of an office machine, and the office server
# has never heard of the DMZ: the first one that answers is the answer.
both = isemon.dns_servers(BOTH)
ok('...and with two servers holding two zones, either name is found',
   [isemon.dns_address('nb-novak.example.loc', both, 2.0),
    isemon.dns_address('www.example.cz', isemon.dns_servers(
        '127.0.0.1:%d, 127.0.0.1:%d' % (dmz_port, office_port)), 2.0)],
   [['10.0.0.5'], ['203.0.113.9']])

office_stop()
dmz_stop()
title('Shortening the interval asks again, rather than waiting the old one out')
# The names read their settings fresh every time they are used - but not the
# deadlines already written down. Every address that has been asked about
# carries "ask again at", worked out from the interval as it was then.
# Somebody who finds the names stale and shortens the interval used to go on
# waiting the old one out while the page showed the new number.
store9, daemon9 = fresh()
isemon.CONFIG.update({'ptr': 1, 'ptr_every_min': 1440})
daemon9.names.next_ask['203.0.113.9'] = time.time() + 1440 * 60
ok('an address that has been asked about is not asked again at once',
   daemon9.names.next_ask.get('203.0.113.9') > time.time() + 3600, True)
daemon9.save_settings({'ptr_every_min': 5}, by='a check')
ok('...but shortening the interval clears what was already written down',
   daemon9.names.next_ask.get('203.0.113.9'), None)
daemon9.names.next_ask['203.0.113.9'] = time.time() + 300
daemon9.save_settings({'ptr_servers': '10.0.0.1'}, by='a check')
ok('...and so does pointing it at a different name server',
   daemon9.names.next_ask.get('203.0.113.9'), None)
daemon9.names.next_ask['203.0.113.9'] = time.time() + 300
daemon9.save_settings({'block_tries': 7}, by='a check')
ok('...while a setting about something else leaves them alone',
   daemon9.names.next_ask.get('203.0.113.9') is not None, True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
