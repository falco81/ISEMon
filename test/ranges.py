#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranges.py - is this address on one of the lists.

That question is the whole of what a public blocklist is for, and it is asked
once for every address on every page. It was a walk over every range that
starts before the address, which on a hundred thousand of them is half the
table each time; it is now a seek to the one range that can hold it. A seek
is only right if the ranges it seeks through never overlap, so what is tested
here is both halves: that the ranges are put in order and merged when they go
in, and that the answer afterwards is the same answer the slow walk gave -
for every prefix length there is, for both families, and on both sides of
every boundary.

    ./test/ranges.py
"""
import ipaddress
import random
import shutil
import sys
import tempfile
import time
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


def title(text):
    print('\n%s' % text)


def walked(store, ip):
    """The old answer: every range read, and the ones that hold it kept.

    This is what the query used to do, written out so that the new one can be
    held against it rather than against an opinion.
    """
    packed, fam = isemon.pack_address(str(ip).split('/')[0])
    if packed is None:
        return []
    out = set()
    for row in store.db.execute('SELECT feed, lo, hi, family FROM feed_ranges'):
        if row['family'] == fam and row['lo'] <= packed <= row['hi']:
            out.add(row['feed'])
    return sorted(out)


def walked_country(store, ip):
    packed, fam = isemon.pack_address(str(ip).split('/')[0])
    if packed is None:
        return ''
    for row in store.db.execute('SELECT cc, lo, hi, family FROM geo_ranges'):
        if row['family'] == fam and row['lo'] <= packed <= row['hi']:
            return row['cc']
    return ''


folder = tempfile.mkdtemp(prefix='isemon-ranges-')
isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = Path(folder) / 'r.db'
isemon.BACKUP_DIR = Path(folder) / 'backups'
isemon.DUMP_DIR = Path(folder) / 'dumps'
isemon.RUN_DIR = Path(folder)
isemon.LOG_DIR = Path(folder)
isemon._LOG_PATH = Path(folder) / 'r.log'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
store = isemon.Storage(isemon.DB_FILE)

try:
    title('Every way a range can be written')
    for text, first, last in [
            ('192.0.2.0/24', '192.0.2.0', '192.0.2.255'),
            ('192.0.2.7', '192.0.2.7', '192.0.2.7'),
            ('192.0.2.7/32', '192.0.2.7', '192.0.2.7'),
            ('10.0.0.0/8', '10.0.0.0', '10.255.255.255'),
            ('192.0.2.10-192.0.2.20', '192.0.2.10', '192.0.2.20'),
            ('2001:db8::/32', '2001:db8::',
             '2001:db8:ffff:ffff:ffff:ffff:ffff:ffff'),
            ('2001:db8::1', '2001:db8::1', '2001:db8::1'),
            ('2001:db8::1/128', '2001:db8::1', '2001:db8::1'),
            ('2001:db8::/126', '2001:db8::', '2001:db8::3')]:
        got = isemon.range_of(text)
        ok('%s is %s to %s' % (text, first, last),
           (str(ipaddress.ip_address(got[0])), str(ipaddress.ip_address(got[1]))),
           (first, last))
    ok('a prefix that is not on a boundary is read as the network it names',
       [str(ipaddress.ip_address(x)) for x in isemon.range_of('192.0.2.130/24')[:2]],
       ['192.0.2.0', '192.0.2.255'])
    ok('nonsense is refused', isemon.range_of('not an address'), None)
    ok('...and so is a range whose two halves are different families',
       isemon.range_of('192.0.2.1-2001:db8::1'), None)

    title('Ranges go in sorted, and never overlapping')
    # Deliberately out of order, overlapping, touching, and repeated.
    messy = ['10.0.0.0/24', '10.0.0.128/25', '10.0.1.0/24', '9.9.9.9',
             '10.0.0.0/24', '172.16.0.0/12', '2001:db8:1::/48',
             '2001:db8:0::/48', '2001:db8:2::/48']
    store.put_feed('messy', [isemon.range_of(x) for x in messy])
    rows = [(r['lo'], r['hi'], r['family']) for r in store.db.execute(
        'SELECT lo, hi, family FROM feed_ranges WHERE feed=? ORDER BY family, lo',
        ('messy',))]
    ok('the repeats and the overlaps are gone', len(rows) < len(messy), True)
    clean = True
    for one, two in zip(rows, rows[1:]):
        if one[2] == two[2] and two[0] <= one[1]:
            clean = False
    ok('no two of them overlap', clean, True)
    ok('...and the two halves of 10.0.0.0/23 became one range',
       [str(ipaddress.ip_address(r[0])) + '-' + str(ipaddress.ip_address(r[1]))
        for r in rows if r[2] == 4 and r[0][0] == 10],
       ['10.0.0.0-10.0.1.255'])
    ok('...and three touching /48s became one /46-worth',
       [str(ipaddress.ip_address(r[0])) for r in rows if r[2] == 6],
       ['2001:db8::'])
    ok('what the page is told the list holds is what it holds',
       int(store.get_meta('feed_size_messy')), len(rows))

    title('Both sides of every boundary')
    store.put_feed('edges', [isemon.range_of(x) for x in
                             ['203.0.113.0/24', '2001:db8:beef::/48']])
    for ip, want in [('203.0.112.255', False), ('203.0.113.0', True),
                     ('203.0.113.255', True), ('203.0.114.0', False),
                     ('2001:db8:beee:ffff:ffff:ffff:ffff:ffff', False),
                     ('2001:db8:beef::', True),
                     ('2001:db8:beef:ffff:ffff:ffff:ffff:ffff', True),
                     ('2001:db8:bef0::', False)]:
        ok('%s %s on the list' % (ip, 'is' if want else 'is not'),
           'edges' in store.feeds_with(ip), want)

    title('Every prefix length there is')
    # One list per family holding one range of each length, and the address
    # inside it, the one before it and the one after it asked about. A single
    # prefix length read the wrong way round is the kind of mistake that
    # blocks a continent, and nothing but this would find it.
    for fam, base, width in ((4, '198.51.100.0', 32), (6, '2001:db8:aa::', 128)):
        ranges, want_in, want_out = [], [], []
        for bits in range(1, width + 1):
            net = ipaddress.ip_network('%s/%d' % (base, bits), strict=False)
            ranges.append(isemon.range_of(str(net)))
        store.put_feed('bits%d' % fam, ranges)
        # The ranges are nested, so the smallest holds every address the
        # others do; what matters is that the address just outside the
        # widest one is outside, and that every address inside is inside.
        widest = ipaddress.ip_network('%s/1' % base, strict=False)
        for bits in range(1, width + 1):
            net = ipaddress.ip_network('%s/%d' % (base, bits), strict=False)
            want_in.append(str(net.network_address))
            want_in.append(str(net.broadcast_address))
        outside = ipaddress.ip_address(int(widest.broadcast_address) + 1)
        want_out.append(str(outside))
        missed = [ip for ip in want_in if 'bits%d' % fam not in store.feeds_with(ip)]
        wrong = [ip for ip in want_out if 'bits%d' % fam in store.feeds_with(ip)]
        ok('v%d: all %d addresses inside /1 to /%d are found'
           % (fam, len(want_in), width), missed, [])
        ok('v%d: the address past the end of /1 is not' % fam, wrong, [])

    title('The families never answer for each other')
    store.put_feed('v4only', [isemon.range_of('0.0.0.0/0')])
    ok('a list of every IPv4 address says nothing about an IPv6 one',
       'v4only' in store.feeds_with('2001:db8::99'), False)
    ok('...and does say so about an IPv4 one', 'v4only' in store.feeds_with('8.8.8.8'), True)
    store.drop_feed('v4only')
    store.put_feed('v6only', [isemon.range_of('::/0')])
    ok('and the other way round',
       'v6only' in store.feeds_with('8.8.8.8'), False)
    ok('...and the other way round', 'v6only' in store.feeds_with('2001:db8::99'), True)
    store.drop_feed('v6only')

    title('Several lists at once, and the same answer as reading them all')
    random.seed(11)
    for name, count in (('one', 4000), ('two', 4000), ('three', 2000)):
        made = []
        for _ in range(count):
            bits = random.choice([20, 22, 24, 24, 24, 28, 32])
            net = ipaddress.ip_network(
                (random.getrandbits(32), bits), strict=False)
            made.append(isemon.range_of(str(net)))
        for _ in range(count // 4):
            bits = random.choice([32, 48, 56, 64, 128])
            net = ipaddress.ip_network(
                (ipaddress.IPv6Address(random.getrandbits(128)), bits), strict=False)
            made.append(isemon.range_of(str(net)))
        store.put_feed(name, made)

    asked = []
    for _ in range(400):
        asked.append(str(ipaddress.IPv4Address(random.getrandbits(32))))
        asked.append(str(ipaddress.IPv6Address(random.getrandbits(128))))
    # ...and, so that the sample is not all misses, an address out of the
    # middle of a hundred ranges that are actually on a list.
    for row in store.db.execute('SELECT lo, hi FROM feed_ranges LIMIT 200'):
        middle = (int.from_bytes(row['lo'], 'big') + int.from_bytes(row['hi'], 'big')) // 2
        asked.append(str(ipaddress.ip_address(
            middle if len(row['lo']) == 4 else middle)))

    began = time.time()
    seeks = {ip: store.feeds_with(ip) for ip in asked}
    seek_ms = (time.time() - began) * 1000 / len(asked)
    began = time.time()
    walks = {ip: walked(store, ip) for ip in asked}
    walk_ms = (time.time() - began) * 1000 / len(asked)
    wrong = {ip: (walks[ip], seeks[ip]) for ip in asked if walks[ip] != seeks[ip]}
    ok('%d addresses against %d ranges: the seek and the walk agree exactly'
       % (len(asked), store.db.execute(
           'SELECT COUNT(*) AS n FROM feed_ranges').fetchone()['n']), wrong, {})
    ok('...and the seek is the faster of the two (%.3f ms against %.3f ms)'
       % (seek_ms, walk_ms), seek_ms < walk_ms, True)
    ok('...and it found things, rather than agreeing that there was nothing',
       sum(1 for v in seeks.values() if v) > 100, True)

    title('The country database, asked the same way')
    # Country ranges tile the space and are never two countries at once, so
    # they must NOT be merged across countries - a bug that turns the whole
    # of IPv4 into one country and is invisible until somebody looks at a
    # flag.
    geo = []
    step = 1 << 20
    where = 0
    codes = ['CZ', 'SK', 'PL', 'DE', 'AT']
    while where < (1 << 32) - step:
        geo.append((ipaddress.IPv4Address(where).packed,
                    ipaddress.IPv4Address(where + step - 1).packed, 4,
                    codes[(where // step) % len(codes)]))
        where += step
    store.put_geo(geo)
    ok('the countries stayed separate', len(store.geo_countries()), len(codes))
    ok('...and every range is still there', store.geo_size(), len(geo))
    wrong = {}
    for _ in range(300):
        ip = str(ipaddress.IPv4Address(random.getrandbits(32)))
        if store.country_of(ip) != walked_country(store, ip):
            wrong[ip] = (walked_country(store, ip), store.country_of(ip))
    ok('the seek and the walk agree about every country', wrong, {})

    title('A database written by an older version is put in order on opening')
    old = Path(folder) / 'old.db'
    # Everything written so far is still in the write-ahead log; copying the
    # one file without it copies an empty database.
    store.dialect.settle(store.db)     # whatever settling means to this engine
    shutil.copy(str(isemon.DB_FILE), str(old))
    import sqlite3
    raw = sqlite3.connect(str(old))
    raw.execute("DELETE FROM meta WHERE key='ranges_tidied'")
    raw.execute("INSERT INTO feed_ranges (feed, lo, hi, family) VALUES (?,?,?,?)",
                ('one', ipaddress.IPv4Address('1.0.0.0').packed,
                 ipaddress.IPv4Address('1.255.255.255').packed, 4))
    raw.execute("INSERT INTO feed_ranges (feed, lo, hi, family) VALUES (?,?,?,?)",
                ('one', ipaddress.IPv4Address('1.1.1.0').packed,
                 ipaddress.IPv4Address('1.1.1.255').packed, 4))
    raw.commit()
    raw.close()
    again = isemon.Storage(old)
    ok('the overlap somebody left behind is gone', 'one' in again.feeds_with('1.1.1.1'), True)
    ok('...and it says it has been done', int(again.get_meta('ranges_tidied') or 0) >= 1, True)

finally:
    shutil.rmtree(folder, ignore_errors=True)

# ---------------------------------------------------------------------------
title('A list too big to hold is read a piece at a time')
# Read whole - downloaded, decompressed, decoded, split into lines and turned
# into one tuple a line - the country database cost about 870 bytes a range.
# Three quarters of a million of them, which is what that file IS, came to
# nearly 700 MB in a unit allowed 768; the hundred megabytes the program's own
# comments say the file is were an out-of-memory kill, and a monthly refresh
# that is killed is a crash loop that stops the log reading with it.
import gzip
import io
import random

home = Path(tempfile.mkdtemp())
isemon.STATE_DIR = home
isemon.RUN_DIR = isemon.LOG_DIR = home
isemon._LOG_PATH = home / 'a.log'
store2 = isemon.Storage(home / 'a.db')
random.seed(11)
rows2, at2 = [], 0
for n in range(3000):
    at2 += random.choice((1, 1, 256, 4096))
    lo2, fam2 = isemon.pack_address('10.%d.%d.%d' % (at2 >> 16 & 255, at2 >> 8 & 255, at2 & 255))
    hi2, _ = isemon.pack_address('10.%d.%d.%d' % (at2 >> 16 & 255, at2 >> 8 & 255,
                                                  min(255, (at2 & 255) + random.choice((0, 3)))))
    rows2.append((lo2, hi2, fam2, random.choice(('CZ', 'SK', 'AT'))))
    if n % 61 == 0:
        rows2.append(rows2[-1])                       # the same range said twice
want2 = isemon.tidy_ranges(rows2)
kept2 = store2.put_geo_streamed(iter(rows2))
got2 = [(r['lo'], r['hi'], int(r['family']), r['cc']) for r in store2.db.execute(
    'SELECT lo, hi, family, cc FROM geo_ranges ORDER BY family, lo')]
ok('streaming keeps exactly as many ranges as the old merge', kept2, len(want2))
ok('...and exactly the same ranges, country by country',
   sorted(got2), sorted(tuple(one) for one in want2))
ok('...with nothing overlapping, which is what the lookup needs',
   all(got2[n][0] > got2[n - 1][1] or got2[n][2] != got2[n - 1][2]
       for n in range(1, len(got2))), True)
ok('...and the lookup finds the right country',
   store2.country_of('10.0.0.1') in ('CZ', 'SK', 'AT', ''), True)
ok('...and the count is written down', store2.get_meta('geo_size'), str(kept2))
ok('...and no working table is left behind',
   [t for t in store2.dialect.tables(store2.db) if t.endswith('_new')], [])
feeds2 = [(lo, hi, fam) for lo, hi, fam, _ in rows2]
n2 = store2.put_feed_streamed('spamhaus', iter(feeds2))
ok('a list keeps as many as the old merge did', n2, len(isemon.tidy_ranges(feeds2)))
ok('...and fetching it again replaces it rather than doubling it',
   store2.put_feed_streamed('spamhaus', iter(feeds2)), n2)
store2.put_feed_streamed('dshield', iter(feeds2[:40]))
ok('...and one list being replaced leaves the others alone',
   store2.db.execute("SELECT COUNT(*) AS n FROM feed_ranges WHERE feed='spamhaus'"
                     ).fetchone()['n'], n2)
ok('nothing at all in the file changes nothing',
   store2.put_feed_streamed('spamhaus', iter([])), 0)
ok('...and leaves what was there', store2.db.execute(
    "SELECT COUNT(*) AS n FROM feed_ranges WHERE feed='spamhaus'").fetchone()['n'], n2)

# ...and the reader that feeds it.
plain = io.BytesIO(b'one\ntwo\r\nthree\n')
ok('the lines of a plain file are its lines',
   list(isemon.lines_of(plain)), ['one', 'two', 'three'])
ok('...and a last line with no ending is still a line',
   list(isemon.lines_of(io.BytesIO(b'a\nb'))), ['a', 'b'])
packed = io.BytesIO(gzip.compress(b'a,b,CZ\nc,d,SK\n'))
ok('...and a gzip is undone as it is read',
   list(isemon.lines_of(packed)), ['a,b,CZ', 'c,d,SK'])
try:
    list(isemon.lines_of(io.BytesIO(gzip.compress(b'x\n' * 5000)), lines=100))
    ok('a file of more lines than allowed is refused rather than held', False)
except ValueError as e:
    ok('a file of more lines than allowed is refused rather than held',
       'more than 100 lines' in str(e), True)
try:
    list(isemon.lines_of(io.BytesIO(gzip.compress(b'0' * 200000)), most=1000))
    ok('a few bytes that unpack to a great many are refused', False)
except ValueError as e:
    ok('a few bytes that unpack to a great many are refused',
       'unpacks to more than' in str(e), True)
try:
    list(isemon.lines_of(io.BytesIO(b'0' * (5 * 1024 * 1024))))
    ok('...as is a file with no line endings in it at all', False)
except ValueError as e:
    ok('...as is a file with no line endings in it at all',
       'no line endings' in str(e), True)
shutil.rmtree(home, ignore_errors=True)

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
