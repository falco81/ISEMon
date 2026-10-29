#!/usr/bin/env python3
"""1.10.176: the whole program gone over again - the reading of the logs,
the database (PostgreSQL first), the API, the banning and the router, and
the page.

    ./test/fixes176.py
"""
import gzip
import json
import os
import random
import shutil
import sqlite3
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


source = (HERE.parent / 'isemon.py').read_text(encoding='utf-8')
page = (HERE.parent / 'web' / 'index.php').read_text(encoding='utf-8')

folder = tempfile.mkdtemp(prefix='isemon-176-')
isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = Path(folder) / 'c.db'
isemon.BACKUP_DIR = Path(folder) / 'backups'
isemon.DUMP_DIR = Path(folder) / 'dumps'
isemon.RUN_DIR = Path(folder)
isemon.LOG_DIR = Path(folder)
isemon.CONFIG_FILE = Path(folder) / 'config.json'
isemon._LOG_PATH = Path(folder) / 'c.log'
isemon.TOKEN_FILE = Path(folder) / 'api-token'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({'api_port': 19960, 'geo': 0, 'ise_paths': [folder], 'mikrotik1': 0})
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)
NOW = time.time()
logs = Path(folder) / 'logs'
logs.mkdir()


def lines_of(records):
    return [str(r).rstrip('\n') for r in records]


print('\nA tac_plus line from no time anybody lived in')
when, exact = isemon.tacplus_when('', {'Started': ['99999999999999999999']}, now=NOW)
ok('a start_time of twenty digits is not believed', (when, exact), (None, False))
when, exact = isemon.tacplus_when('', {'Started': ['%d' % (NOW - 60)]}, now=NOW)
ok('...one a minute ago is', (abs(when - (NOW - 60)) < 1.5, exact), (True, True))

print('\nA line the parser cannot take costs that line, not the window')


def picky(lines, hold):
    out = []
    for line in lines:
        if 'BAD' in line:
            raise ValueError('cannot read this one')
        out.append(line)
    return out


path = logs / 'picky.log'
path.write_text('one\ntwo\nBAD three\nfour\n', encoding='utf-8')
tail = isemon.LogTail(str(path), parser=picky)
ok('the lines around it are read', lines_of(tail.read()), ['one', 'two', 'four'])
ok('...and the file is read to its end', tail.offset, path.stat().st_size)



def gathering(lines, hold):
    # Puts lines together until END, as ISE's halves are; falls over on BAD.
    out = []
    for line in lines:
        if 'BAD' in line:
            raise ValueError('cannot read this one')
        hold.setdefault(('rec',), {'at': 0, 'parts': {}})['parts'][len(
            hold[('rec',)]['parts'])] = line
        if line == 'END':
            out.append('+'.join(hold.pop(('rec',))['parts'].values()))
    return out


path = logs / 'gather.log'
path.write_text('a1\na2\n', encoding='utf-8')
tail = isemon.LogTail(str(path), parser=gathering)
tail.read()
with open(path, 'a', encoding='utf-8') as f:
    f.write('END\nBAD\nb1\nEND\n')
ok('a record begun in the window before is whole after a line that fell over',
   lines_of(tail.read()), ['a1+a2+END', 'b1+END'])

print('\nA rotated file compressed, bigger than one pass reads')
path = logs / 'big.log'
body = ''.join('line %06d %s\n' % (k, 'x' * 40) for k in range(20000))
path.write_text('', encoding='utf-8')
tail = isemon.LogTail(str(path), parser=lambda lines, hold: list(lines))
with open(path, 'w', encoding='utf-8') as f:
    f.write(body[:100])
first = lines_of(tail.read())
# Rotated and compressed at once, the way logrotate without delaycompress does.
with open(str(path) + '.1', 'w', encoding='utf-8') as f:
    f.write(body)
with open(str(path) + '.1', 'rb') as f, gzip.open(str(path) + '.1.gz', 'wb') as g:
    g.write(f.read())
os.unlink(str(path) + '.1')
os.unlink(str(path))
path.write_text('new 1\n', encoding='utf-8')
got = list(first)
for _ in range(40):
    got += lines_of(tail.read(limit_bytes=64 * 1024))
    if not getattr(tail, 'prev', None):
        break
ok('every line of it read, over several passes', len([g for g in got if g.startswith('line')]),
   20000)
ok('...none of them twice', len(set(g for g in got if g.startswith('line'))), 20000)

print('\nRotated again before the first rotated copy was read to its end')
path = logs / 'twice.log'
path.write_text('', encoding='utf-8')
tail = isemon.LogTail(str(path), parser=lambda lines, hold: list(lines))
tail.read()
with open(path, 'w', encoding='utf-8') as f:
    f.write(''.join('a %05d %s\n' % (k, 'y' * 60) for k in range(3000)))
got = lines_of(tail.read(limit_bytes=16 * 1024))
os.rename(str(path), str(path) + '.1')
with open(str(path) + '.1', 'a', encoding='utf-8') as f:
    f.write(''.join('b %05d %s\n' % (k, 'y' * 60) for k in range(3000)))
path.write_text('c 1\n', encoding='utf-8')
got += lines_of(tail.read(limit_bytes=16 * 1024))
os.rename(str(path.parent / 'twice.log.1'), str(path.parent / 'twice.log.2'))
os.rename(str(path), str(path) + '.1')
path.write_text('d 1\n', encoding='utf-8')
for _ in range(60):
    got += lines_of(tail.read(limit_bytes=16 * 1024))
ok('the first rotated copy is read to its end', len([g for g in got if g.startswith(('a ', 'b '))]),
   6000)
ok('...and the next one, and the new file', ('c 1' in got, 'd 1' in got), (True, True))

print('\nA file emptied in place, with an old rotated copy beside it')
path = logs / 'empty.log'
(logs / 'empty.log.1').write_text(''.join('OLD %04d\n' % k for k in range(3000)), encoding='utf-8')
path.write_text(''.join('now %04d\n' % k for k in range(100)), encoding='utf-8')
tail = isemon.LogTail(str(path), parser=lambda lines, hold: list(lines))
tail.read()
with open(path, 'w', encoding='utf-8') as f:
    f.write('after 1\n')
got = lines_of(tail.read())
ok('last week’s copy is not read as "recovered"', [g for g in got if g.startswith('OLD')], [])
ok('...and the new line is', 'after 1' in got)

print('\nAn FTD line without a stamp')
line = ('%ASA-6-302014: Teardown TCP connection 123 for outside:1.2.3.4/5 to '
        'inside:10.0.0.1/80 duration 0:00:01 bytes 100 TCP FINs')
a = isemon.ftd_record_from(line, now=NOW)
b = isemon.ftd_record_from(line, now=NOW + 7)
ok('the same id however late it is read', a.facts['ident'], b.facts['ident'])

print('\nISE’s own moment, read once a second')


def ise_time_old(when, offset):
    try:
        return datetime.strptime('%s%s' % (when, offset.replace(':', '')),
                                 '%Y-%m-%d %H:%M:%S.%f%z').timestamp()
    except (ValueError, TypeError):
        return None


cases = [('2026-10-09 13:00:00.500', '+02:00'), ('2026-10-09 13:00:00.5', '+0200'),
         ('2026-10-09 13:00:00', '+02:00'), ('2026-10-09 13:00:00.1234567', '+02:00'),
         ('2026-02-30 13:00:00.5', '+02:00'), ('2026-03-29 02:30:00.000', '+01:00'),
         ('2026-10-09 13:00:00.123456', '-05:30'), ('nothing', 'Z')]
ok('the same moments as reading every one whole',
   [isemon.ise_time(*c) for c in cases], [ise_time_old(*c) for c in cases])

print('\nAn address range in a record is nobody’s address')
fields = {'Tunnel-Client-Endpoint': ['(tag=0) 198.51.100.0/24'],
          'cisco-av-pair': ['ip:source-ip=203.0.113.0/25']}
ok('neither is taken as where it came from', isemon.ise_source_ip(fields), '')

print('\nA ban whose time has run out')
store.block('192.0.2.50', time.time() - 5, 'ran out', auto=True)
store.block('192.0.2.51', time.time() + 600, 'still on', auto=True)
ok('keeps nobody out before the sweep comes', store.blocked_until('192.0.2.50'), None)
ok('...asked many at once as well', store.blocked_lookup()('192.0.2.50'), None)
ok('...while one still on does', store.blocked_until('192.0.2.51') is not None)
ok('the two numbers on the status, counted', store.blocked_tally(), (2, 0))
ok('bans found by the database for the search box',
   [r['ip'] for r in store.find_bans('still')], ['192.0.2.51'])

print('\nA ban by hand, and how long')
for minutes, good in ((-5, False), ('1.5', True), ('0', True), (None, True), (1e308, False),
                      (10 ** 9, False), ('x', False)):
    try:
        got = daemon.ban('192.0.2.%d' % random.randint(100, 200), minutes=minutes, by='t')
        fine = True
        if minutes in ('0', None):
            fine = got['until'] is None
    except ValueError:
        fine = False
    ok('minutes=%r %s' % (minutes, 'taken' if good else 'refused'), fine, good)

print('\nNever kept out, everything')
for value, good in (('0.0.0.0/0', False), ('::/0', False), ('10.0.0.0/8', True)):
    try:
        isemon.check_setting('never_block', value)
        fine = True
    except ValueError:
        fine = False
    ok('%s %s' % (value, 'taken' if good else 'refused'), fine, good)

print('\nA configuration imported')
store.block('192.0.2.70', None, 'for good already', auto=False)
said = daemon.import_config({'_what': 'isemon configuration', 'blocked': [
    {'ip': '::FFFF:192.0.2.71', 'until': None, 'why': 'mapped'},
    {'ip': '192.0.2.70', 'until': time.time() + 60, 'why': 'shorter'},
    {'ip': '0.0.0.0/0', 'until': None, 'why': 'everything'},
    {'ip': '192.0.2.72', 'until': 'soon', 'why': 'broken'}],
    'whitelist': [{'ip': '0.0.0.0/0'}, {'ip': '::ffff:198.51.100.9'}]}, by='t')
ok('an address written the IPv6 way is banned as itself',
   store.blocked_until('192.0.2.71', networks=False), 0)
ok('...a ban for good is not cut short by an older export',
   store.blocked_until('192.0.2.70', networks=False), 0)
ok('...everything is not banned, and a broken time is left out',
   (store.blocked_until('0.0.0.0/0', networks=False),
    store.blocked_until('192.0.2.72', networks=False)), (None, None))
ok('...the whitelist takes the one address, written its own way, and not everything',
   sorted(r['ip'] for r in store.whitelist()), ['198.51.100.9'])

print('\nBans written another way than the one compared by')
with store.db_write() as db:
    db.execute("INSERT INTO blocked (ip, since, until, why, hits, auto, by) "
               "VALUES ('2001:DB8::7', ?, NULL, 'upper', 0, 0, '')", (time.time(),))
    db.execute("DELETE FROM meta WHERE key = 'mended_ban_spellings'")
store.mend_ban_spellings()
ok('written again the one way', [r['ip'] for r in store.blocked_all() if 'db8' in r['ip'].lower()],
   ['2001:db8::7'])
ok('...and the Unban button finds it', daemon.unban('2001:DB8::7', by='t') is not None)

print('\nSettings with a list that has no name')
isemon.CONFIG['geolist_name'] = 'isemon-geo'
try:
    daemon.save_settings({'geolist_name': ''}, by='t')
    fine = True
except ValueError as e:
    fine = 'name' not in str(e)
ok('saved without falling over after it was saved', fine)

print('\nThe tabs count the window the list shows')
for k in range(5):
    store.add_failed({'session': 'w%d' % k, 'ts': NOW - 7200 + k * 1800, 'ip': '203.0.113.%d' % k,
                      'username': 'u', 'kind': 'vpn', 'server': 'ise1'})
ok('from and to', store._failed_kinds_now(NOW - 7300, NOW - 3000)['vpn'], 3)
ok('...and from alone', store._failed_kinds_now(NOW - 7300)['vpn'], 5)

print('\nThe events, counted only where the page is full')
rows, total = store.events(limit=500)
ok('a first page holding everything is the count', total, len(rows))

print('\nA list worked out while the data was erased is not kept')
daemon._lists_gen = 0
gen_seen = []


def make():
    gen_seen.append(1)
    daemon.forget_all_kept('a test')          # the erase, while it was worked out
    return [{'a': 1}], 1


daemon.listed('k/test', make)
ok('not kept', 'k/test' in daemon._lists, False)

print('\nA flag two presses set at once')
daemon._testing_flag = False
ok('the first press has it', daemon.claim('_testing_flag'))
ok('...the second does not', daemon.claim('_testing_flag'), False)

ok('the token list\u2019s own answers do not stand for the list\u2019s window',
   "list_until = asked['until']" in source and "until=asked['until'])" not in source)

def vpn_lines(n, people, seed):
    r = random.Random(seed)
    out = []
    ts = NOW - 6 * 86400
    for k in range(n):
        ts += r.random() * 30
        who = 'user%02d' % r.randrange(people)
        ip = '198.51.100.%d' % r.randrange(1, 40)
        inner = '10.8.0.%d' % r.randrange(1, 30)
        fw = r.choice(['ftd-a', 'ftd-a', 'ftd-b'])
        roll = r.random()
        if roll < 0.2:
            msgid, f = r.choice(['113039', '722022', '716001']), {}
        elif roll < 0.35:
            msgid, f = r.choice(['113019', '716002']), {'reason': 'User Requested'}
        elif roll < 0.5:
            msgid, f = '737016', {'assigned': inner}
            if r.random() < 0.5:
                who = ''
        elif roll < 0.6:
            msgid, f = r.choice(['109210', '737031']), {'assigned': inner}
            who = ''
        elif roll < 0.75:
            msgid, f = '722051', {'assigned': inner, 'group_policy': 'GP%d' % r.randrange(3)}
            if r.random() < 0.3:
                f['handle'] = 'h%d' % r.randrange(20)
        elif roll < 0.85:
            msgid, f = '737006', {'handle': 'h%d' % r.randrange(20), 'pool': 'P1',
                                  'assigned': inner}
            who = ''
        elif roll < 0.92:
            msgid, f = r.choice(['722037', '722035']), {'reason': 'DPD', 'packet': '1500',
                                                        'threshold': '1400'}
        else:
            msgid, f = '', {'tunnelid': str(r.randrange(1, 9)), 'assigned': inner}
        f['msgid'] = msgid
        out.append({'ts': ts, 'fw': fw, 'dev': fw, 'area': 'client-vpn', 'type': 'event',
                    'sub': 'vpn', 'action': r.choice(['tunnel-up', 'tunnel-stats', 'tunnel-down',
                                                      '']) if not msgid else '',
                    'verdict': r.choice(['', '', '', 'fail']) if r.random() < 0.1 else '',
                    'srcip': ip, 'dstip': '', 'user': who, 'msg': '', 'sent': r.randrange(9999),
                    'rcvd': r.randrange(9999), 'duration': r.randrange(0, 900),
                    'fields': f})
        if r.random() < 0.05:
            out.append({'ts': ts, 'fw': fw, 'dev': fw, 'area': 's2s-vpn', 'type': 'event',
                        'sub': 'vpn', 'action': r.choice(['tunnel-up', 'tunnel-down',
                                                          'tunnel-stats', 'install_sa']),
                        'verdict': '', 'srcip': '203.0.113.%d' % r.randrange(1, 6),
                        'dstip': '192.0.2.1', 'user': '', 'msg': '', 'sent': 1, 'rcvd': 1,
                        'duration': 60, 'fields': {'spi': str(r.randrange(99))}})
    return out



print('\nThe VPN as it stands, made from what arrived since the last look')
rows = vpn_lines(8000, 60, 176)
whole = isemon.fw_vpn_fold(json.loads(json.dumps(rows)), NOW)
feed, result = isemon.fw_vpn_folder()
said = []
for at in range(0, len(rows), 997):
    feed(json.loads(json.dumps(rows[at:at + 997])))
    said.append(result(NOW))              # looked at between, as the page does
ok('fed a piece at a time, looked at between: the same clients and tunnels',
   json.dumps(said[-1], sort_keys=True), json.dumps(whole, sort_keys=True))
ok('...and what was handed out before is not changed by what came after',
   json.dumps(said[0], sort_keys=True) == json.dumps(
       isemon.fw_vpn_fold(json.loads(json.dumps(rows[:997])), NOW), sort_keys=True))

print('\nThe public lists, held in memory')
store.put_feed('listA', [(isemon.pack_address('198.51.100.0')[0],
                          isemon.pack_address('198.51.100.255')[0], 4),
                         (isemon.pack_address('203.0.113.8')[0],
                          isemon.pack_address('203.0.113.8')[0], 4)])
store.put_feed('listB', [(isemon.pack_address('198.51.100.128')[0],
                          isemon.pack_address('198.51.100.200')[0], 4)])
asked = ['198.51.100.7', '198.51.100.150', '203.0.113.8', '203.0.113.9', '2001:db8::1']
from_memory = [sorted(store.feeds_with(ip)) for ip in asked]
store.FEED_INDEX_MOST = 0                  # too many to hold: asked of the database
store._feed_index = None
from_db = [sorted(store.feeds_with(ip)) for ip in asked]
store.FEED_INDEX_MOST = isemon.Storage.FEED_INDEX_MOST
store._feed_index = None
ok('the same lists for each address, from memory and from the database',
   from_memory, from_db)
ok('...and the right ones', from_memory, [['listA'], ['listA', 'listB'], ['listA'], [], []])
store.drop_feed('listB')
ok('a list dropped is dropped from memory too', sorted(store.feeds_with('198.51.100.150')),
   ['listA'])
ok('the router\u2019s sync no longer works out the whole Banned page',
   "want = {same_address(r['ip']): r for r in self._blocked_for_router()}" in source)

print('\nThe router')
ok('each command in a batch has an on-error of its own',
   "'; '.join(':do { %s } on-error={}' % one" in source
   and "':do { %s } on-error={}' % '; '.join(" not in source)
ok('a ban longer than RouterOS keeps a timeout is written without one',
   'left > self.MIKROTIK_TIMEOUT_MOST' in source)
ok('...the most it keeps is under 35 weeks and 3 days',
   isemon.Daemon.MIKROTIK_TIMEOUT_MOST < (35 * 7 + 3) * 86400)

print('\nThe database server (PostgreSQL)')
ok('the counted buckets’ days are made with room in each page',
   store.split_leaf_with(isemon.Storage.SPLIT['fw_roll']), ' WITH (fillfactor = 70)')
ok('...the lines’ days as before', store.split_leaf_with(isemon.Storage.SPLIT['fw_events']), '')
ok('two indexes the refusals carry for nothing, on PostgreSQL only',
   [n for n, _w in isemon.Storage.REDUNDANT_ON_PG], ['failed_kind_ts', 'failed_country_ts'])
ok('connections are named, and an idle transaction let go',
   "more['application_name']" in source and 'idle_in_transaction_session_timeout' in source)
ok('the writes of what was read are not waited on to reach the disk',
   # ...and the names of addresses since 1.10.192
   source.count('self.commit_lazily(db)') + source.count('store.commit_lazily(db)'), 4)
ok('a statement stopped at its limit leaves its connection usable',
   'self.broken = bool(self.in_tx) or not statement_stopped(e)' in source)
ok('the tuning asks for a quarter-hour checkpoint and a cap on each vacuum’s memory',
   {'checkpoint_timeout', 'autovacuum_work_mem'} <= set(isemon.TUNE_PG_NAMES))
plan = {it['name']: it['want'] for it in isemon.tune_plan_pg(
    {'ram': 32 * 1024 ** 3, 'cpus': 8, 'disk': 'ssd'}, {})}
ok('...a quarter of an hour', plan['checkpoint_timeout'], 900)
ok('...and a gigabyte at most for each', plan['autovacuum_work_mem'] <= 1024 ** 3)
if store.dialect.name == 'postgres':
    with store.db_write() as db:
        db.execute("DELETE FROM meta WHERE key = 'mended_pg_tables'")
    store.mend_pg_tables()
    opts = store.db.execute("SELECT reloptions FROM pg_class WHERE relname = 'failed'"
                            ).fetchone()['reloptions'] or []
    ok('the refusals are looked at by vacuum after 2% more',
       any('autovacuum_analyze_scale_factor=0.02' in str(o) for o in opts))
    store.release()
    with isemon.statement_limit(1):
        conn = store.db
        try:
            store.db.execute('SELECT pg_sleep(3)').fetchall()
        except sqlite3.Error:
            pass
        ok('...the connection stopped at its limit is not thrown away', conn.broken, False)
    store.release()
    name = store.db.execute('SELECT current_setting(\'application_name\') AS n').fetchone()['n']
    ok('the connection says whose it is', str(name).startswith('isemon'))

print('\nThe page')
ok('a database restored only with a header of ours',
   "HTTP_X_ISEMON_RESTORE" in page and "'X-Isemon-Restore': '1'" in page)
ok('the ban list draws only the newest answer', 'if (mine !== BANS_ASKED) return;' in page)
ok('closing a job’s popup does not stop what comes after it',
   'var shut = false;' in page and 'if (stop) return;' not in page)
ok('a value inside explained words is escaped once', 'function wordsIn(text)' in page
   and "richText(r.fw) + '</b>" not in page)
ok('sizes sorted in 1024s, as they are written', 'kB: 1024, KB: 1024' in page)
ok('a page past the end goes to the last', 'if (total > 0 && page >= pages && go && !capped)' in page)
ok('yesterday starts at midnight across a change of the clocks',
   "['yesterday', function () { return [midnight(1), today]; }]" in page)
ok('the firewall’s values in suggestions are not translated',
   "row.appendChild(noI18n(el('span', 't-sug-val'" in page)
ok('the Domain page does not ask while hidden', "if (TAB === 'windows' && !document.hidden) "
   "loadWindows(true);" in page)

shutil.rmtree(folder, ignore_errors=True)
print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
