#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
router.py - the whole router half, against a Mikrotik that is not there.

mockrouter.py stands in for ssh and answers the way RouterOS does. What is
being tested is the part nobody can test on a live firewall without either
trusting it or breaking it: that a sync sends what it should, that taking ours
off takes only ours, that somebody else's entries survive all of it, and that
a country list of tens of thousands of prefixes goes out in batches rather
than one ssh call at a time.

    ./test/router.py
"""
import ipaddress
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import isemon                                       # noqa: E402

PASS, FAIL = 0, 0


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


folder = tempfile.mkdtemp(prefix='isemon-router-')
bin_dir = Path(folder) / 'bin'
bin_dir.mkdir()
shutil.copy(str(HERE / 'mockrouter.py'), str(bin_dir / 'ssh'))
os.chmod(str(bin_dir / 'ssh'), 0o755)
os.environ['PATH'] = str(bin_dir) + os.pathsep + os.environ['PATH']
os.environ['MOCK_ROUTER_STATE'] = str(Path(folder) / 'router.json')
isemon._SSH_THERE = None

isemon.STATE_DIR = Path(folder)
isemon.DB_FILE = Path(folder) / 'r.db'
isemon.BACKUP_DIR = Path(folder) / 'backups'
isemon.DUMP_DIR = Path(folder) / 'dumps'
isemon.RUN_DIR = Path(folder)
isemon.LOG_DIR = Path(folder)
isemon._LOG_PATH = Path(folder) / 'r.log'
isemon.CONFIG.clear()
isemon.CONFIG.update(isemon.DEFAULTS)
isemon.CONFIG.update({
    'mikrotik_host': '10.0.0.1', 'mikrotik_user': 'isemon', 'mikrotik_auth': 'password',
    'mikrotik_password': 'x', 'mikrotik_list': 'isemon', 'mikrotik_sync': 0,
    'geolist': 1, 'geolist_name': 'isemon-geo', 'geolist_countries': 'CZ, SK',
    'geolist_chunk': 50, 'geo': 0,
})
store = isemon.Storage(isemon.DB_FILE)
daemon = isemon.Daemon(store)


# One file per router: there can be two of them, and the tests around a pair
# are all about what happens when the two hold different things.
FIRST = '10.0.0.1'
SECOND = '10.0.0.2'


def router_file(host=FIRST):
    return Path(folder) / ('router-%s.json' % host)


def router(host=FIRST):
    try:
        return json.loads(router_file(host).read_text())
    except (OSError, ValueError):
        return {'entries': [], 'log': [], 'calls': 0}


def put(state, host=FIRST):
    router_file(host).write_text(json.dumps(state))


def entries(listed=None, host=FIRST):
    return [e for e in router(host)['entries'] if listed is None or e['list'] == listed]


def calls(host=FIRST):
    return router(host)['calls']


try:
    title('Reaching it at all')
    ok('it answers', daemon.mikrotik_run('/system identity print').strip(), 'name: MockTik')
    # "Try reaching it" said the name one letter to a line: RouterOS lays a
    # print out for a terminal ssh does not have.
    ok('trying it says the name on one line', daemon.mikrotik_identity(), 'name: MockTik')
    os.environ['MOCK_ROUTER_NO_PUT'] = '1'
    os.environ['MOCK_ROUTER_NARROW'] = '1'
    ok('...and a print wrapped a letter to a line is put back together',
       daemon.mikrotik_identity(), 'name: MockTik')
    del os.environ['MOCK_ROUTER_NO_PUT'], os.environ['MOCK_ROUTER_NARROW']
    ok('a wrapped value with more fields after it is mended field by field',
       isemon.unwrap_router_print('name: CORP\n      NET-X\nother: 1\n  2'),
       'name: CORPNET-X\nother: 12')

    title('Somebody else was here first')
    # Two entries a person put on the same list by hand, and one on a list of
    # their own. None of them carries our mark, and none of them may move.
    for one in [{'family': '/ip', 'list': 'isemon', 'address': '10.9.9.9',
                 'comment': 'put here by hand, do not touch'},
                {'family': '/ip', 'list': 'isemon', 'address': '10.9.9.10', 'comment': ''},
                {'family': '/ip', 'list': 'their-own-list', 'address': '10.8.8.8',
                 'comment': 'nothing of ours'},
                {'family': '/ip', 'list': 'isemon-geo', 'address': '10.7.7.7',
                 'comment': 'theirs, on the country list'}]:
        state = router()
        state['entries'].append(one)
        put(state)

    title('Putting the banned list on it')
    store.block('45.9.148.9', None, 'for good')
    store.block('81.200.10.0/24', None, 'a whole street')
    store.block('2a01:430:17::5', time.time() + 3600, 'an hour')
    said = daemon.mikrotik_sync('a test')
    ok('three of ours went on', said['added'], 3)
    ok('...and nothing was taken off', said['removed'], 0)
    ok('...and it knew two were not its business', said['kept'], 2)
    ours = [e for e in entries('isemon') if e['comment'].startswith('isemon:')]
    ok('the router holds all three', sorted(e['address'] for e in ours),
       ['2a01:430:17::5', '45.9.148.9', '81.200.10.0/24'])
    ok('IPv6 went in the IPv6 list',
       [e['family'] for e in ours if ':' in e['address']], ['/ipv6'])
    ok('a subnet went on as a subnet',
       [e['address'] for e in ours if '/' in e['address']], ['81.200.10.0/24'])
    ok('one that runs out carries a timeout',
       bool([e for e in ours if e['address'] == '2a01:430:17::5'][0]['timeout']), True)
    ok('one that is for good does not',
       [e for e in ours if e['address'] == '45.9.148.9'][0]['timeout'], None)
    ok('the two somebody put there by hand are still there',
       sorted(e['address'] for e in entries('isemon')
              if not e['comment'].startswith('isemon:')), ['10.9.9.10', '10.9.9.9'])

    title('Doing it again changes nothing')
    before = len(entries())
    said = daemon.mikrotik_sync('again')
    ok('nothing is added a second time', (said['added'], said['removed']), (0, 0))
    ok('...and the list is the same length', len(entries()), before)

    title('An address written two ways is one address')
    # The router prints an IPv6 single address back as a /128. Comparing those
    # as text made every IPv6 entry look missing, so it was added again on
    # every sync and the router answered "already have such entry" every time.
    state = router()
    for e in state['entries']:
        if e['address'] == '2a01:430:17::5':
            e['address'] = '2A01:0430:0017:0000:0000:0000:0000:0005/128'
    put(state)
    said = daemon.mikrotik_sync('after the router rewrote it')
    ok('it is recognised, not added again', said['added'], 0)

    title('Letting one back in takes it off')
    store.unblock('45.9.148.9')
    said = daemon.mikrotik_sync('after an unban')
    ok('it came off', said['removed'], 1)
    ok('...and only it', sorted(e['address'] for e in entries('isemon')
                                if e['comment'].startswith('isemon:')),
       ['2A01:0430:0017:0000:0000:0000:0000:0005/128', '81.200.10.0/24'])

    title('Never kept out means never on the router')
    store.block('192.0.2.5', None, 'banned before the setting changed')
    isemon.CONFIG['never_block'] = '192.0.2.0/24'
    daemon._spare_from = None
    said = daemon.mikrotik_sync('with a spared address on the list')
    ok('a spared address is never sent', said['added'], 0)
    ok('...and is not on the router',
       [e for e in entries('isemon') if e['address'] == '192.0.2.5'], [])
    isemon.CONFIG['never_block'] = ''
    daemon._spare_from = None
    store.unblock('192.0.2.5')

    title('The country list')
    # A few thousand ranges, made up, so the batching is really exercised.
    #
    # Every other /24, with a gap between: ranges of one country that touch
    # each other are joined into one when they are stored, which is right -
    # two halves of a subnet are one subnet and there is no sense putting
    # both on a router - but a made-up country of fifteen hundred touching
    # /24s would arrive here as a handful of ranges and the batching this is
    # here to exercise would never happen.
    rows = []
    for i in range(1500):
        n = i * 2
        lo = ipaddress.ip_address('81.%d.%d.0' % (n // 256, n % 256)).packed
        hi = ipaddress.ip_address('81.%d.%d.255' % (n // 256, n % 256)).packed
        rows.append((lo, hi, 4, 'CZ'))
    for i in range(200):
        n = i * 2
        lo = ipaddress.ip_address('95.%d.%d.0' % (n // 256, n % 256)).packed
        hi = ipaddress.ip_address('95.%d.%d.255' % (n // 256, n % 256)).packed
        rows.append((lo, hi, 4, 'SK'))
    for i in range(50):
        net = ipaddress.ip_network('2a02:%x::/32' % (0x100 + i * 2))
        rows.append((net.network_address.packed, net.broadcast_address.packed, 6, 'CZ'))
    store.put_geo(rows)
    daemon._geo_any = True

    plan = daemon.geolist_plan()
    ok('the plan counts what is there', plan['ranges'], 1750)
    ok('...and names the countries', [c['cc'] for c in plan['countries']], ['CZ', 'SK'])

    seen = []
    before_calls = calls()
    said = daemon.geolist_sync('a test', progress=lambda d, t, w: seen.append((d, t, w)))
    ok('every range went on', said['added'], 1750)
    geo = [e for e in entries('isemon-geo') if e['comment'].startswith('isemon-geo:')]
    ok('the router is carrying them', len(geo), 1750)
    ok('...on the country list, not the ban list',
       len([e for e in entries('isemon') if e['comment'].startswith('isemon-geo:')]), 0)
    ok('IPv6 ranges went in the IPv6 list',
       len([e for e in geo if e['family'] == '/ipv6']), 50)
    ok('each entry says which country it is',
       sorted(set(e['comment'] for e in geo)), ['isemon-geo:CZ', 'isemon-geo:SK'])
    ok('somebody else’s entry on that list survived',
       [e['address'] for e in entries('isemon-geo')
        if not e['comment'].startswith('isemon-geo:')], ['10.7.7.7'])
    ok('the ban list was not touched',
       len([e for e in entries('isemon') if e['comment'].startswith('isemon:')]), 2)
    # 1750 lines at 50 to a batch is 35 sends, plus the reads and the clears.
    ok('it was sent in batches, not one ssh call per line',
       calls() - before_calls < 60, True)
    ok('...and it said so as it went', len(seen) > 10, True)
    ok('the last thing it said counts them all', seen[-1][0], 1750)
    # A count past its own total is a total that was wrong. The progress is
    # counted in LINES sent, so the total has to be lines and not the ranges
    # in the database - one range is several prefixes, and the bar used to
    # finish at "14 000 of 10 306".
    ok('nothing it reported ever went past its own total',
       [x for x in seen if x[1] and x[0] > x[1]], [])
    ok('...and the total is the number of lines, not of ranges',
       sorted({x[1] for x in seen}), [1750])

    title('Filling it again replaces rather than piles up')
    said = daemon.geolist_sync('again')
    ok('the same number is on it', len([e for e in entries('isemon-geo')
                                        if e['comment'].startswith('isemon-geo:')]), 1750)
    ok('...and theirs is still there',
       len([e for e in entries('isemon-geo')
            if not e['comment'].startswith('isemon-geo:')]), 1)

    title('A burst of bans is one sync, not one each')
    # A pass over a busy ISE log bans two hundred addresses in under a second.
    # Each one used to start its own sync, and each sync reads the whole list
    # off the router before it writes - two hundred round trips for one piece
    # of work.
    isemon.CONFIG['mikrotik_sync'] = 1
    daemon.MIKROTIK_SETTLE_S = 0.3
    before_calls = calls()
    for n in range(25):
        store.block('198.19.%d.9' % n, None, 'a burst')
        daemon.mikrotik_after_change()
    for _ in range(80):
        time.sleep(0.1)
        with daemon._mikrotik_want:
            if not daemon._mikrotik_busy:
                break
    spent = calls() - before_calls
    on_it = [e['address'] for e in entries('isemon')
             if e['comment'].startswith('isemon:') and e['address'].startswith('198.19.')]
    ok('every one of the burst reached the router', len(on_it), 25)
    ok('...in one sync rather than twenty-five', spent < 8, True)
    for n in range(25):
        store.unblock('198.19.%d.9' % n)
    daemon.mikrotik_sync('tidying the burst away')
    isemon.CONFIG['mikrotik_sync'] = 0
    daemon.MIKROTIK_SETTLE_S = 2.0

    title('The banned list goes on in batches, not one call per address')
    # Three hundred bans used to be three hundred ssh round trips. A router
    # on the other side of a site answers in a few hundred milliseconds, so
    # that was minutes of waiting for a second of work.
    daemon.mikrotik_purge('blocked')
    for n in range(120):
        store.block('192.0.2.%d' % (n % 250) if n < 250 else '198.18.%d.1' % (n - 250),
                    None, 'a batching test')
    for n in range(120):
        store.block('198.18.%d.7' % n, None, 'a batching test')
    isemon.CONFIG['mikrotik_chunk'] = 40
    before_calls = calls()
    said = daemon.mikrotik_sync('in batches')
    spent = calls() - before_calls
    on_it = len([e for e in entries('isemon') if e['comment'].startswith('isemon:')])
    ok('every one of them went on', on_it >= 120, True)
    # 120-odd adds at 40 to a call is 3 sends, plus the read before and the
    # check after. One call per address would be 120.
    ok('...in a handful of calls rather than one each', spent < 12, True)
    ok('...and it says how many', said['added'] >= 120, True)
    # ...and a second sync sends nothing at all.
    before_calls = calls()
    said = daemon.mikrotik_sync('again')
    ok('doing it again sends no adds', said['added'], 0)
    ok('...and costs one call to look', calls() - before_calls <= 2, True)
    for row in list(store.blocked_all()):
        if (row['why'] or '') == 'a batching test':
            store.unblock(row['ip'])
    daemon.mikrotik_sync('tidying the batching test away')

    title('One press puts everything on it')
    daemon.mikrotik_purge('both')
    job = daemon.mikrotik_job(by='a test')
    for _ in range(600):
        if job['done']:
            break
        time.sleep(0.05)
    ok('the job finished', job['done'] and job['ok'], True)
    ok('...and the ban list went on',
       len([e for e in entries('isemon') if e['comment'].startswith('isemon:')]), 2)
    ok('...and the country list went on in the same press',
       len([e for e in entries('isemon-geo')
            if e['comment'].startswith('isemon-geo:')]), 1750)
    ok('...and it says what it did to both',
       'the blocked list' in job['result']['message']
       and 'the country list' in job['result']['message'], True)

    title('Whether each list is in sync, said in one place')
    state = daemon.router_picture()['state']
    ok('the banned list is in sync after a sync', state['blocked']['in_sync'], True)
    ok('...and says how many of ours are on it', state['blocked']['on_router'], 2)
    ok('...and counts what somebody else put there separately',
       state['blocked']['theirs'], 2)
    ok('the country list is in sync too', state['geo']['in_sync'], True)
    ok('...against the number that was actually sent', state['geo']['want'], 1750)

    # The countries all taken off after a fill: nothing should be on it now,
    # whatever that fill put there.
    was = isemon.CONFIG['geolist_countries']
    isemon.CONFIG['geolist_countries'] = ''
    state = daemon.router_picture()['state']
    ok('with no country chosen, nothing is expected on the country list',
       state['geo']['want'], 0)
    ok('...so what the last fill left there is out of sync, not taken as expected',
       state['geo']['in_sync'], False)
    daemon.mikrotik_purge('geo')
    state = daemon.router_picture()['state']
    ok('...and an emptied list with no country chosen is in sync',
       (state['geo']['on_router'], state['geo']['in_sync']), (0, True))
    isemon.CONFIG['geolist_countries'] = was
    job = daemon.mikrotik_job(by='a test')
    for _ in range(600):
        if job['done']:
            break
        time.sleep(0.05)
    state = daemon.router_picture()['state']
    ok('...and choosing them again fills it back in sync', state['geo']['in_sync'], True)

    store.block('203.0.113.99', None, 'banned but never written', auto=True)
    state = daemon.router_picture()['state']
    ok('an address banned here and not there puts it out of sync',
       (state['blocked']['in_sync'], state['blocked']['missing']), (False, 1))
    store.unblock('203.0.113.99')

    # Something of ours on the router that nothing here bans any more.
    daemon.mikrotik_run('/ip firewall address-list add list=isemon '
                        'address=203.0.113.98 comment="isemon: left behind"')
    state = daemon.router_picture()['state']
    ok('...and so does one of ours on the router that nothing bans',
       (state['blocked']['in_sync'], state['blocked']['extra']), (False, 1))
    ok('...and it says which', state['blocked']['extra_few'], ['203.0.113.98'])
    daemon.mikrotik_run('/ip firewall address-list remove '
                        '[find list=isemon address=203.0.113.98 comment~"^isemon:"]')

    title('Taking ours off, and only ours')
    said = daemon.mikrotik_purge('both')
    ok('nothing of ours is left on the ban list',
       [e for e in entries('isemon') if e['comment'].startswith('isemon:')], [])
    ok('nothing of ours is left on the country list',
       [e for e in entries('isemon-geo') if e['comment'].startswith('isemon-geo:')], [])
    ok('the two put on the ban list by hand are untouched',
       sorted(e['address'] for e in entries('isemon')), ['10.9.9.10', '10.9.9.9'])
    ok('theirs on the country list is untouched',
       [e['address'] for e in entries('isemon-geo')], ['10.7.7.7'])
    ok('their own separate list was never even mentioned',
       [e['address'] for e in entries('their-own-list')], ['10.8.8.8'])
    ok('it says how many it took off', said['taken']['isemon']['gone'], 2)

    title('Taking off only one of the two lists')
    daemon.mikrotik_sync('putting them back')
    daemon.geolist_sync('putting them back')
    daemon.mikrotik_purge('geo')
    ok('the country list is empty of ours',
       [e for e in entries('isemon-geo') if e['comment'].startswith('isemon-geo:')], [])
    ok('...and the ban list is not',
       len([e for e in entries('isemon') if e['comment'].startswith('isemon:')]), 2)

    title('When the router cannot be reached')
    os.environ['MOCK_ROUTER_DOWN'] = '*'          # every router is away
    try:
        daemon.mikrotik_sync('with the router away')
        ok('a sync to a router that is away raises', False)
    except RuntimeError as e:
        ok('a sync to a router that is away raises', 'refused' in str(e).lower()
           or 'connect' in str(e).lower())
    daemon._mikrotik_peek()
    ok('...and the trouble is written down where the page can show it',
       bool(store.get_meta('mikrotik_trouble')), True)
    os.environ.pop('MOCK_ROUTER_DOWN')
    daemon._mikrotik_peek()
    ok('...and cleared when it comes back', store.get_meta('mikrotik_trouble'), '')

    title('Reading the list back beside what is known here')
    picture = daemon.router_picture()
    ok('it reads the list', len(picture['carrying']) >= 2, True)
    ours_now = [r for r in picture['carrying'] if r['ours']]
    ok('ours are marked as ours', len(ours_now), 2)
    ok('...and carry the reason from here',
       all(r['why'] for r in ours_now), True)
    ok('theirs are marked as not ours',
       sorted(r['address'] for r in picture['carrying'] if not r['ours']),
       ['10.9.9.10', '10.9.9.9'])

    title('The list is refused while banning is switched off')
    isemon.CONFIG['blacklist'] = 0
    try:
        daemon.mikrotik_sync('with banning off')
        ok('a sync is refused while banning is off', False)
    except ValueError:
        ok('a sync is refused while banning is off', True)
    isemon.CONFIG['blacklist'] = 1

    title('Two lists may not share a name')
    isemon.CONFIG['geolist_name'] = 'isemon'
    try:
        daemon.geolist_sync('with one name for both')
        ok('a country sync into the ban list is refused', False)
    except ValueError:
        ok('a country sync into the ban list is refused', True)
    isemon.CONFIG['geolist_name'] = 'isemon-geo'

    title('The country list is counted on the router, not assumed')
    def set_router(key, value):
        state = router()
        state[key] = value
        put(state)


    got = daemon.geolist_count()
    ok('both families answer with a number',
       [isinstance(got.get('v4'), int), isinstance(got.get('v6'), int)], [True, True])
    # Ours, and only ours: an entry somebody else put on that list is never
    # touched by this, so counting it would make a list that is exactly right
    # read as one more than expected for ever.
    ok('...and it counts ours and not somebody else\u2019s',
       got['v4'] + got['v6'],
       sum(1 for e in router()['entries']
           if e['list'] == daemon.mikrotik_name(isemon.CONFIG['geolist_name'])
           and str(e.get('comment') or '').startswith(daemon.GEO_MARK)))
    picture = daemon.geolist_picture()
    ok('the picture says what is carried', picture['total'], got['v4'] + got['v6'])
    ok('...and compares it with what the last fill sent',
       picture['should_be_entries'] is not None, True)
    ok('...and has no trouble to report', picture['trouble'], '')

    # A router that will not say how many is not a router saying nought: an
    # invented zero reads as "the list is empty", which is a different and far
    # more alarming thing to be wrong about.
    set_router('mute_count', True)
    quiet = daemon.geolist_count()
    ok('a router that answers with nothing says nothing, not zero',
       [quiet['v4'], quiet['v6']], [None, None])
    shy = daemon.geolist_picture()
    ok('...so the page is told it could not be counted', shy['total'], None)
    ok('...and says so', 'would not say' in (shy['trouble'] or ''), True)
    set_router('mute_count', False)

    # ------------------------------------------------------------------
    title('A pair of firewalls, kept saying the same thing')
    # This is what the second one is for: two machines in high availability,
    # where whichever of them is carrying the traffic at any moment has to
    # already hold every address the other does. Anything less is a ban that
    # works until the pair fails over.
    isemon.CONFIG.update({'mikrotik2': 1, 'mikrotik2_host': SECOND,
                          'mikrotik2_user': 'isemon', 'mikrotik2_auth': 'password',
                          'mikrotik2_password': 'x'})
    ok('both of them are now in use', daemon.firewalls(), ['mikrotik', 'mikrotik2'])
    ok('...and the first one still answers on its own',
       daemon.mikrotik_run('/system identity print').strip(), 'name: MockTik')
    ok('...and so does the second, at its own address',
       daemon.mikrotik_run('/system identity print', fw='mikrotik2').strip(), 'name: MockTik')

    said = daemon.mikrotik_sync_all('a pair')
    ok('one press writes to both', sorted(said['firewalls']), ['mikrotik', 'mikrotik2'])
    ok('...and nothing went wrong on either', said['trouble'], {})
    first_has = sorted(e['address'] for e in entries('isemon', FIRST)
                       if e['comment'].startswith('isemon:'))
    second_has = sorted(e['address'] for e in entries('isemon', SECOND)
                        if e['comment'].startswith('isemon:'))
    ok('...and the second one is carrying exactly what the first is',
       second_has, first_has)
    ok('...which is not nothing', len(second_has) > 0, True)

    # Somebody else's entries on the second one are as untouchable as they
    # are on the first.
    state = router(SECOND)
    state['entries'].append({'family': '/ip', 'list': 'isemon', 'address': '10.6.6.6',
                             'comment': 'theirs, on the second one'})
    put(state, SECOND)
    daemon.mikrotik_sync_all('again')
    ok('an address somebody put on the second one by hand is left alone',
       [e['address'] for e in entries('isemon', SECOND) if e['address'] == '10.6.6.6'],
       ['10.6.6.6'])

    title('...and the page says whether they agree')
    picture = daemon.router_picture()
    ok('it reports both', [w['fw'] for w in picture['firewalls']],
       ['mikrotik', 'mikrotik2'])
    ok('...and says they are saying the same thing', picture['agree'], True)
    ok('...with nothing differing', picture['differs_n'], 0)
    ok('the header says the same without reading either of them again',
       daemon.firewall_marks()['agree'], True)

    # Take one address off the second one behind the daemon's back: that is
    # exactly the state a pair must never be left in silently.
    state = router(SECOND)
    dropped = [e for e in state['entries']
               if e['list'] == 'isemon' and e['comment'].startswith('isemon:')][0]
    state['entries'] = [e for e in state['entries'] if e is not dropped]
    put(state, SECOND)
    picture = daemon.router_picture()
    ok('one of them losing an address is noticed', picture['agree'], False)
    ok('...and the address is named', picture['differs_n'], 1)
    ok('...and the row for it says which one has it',
       [r['on'] for r in picture['carrying']
        if isemon.same_address(r['address']) == isemon.same_address(dropped['address'])],
       [{'mikrotik': True, 'mikrotik2': False}])
    ok('...and the second one is counted as behind',
       [w['missing_n'] for w in picture['firewalls'] if w['fw'] == 'mikrotik2'], [1])
    said = daemon.mikrotik_sync_all('putting it right')
    ok('a sync puts it back', said['firewalls']['mikrotik2']['added'], 1)
    ok('...and nothing was added to the one that already had it',
       said['firewalls']['mikrotik']['added'], 0)
    ok('...and they agree again', daemon.router_picture()['agree'], True)

    title('One of the pair being away does not stop the other')
    os.environ['MOCK_ROUTER_DOWN'] = SECOND
    store.block('203.0.113.77', None, 'while the second one is away')
    said = daemon.mikrotik_sync_all('one is away')
    ok('the one that is there still takes it',
       said['firewalls']['mikrotik']['added'], 1)
    ok('...and the one that is away is reported, not hidden',
       'mikrotik2' in said['trouble'], True)
    ok('...and it is written down against that one',
       bool(store.get_meta('mikrotik2_trouble')), True)
    ok('...and not against the one that is fine',
       store.get_meta('mikrotik_trouble'), '')
    ok('the address is on the first one',
       [e['address'] for e in entries('isemon', FIRST) if e['address'] == '203.0.113.77'],
       ['203.0.113.77'])
    # And what the dashboard says about that address: it is not carried,
    # because one of the two is letting it through.
    rows = {r['ip']: r for r in daemon.blocked_list()}
    ok('...but the ban is not shown as carried, because half a pair is not a ban',
       rows['203.0.113.77']['router'], 'no')
    os.environ.pop('MOCK_ROUTER_DOWN')
    daemon.mikrotik_sync_all('it came back')
    ok('when it comes back the next sync catches it up',
       [e['address'] for e in entries('isemon', SECOND) if e['address'] == '203.0.113.77'],
       ['203.0.113.77'])
    ok('...and the trouble is cleared', store.get_meta('mikrotik2_trouble'), '')
    rows = {r['ip']: r for r in daemon.blocked_list()}
    ok('...and the dashboard says it is carried again', rows['203.0.113.77']['router'], 'yes')

    title('Both of them away is a failure, not a result')
    os.environ['MOCK_ROUTER_DOWN'] = '*'
    try:
        daemon.mikrotik_sync_all('nobody is there')
        ok('a sync with neither of them reachable raises', False)
    except ValueError as e:
        ok('a sync with neither of them reachable raises',
           'mikrotik' in str(e) or 'refused' in str(e).lower() or 'firewall' in str(e), True)
    os.environ.pop('MOCK_ROUTER_DOWN')

    title('The country list goes on both as well')
    said = daemon.geolist_sync_all('a pair')
    ok('both were filled', sorted(said['firewalls']), ['mikrotik', 'mikrotik2'])
    on_first = len([e for e in entries('isemon-geo', FIRST)
                    if e['comment'].startswith('isemon-geo:')])
    on_second = len([e for e in entries('isemon-geo', SECOND)
                     if e['comment'].startswith('isemon-geo:')])
    ok('...with the same number of ranges on each', on_second, on_first)
    ok('...which is not nothing', on_first > 0, True)

    title('Taking ours off takes it off both')
    daemon.mikrotik_purge('both')
    ok('nothing of ours is left on the first',
       [e for e in entries(None, FIRST) if e['comment'].startswith('isemon')], [])
    ok('...nor on the second',
       [e for e in entries(None, SECOND) if e['comment'].startswith('isemon')], [])
    ok('...and what was theirs is still on the second',
       [e['address'] for e in entries('isemon', SECOND) if e['address'] == '10.6.6.6'],
       ['10.6.6.6'])

    title('Switched off, the second one is not written to at all')
    isemon.CONFIG['mikrotik2'] = 0
    ok('only the first is in use', daemon.firewalls(), ['mikrotik'])
    before = calls(SECOND)
    store.block('203.0.113.78', None, 'with the second one switched off')
    daemon.mikrotik_sync_all('one only')
    ok('the second one was not spoken to', calls(SECOND), before)
    ok('...and the first one has it',
       [e['address'] for e in entries('isemon', FIRST) if e['address'] == '203.0.113.78'],
       ['203.0.113.78'])

    title('The first one has a switch of its own too')
    # Before this it was turned off by deleting its address, which loses the
    # account, the port and the key along with it. The point of a switch is
    # that stopping is stopping rather than forgetting.
    isemon.CONFIG['mikrotik2'] = 1
    isemon.CONFIG['mikrotik1'] = 0
    ok('switched off, it is not one of the firewalls in use',
       daemon.firewalls(), ['mikrotik2'])
    kept = calls(FIRST)
    store.block('203.0.113.79', None, 'with the first one switched off')
    daemon.mikrotik_sync_all('the second one only')
    ok('...and nothing is said to it', calls(FIRST), kept)
    ok('...while the other one is kept exactly as it should be',
       [e['address'] for e in entries('isemon', SECOND) if e['address'] == '203.0.113.79'],
       ['203.0.113.79'])
    ok('...and its address is still in the settings, waiting',
       isemon.CONFIG['mikrotik_host'], FIRST)
    isemon.CONFIG['mikrotik1'] = 1
    ok('switched back on, it is in use again with nothing retyped',
       daemon.firewalls(), ['mikrotik', 'mikrotik2'])
    daemon.mikrotik_sync_all('and back')
    ok('...and the next sync catches it up',
       [e['address'] for e in entries('isemon', FIRST) if e['address'] == '203.0.113.79'],
       ['203.0.113.79'])
    ok('a configuration written before this key existed still means "on"',
       isemon.DEFAULTS['mikrotik1'], 1)

finally:
    shutil.rmtree(folder, ignore_errors=True)

print('\nThe router\u2019s key is remembered across a restart')
import base64 as _b64, hashlib as _hl, hmac as _hm, tempfile as _tf
_was_state, _was_run = isemon.STATE_DIR, isemon.RUN_DIR
_kd = Path(_tf.mkdtemp(prefix='isemon-keys-'))
isemon.STATE_DIR, isemon.RUN_DIR = _kd, _kd / 'run'
isemon.RUN_DIR.mkdir()
KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl'
(isemon.RUN_DIR / 'known_hosts').write_text('10.0.0.1 %s\n' % KEY)
ok('not in /run, which systemd empties at every restart',
   str(isemon.ssh_known_hosts()).startswith(str(_kd / 'run')), False)
ok('...with what /run had learned carried across once',
   (_kd / 'known_hosts').read_text().startswith('10.0.0.1 '), True)
ok('...and that is the file ssh is told to use',
   'UserKnownHostsFile=%s' % (_kd / 'known_hosts')
   in isemon._ssh_argv({'ssh_user': 'admin'}, '10.0.0.1'), True)
_salt = b'0123456789abcdefghij'
_hashed = '|1|%s|%s' % (_b64.b64encode(_salt).decode(), _b64.b64encode(
    _hm.new(_salt, b'10.0.0.2', _hl.sha1).digest()).decode())
(_kd / 'known_hosts').write_text('10.0.0.1 %s\n%s %s\n10.0.0.3 %s\n' % (KEY, _hashed, KEY, KEY))
ok('a router replaced on purpose is forgotten', isemon.ssh_forget_host('10.0.0.1'), True)
ok('...and one remembered hashed as well', isemon.ssh_forget_host('10.0.0.2'), True)
ok('...and no other', (_kd / 'known_hosts').read_text(), '10.0.0.3 %s\n' % KEY)
ok('...and nothing that is not a host name is taken for one',
   isemon.ssh_forget_host('-oProxyCommand=x'), False)
isemon.STATE_DIR, isemon.RUN_DIR = _was_state, _was_run

print('\n%d ok, %d failed' % (PASS, FAIL))
sys.exit(1 if FAIL else 0)
