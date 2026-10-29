#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
replay.py - run real ISE logs through the daemon's own reader and ban engine,
in a throwaway database, and print what it made of them.

Nothing here talks to a router or to the network. It exists to answer the one
question a parser cannot answer about itself: given these actual files, how
many records came out, how many addresses were kept out, and for how long.

    ./test/replay.py /path/to/logs          (a folder holding ise1/ ise2/)
"""
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path


def short(ts):
    return time.strftime('%H:%M:%S', time.localtime(float(ts or 0)))

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import isemon                                     # noqa: E402


def run(where, ladder='10, 60, 1440, forever', tries=5, window=10, devices='FTD-VPN'):
    folder = tempfile.mkdtemp(prefix='isemon-replay-')
    isemon.STATE_DIR = Path(folder)
    isemon.DB_FILE = Path(folder) / 'replay.db'
    isemon.BACKUP_DIR = Path(folder) / 'backups'
    isemon.DUMP_DIR = Path(folder) / 'dumps'
    isemon.RUN_DIR = Path(folder)
    isemon.LOG_DIR = Path(folder)
    isemon._LOG_PATH = Path(folder) / 'replay.log'

    paths = sorted(str(p) for p in Path(where).iterdir() if p.is_dir()) or [str(where)]
    isemon.CONFIG.update({
        'ise_paths': paths,
        'watch_devices': devices,
        'block_ladder': ladder,
        'block_tries': tries,
        'block_window_min': window,
        'blacklist': 1,
        'block_mode': 'temporary',
        'geo': 0,
        'mikrotik_host': '',
        'debug': False,
    })
    store = isemon.Storage(isemon.DB_FILE)
    daemon = isemon.Daemon(store)
    # One pass reads at most eight megabytes of each file, which is what
    # keeps a daemon that has been off for a week from swallowing a gigabyte
    # in one breath. A replay is not a daemon and has nothing else to do, so
    # it goes round until the files are used up - otherwise a twenty-five
    # megabyte log quietly becomes the first eight.
    began = time.time()
    new = passes = 0
    while True:
        got = daemon.read_logs()
        new += got
        passes += 1
        if not got or passes > 400:
            break
    took = time.time() - began

    failed, n_failed = store.failed_rows(limit=1)
    passed, n_passed = store.passed_rows(limit=1)
    blocked = daemon.blocked_list()
    print('read %d record(s) from %d file(s) in %.2f s, over %d pass(es)'
          % (new, len(daemon.log_files()), took, passes))
    print('  failed attempts recorded: %d' % n_failed)
    print('  successful logins recorded: %d' % n_passed)
    print('  addresses kept out: %d' % len(blocked))

    # The three kinds of successful record, and whether every downloadable
    # ACL found the login it belongs to. A DACL that lands in the list of
    # logins, or a login whose firewall cannot be found, is the whole of what
    # the splitting was for.
    kinds = {r['kind'] or 'vpn': r['n'] for r in store.db.execute(
        "SELECT COALESCE(kind,'vpn') AS kind, COUNT(*) AS n FROM passed GROUP BY 1")}
    print('  of those: %d AnyConnect and %d TACACS sign-in(s); %d downloadable ACL(s) and '
          '%d command(s) are not logins and are not listed as any'
          % (kinds.get('vpn', 0), kinds.get('tacacs', 0), kinds.get('dacl', 0),
             kinds.get('tacacs-cmd', 0)))
    # Every command somebody ran on a switch, under the sign-in it was typed in.
    signins, n_tac = store.passed_rows(kind='tacacs', limit=2000)
    joined = ran = denied = orphan = 0
    for row in signins:
        got = daemon.commands_for_login(row)
        if got and got['have']:
            joined += 1
            ran += got['ran']
            denied += got['denied']
    every = store.db.execute("SELECT COUNT(*) AS n FROM passed WHERE kind='tacacs-cmd' "
                             "AND COALESCE(cmd,'') <> ''").fetchone()['n']
    print('  %d of the %d TACACS sign-in(s) have commands under them: %d command(s) of the %d '
          'recorded, %d of them refused'
          % (joined, n_tac, ran, every, denied))
    for row in signins[:1]:
        got = daemon.commands_for_login(row)
        if not (got and got['ran']):
            continue
        print('  for example, %s on %s ran:' % (row['username'], row['device']))
        for one in got['commands']:
            if one['shell']:
                print('      %s  (the shell itself was granted)' % short(one['ts']))
            else:
                print('      %s  %-8s %s' % (short(one['ts']), one['verdict'], one['cmd']))
    vpn, n_vpn = store.passed_rows(kind='vpn', limit=2000)
    with_acl = [r for r in vpn if r.get('acl')]
    joined = matched_by_name = rules_total = 0
    for row in with_acl:
        got = daemon.acl_for_login(row)
        if got and got.get('have'):
            joined += 1
            rules_total += len(got['rules'])
            if got.get('matched') == 'name':
                matched_by_name += 1
    print('  %d of the %d AnyConnect logins were handed a firewall; %d of those were joined '
          'to it (%d by session, %d by the ACL\'s name), %d rule(s) read'
          % (len(with_acl), n_vpn, joined, joined - matched_by_name, matched_by_name,
             rules_total))
    if with_acl:
        shown = daemon.acl_for_login(with_acl[0])
        if shown and shown.get('rules'):
            print('  for example, %s was given %s:'
                  % (with_acl[0]['username'], shown['name']))
            for rule in shown['rules'][:6]:
                if rule['kind'] == 'remark':
                    print('      -- %s' % rule['note'])
                else:
                    print('      %-6s %-4s %-22s -> %-24s %s'
                          % (rule['kind'], rule.get('proto', ''), rule.get('src', ''),
                             rule.get('dst', ''), rule.get('dst_port', '')))
            if len(shown['rules']) > 6:
                print('      ... and %d more' % (len(shown['rules']) - 6))
    print()
    print('%-20s %-9s %-26s %s' % ('ADDRESS', 'LEFT', 'HOW LONG, AND WHY', 'WHY'))
    for row in sorted(blocked, key=lambda r: -(r.get('tries') or 0))[:25]:
        print('%-20s %-9s %-26s %s' % (
            row['ip'],
            'for good' if row['forever'] else '%d min' % (row['left'] // 60),
            (row['how'] or '')[:26], (row['why'] or '')[:60]))
    print()
    # A second pass over the same files must add nothing at all: the offsets
    # say there is nothing new, and even if they did not the session ids would
    # catch it. Both halves are worth proving, so the offsets are thrown away
    # and the files are read from the beginning again.
    daemon._tails = {}
    daemon.restore_tails()
    for tail in daemon._tails.values():
        tail.offset, tail.inode = 0, 0
    again = daemon.read_logs()
    print('reading every file from the beginning a second time added %d record(s) '
          '(it must be 0)' % again)
    after = store.failed_rows(limit=1)[1]
    print('failed attempts after the second pass: %d (it must be %d)' % (after, n_failed))

    ok = (again == 0 and after == n_failed and n_failed > 0)
    shutil.rmtree(folder, ignore_errors=True)
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(run(sys.argv[1] if len(sys.argv) > 1 else '/var/log/remote'))
