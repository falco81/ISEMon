#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mockrouter.py - a RouterOS that answers the way one does, without a router.

It is installed as `ssh` on PATH for the length of a test, keeps its address
lists in a JSON file, and understands exactly the handful of commands this
daemon sends: print terse, add, remove [find ...] and the :do {...} script the
country sync uses to send two hundred adds in one go.

It exists so the router half can be tested at all. A Mikrotik is the one part
of this that cannot be stood up in a test, and it is also the part where a
mistake is a firewall that stops working - so the commands it would be sent
are checked here, one by one, against something that reads them the way it
does.
"""
import json
import os
import re
import sys
from pathlib import Path

BASE = Path(os.environ.get('MOCK_ROUTER_STATE', '/tmp/mock-router.json'))


def where(host):
    """One file per router.

    There can be two of them now - a pair in high availability - and the
    whole point of the tests around that is what happens when the two are
    NOT carrying the same thing. One shared file could never show it.
    """
    if not host:
        return BASE
    kept = re.sub(r'[^A-Za-z0-9._-]', '', str(host))
    return BASE.with_name('%s-%s%s' % (BASE.stem, kept, BASE.suffix or '.json'))


def load(host=None):
    try:
        return json.loads(where(host).read_text())
    except (OSError, ValueError):
        return {'entries': [], 'log': [], 'calls': 0, 'host': host or ''}


def save(state, host=None):
    where(host).write_text(json.dumps(state))


def answer(command, state):
    state['log'].append(command)

    if command == ':put [/system identity get name]':
        if os.environ.get('MOCK_ROUTER_NO_PUT'):
            return 'syntax error (line 1 column 6)\n'
        return 'MockTik\n'
    if command.startswith('/system identity'):
        # Laid out for a terminal a few columns wide, the way a real one
        # answered over ssh: the name broken onto a line per letter.
        if os.environ.get('MOCK_ROUTER_NARROW'):
            return 'name: M\n      o\n      c\n      k\n      T\n      i\n      k\n'
        return 'name: MockTik\n'

    # How many entries a list holds, which is how the daemon checks that what
    # it sent actually landed. A real RouterOS answers with the bare number.
    m = re.match(r'^:put \[:len \[(/ip|/ipv6) firewall address-list find list=(\S+)'
                 r'(?: comment~"\^([^"]*)")?\]\]$', command)
    if m:
        if state.get('mute_count'):
            return '\n'          # a router that will not say
        family, listed, mark = m.group(1), m.group(2), m.group(3)
        return '%d\n' % sum(1 for e in state['entries']
                            if e['family'] == family and e['list'] == listed
                            and (not mark or str(e.get('comment') or '').startswith(mark)))

    # The country sync wraps many adds in one script - since 1.10.159 each
    # in a block of its own, `:do { a } on-error={}; :do { b } on-error={}`,
    # the way RouterOS goes on past one that fails.
    if command.startswith(':do { '):
        out = []
        for block in re.findall(r':do \{ (.*?) \} on-error=\{\}', command, re.S):
            for one in block.split('; '):
                out.append(answer(one.strip(), state) or '')
        return ''.join(out)

    m = re.match(r'^(/ip|/ipv6) firewall address-list print terse where list=(\S+)$', command)
    if m:
        family, listed = m.group(1), m.group(2)
        lines = []
        for i, e in enumerate(state['entries']):
            if e['family'] != family or e['list'] != listed:
                continue
            lines.append('%d   list=%s address=%s comment="%s"%s'
                         % (i, e['list'], e['address'], e['comment'],
                            (' timeout=%s' % e['timeout']) if e.get('timeout') else ''))
        return '\n'.join(lines) + ('\n' if lines else '')

    m = re.match(r'^(/ip|/ipv6) firewall address-list add list=(\S+) address=(\S+)'
                 r'(?: timeout=(\S+))? comment="([^"]*)"$', command)
    if m:
        family, listed, address, timeout, comment = m.groups()
        for e in state['entries']:
            if e['family'] == family and e['list'] == listed and e['address'] == address:
                # RouterOS says this and carries on; the daemon must not treat
                # it as the end of the world, which is why it is here.
                return 'failure: already have such entry\n'
        state['entries'].append({'family': family, 'list': listed, 'address': address,
                                 'comment': comment, 'timeout': timeout})
        return ''

    m = re.match(r'^(/ip|/ipv6) firewall address-list remove '
                 r'\[find list=(\S+) address=(\S+) comment~"\^([^"]*)"\]$', command)
    if m:
        family, listed, address, mark = m.groups()
        before = len(state['entries'])
        state['entries'] = [e for e in state['entries']
                            if not (e['family'] == family and e['list'] == listed
                                    and e['address'] == address
                                    and e['comment'].startswith(mark))]
        return '' if len(state['entries']) < before else ''

    m = re.match(r'^(/ip|/ipv6) firewall address-list remove '
                 r'\[find list=(\S+) comment~"\^([^"]*)"\]$', command)
    if m:
        family, listed, mark = m.groups()
        state['entries'] = [e for e in state['entries']
                            if not (e['family'] == family and e['list'] == listed
                                    and e['comment'].startswith(mark))]
        return ''

    # Anything else is a command this daemon should not be sending. Saying so
    # loudly is the point: a silent success here would hide a typo that on a
    # real router does nothing and is never noticed.
    sys.stderr.write('bad command: %s\n' % command)
    return None


def main():
    argv = sys.argv[1:]
    # ssh's own options, then `-l user -- host` (what 1.10.93 says) or
    # user@host (what came before), then the command.
    host = ''
    while argv and argv[0].startswith('-'):
        opt = argv.pop(0)
        if opt == '--':
            if argv:
                host = argv.pop(0)
            break
        if argv and not argv[0].startswith('-') and len(argv) > 1 \
                and '@' not in argv[0] and not argv[0].startswith('/'):
            argv.pop(0)              # that option's value
    if not host and argv and '@' in argv[0]:
        host = argv.pop(0).split('@', 1)[1]
    command = ' '.join(argv)
    state = load(host)
    state['host'] = host
    # One per launch of ssh, not per command: the country sync sends two
    # hundred adds in one script and the whole point of the test is that it
    # cost one ssh call rather than two hundred.
    state['calls'] += 1
    # Which of them is away: a host name, several separated by commas, or *
    # for all of them. One half of a pair being unreachable is the case worth
    # testing, not both.
    down = str(os.environ.get('MOCK_ROUTER_DOWN') or '')
    if down and (down == '*' or host in [x.strip() for x in down.split(',')]):
        sys.stderr.write('ssh: connect to host port 22: Connection refused\n')
        return 255
    said = answer(command, state)
    save(state, host)
    if said is None:
        return 1
    sys.stdout.write(said)
    return 0


if __name__ == '__main__':
    sys.exit(main())
