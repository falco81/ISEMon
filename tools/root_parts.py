#!/usr/bin/env python3
"""ROOT_PARTS in isemon.py made afresh from deploy/: the files install.sh puts
in as they are (root's helpers, the systemd units, the daemon's logrotate
file), each with where it goes and its sha256. The daemon compares what is
installed against them and says, on every page, when ./install.sh --upgrade
has not been run for this version (1.10.312). Not part of the program: run by
whoever changes one of those files; test/fixes312_alerts.py fails until then.

    python3 tools/root_parts.py
"""
import hashlib
import os
import sys

TREE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# source in the package -> where install.sh puts it (as it is, no substitution)
PARTS = [
    ('deploy/isemon_web.py', '/usr/local/lib/isemon/isemon_web.py'),
    ('deploy/isemon_upgrade.py', '/usr/local/lib/isemon/isemon_upgrade.py'),
    ('deploy/isemon_main.py', '/usr/local/lib/isemon/isemon_main.py'),
    ('deploy/isemon-web.service', '/etc/systemd/system/isemon-web.service'),
    ('deploy/isemon-web.path', '/etc/systemd/system/isemon-web.path'),
    ('deploy/isemon-upgrade.service', '/etc/systemd/system/isemon-upgrade.service'),
    ('deploy/isemon-upgrade.path', '/etc/systemd/system/isemon-upgrade.path'),
    ('deploy/isemon.service', '/etc/systemd/system/isemon.service'),
    ('deploy/isemon.logrotate', '/etc/logrotate.d/isemon'),
]


def block():
    lines = ['ROOT_PARTS = [']
    for src, dest in PARTS:
        with open(os.path.join(TREE, src), 'rb') as f:
            sha = hashlib.sha256(f.read()).hexdigest()
        lines.append("    (%r, %r, %r)," % (src, dest, sha))
    lines.append(']')
    return '\n'.join(lines)


def main():
    path = os.path.join(TREE, 'isemon.py')
    text = open(path, encoding='utf-8').read()
    # Only between its two marks, never further: a pattern that ran on to the
    # next `]` in the file once took a third of it with it.
    start, end = '# -- ROOT_PARTS from tools/root_parts.py --\n', '# -- end of ROOT_PARTS --\n'
    if text.count(start) != 1 or text.count(end) != 1 or text.index(start) > text.index(end):
        print('ROOT_PARTS: the marks around it are not there once each - nothing changed')
        return 1
    a, b = text.index(start) + len(start), text.index(end)
    new = text[:a] + block() + '\n' + text[b:]
    if new == text:
        print('ROOT_PARTS: as it was')
        return 0
    open(path, 'w', encoding='utf-8').write(new)
    print('ROOT_PARTS: made afresh')
    return 0


if __name__ == '__main__':
    sys.exit(main())
