#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# radacct-syslog-ship.py
#
# Sends the contents of every detail file under /var/log/radius/radacct to
# syslog. One detail record - a block ended by a blank line - is sent as ONE
# syslog message, so the collector receives a whole accounting or auth
# record on a single line.
#
# - it does not touch the FreeRADIUS configuration at all
# - it remembers an offset per file (/var/lib/radacct-ship), so running it
#   again sends nothing twice
# - a record still being written at the end of a file is skipped and sent on
#   the next run instead
# - new files (a new day, a new NAS) are found by themselves, no configuration
#
# Written for Python 2.6 (CentOS 6); it runs on Python 3 as well.
#
# Run from cron - see /etc/cron.d/radacct-ship
#
#   -v              say how many records went
#   --every N       go round again every N seconds instead of once and out
#   --seconds M     ...and stop after M seconds
#
# Cron's finest interval is a minute, so a record written a moment after a
# run waits nearly a whole one. `--every 5 --seconds 55` makes the one run a
# minute sweep the minute instead: it checks every five seconds and is gone
# before the next run is due, and the lock below means an overrun costs
# nothing - the next run simply finds the lock held and exits.

import os
import sys
import errno
import fcntl
import time
import hashlib
import syslog

# ----------------------------------------------------------------- settings
RADACCT_DIR = "/var/log/radius/radacct"
STATE_DIR = "/var/lib/radacct-ship"
LOCK_FILE = "/var/lock/radacct-ship.lock"

# which files to send, by what the name starts with
FILE_PREFIXES = ("detail-", "auth-detail-", "reply-detail-")

SYSLOG_IDENT = "radius-detail"
SYSLOG_FACILITY = syslog.LOG_LOCAL5
SYSLOG_PRIORITY = syslog.LOG_NOTICE

# attributes that are never sent (the OTP passcode and its like)
SUPPRESS_ATTRS = ("User-Password", "CHAP-Password", "MS-CHAP-Response",
                  "MS-CHAP2-Response", "Chap-Password")

# the longest one message may be; rsyslog 5.x trims at 2048 by default,
# see $MaxMessageSize in the guide beside this file
MAX_MSG = 1800
# --------------------------------------------------------------------------


# The lock is held by an open file, and a file nobody is holding is closed
# by Python the moment the last name for it goes away - which releases the
# lock with it. So the handle is kept here, alive for as long as the process
# is, rather than in a local variable in whoever called for it.
#
# It mattered little while a run took milliseconds. It matters now: a run
# that sweeps for fifty-five seconds is still going when cron starts the
# next one, and two of them reading and writing one set of offset files
# would send some records twice and skip others.
LOCK_HANDLE = None


def single_instance():
    """Stops two runs at once - cron starts one every minute."""
    global LOCK_HANDLE
    fh = open(LOCK_FILE, "w")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError:
        sys.exit(0)
    LOCK_HANDLE = fh
    return fh


def state_path(path):
    key = path.strip("/").replace("/", "_")
    return os.path.join(STATE_DIR, key + ".offset")


def read_offset(path):
    try:
        f = open(state_path(path))
        try:
            return int(f.read().strip() or 0)
        finally:
            f.close()
    except (IOError, OSError, ValueError):
        return 0


def write_offset(path, offset):
    tmp = state_path(path) + ".tmp"
    f = open(tmp, "w")
    try:
        f.write("%d\n" % offset)
    finally:
        f.close()
    os.rename(tmp, state_path(path))


def find_files():
    out = []
    for root, dirs, files in os.walk(RADACCT_DIR):
        for name in files:
            for pref in FILE_PREFIXES:
                if name.startswith(pref):
                    out.append(os.path.join(root, name))
                    break
    out.sort()
    return out


def records(blob):
    """Splits the text into (record, bytes consumed). Only WHOLE records,
    which means blocks ended by a blank line."""
    consumed = 0
    current = []
    for line in blob.splitlines(True):          # keepends
        if line.strip() == "":
            if current:
                yield ("".join(current), consumed + len(line))
                current = []
            consumed += len(line)
            continue
        if not line.endswith("\n"):             # an unfinished last line
            return
        current.append(line)
        consumed += len(line)
    # a record left without its closing blank line -> next time


def record_id(nas, fname, text):
    """A name this record answers to, and no other record does.

    The same record hashes to the same id however many times it is shipped,
    so a file read again from the beginning does not arrive as a second
    record; and two records never share one, because what goes into the hash
    includes the packet's own timestamp and its Message-Authenticator, which
    the client makes afresh for every packet it sends.

    It is here rather than at the far end because only this side knows which
    file and which NAS a record came out of once it has been flattened onto
    one line.
    """
    said = "%s|%s|%s" % (nas, fname, text)
    if not isinstance(said, bytes):
        said = said.encode("utf-8", "replace")
    return hashlib.sha1(said).hexdigest()[:16]


def format_record(nas, fname, text):
    lines = [l.rstrip("\r\n") for l in text.splitlines() if l.strip()]
    if not lines:
        return None
    header = lines[0].strip()
    parts = []
    for line in lines[1:]:
        item = line.strip()
        if not item:
            continue
        attr = item.split("=", 1)[0].strip()
        if attr in SUPPRESS_ATTRS:
            item = "%s = <suppressed>" % attr
        parts.append(item)
    msg = "nas=%s id=%s file=%s ts=[%s] %s" % (
        nas, record_id(nas, fname, text), fname, header, ", ".join(parts))
    msg = msg.replace("\t", " ")
    if len(msg) > MAX_MSG:
        msg = msg[:MAX_MSG] + " ...TRUNCATED"
    return msg


def ship_file(path):
    try:
        size = os.path.getsize(path)
    except OSError:
        return 0
    offset = read_offset(path)
    if offset > size:          # the file was shortened or replaced
        offset = 0
    if offset == size:
        return 0

    f = open(path, "rb")
    try:
        f.seek(offset)
        blob = f.read()
    finally:
        f.close()

    if not isinstance(blob, str):
        blob = blob.decode("utf-8", "replace")

    nas = os.path.basename(os.path.dirname(path))
    fname = os.path.basename(path)

    sent = 0
    consumed = 0
    for text, upto in records(blob):
        msg = format_record(nas, fname, text)
        if msg:
            syslog.syslog(SYSLOG_PRIORITY, msg)
            sent += 1
        consumed = upto

    if consumed:
        write_offset(path, offset + consumed)
    return sent


def said_after(flag, fallback):
    """The number after a flag on the command line, or the fallback."""
    try:
        at = sys.argv.index(flag)
    except ValueError:
        return fallback
    try:
        got = float(sys.argv[at + 1])
    except (IndexError, ValueError):
        return fallback
    return got if got > 0 else fallback


def sweep(loud):
    """Every file, once."""
    total = 0
    for path in find_files():
        try:
            total += ship_file(path)
        except Exception as e:
            syslog.syslog(syslog.LOG_ERR,
                          "radacct-ship error on %s: %s" % (path, e))
    if loud:
        sys.stdout.write("shipped %d records\n" % total)
        sys.stdout.flush()
    return total


def main():
    try:
        os.makedirs(STATE_DIR)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise

    single_instance()
    syslog.openlog(SYSLOG_IDENT, syslog.LOG_PID, SYSLOG_FACILITY)

    loud = "-v" in sys.argv
    every = said_after("--every", 0)
    # Left alone, this is what it always was: one sweep and out.
    if not every:
        sweep(loud)
        return
    # Otherwise it keeps the lock for a while and goes round. Stopping before
    # the next run is due rather than being killed by it: the lock is held
    # for exactly as long as this runs, and a run that overstayed would make
    # the next minute's run do nothing at all.
    until = time.time() + said_after("--seconds", 55.0)
    total = 0
    while True:
        total += sweep(loud)
        left = until - time.time()
        if left <= 0:
            break
        time.sleep(every if every < left else left)


if __name__ == "__main__":
    main()
