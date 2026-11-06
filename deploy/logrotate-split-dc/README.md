# Rotating a domain controller's log apart from everything else

The two files here are one site's working pair, in use on a domain whose
biggest controller writes **about 2.8 GB a day**. They go in
`/etc/logrotate.d/` under these names and they replace the single
`remote-logs.logrotate` stanza that ships beside them — use one shape or the
other, never both.

Why split them at all: at that volume one gzip of a three gigabyte file is
minutes of a core, and doing every source in one `sharedscripts` run means
the reload that follows waits for all of it. Splitting also lets the
controllers be compressed differently — `remote-dc` has the zstd lines ready
to uncomment, which is a different binary and no extra service.

**The one rule.** logrotate refuses two stanzas that match the same file
(`error: duplicate log entry for ...`), and it refuses the *whole run*, not
just the stanza. So every controller directory named in `remote-dc` must be
absent from `remote-logs` — which is why `remote-logs` here lists its sources
one by one instead of using `/var/log/remote/*/*.log`. **Adding a new source
means adding a line to one of these two files**, and nothing will remind you:
a source that is in neither simply never rotates.

Both keep `create 0640 root isemon`, which is what lets the daemon go on
reading after a rotation, and both let the reload's exit status through
rather than swallowing it with `|| true`. The reasoning behind those two is
in [../../docs/log-rotation-and-permissions.md](../../docs/log-rotation-and-permissions.md).

**`remote-fw`** is the third of the set (1.10.309): the firewalls, which on a
site that logs the sessions they let through are by far the most of it - tens
of GB a day - and kept only two days, because isemon keeps what it needs of
them in the database. Put the firewalls' folders in it and in neither of the
other two.

**Settings → Disk and logs** looks at every folder under `/var/log/remote`
and says which one no file takes, with the logrotate file that would take it
written out, so a sender added and forgotten is found the day it is added
rather than the day the disk is full.

Check the set before trusting it:

```bash
logrotate -d /etc/logrotate.conf 2>&1 | grep -i "duplicate\|error"
```

Silence there means the two stanzas do not overlap.
