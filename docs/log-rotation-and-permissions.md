# Rotating the logs under `/var/log/remote`, and keeping them readable

A complete, tested procedure for rotating the logs that arrive on the isemon
machine over syslog, without the daemon losing sight of them.

This is worth its own document for one reason: **when it is wrong, nothing
looks wrong.** The logs keep arriving, the dashboard keeps drawing, the chart
keeps a shape — it is just that the newest thing on it is from before the last
rotation, and nobody notices until an attack goes unanswered and somebody
compares the screen with the file.

---

## 1. What the daemon needs, and why

`isemon` does not run as root and never has. It reads the files as its own
account — `systemctl show isemon -p User --value`, `isemon` unless you changed
it — which means every file it reads has to be readable by that account, and
every folder it reads them from has to be enterable by it.

Three things it does on its own, which shape everything below:

* **It follows a file by inode, not by name.** When logrotate renames the
  file, the daemon notices that the thing it was reading is no longer at that
  path, finds it under its new name, reads whatever was written to it after
  the last read, and then starts the new file at its beginning. Nothing is
  lost across a rotation and nothing is read twice — every record is stored
  under its own session id.
* **It reads the rotated copies too, compressed ones included,** but only when
  asked to go back over every log. Day to day it reads the live file.
* **It says so when it cannot read something** — *"this daemon runs as isemon
  and may not read that file"* — on the front page, in `isemon --status` and
  in `isemon --check`, with the command that puts it right. That message is
  the one to watch for.

## 2. The four places a permission is decided

A file under `/var/log/remote` gets its ownership and mode from whichever of
these made it, and they are easy to get out of step with each other:

| | What it decides | Gets it wrong by |
|---|---|---|
| `$FileCreateMode` / `$FileGroup` in rsyslog | the file rsyslog creates | defaulting to `0600 root:root` |
| `$DirCreateMode` / `$DirGroup` in rsyslog | the folder rsyslog creates for a new sender | defaulting to `0700 root:root` |
| `UMask=` on the rsyslog service | both of the above, applied on top | `UMask=0066` turns `0640` into `0600` |
| `create` in logrotate | the file logrotate creates after a rotation | `create 0640 root root` |

The last one is the one that bites late: everything works for weeks, and then
one night the rotation makes a file the daemon cannot read.

The service umask is the one that is hardest to see, because it silently
undoes a setting that still reads correctly everywhere you look:

```
0640 & ~0066 = 0600
```

An ACL (`setfacl`) is the usual field fix and it does work — a *default* ACL
on the folder is inherited by every file created in it, including the one
logrotate makes. Two things to know about it: it is masked by the mode, so a
file created `0600` has its ACL masked out and is unreadable no matter what
`getfacl` shows; and it does not exist on a folder rsyslog creates tomorrow.
Prefer the group. Keep the ACL only as a belt.

## 3. Setting it up

`install.sh` does all of §3.2 to §3.5 on a fresh install since 1.10.201, and
on an installed machine with `--upgrade --with-syslog` (a plain `--upgrade`
never touches it) - the permissions file, rsyslog's umask where it is
`0066`, the rotation and the daily tidy, the group and an ACL on what is
already under `/var/log/remote` - adding only what is missing and never
replacing a file of the machine's own (see INSTALL.md, *On this machine*).
What follows is the same by hand, and how to check it.

### 3.1 Check what you have

```bash
systemctl show isemon  -p User --value        # the account, used below as isemon
systemctl show rsyslog -p UMask               # 0022 or 0027, never 0066
ls -l /var/log/remote/*/                      # a "+" means an ACL is in play
ls /etc/logrotate.d/                          # is anything rotating these at all?
du -sh /var/log/remote/*                      # how big they have grown meanwhile
```

If `UMask=0066`:

```bash
mkdir -p /etc/systemd/system/rsyslog.service.d
printf '[Service]\nUMask=0022\n' > /etc/systemd/system/rsyslog.service.d/umask.conf
systemctl daemon-reload && systemctl restart rsyslog
systemctl show rsyslog -p UMask
```

`systemctl edit rsyslog` is the documented way to do this and it is worth
checking it actually wrote something — on more than one machine it has left no
drop-in behind at all. `systemctl cat rsyslog | tail` shows what is really in
force.

### 3.2 What rsyslog creates from now on

`/etc/rsyslog.d/00-isemon-permissions.conf` — shipped as
`deploy/rsyslog-permissions.conf`:

```
$FileCreateMode 0640
$FileGroup      isemon
$DirCreateMode  0750
$DirGroup       isemon
$Umask          0022
```

**The `00` is the point.** rsyslog applies these to actions defined after
them; named `50-` it would be read after the file that writes the ISE logs and
would change nothing.

### 3.3 The rotation

`/etc/logrotate.d/remote-logs` — shipped as `deploy/remote-logs.logrotate`:

```
/var/log/remote/*/*.log {
    daily
    dateext
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root isemon
    sharedscripts
    postrotate
        /usr/bin/systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}
```

Four things in there are not decoration:

* `create 0640 root isemon` — the group is the account the daemon runs as.
* **One stanza for the whole tree.** logrotate refuses two stanzas that match
  the same file — `error: duplicate log entry for .../radius.log` — and it
  refuses the whole run rather than the stanza. So this cannot be split into
  "the folders isemon reads" and "everything else". One rule, one group, and a
  folder that appears tomorrow for a sender nobody has thought of yet is
  covered without anybody editing this file.

  **Unless one sender is very much bigger than the others.** A domain
  controller can write a couple of gigabytes a day on its own, and at that
  size one gzip is minutes of a core with every other source's reload waiting
  behind it in the same `sharedscripts` run. `deploy/logrotate-split-dc/` is
  one site's working pair for exactly that — the controllers in a stanza of
  their own, with zstd ready to uncomment, and everything else naming its
  sources one by one so that the two cannot overlap. Its cost is the sentence
  above in reverse: **a new sender has to be added to one of the two files by
  hand**, and nothing will tell you if it is in neither. Use one shape or the
  other, never both, and check with
  `logrotate -d /etc/logrotate.conf 2>&1 | grep -i "duplicate\|error"`.
* `delaycompress` — without it logrotate compresses a file rsyslog still has
  open.
* `postrotate ... reload rsyslog` — rsyslog holds the file open, so until it
  is told to reopen, every further line goes into the renamed file. (The
  daemon copes with that either way: it reads the tail off the renamed file.
  The reload is what stops it happening for the rest of the day.)

### 3.4 What logrotate must not touch

`/etc/cron.daily/isemon-logs-tidy` — shipped as `deploy/isemon-logs-tidy`,
`chmod 755`:

```sh
#!/bin/sh

KEEP_DAYS=30
PACK_AFTER=3

find /var/log/remote -type f -name 'detail-*' ! -name '*.gz' -mtime +2 \
     -exec gzip -9 {} + 2>/dev/null

find /var/log/remote -type f -name 'detail-*' -mtime +"$KEEP_DAYS" \
     -delete 2>/dev/null

find /var/log/remote -regextype posix-extended \
     -regex '.*\.log\.[0-9]+(\.gz)?$' -mtime +"$KEEP_DAYS" \
     -delete 2>/dev/null

find /var/log/remote -type f -regextype posix-extended \
     -regex '.*\.log(\.[0-9]+|-[0-9]{8})$' -mtime +"$PACK_AFTER" \
     -exec gzip -9 {} + 2>/dev/null

exit 0
```

**The FreeRADIUS accounting files are not logrotate's business.** They have no
`.log` on the end, so `*/*.log` does not match them and they would otherwise
accumulate for ever — with eduroam switched on, tens of megabytes a day. But
do not point logrotate at them either: they are already one file per day, and
logrotate has no "only throw the old ones away" — it rotates the live file
first, and with `rotate 0` it deletes the day being written. Age them out
instead, as above.

Compressing them is safe. The daemon deliberately follows the newest
**uncompressed** accounting file: a `.gz` beside it is skipped rather than
followed and read as empty.

The third `find` is for rotated copies left behind by a change of naming.
logrotate prunes only the series it is currently using, so the day somebody
adds or removes `dateext` the other series stops being counted and sits there
for ever.

The fourth packs rotated copies that were left plain — the ones from before
`compress` went into the logrotate file. Copies only: the pattern ends in `.N`
or `-YYYYMMDD`, so a live `x.log` can never match it, and three days keeps it
out of the way of logrotate's own `delaycompress`. See section 5.

### 3.5 Put right what is already on disk

```bash
setfacl -R -b /var/log/remote                 # only if step 3.1 showed a "+"
chgrp -R isemon /var/log/remote
find /var/log/remote -type d -exec chmod 750 {} +
find /var/log/remote -type f -exec chmod 640 {} +
```

Folders need `750`, not `740`: without the `x` the account cannot enter them,
however readable the files inside are.

### 3.6 Verify

```bash
systemctl restart rsyslog isemon
sudo -u isemon head -1 /var/log/remote/<node>/CISE_Failed_Attempts.log
isemon --check
isemon --status
```

`--check` should end with *everything is as it should be*, and the TROUBLE
column in `--status` should be empty for every file.

### 3.7 Prove the rotation, rather than waiting for it

```bash
logrotate -d /etc/logrotate.d/remote-logs     # says what it would do, changes nothing
logrotate -f /etc/logrotate.d/remote-logs     # does it
ls -l /var/log/remote/<node>/
sleep 20 && isemon --status
```

The new live file must be `root:isemon` — and with no `+`, if you removed the
ACLs, because that is what proves it is standing on the group. `records read`
must keep climbing. In the daemon's own log you will see

```
N record(s) read off the rotated CISE_Failed_Attempts.log, from where the last read stopped
```

which is the daemon doing its job, not a complaint.

## 4. Compressing the rotated copies, and importing the lot

**Compress them.** ISE syslog is the most compressible thing on the machine —
the same words, the same field names, the same device, thousands of times a
minute. Measured on a real day's file:

```
40 MB of CISE_Failed_Attempts.log  ->  1.78 MB gzipped      about 23 to one
```

A month at `rotate 30` is the difference between roughly 1.2 GB and 55 MB.

The daemon reads the compressed copies — `.gz`, `.bz2`, `.xz` — wherever it
reads rotated copies at all, which is the pass back over every log. Day to day
it follows the live file, and the live file is never compressed: that is what
`delaycompress` is for.

**A full import takes all of them, whatever they are called.** Wipe the
database and do it, and it reads the live file, the `.1`, the `.2.gz`, the
`-20260923`, the `-20260923.gz`, in the order they were last written — that
ordering is the one thing that means the same in every naming scheme, which
matters on a machine carrying two of them side by side. Everything is stored
under its own session id, so a copy read twice adds nothing.

```bash
isemon --erase records --yes        # if you really want to start from nothing
isemon --rescan                     # reads every file from the beginning
```

Measured on 240 MB of raw ISE log left as 84 MB plain + 11 MB gzipped, eight
files across two naming schemes:

| | |
|---|---|
| records in the files | 421,758 |
| records in the database afterwards | **421,758** |
| how long | 174 s, about 2,400 a second |
| memory while it ran | 207 MB, flat |
| a second full import | 421,758 read, **0 added**, 69 s |

## 5. Switching an installation that is already running to compressed copies

The rotation was set up without `compress`, or was never set up at all, and
there are uncompressed copies on disk. Nothing below interrupts anything: the
live file is never touched, and the daemon reads a compressed copy as readily
as a plain one.

**1. Put `compress` and `delaycompress` in the logrotate file.** From the next
rotation on, every copy is packed a day after it is made. `delaycompress` is
what leaves the newest one alone, because rsyslog may still have it open.

```
    compress
    delaycompress
```

**2. Pack the copies that are already there.** Only copies — the pattern ends
in `.N` or `-YYYYMMDD`, so a live `x.log` can never match it:

```bash
find /var/log/remote -type f -regextype posix-extended \
     -regex '.*\.log(\.[0-9]+|-[0-9]{8})$' -mtime +3 \
     -exec gzip -9 {} +
```

`-mtime +3` is not caution about the file, it is about logrotate:
`delaycompress` means logrotate intends to compress yesterday's copy itself on
its next run, and two things reaching for one file is how you get
`error: destination already exists`. Three days puts them out of each other's
way. `/etc/cron.daily/isemon-logs-tidy` does exactly this every night, so on a
machine that has it, step 2 happens by itself — this is only to have it now
rather than tomorrow.

**3. Check the result.**

```bash
ls -l /var/log/remote/<node>/
du -sh /var/log/remote/
isemon --status
```

The live `.log` must still be plain, everything older packed, and the TROUBLE
column empty.

**4. If you want the history in the database as well** — a machine that was
installed after the logs had been running, or a database that was erased:

```bash
isemon --rescan
```

It reads the live file and every rotated copy from the beginning, plain and
packed alike, in the order they were last written. Everything is stored under
its own session id, so a copy read twice adds nothing: a second `--rescan`
reads exactly as much and writes none of it.

### What was measured

Ten days of rotation with the shipped logrotate file and the shipped nightly
tidy running beside each other, starting from a folder in the state a machine
switching over is really in — two naming series, none of them packed:

| | |
|---|---|
| errors from either of them, over ten days | **none** |
| on disk afterwards | the live file plain, `.1` plain (`delaycompress`), twelve packed copies |
| records in them all | 485 |
| after a full import | **485**, none of them twice |
| a second full import | 485 read, **0 added** |

And at size, on 240 MB of real ISE log left as 84 MB plain + 11 MB gzipped,
eight files across two naming schemes: 421,758 records in the files, 421,758
in the database, 174 s, memory flat at 207 MB.

One thing to know before you try it by hand: **`logrotate -f` twice in one day
with `dateext` fails the second time** — `error: destination
.../x.log-20260925 already exists, skipping rotation` — because the name is
made from the date. It is harmless, nothing is rotated and nothing is lost,
but it is not a sign that anything is wrong with the configuration. Across
real days the name differs each time.

## 6. When it is wrong, this is what it looks like

| What you see | What it is |
|---|---|
| `this daemon runs as isemon and may not read that file` | the file or its folder is not readable by the account; `--status` prints the command that fixes it |
| TROUBLE empty but `last read` hours old, `records read` not moving | the file is readable and nothing new is arriving — look at the sender, not at this machine |
| `error: duplicate log entry for ...` from logrotate | two stanzas match one file; there can only be one |
| times on the page six hours from the times in the log | not this at all — the machine's own time zone. See `log_zone` in Settings → The ISE logs, and `isemon --check` |

## 7. The files in this package

| File | Goes to |
|---|---|
| `deploy/rsyslog-permissions.conf` | `/etc/rsyslog.d/00-isemon-permissions.conf` |
| `deploy/remote-logs.logrotate` | `/etc/logrotate.d/remote-logs` |
| `deploy/isemon-logs-tidy` | `/etc/cron.daily/isemon-logs-tidy`, `chmod 755` |
| `deploy/isemon.logrotate` | `/etc/logrotate.d/isemon` — the daemon's **own** log, installed by `install.sh`. Not this. |

`./install.sh --with-syslog` puts the first three in place for you, and leaves
any of them that already exists exactly as it is.

Every command and every file above was run against a copy of a real
installation's log tree, with a real `logrotate`, with the daemon reading as
its own account across the rotation: 206 records in the files — rotated and
compressed copies included — came out as 206 rows in the database, none of
them twice.
