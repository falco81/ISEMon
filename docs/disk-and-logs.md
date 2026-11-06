# Disk and logs (1.10.309)

**Settings → Data → Disk and logs** answers "what is filling the disk" with
numbers rather than guesses, and says what looks wrong with the steps that
put it right. For a full admin only (`GET /api/storage`); looked at when the
pane is opened, kept a minute, *Look again* asks afresh.

It was written after one install whose disk reached 94 %: the database was
70 GB, which is what it should have been, and 418 GB was syslog in
`/var/log/remote` - four firewalls' folders that no logrotate file named,
written since the firewalls were added and never rotated.

## What it shows

- **The verdict** - nothing wrong, things worth a look, or trouble - with the
  fullest disk, the database and the logs in one line.
- **Each disk** something of ours is on, as one bar: the logs that arrive over
  syslog, the database (and PostgreSQL's write-ahead log, where it may be
  asked), the dumps, the backups, everything else on the disk and what is
  free; the dashed line is 85 %. Below it, how much a day goes on to it and
  when it is full at that rate.
- **What to put right**, worst first. Each with what was found and numbered
  steps, every command and file ready to copy - a file as it is, or as one
  command (`cat > … <<'EOF'`) that writes it.
- **Logs that arrive over syslog**: every folder under `/var/log/remote`
  (one per sender, as rsyslog files them) with its size split into live
  files, copies and packed copies; its biggest live file; how much a day it
  grows; how long its copies are kept; which logrotate file takes it; and
  whether isemon reads it. A row opened shows its biggest files and the files
  no logrotate file takes.
- **Which logrotate files take them**: each file under `/etc/logrotate.d`
  that names those folders, its patterns, how often, how many copies and
  whether compressed.
- **Inside the database**: altogether, the rows, the indexes, dead rows and
  the write-ahead log; every table biggest first with its rows, indexes and
  the rest - a table split by day (PostgreSQL) as one, by its kind of day
  (the firewall's sessions let through apart from the rest, the domain's
  logons apart from its reads); how far back the main tables go.
- **The biggest indexes**, the same index of every day added up, with how
  often the server has used it since its counters were last reset.
- **Copies kept on this machine**: the dumps and the backups.

## What it says is wrong

| | When | What it gives |
|---|---|---|
| trouble | a disk 95 % full, or full in less than 3 days at the rate measured (85 % or 14 days: worth a look) | what of ours is on it |
| trouble | files under `/var/log/remote` that **no logrotate file takes** (over 5 GB; less: worth a look) | `/etc/logrotate.d/remote-isemon` written out for those folders (2 copies where they are big, 30 where not), the check that no two files now take one log, a rotation now, and how to let the copies go |
| trouble | a log taken by **two** logrotate files - logrotate refuses the whole run over it | the check |
| worth a look | a live file over 2 GB taken by logrotate, but no copy for over two and a half of its periods | what logrotate says run by hand, and whether its timer runs |
| worth a look | copies older than three days never compressed (over 1 GB) | the command that packs them |
| worth a look | a table over 1 GB with more than a fifth of its rows dead | `VACUUM (ANALYZE)` |
| worth a look | over 8 GB of PostgreSQL write-ahead log | the replication slots and how far behind each is |
| worth a look | the dumps take more than is free | where fewer are kept |
| worth knowing | big senders (over 2 GB a day) kept more than 14 days | what that comes to on the disk |
| worth knowing | the sessions a firewall let through over 30 % of the database | the setting that keeps them |
| worth knowing | indexes over 1 GB not used yet | nothing to do unless room is short |

How much a day a folder grows is measured: what its live files gained
between two looks at least ten minutes apart (noted in `meta`, so a restart
does not lose it), or else, where it is rotated daily, the size of
yesterday's uncompressed copy.

## Limits

- A logrotate file is read for its patterns and the few options that say how
  long things are kept; its scripts are skipped. Files logrotate itself skips
  (`.rpmsave`, `.dpkg-old`, `~`, …) are skipped here too.
- At most 20 000 files are looked at in one scan.
- PostgreSQL's write-ahead log is measured only where the account may call
  `pg_ls_waldir()` (`pg_monitor`); the server's own data folder is measured by
  the database's size, not walked.
- Nothing here changes anything: every step is for root to run.

The three logrotate files a site that rotates its domain controllers apart
uses - `remote-logs`, `remote-dc` and now `remote-fw` for the firewalls - are
in `deploy/logrotate-split-dc/`.
