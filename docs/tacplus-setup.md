# Setting up a tac_plus server for isemon, step by step

The procedure, in the order it is done, with what to check after each step.
Why each piece is the way it is — the fields, the year, the sittings — is in
[tacplus-logs.md](tacplus-logs.md). The three rsyslog files are ready to copy
in [`deploy/tacplus/`](../deploy/tacplus/).

Written against a real server: CentOS 7, rsyslog 8.24, Shrubbery's
`tac_plus`. Anything newer works the same way.

**Install isemon 1.10.85 or later before step 4.** Older versions read none of
what rsyslog delivers with its defaults — every TAB arrives as `#011` — and
would file thousands of history lines as the afternoon they were sent.

---

## On the tac_plus server

### 1. Find where tac_plus really writes its accounting

The configuration file you edit is not always the one the daemon runs with.
Its command line says which it read:

```bash
ps -ef | grep [t]ac_plus                    # -C <file> is the config it is using
grep -i 'accounting file' /path/from/-C
ls -la /var/log/tacacs/
find / -xdev -name 'tac_acct*' 2>/dev/null
```

What you want to see is a file that grows as people type on the switches.
If the folder named in `accounting file` does not exist, make it —
tac_plus does not:

```bash
mkdir -p /var/log/tacacs
systemctl restart tac_plus          # or however it is started on this machine
```

**Check:** run `show clock` on a switch and see it arrive:

```bash
tail -f /var/log/tacacs/tac_acct.log
```

> If rsyslog later says `imfile: on startup file '…' does not exist`, it is
> this step: the path in `60-tacplus-ship.conf` is not where tac_plus writes.

### 2. Find out whether this tac_plus writes refusals at all

The accounting log holds what happened, never what was turned away. Refusals
are in the daemon's own syslog messages — if this build writes them. Type a
wrong password on a switch on purpose, once, then:

```bash
grep tac_plus /var/log/messages | grep -v 'connect from' | tail -30
```

The `connect from` lines are one per connection, thousands a day, and isemon
ignores them. What matters is what is left. isemon reads these shapes:

```
… tac_plus[2461]: login query for 'jnovak' tty2 from 10.10.10.9 rejected
… tac_plus[2461]: login failure: admin 192.9.211.198 (192.9.220.153) tty1
… tac_plus[2461]: authorization query for 'dpmo' tty1 from 192.9.220.153 rejected
… tac_plus[2461]: Authentication failed for 'svc-backup' from 10.20.0.7
```

If your wrong password left **nothing**, this build writes refusals only in
its debug mode, and the TAC_Plus button on *Failed attempts* will stay empty —
everything else still works. If it left a line in **another wording**, send
that line and isemon will be taught it.

### 3. Copy the two sending files

```bash
cp deploy/tacplus/50-tacplus.conf      /etc/rsyslog.d/
cp deploy/tacplus/60-tacplus-ship.conf /etc/rsyslog.d/
```

In **both**, replace `ISEMON` with the machine isemon runs on. In
`60-tacplus-ship.conf`, set `File=` to the path found in step 1.

| File | What it does |
|---|---|
| `50-tacplus.conf` | the daemon's own messages: a copy in `/var/log/tacacs/tac_plus.log`, and each one forwarded to isemon as it happens. They stop going into `/var/log/messages`. |
| `60-tacplus-ship.conf` | the accounting file, read by imfile as it grows and forwarded. |

Both forward over TCP with a queue on disk, so a reboot of either machine
loses nothing: rsyslog keeps what it could not send and sends it when the
other end is back.

If you tried an earlier version of these files, **remove it** — one that
built its own line with `%TIMESTAMP:::date-rfc3339% %msg%` sends something
that is not syslog, and the receiving end reads the wrong host and tag out of
it.

### 4. Check, then restart

```bash
rsyslogd -N1                 # checks the configuration without taking logging down
systemctl restart rsyslog
systemctl status rsyslog     # no imfile "does not exist" lines
```

`rsyslogd`, with the `d` — there is no command called `rsyslog`.

The first time imfile starts it sends the **whole** accounting file, years of
it at once. That is how the history gets across, and isemon 1.10.85 and later
date every one of those lines by what is written on it rather than by when it
was sent.

---

## On the isemon machine

### 5. Store what arrives

```bash
cp deploy/tacplus/05-tacplus-store.conf /etc/rsyslog.d/
rsyslogd -N1 && systemctl restart rsyslog
```

It writes one folder per sending host under `/var/log/remote`, readable by
the `isemon` group — exactly as the ISE logs are stored — and it comes
before `10-ise.conf`, which is where the listeners on port 514 are.

**Check:**

```bash
ls -la /var/log/remote/                     # a folder named after the tac_plus server
head -2 /var/log/remote/tacacs/tac_acct.log
```

A line looks like this — a full stamp, the host, the tag, then the line as
tac_plus wrote it:

```
2026-09-29T16:20:00.123456+02:00 tacacs tac_acct: Sep 16 11:56:52	192.9.212.254	admin	tty1	…
```

`#011` where the tabs were is fine; isemon reads either. `tac_plus.log`
appears only when the daemon first says something about somebody.

If the files come out `-rw-------` and isemon says *Permission denied*, that
is the rsyslog unit's `UMask`, not these settings — see
[freeradius-rsyslog-forwarding.md](freeradius-rsyslog-forwarding.md).

### 6. Switch the module on

**Settings → The tac_plus logs:**

| Setting | Value |
|---|---|
| Read a tac_plus server's logs | on |
| Where tac_plus writes | `/var/log/remote/tacacs` — the folder from step 5 |
| The accounting log in each | `tac_acct.log` |
| The daemon's own log beside it | `tac_plus.log` |

A **TAC_Plus** button appears on *Logins* and on *Failed attempts*. On an
installation that reads no ISE at all, switch **Settings → The ISE logs →
Read the ISE logs** off as well, and the VPN and TACACS buttons go away.

**Check:**

```bash
isemon --passed --kind tacplus --limit 5            # the sittings
isemon --passed --kind tacplus-commands --limit 5   # what was typed
isemon --failed --limit 20                          # refusals: the tac_plus server is the last column
```

...and on the page, *Settings → The database → What is in it* says how many
sittings, commands and refusals are stored and how far back they go.

---

## On the switches — what makes it complete

### 7. NTP, so every line carries its own moment

A switch with a clock sends `start_time` — seconds since the epoch, which
cannot be a year or a zone out — and isemon believes it over everything else.
Lines from a switch without one are dated by tac_plus's own stamp, which has
no year in it; isemon works the year out from the lines around them, but a
clock is better than working anything out.

```
ntp server <your NTP server>
clock timezone CET 1
clock summer-time CEST recurring last Sun Mar 2:00 last Sun Oct 3:00
```

### 8. Accounting of the sittings, and of every command

```
aaa accounting exec default start-stop group tacacs+
aaa accounting commands 0 default start-stop group tacacs+
aaa accounting commands 1 default start-stop group tacacs+
aaa accounting commands 15 default start-stop group tacacs+
```

* `accounting exec` writes the **sitting itself** — who sat down, when they
  left — and isemon then uses it rather than reading the sitting out of the
  commands.
* `commands 0` and `1` catch what an unprivileged shell ran; `commands 15`
  alone is why a log is all `configure terminal` and no `show`.

On an AireOS wireless controller: *Security → AAA → TACACS+ → Accounting*.

---

## If something is not right

| What you see | What it is |
|---|---|
| `imfile: on startup file '…' does not exist` | step 1 — the path in `60-tacplus-ship.conf` is not where tac_plus writes |
| no folder under `/var/log/remote` | nothing is arriving: port 514/TCP between the two machines, `ISEMON` in both sending files, `rsyslogd -N1` on both |
| the folder is there, TAC_Plus is empty | step 6 — the path in the settings, or *Permission denied* on the front page (step 5) |
| Logins full, Failed attempts empty | step 2 — this tac_plus does not write refusals, or writes them in a wording isemon has not been taught |
| every line filed as today | isemon older than 1.10.85 |
| TAC_Plus empty, no error anywhere | isemon older than 1.10.85 and rsyslog escaping the tabs |
| one sitting shown as several | the switch has no `accounting exec` and the prompt sat quiet longer than *A prompt sitting quiet this long is a new sitting* (30 min by default) |

To read everything again from the beginning once something has been put right:

```bash
isemon --rescan --logs tacplus
```

Only the tac_plus files are read, nothing is weighed, and nothing can be
banned by it.
