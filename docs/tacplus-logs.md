# A TACACS+ daemon of your own, read beside ISE's

Not every site puts its switches behind ISE. `tac_plus` — Shrubbery's, and the
`tac_plus-ng` that came after it — is a TACACS+ daemon a site runs itself, and
where one is in front of the network gear it holds exactly what the TACACS tab
holds about ISE: who signed in to which switch, from where, and every command
they ran once they were in.

Switch it on under **Settings → The tac_plus logs** and a **TAC_Plus** button
appears on **Logins** and on **Failed attempts**, beside the TACACS+ one that
is ISE's. The two are never mixed: either daemon may be in front of any switch,
and which of them answered is most of what somebody wants to know.

**Nothing read here is ever judged and nothing here can earn anybody a ban.**
Signing in to a switch never has been, through ISE either, and the address on
one of these lines is as often as not the jump host the whole of the network
staff comes through. There is no ban button on the row.

---

## Setting the server up

**The procedure, step by step with a check after each step, is in
[tacplus-setup.md](tacplus-setup.md)**, and the three rsyslog files are
ready to copy in [`deploy/tacplus/`](../deploy/tacplus/). What follows is
why each piece is the way it is.

Four things decide how much of the picture reaches this page. Each of them is
worth doing and each of them buys something you can point at.

### 1. The accounting log — what people did

In `tac_plus.conf`:

```
accounting file = /var/log/tacacs/tac_acct.log
```

One record to a line, tab separated: five things in a fixed order and then
whatever the device sent, as `key=value`.

```
Sep 16 11:56:52<TAB>192.9.212.254<TAB>admin<TAB>tty1<TAB>10.10.10.9<TAB>stop<TAB>task_id=9947<TAB>timezone=UTC<TAB>service=shell<TAB>start_time=1631786213<TAB>priv-lvl=15<TAB>cmd=configure terminal <cr>
```

| | |
|---|---|
| `Sep 16 11:56:52` | when the record was written — **with no year in it** |
| `192.9.212.254` | the switch |
| `admin` | who |
| `tty1` | which line of it — a console, a vty, `webui_port` |
| `10.10.10.9` | where they came from, or `unknown` |
| `stop` | what kind of record this is |
| `cmd=…` | what they ran. Everything after it belongs to it |

### 2. The daemon's own log — what was turned away

**The accounting log holds what happened, never what did not.** A sign-in that
was refused is in the daemon's own log and nowhere else, so without this the
TAC_Plus button on *Failed attempts* is empty however much is on *Logins*.

`tac_plus` writes its own messages through **syslog**, into
`/var/log/messages` unless something says otherwise:

```
grep tac_plus /var/log/messages | grep -v 'connect from' | tail -30
```

The `connect from` lines are every connection a device opens, and on a switch
with command accounting that is one per command — thousands a day. They are
the daemon talking about itself, and this leaves them alone. What matters is
what is left after them; the shapes this reads are:

```
Sep 29 09:14:02 tacsrv tac_plus[2461]: login query for 'jnovak' tty2 from 10.10.10.9 rejected
Sep 29 10:02:11 tacsrv tac_plus[2461]: login failure: admin 192.9.211.198 (192.9.220.153) tty1
Sep 29 10:47:55 tacsrv tac_plus[2461]: authorization query for 'dpmo' tty1 from 192.9.220.153 rejected
Sep 29 12:20:44 tacsrv tac_plus[2461]: Authentication failed for 'svc-backup' from 10.20.0.7
```

**If your daemon writes refusals in some other wording, send one of those
lines and it will be taught it.** Which of them a given build writes, and
whether it writes them at all without `-d`, differs between versions.

### 3. Getting both here — and the two things rsyslog does to them

Both files go to this machine over syslog. What arrives has to be exactly what
tac_plus wrote, and rsyslog left to its defaults does two things to it on the
way, each of which on its own ruins the first import:

* **It turns every TAB into `#011`.** The tabs are the only thing between one
  field of an accounting line and the next. From 1.10.85 this reads `#011` as
  a tab, so it no longer matters — but a receiver that already has
  `parser.escapeControlCharactersOnReceive="off"` (the eduroam set-up does)
  keeps the real ones.
* **The first time it is pointed at a file, it sends all of it** — five years
  of a switch at once — and every line arrives stamped with the moment it was
  *sent*. From 1.10.85 a stamp in front of the line is never believed over the
  one tac_plus wrote on it: it only says the line was written no later than
  that. Measured on the log this was written against, the version before would
  have filed 15,356 lines as the afternoon they were shipped; this one files
  none.

#### On the tac_plus server

Find the accounting file first. The configuration a daemon is actually running
with is on its command line, and it is not always the one in `/etc`:

```bash
ps -ef | grep [t]ac_plus                 # -C says which config it read
grep -i 'accounting file' /path/from/-C
ls -la /var/log/tacacs/
```

If rsyslog says `imfile: on startup file '…' does not exist`, it is this: the
path it was given is not where tac_plus writes. `mkdir -p /var/log/tacacs` if
the directory itself is missing — tac_plus does not make it.

```
# /etc/rsyslog.d/50-tacplus.conf
#
# The daemon's own messages: a copy here, and straight on to isemon as they
# happen. Forwarded as they are written rather than read back out of a file,
# so the stamp on each is the moment it happened.
if $programname == 'tac_plus' then {
    action(type="omfile" file="/var/log/tacacs/tac_plus.log")
    action(type="omfwd" target="isemon.example.int" port="514" protocol="tcp"
           template="RSYSLOG_ForwardFormat"
           queue.type="LinkedList" queue.filename="tacplus_said"
           queue.saveOnShutdown="on" action.resumeRetryCount="-1")
    stop
}
```

```
# /etc/rsyslog.d/60-tacplus-ship.conf
#
# The accounting file, which tac_plus writes itself rather than through syslog,
# read as it grows and sent on. Nothing is added to the line.
module(load="imfile")

input(type="imfile"
      File="/var/log/tacacs/tac_acct.log"
      Tag="tac_acct:"
      ruleset="tacplus_acct")

ruleset(name="tacplus_acct") {
    action(type="omfwd" target="isemon.example.int" port="514" protocol="tcp"
           template="RSYSLOG_ForwardFormat"
           queue.type="LinkedList" queue.filename="tacplus_acct"
           queue.saveOnShutdown="on" action.resumeRetryCount="-1")
}
```

`isemon.example.int` is the machine this program runs on — put yours in
both places. The queue lines are what keeps a reboot of this machine from
losing whatever was written while it was down: rsyslog holds it on disk and sends it when the
receiver is back.

Check it before restarting — the one command that says what is wrong with a
configuration without taking logging down to find out:

```bash
rsyslogd -N1
systemctl restart rsyslog
```

(`rsyslogd`, with the `d`. On CentOS 7 it is 8.24, and everything above is
written for that version.)

#### On this machine

The same shape as the ISE logs (`deploy/rsyslog-ise.conf`): one folder per
sending host under `/var/log/remote`, readable by the `isemon` group. The
host's name becomes a directory name, which is why it goes through
`secpath-replace` — it arrives over the network. Put it
**before** whatever rule stores everything else that arrives, because of the
`stop`:

```
# /etc/rsyslog.d/05-tacplus-store.conf
template(name="tacplusAcctFile" type="string"
         string="/var/log/remote/%HOSTNAME:::secpath-replace%/tac_acct.log")
template(name="tacplusSaidFile" type="string"
         string="/var/log/remote/%HOSTNAME:::secpath-replace%/tac_plus.log")

if $programname == 'tac_acct' then {
    action(type="omfile" dynaFile="tacplusAcctFile" template="RSYSLOG_FileFormat"
           dirCreateMode="0750"  dirOwner="root"  dirGroup="isemon"
           fileCreateMode="0640" fileOwner="root" fileGroup="isemon")
    stop
}
if $programname == 'tac_plus' then {
    action(type="omfile" dynaFile="tacplusSaidFile" template="RSYSLOG_FileFormat"
           dirCreateMode="0750"  dirOwner="root"  dirGroup="isemon"
           fileCreateMode="0640" fileOwner="root" fileGroup="isemon")
    stop
}
```

`RSYSLOG_FileFormat` writes a full stamp — the year, the zone, to the
microsecond — then the host and the tag, then the line exactly as it was
sent:

```
2026-09-29T16:20:00.123456+02:00 tacacs tac_acct: Sep 16 11:56:52	192.9.212.254	admin	tty1	…
2026-09-29T09:14:02.004211+02:00 tacacs tac_plus[2461]: login query for 'jnovak' tty2 from 10.10.10.9 rejected
```

Both are read as they stand. The `umask` note in
[freeradius-rsyslog-forwarding.md](freeradius-rsyslog-forwarding.md) applies
here word for word: if the files come out `-rw-------`, that is the rsyslog
unit's `UMask`, not these settings.

Then, under **Settings → The tac_plus logs**:

| | |
|---|---|
| Where tac_plus writes | `/var/log/remote/tacacs` (the sending host's name) |
| The accounting log in each | `tac_acct.log` |
| The daemon's own log beside it | `tac_plus.log` |

#### The year, and what actually decides it

**tac_plus cannot write a year.** `Sep 16 11:56:52` is all its accounting file
ever says. What dates a line here, in the order it is believed:

1. **`start_time`** from the device — seconds since the epoch, which cannot be
   a year or a zone out. 236,177 of the 251,533 lines in the log this was
   written against carry it; the rest came from devices with no clock.
2. **tac_plus's own stamp**, with the year taken from where the file has got
   to — the line before it — rather than from today. Every one of those
   15,356 lines lands between the exact moments either side of it.
3. **The stamp the shipper put in front**, only where tac_plus's own is not on
   the line at all; otherwise it only bounds it.

So the cure for "there is no year in it" is on the devices, not here: **NTP**,
so that every record carries `start_time`.

```
ntp server 192.9.211.10
clock timezone CET 1
clock summer-time CEST recurring last Sun Mar 2:00 last Sun Oct 3:00
```

### 4. What the devices send

The daemon writes down what it is told, and what it is told is set on the
switches and controllers. On IOS / IOS-XE:

```
aaa accounting exec default start-stop group tacacs+
aaa accounting commands 0 default start-stop group tacacs+
aaa accounting commands 1 default start-stop group tacacs+
aaa accounting commands 15 default start-stop group tacacs+
```

* `accounting exec` is the one worth adding if you have only the commands
  today. It writes the **sitting itself** — somebody sat down, somebody left,
  and how long they were there — and where those records exist this page uses
  them instead of working the sitting out for itself. The log sent here had
  none: 251,533 lines and every single one a command.
* `commands 0` and `commands 1` catch what an unprivileged shell ran.
  `commands 15` alone is why a log can be all `configure terminal` and no
  `show`.

On a wireless controller (AireOS), accounting is under *Security → AAA →
TACACS+ → Accounting*, and the same records arrive with `service=ciscowlc`.

**What is typed inside `configure terminal`.** A Cisco device asks the
TACACS+ server about a command typed in configuration mode only when it is
told to:

```
aaa authorization config-commands
```

Without it, ISE's log (and the session on this dashboard) shows
`configure terminal`, the `show` commands and `write`, and not one line of
what was changed in between. One site's ISE, read for a week across every
device, had authorised nothing but `show`, `configure`, `write` and `exit`.
With it, every configuration line is asked about and arrives like any other
command. Keep a fallback in the command method list
(`aaa authorization commands 15 default group <ISE> if-authenticated`), so
that an unreachable server does not leave nobody able to configure the
device. Command **accounting** at level 15 (above) writes configuration-mode
commands down whether or not they are authorised, which is how tac_plus sees
them.

---

## The sitting a command belongs to

TACACS+ carries nothing across a sign-in and the commands after it, whichever
daemon is answering: ISE writes a different session id on every record, and
tac_plus writes none at all. So a command is tied to a sitting by the four
things that genuinely do not change while somebody is at that prompt — **who,
which device, which line of it, where they came from** — which is the same
reading a person does looking down the log, and exactly how the TACACS+ rows
beside it are already drawn.

Where `aaa accounting exec` is on, the daemon writes the sitting and that is
used. Where it is not, the sitting is read out of the commands themselves: a
gap at the prompt, and then somebody is back. How long that gap is, is
`tacplus_gap_min` — thirty minutes by default. A row read that way says so:
*Session · read from the commands*.

## Reading them again

`isemon --rescan --logs tacplus` reads that module's files from the beginning
and nothing else. A record is stored under an id made out of the line itself,
so reading a file again adds what was missing and changes nothing that is
already here. Because nothing in these logs is ever judged, nothing is weighed
and nothing can be banned by it.

One caution, and it is the reason this is something you ask for by name: a line
with no stamp of its own carries no zone either. If **this machine's zone has
been changed** since they were last read, those lines arrive again at the new
time as well as at the old. Erase the module's records first where that is what
you are putting right — *Settings → The database → Erase collected data → the
records read from a tac_plus server's logs* — which also forgets where the
files were read up to. Lines that carry `start_time`, or that were shipped with
a stamp in front, are not affected by any of this.

## What is kept, and getting rid of it

*Settings → The database → What is in it* breaks out what lives **inside** the
two big tables rather than in one of their own: how many sittings, how many
commands, how many refusals, and how far back they go. On the site this was
written for the commands are far and away the biggest part of it — a quarter of
a million rows for five years of three accounts.

Erasing them is a group of its own on the same page, and on the command line:

```
isemon --erase tacplus
```

Nothing else is touched, and nothing anybody is banned for is in it.
