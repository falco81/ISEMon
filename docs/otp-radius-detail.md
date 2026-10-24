# The RADIUS detail log beside the token log

The token log answers one question — *was the number right* — and nothing
else. It cannot answer any other, because the token software is asked over
the loopback by whatever stands in front of it, so the only address on one of
its lines is the token server's own:

```
Sep 26 12:28:23 otp2 totp.cgi[15642]: Success: user=someone@example.cz, \
    mode=PAM_SM_AUTH, host=127.0.0.1, message=Valid token used
```

Everything a person actually wants to know about that attempt is in the
RADIUS packet that caused it, and that is in a different file — the detail
log of the FreeRADIUS the token software sits behind:

```
Sep 26 12:29:01 otp2 radius-detail[1682]: nas=172.22.0.137 id=a45245e92d9ed98c \
    file=auth-detail-20260926 ts=[Sat Sep 26 12:28:23 2026] \
    Packet-Type = Access-Request, User-Name := "someone@example.cz", \
    Calling-Station-Id = "203.0.113.9", NAS-Port-Type = Virtual, \
    Cisco-AVPair = "mdm-tlv=computer-name=DESKTOP-PUNVEJN", \
    Cisco-AVPair = "audit-session-id=2ee3a9694792a0006ab79e47", ...
```

That one line holds the person's own public address, the machine they were
on, the AnyConnect they were running, the tunnel group they came through and
the session id ISE wrote about the other half of the very same sign-in. With
this set up, isemon shows all of it beside every token attempt.

**It is read, never judged.** Nothing here is counted towards a ban and no
address in it is ever blocked, exactly as with the token log itself.

Everything in this document is the work of somebody else's server: it is set
up on the **token server**, not on the isemon machine. The files to do it
with are in `docs/otp-radius-detail/` beside this one.

---

## 0. What it is for, in one paragraph

FreeRADIUS writes its detail records as **multi-line blocks**, into files
named after the day and the NAS — `radacct/172.22.0.137/auth-detail-20260926`.
No syslog daemon of the CentOS 6 vintage can follow that: rsyslog 5.8 has no
wildcards in `$InputFileName` (they arrived in 8.25) and no multi-line
`readMode` (7.x). So a small script walks those files, puts each record back
together on one line, and hands it to syslog — from where the existing
forwarding rule carries it to the collector exactly as it already carries
`totp.cgi`. The FreeRADIUS configuration is not touched by the script at all.

The script runs **once a minute**. A record therefore reaches isemon up to a
minute after the token line it belongs to. That is by design, and isemon
expects it: a token attempt with nothing beside it yet says so rather than
looking broken.

## 1. What is in the package

| file | where it goes | md5 |
|---|---|---|
| `otp-radius-setup.sh` | run on the token server — §6.2 does all of it | `1896e98d0b81305af67987ca33aa4350` |
| `raddb-accounting-logging.patch` | applied in `/etc/raddb` | `8b810af4b6b406ae1d8efcacce58d89f` |
| `radacct-syslog-ship.py` | `/usr/local/sbin/radacct-syslog-ship.py` | `617ca6e536a16c1c47fc32e964a199e3` |
| `radacct-ship-cron` | `/etc/cron.d/radacct-ship` | `8d2e551e39d341f6ed7e27cbb2dfbf1e` |
| `31-forward-radacct.conf` | `/etc/rsyslog.d/31-forward-radacct.conf` | `2e2367181ea173b3511d97b797b34ead` |
| `totpcgi-handler-reason.patch` | applied in `/etc/raddb` — §6.1 | `fe54e7fe45da0d76efe772730daa9a2c` |
| `totpcgi-index-rid.patch` | applied in `/var/www/totpcgi` — §6.1 | `02a4de08e939893828f1e7bbcbc5bb26` |

Those sums are of the files shipped beside this document. **`otp-radius-setup.sh`
does everything the rest of this page describes** — §6.2 — and the six files
under it are what it does it with; it checks them against these same sums
before it touches anything.

Nothing in any of them has an address of this or any other site in it. The
one address there is to know — where the records are forwarded to — is asked
for when the script runs, or given to it with `--collector`.

**Copy them with scp or WinSCP. Do not paste them into a terminal** — a paste
joins lines together and Python then dies on `SyntaxError: invalid syntax`.

```bash
# from your own machine: the whole folder, and the script runs out of it
scp -r otp-radius-detail root@otp:/root/install/
```

Afterwards **always** check the sums against the table above:

```bash
cd /root/install && md5sum *
```

If a sum does not match, that file arrived damaged — do not carry on, send it
again. If scp is impossible, the file can be typed in `vi`: `:set paste`, `i`,
paste, `Esc`, `:wq` — and then check the sum again.

### 1.1 Before the script: `patch`, and yum on CentOS 6

The script applies three patches, so it needs `patch`. A minimal CentOS 6 does
not have it, and the script checks for it and stops before touching anything:

```
stopped: patch is not installed. yum install patch - ...
```

On CentOS 6 `yum install patch` usually fails too. CentOS 6 reached end of
life in 2020, its mirrors were emptied, and the repositories it was installed
with no longer answer. The packages are still on **vault.centos.org**. The
folder `centos6-yum/` beside the script holds the repository files that point
there, taken from a token server where they work:

| file | md5 |
|---|---|
| `centos6-yum/centos6-yum-repos.tgz` | `ece2017aefb04b1bda98ea1688cfd1ac` |

It contains `/etc/yum.repos.d/` as a whole: `CentOS-Base.repo` pointed at the
vault, plus the stock `CentOS-Vault`, `-Media`, `-Debuginfo` and `-fasttrack`
files and EPEL 6.

```bash
cd /root/install
md5sum centos6-yum/centos6-yum-repos.tgz        # against the table above

# 1) what is there now, kept
tar czf /root/yum.repos.d-before.tgz -C / etc/yum.repos.d

# 2) the files that point at the vault (the paths in it start at /etc)
tar xzf centos6-yum/centos6-yum-repos.tgz -C /

# 3) and patch
yum clean all
yum install patch
```

**If yum stops with `Cannot retrieve metalink for repository: epel`:** EPEL 6
was archived as well, and its `mirrorlist` no longer answers. `patch` is in
CentOS's own repositories, so skip EPEL for this:

```bash
yum --disablerepo=epel install patch
```

To use EPEL itself again, point it at the archive:

```bash
sed -i -e 's|^mirrorlist=https://mirrors.fedoraproject.org/metalink?repo=epel-6&.*|baseurl=https://archives.fedoraproject.org/pub/archive/epel/6/$basearch|' \
    /etc/yum.repos.d/epel.repo
```

`centos6-yum/` is not one of the files the script uses, and it checks none of
it. `md5sum *` in `/root/install` says `centos6-yum: Is a directory`, which
is harmless.

## 2. The patch on FreeRADIUS

It switches on:

- `auth = yes` in `radiusd.conf` → `Login OK` / `Login incorrect` into
  `radius.log`
- `auth_log` in `authorize {}` → `radacct/<IP>/auth-detail-YYYYMMDD`, the
  whole of the request's attributes, with `User-Password` suppressed
- `reply_log` in `post-auth {}` and in `Post-Auth-Type REJECT {}` →
  `radacct/<IP>/reply-detail-YYYYMMDD`: Accept, Challenge and Reject alike
- `log_packet_header = yes` on every detail instance → the packet type and
  the source and destination address and port
- a new `linelog_acct` instance, wired into `accounting {}` → a readable
  one-line log at `/var/log/radius/acct-linelog`

Accounting itself was already on (`detail`, `radutmp`, `acct_unique`, a
listener of `type = acct` on port 1813); the patch only widens it.

```bash
# 1) a copy of the whole configuration first
cp -a /etc/raddb /etc/raddb.bak-$(date +%F)

# 2) dry, then for real
cd /etc/raddb
patch -p1 --dry-run < /root/install/raddb-accounting-logging.patch
patch -p1           < /root/install/raddb-accounting-logging.patch

# 3) check the syntax WITHOUT restarting - the server carries on as it is
radiusd -XC
#    it has to end: "Configuration appears to be OK"

# 4) the logs' ownership
chown -R radiusd:radiusd /var/log/radius

# 5) and only now, the restart
service radiusd restart
tail -30 /var/log/radius/radius.log
```

Going back, if `radiusd -XC` complains:

```bash
rm -rf /etc/raddb && mv /etc/raddb.bak-$(date +%F) /etc/raddb
service radiusd restart
```

Three things worth knowing:

- `sites-enabled/default` is **not** a symlink to `sites-available/default`
  on this machine — the two drifted apart at some point. The patch changes
  `sites-enabled/default`, which is the one in use.
- Leave `suppress { User-Password }` on `auth_log` alone, or you will be
  writing OTP passcodes into a log file.
- Leave `auth_badpass` and `auth_goodpass` at `no`, for the same reason.

To check that accounting is arriving from the VPN head end or the VDI broker
at all:

```bash
netstat -anup | grep 1813
iptables -L INPUT -n | grep 1813      # if missing: -A INPUT -p udp --dport 1813 -j ACCEPT
tcpdump -ni any udp port 1813 -vv
```

A made-up test (the secret for `localhost` is in `clients.conf`):

```bash
echo "User-Name=testuser,Acct-Status-Type=Start,Acct-Session-Id=\"test001\",NAS-IP-Address=127.0.0.1,Framed-IP-Address=10.9.9.9" \
  | radclient -x 127.0.0.1:1813 acct SECRET

tail -3 /var/log/radius/acct-linelog
ls -l /var/log/radius/radacct/127.0.0.1/
```

If `radacct` stays empty and tcpdump shows no packets, the problem is not in
RADIUS: the head end is not sending accounting, or the shared secret does not
match.

## 3. Shipping the records to syslog

### 3.1 The script

`radacct-syslog-ship.py` walks every `detail-*`, `auth-detail-*` and
`reply-detail-*` file in every subdirectory of `radacct` — new days and new
NASes included, with nothing to configure — and sends the new records to
syslog.

- one detail record, a block ended by a blank line, is one syslog message
- every record carries an `id=`, a hash of the NAS, the file and the record
  itself. The same record always hashes to the same id and two records never
  share one, because the packet's own timestamp and its Message-Authenticator
  go into it — so a file read again from the beginning arrives as the records
  isemon already holds rather than as new ones that merely look the same
- offsets live in `/var/lib/radacct-ship`, so nothing is ever sent twice
- a record still being written at the end of a file is skipped and sent on
  the next run
- a file that has shrunk or been replaced is noticed and read from the start
- `User-Password`, `CHAP-Password` and the MS-CHAP responses are replaced
  with `<suppressed>`
- `flock` against two runs at once; Python 2.6 (CentOS 6)
- **it does not touch the FreeRADIUS configuration**

```bash
install -m 700 /root/install/radacct-syslog-ship.py /usr/local/sbin/
mkdir -p /var/lib/radacct-ship

# that it did not arrive damaged
md5sum /usr/local/sbin/radacct-syslog-ship.py
python -m py_compile /usr/local/sbin/radacct-syslog-ship.py && echo "syntax OK"

# the first run, by hand
/usr/local/sbin/radacct-syslog-ship.py -v
```

To start **from now** rather than send the whole history, set the offsets to
the current sizes **before** the cron entry goes in:

```bash
for f in $(find /var/log/radius/radacct -type f -name '*detail-*'); do
  k=$(echo "${f#/}" | tr '/' '_')
  stat -c %s "$f" > "/var/lib/radacct-ship/${k}.offset"
done
```

### 3.2 rsyslog

```bash
cp /root/install/31-forward-radacct.conf /etc/rsyslog.d/
```

Its one working rule is:

```
local5.*   @COLLECTOR:514;RSYSLOG_ForwardFormat
```

— the same shape as the existing `/etc/rsyslog.d/30-forward-otp.conf` for
`totp.cgi`. A commented-out `local5.* ~` is in the file; uncomment it if you
do not also want these messages in `/var/log/messages` (it has to come after
the forward).

**The message length limit has to be raised.** rsyslog cuts at 2048 bytes by
default and a longer detail record goes past it. On the very first line of
`/etc/rsyslog.conf`, before every `$ModLoad` and every rule:

```
$MaxMessageSize 8192
```

Set the same on the collector, or the receiving side cuts the message
instead.

```bash
grep -n "WorkDirectory" /etc/rsyslog.conf                       # /var/lib/rsyslog
grep -rn "local5" /etc/rsyslog.conf /etc/rsyslog.d/             # a clash of facilities?
service rsyslog restart
```

If `local5` is already in use for something else, change the facility in
`31-forward-radacct.conf` and in `SYSLOG_FACILITY` in the script to match —
`syslog.LOG_LOCAL6`, say.

### 3.3 cron

```bash
install -m 644 /root/install/radacct-ship-cron /etc/cron.d/radacct-ship
```

It starts the script every minute, and at 4:17 each day deletes the offset
files of detail files that are gone.

**Every minute is not often enough, and the line says so.** Cron's finest
interval is a minute, so a record written a moment after a run waits nearly
a whole one before it leaves the machine — and that is exactly the wait
somebody sees as a token attempt sitting there with nothing beside it. The
line shipped runs

```
/usr/local/sbin/radacct-syslog-ship.py --every 5 --seconds 55
```

— one run a minute that sweeps the minute: it looks every five seconds and
is gone at fifty-five, before the next run is due. The wait for a record to
leave drops from up to sixty seconds to up to five. Take the two flags off
for the old behaviour.

The run holds a lock the whole time, so two can never overlap whatever cron
does; if one ever did overstay, the next minute's run finds the lock held
and exits, which costs one sweep and nothing else.

## 4. Proving the whole path

```bash
# 1) watch what leaves
tcpdump -ni any udp port 514 and host COLLECTOR &

# 2) make an accounting record
echo "User-Name=testuser,Acct-Status-Type=Start,Acct-Session-Id=\"syslogtest\",NAS-IP-Address=127.0.0.1,Framed-IP-Address=10.9.9.9" \
  | radclient -x 127.0.0.1:1813 acct SECRET

# 3) ship it
/usr/local/sbin/radacct-syslog-ship.py -v
#   shipped N records
```

tcpdump has to show a packet to the collector holding `syslogtest`. On the
collector the messages arrive under programname `radius-detail`, so the
filter is written exactly as the one for `totp.cgi`:

```
:programname, isequal, "radius-detail"
```

Also watch the OUTPUT chain: UDP 514 to the collector has to be allowed. It
already is for `totp.cgi`, so it almost certainly is.

## 5. Telling isemon about it

Settings → **The OTP logs**:

| setting | what to put |
|---|---|
| *Read the RADIUS log beside it* | on |
| *What that one is called* | `radius-detail.log` — whatever the collector writes it as |
| *Where OTP sign-ins come from* | `172.22.0.137=VPN, 192.168.4.0/24=VDI` |
| *Mark a sign-in from anywhere else* | on |

The file has to be in the **same folder** as the token log of that server:
one folder per token server, `totp.cgi.log` and `radius-detail.log` side by
side in each. That is what the collector's own rules already produce.

From the shell instead:

```bash
isemon --set otp_detail=1 --set otp_detail_name=radius-detail.log \
       --set otp_from='172.22.0.137=VPN, 192.168.4.0/24=VDI'
```

*Where OTP sign-ins come from* is the OTP twin of *Where TACACS sign-ins come
from*: an address or a range, optionally named, and the names are used
wherever those addresses are drawn. It is what turns "172.22.0.137 asked" into
"somebody signed in to the VPN", and what makes a **new** box appearing in
front of the token server something anybody notices.

Once it is on, every token attempt on the Failed attempts and Logins pages
shows the person's own address and the door they came through instead of
*the server itself*, and opening one shows the rest: the machine, the client
software, the ISE session id, and every attribute on the packet.

## 6. How an attempt and its packet are put together

Worth reading once, because it is the one part of this that is a judgement
rather than a fact.

The two logs are written by two different programs. `totp.cgi` says whether
the number was right; FreeRADIUS says who was asking and from where. Neither
writes anything the other also writes — no shared id, no shared request
number — so isemon joins them on **who, where and when**, and makes that as
hard to get wrong as those three allow:

* **the whole account wins over the bare name.** Both sides write
  `somebody@example.cz`. Matching on the half in front of the `@` would make
  one person out of two on a site with two realms in front of one token
  server, so the whole of it is tried first and the bare name is only the
  fallback.
* **a verdict that agrees wins over one that does not.** Between two
  candidates a second apart, one that answered the way the token log says it
  went is the better bet.
* **one packet belongs to one attempt.** Once the nearest attempt has taken
  it, it is not offered to the next — so three tries in ten seconds get three
  packets in the order they happened, not the same one three times.
* **the window is five seconds either way.** The two programs run on one
  machine, one calling the other, so in practice they agree to the second or
  are one apart.
* **and where it is still a guess, the record says so.** Two candidates
  equally close and equally good is a tie nothing in either log can break.
  The nearer one is shown, with a line saying it is the likely one rather
  than the known one.

### Why a packet arrives after the attempt it belongs to

The token line is written by the token server the instant it answers. The
RADIUS record beside it is written to a file, and gets to isemon only when
the shipper next runs — so it is **always** behind, and the page shows the
attempt before it can show anything about it.

Where the wait comes from, on a machine set up as above:

| | how long |
|---|---|
| FreeRADIUS writing the record | none worth measuring — `auth_log` writes it while the request is still in hand |
| waiting for the next sweep of the shipper | **0 to 5 seconds** with the line in §3.3, 0 to 60 with a plain one-a-minute cron |
| syslog carrying it to the isemon machine | milliseconds on a local network |
| isemon noticing the new line | 0 to `read_every_s` — five seconds as it ships |

So a few seconds, and up to about ten. Longer than that and something is
stopped rather than slow: the record's own page says how far behind the
shipping is running, and §4 proves the path end to end.

isemon draws the row again by itself when the packet turns up — there is
nothing to reload and nothing to wait for beyond the above.

### Why both logs are read, and not just this one

A fair question once the RADIUS log is arriving: it holds who, where, which
machine and which door — why keep reading the token log at all?

Because the one thing it does not hold is **why**. Counted over two days of
one real site's traffic:

| what the token server said | how often | what RADIUS shows |
|---|---:|---|
| Valid token used | 80 | Access-Accept |
| Valid token within window size used | 3 | Access-Accept |
| Token has already been used once | 5 | Access-Reject |
| Rate-limit reached, please try again later | 5 | Access-Reject |
| Not a valid token | 2 | Access-Reject |
| Token is not an integer | 1 | Access-Reject |
| …totp does not exist or is not readable | 2 | Access-Reject |

Every one of those fifteen refusals is the same Access-Reject in the RADIUS
log, and they are not the same thing at all: *token already used* is a
passcode being replayed, *rate-limit reached* is somebody leaning on one
account, and *within window size* is an accepted sign-in from a phone whose
clock is drifting — which in RADIUS is indistinguishable from an ordinary
one. An Access-Reject can also happen without the token software being asked
at all, so even the verdict is not quite the same question on both sides.

So: **RADIUS has who and from where, the token log has why**, and neither
has both.

### 6.1 Making it exact instead

**Three things, and all three are needed.** Two of them are patches that
ship beside this document and the third is two lines of configuration;
between them they turn all of the above into a lookup. Leaving any one out
is not half of it — it is none of it, because the id has to be created, then
passed along, and then written down, and each of the three does exactly one
of those:

| | what it does | without it |
|---|---|---|
| the two configuration lines below | **makes** the id, out of the address and port the packet came from | the handler has nothing to pass on and sends no `rid` at all |
| `totpcgi-handler-reason.patch` | **passes** it from FreeRADIUS to the token server | the token server is never told, so it cannot write it |
| `totpcgi-index-rid.patch` | **writes** it on the token server's own log line | the id exists on the RADIUS side only and there is nothing to join to |

§6.2 does all three, with one command. What
follows here is what each one is and why. All three are reversible, and
nothing on this page stops working if you never apply any of them.

**`totpcgi-handler-reason.patch`** — `/etc/raddb/totpcgi-handler.pl`, the
`rlm_perl` module FreeRADIUS calls to check a token. It does two things:

1. **It puts the token server's own reason into the reply.** The handler
   already has the CGI's answer in its hands; today it throws the body away
   and reports the HTTP status, so every refusal reaches the RADIUS log as
   the same sentence, `Denied access by rlm_perl authenticate function.
   ERROR: 400 BAD REQUEST`. With this, the reply says
   `Denied by the token server: Token has already been used once` — and
   that lands in `reply-detail`, where everything else about the attempt
   already is.
2. **It passes the RADIUS client's own address and port through to the CGI**
   as one more form field, `rid`. That pair is what makes one packet
   different from every other: the detail log writes it as
   `Packet-Src-IP-Address` and `Packet-Src-Port`, and the reply goes back
   to it.

**Two lines of FreeRADIUS configuration**, because the pair the client asked
from is **not a RADIUS attribute**. The server can expand
`%{Packet-Src-IP-Address}` in its own configuration, but it is not in the
list of attributes a module is handed — ask `rlm_perl` for it and you get
nothing, which on a first attempt showed up as a token log line reading
`rid=:` and meaning nothing at all. So the configuration is asked to put it
somewhere the module can read.

In `/etc/raddb/dictionary`, at the end:

```
ATTRIBUTE	Totp-Request-Id		3000	string
```

An attribute numbered above 255 in that file is internal to the server and
never goes out on the wire, which is what this one wants to be.

In `/etc/raddb/sites-enabled/default`, as the first thing inside
`authorize {`:

```
	update request {
		Totp-Request-Id := "%{Packet-Src-IP-Address}:%{Packet-Src-Port}"
	}
```

**The port is `Packet-Src-Port`, with no `IP` in it** — and the same server
writes it into its own log under the other name. This is worth saying
slowly, because it is where a day went.

The attribute the configuration expands is in FreeRADIUS's own internal
dictionary, where `Packet-Src-IP-Address` and `Packet-Src-Port` sit side by
side under names that do not match each other. Asking for
`%{Packet-Src-IP-Port}` there is asking for an attribute that does not
exist: the server does not complain, it expands it to nothing, and the token
log then reads

```
rid=127.0.0.1:, message=Valid token used
```

— an address, a colon, and nothing. An id that is only the address is no id
at all, because every packet from one VPN head end carries the same one. If
that is what a token line says, it is this name and nothing else.

The detail module then writes the very same value into the file under
`Packet-Src-IP-Port`, `IP` and all. Both names, one server, one run — this
is 2.2.6:

```
Totp-Request-Id := "%{Packet-Src-IP-Address}:%{Packet-Src-Port}"     the configuration

nas=127.0.0.1 file=auth-detail-20260926 ts=[Sat Sep 26 16:10:38 2026] \
    Packet-Type = Access-Request, Packet-Src-IP-Address = 127.0.0.1, \
    Packet-Src-IP-Port = 43537, ... Totp-Request-Id = "127.0.0.1:43537"
```

So the rule is: **`Packet-Src-Port` when you are asking the server for it,
`Packet-Src-IP-Port` when you are reading its log.** isemon reads both and
does not care which a server chose.

`radiusd -XC` has to say *Configuration appears to be OK* before the
restart. Without these two the handler simply sends no id and everything
falls back to the matching in §6 — it does not send an empty one, because a
field that says nothing is worse than a field that is not there.

**`totpcgi-index-rid.patch`** — `/var/www/totpcgi/index.cgi`, the token
server itself. It writes that `rid` on both of its own log lines, and it
returns which kind of success a success was, which is knowledge it alone
has. A caller that sends no `rid` is answered exactly as before, and both
additions sit behind a `try`: a line meant for whoever reads the logs
afterwards must never be the reason somebody cannot sign in.

**Do not run `patch` on `index.cgi` directly.** It does not edit a file in
place: it writes a new one and renames it over the old, so the file that
ends up there is owned by whoever ran the command. Apache serves that CGI
through **suexec** (`SuexecUserGroup totpcgi totpcgi` in the vhost), and
suexec refuses to run a script it does not own:

```
suexec policy violation: see suexec log for more details
Premature end of script headers: index.cgi
target uid/gid (500/500) mismatch with directory (500/500) or program (0/500)
```

— which reaches whoever is signing in as a bare **500 with an empty body**,
and reaches the RADIUS log as `the token server answered 500 Internal Server
Error`. The file's contents are perfectly fine; it is the ownership that is
wrong, and `cat index.cgi` shows nothing amiss.

So patch a **copy** and pour it back through the original file, which leaves
the inode, its owner, its mode and its SELinux context exactly as they were:

```bash
cp -a /etc/raddb/totpcgi-handler.pl /etc/raddb/totpcgi-handler.pl.bak-$(date +%F)
cp -a /var/www/totpcgi/index.cgi    /var/www/totpcgi/index.cgi.bak-$(date +%F)

# the token server's CGI - through the inode, never over it
cp -a /var/www/totpcgi/index.cgi /tmp/index.cgi.work
patch -p0 /tmp/index.cgi.work < /root/install/totpcgi-index-rid.patch
cat /tmp/index.cgi.work > /var/www/totpcgi/index.cgi
rm -f /tmp/index.cgi.work
ls -lZ /var/www/totpcgi/index.cgi     # the same owner as before: totpcgi

# the RADIUS handler, which radiusd reads as root and suexec never sees
cd /etc/raddb && patch -p0 --dry-run < /root/install/totpcgi-handler-reason.patch
cd /etc/raddb && patch -p0           < /root/install/totpcgi-handler-reason.patch
```

If it has already been patched the other way, one command puts it right:

```bash
chown totpcgi:totpcgi /var/www/totpcgi/index.cgi
```

Then check the syntax with the token server's **own** Python and Perl before
anything is restarted — a CGI that will not compile is the same empty 500,
for a different reason:

```bash

perl -c /etc/raddb/totpcgi-handler.pl        # "syntax OK"
python -m py_compile /var/www/totpcgi/index.cgi && echo "syntax OK"
python -V                                    # what it was checked against

# the CGI answering by itself, before anything restarts. A user and a token
# have to be in it: without them it stops at "Missing field" before it
# reaches any of this, and proves nothing at all. It must print a 400 and a
# reason - not a traceback, and not an HTML page.
cd /var/www/totpcgi
REQUEST_METHOD=GET REMOTE_ADDR=127.0.0.1 \
  QUERY_STRING='user=nobody&token=000000&mode=PAM_SM_AUTH&rid=1.2.3.4:5678' \
  python index.cgi

radiusd -XC              # "Configuration appears to be OK"
service radiusd restart
radtest USER TOKEN 127.0.0.1 1812 testing123
```

Nothing the patches add is newer than **Python 2.4** or needs a Perl module
the handler did not already use, so an old token server takes them as
happily as a new one. Going back is `patch -R` with the same two files, or
the copies taken above.

If a sign-in does fail afterwards, the reply says which of the two ends it
was. `Denied by the token server: <the reason>` is the token server
refusing, which is the whole point of the patch. `Denied by the token
server: the token server answered 500 Internal Server Error` is the token
server itself being broken, and there are exactly two places to look — in
this order:

```bash
# 1) the vhost's own log, NOT /var/log/httpd/error_log: that CGI is a vhost
#    of its own (Listen 8443) and writes somewhere of its own
grep -n ErrorLog /etc/httpd/conf.d/totpcgi.conf
tail -40 /var/log/httpd/totpcgi-error.log

# 2) suexec, whose refusals appear in the log above only as "policy
#    violation" and say what they were here. Filter out the other vhost's
#    CGI or it drowns this one: some sites poll it every few seconds.
grep -v totpcgiprov /var/log/httpd/suexec.log | tail -20
```

`Premature end of script headers` with a `suexec policy violation` beside it
is the ownership above. `Premature end of script headers` on its own is an
exception inside the CGI: it has `cgitb.enable()` at the top, which prints a
traceback as HTML **without writing any headers first**, so Apache sees a
malformed answer and sends its own 500. Running the CGI by hand, as above,
prints that traceback where you can read it.

Afterwards a token line looks like this, and the shape of its `rid=` says
which of the three is missing:

| the token line says | what is not in place |
|---|---|
| no `rid=` at all | the two configuration lines, or the dictionary entry among them — the handler found nothing and sent nothing |
| `rid=` with nothing after it | the same, but the handler was patched a way that sends an empty one. The one here never does |
| `rid=127.0.0.1:` — an address, a colon, nothing | `%{Packet-Src-IP-Port}` in the `update request` where it should say `%{Packet-Src-Port}` |
| nothing changed on the line at all | `totpcgi-index-rid.patch` on `/var/www/totpcgi/index.cgi` — the CGI is being sent the id and is throwing it away |

Right, it reads — and this is a real one, off a server with all three in
place:

```
Sep 26 16:10:39 otp1 totp.cgi[9499]: Success: user=mdolezal@example.cz, \
    mode=PAM_SM_AUTH, host=127.0.0.1, rid=127.0.0.1:43537, \
    message=Valid token used

Sep 26 16:11:01 otp1 radius-detail[9512]: nas=127.0.0.1 id=9572d1b230a58771 \
    file=auth-detail-20260926 ts=[Sat Sep 26 16:10:38 2026] \
    Packet-Type = Access-Request, ... User-Name := "mdolezal@example.cz", \
    Totp-Request-Id = "127.0.0.1:43537"
```

— the same `127.0.0.1:43537` on both, twenty-two seconds apart because the
second one waited for the shipper, and isemon joins them **by that name**:
no window, no tie-breaking, no clocks. On a real VPN sign-in the address is
the head end's rather than the loopback; the shape is the same. The record
says so, too: *matched by the id both logs carry*. It goes on working when
the two machines' clocks are minutes apart, which is the case nothing else
here can survive.

Rolling back is `patch -R` with the same two files, and everything falls back
to the matching above.

### 6.2 All of it, done

Everything on this page, in the order it has to happen, as a file you run:

```bash
cd /root/install/otp-radius-detail
./otp-radius-setup.sh
```

It asks where the records are to be forwarded to — the isemon machine, by
address or by name, because there is no sensible guess and nothing in the
package has one built in — and then, **before it writes anything at all**, it
prints every file it is about to change or create and puts a copy of all of
them into one `.tar.gz` in the folder you started it from:

```
== what this is going to write, and nothing has been written yet
   change   /etc/raddb/dictionary
   change   /etc/raddb/modules/detail
   change   /etc/raddb/modules/detail.log
   change   /etc/raddb/modules/linelog
   change   /etc/raddb/radiusd.conf
   change   /etc/raddb/sites-enabled/default
   change   /etc/raddb/totpcgi-handler.pl
   change   /etc/rsyslog.conf
   create   /etc/rsyslog.d/31-forward-radacct.conf
   create   /usr/local/sbin/radacct-syslog-ship.py
   create   /etc/cron.d/radacct-ship
   change   /var/www/totpcgi/index.cgi
   chown    /var/log/radius, /var/www/totpcgi/index.cgi
   write    /var/lib/radacct-ship/*.offset  (how far each log was read)
   restart  radiusd, rsyslog

== keeping a copy of all of that first
   /root/install/otp-radius-detail/otp-radius-backup-otp1-20260926-160418.tar.gz
   9 file(s) in it. Putting them all back is:
       tar -xzf .../otp-radius-backup-otp1-20260926-160418.tar.gz -C /

Go ahead and write all of that? [y/N]
```

That list is not written down in the script: the raddb files are read out of
the patches themselves, so what it shows is what it will really write on
whatever server it is run on. The copy goes where you started it rather than
somewhere under `/etc`, so that a mistake in the next ten minutes cannot take
the copy with it, and it unpacks straight back over the original paths with
`tar -xzf … -C /`.

Then it does the work, and only the work. No test sign-ins and no tcpdump:
those are in §2, §4 and §6.1 and they are worth doing, but they are not what
a script should decide to do on a live server. The one check it does make is
`radiusd -XC` **before** the restart, and on a configuration that does not
parse it stops there, restarts nothing, and leaves the server running on
what it had.

| it takes | for |
|---|---|
| `--collector HOST` | answering the one question in advance |
| `--yes` | not being asked before it writes. The list and the copy are still made, and still shown |
| `--from DIR` | the six files being somewhere other than beside it |
| `--no-restart` | changing everything and restarting nothing |
| `--skip-sums` | not checking the six against the table in §1 |

It is **safe to run twice**, and on a server that is already half-way there:
a patch that is in is said out loud and left alone rather than taken for a
failure, and the two configuration lines are only written if they are not
there. Run on a server that already had §2 and on one that had nothing, it
leaves the two identical.

#### The same thing as a block to paste

For a server one would rather not put a file on. It is the script without the
asking, the list of what it will touch or the copy of it, so `COLLECTOR` in
`31-forward-radacct.conf` has to be replaced by hand first. It wants the six
files beside this document to be in `/root/install` already, with their sums
checked as in §1, and nothing else.

Paste it as one block. It does not mind a server that is already half-way
there: a patch that is in is reported and left alone rather than being taken
for a failure, and the two configuration lines are only written if they are
not there — so it can be pasted on a server that is as it came, on one that
already has §2, and twice on the same one. Every step keeps a copy of what
it changes first, and the very last lines are the only ones that restart
anything.

```bash
set -e
cd /root/install

#  A patch that is already in is not a failure: this says so and carries
#  on, so the block is safe to paste on a server that is half-way there
#  and safe to paste twice. Anything else that goes wrong still stops
#  everything, which is what set -e is here for.
#     apply <-pN> <patch file> [the one file to patch]
apply() {
  strip=$1; pf=$2; tgt=$3
  if patch $strip -R -f --dry-run $tgt -i "$pf" >/dev/null 2>&1; then
    echo "   already applied, left alone: $pf"
  else
    patch $strip -N $tgt -i "$pf"
  fi
}

#  everything this touches, kept first
cp -a /etc/raddb /etc/raddb.bak-$(date +%F)
cp -a /var/www/totpcgi/index.cgi /var/www/totpcgi/index.cgi.bak-$(date +%F)

#  1) the detail and reply logs, and the one-line accounting log
cd /etc/raddb
apply -p1 /root/install/raddb-accounting-logging.patch
chown -R radiusd:radiusd /var/log/radius

#  2) the id itself: an attribute the server keeps to itself,
#     filled in before anything else in authorize{} looks at the request
grep -q Totp-Request-Id /etc/raddb/dictionary \
  || printf '\nATTRIBUTE\tTotp-Request-Id\t\t3000\tstring\n' >> /etc/raddb/dictionary
grep -q Totp-Request-Id /etc/raddb/sites-enabled/default \
  || perl -0pi -e 's/^authorize \{\n/authorize {\n\tupdate request {\n\t\tTotp-Request-Id := "%{Packet-Src-IP-Address}:%{Packet-Src-Port}"\n\t}\n\n/m' \
       /etc/raddb/sites-enabled/default

#  3) passing it on, and the token server's own reason into the reply
cd /etc/raddb
apply -p0 /root/install/totpcgi-handler-reason.patch

#  4) writing it down on the token server's own log line. Through the
#     inode, never over it: patch renames a new file over the old and
#     suexec then refuses to run a CGI it does not own - see §6.1
cp -a /var/www/totpcgi/index.cgi /tmp/index.cgi.work
apply -p0 /root/install/totpcgi-index-rid.patch /tmp/index.cgi.work
cat /tmp/index.cgi.work > /var/www/totpcgi/index.cgi
rm -f /tmp/index.cgi.work
chown totpcgi:totpcgi /var/www/totpcgi/index.cgi

#  5) shipping the records to syslog
install -m 700 /root/install/radacct-syslog-ship.py /usr/local/sbin/
mkdir -p /var/lib/radacct-ship
cp /root/install/31-forward-radacct.conf /etc/rsyslog.d/
grep -q '^\$MaxMessageSize' /etc/rsyslog.conf \
  || sed -i '1i $MaxMessageSize 8192' /etc/rsyslog.conf

#  6) from now on rather than from the beginning of the history
for f in $(find /var/log/radius/radacct -type f -name '*detail-*' 2>/dev/null); do
  k=$(echo "${f#/}" | tr '/' '_')
  stat -c %s "$f" > "/var/lib/radacct-ship/${k}.offset"
done
install -m 644 /root/install/radacct-ship-cron /etc/cron.d/radacct-ship

#  7) and only now
radiusd -XC
service radiusd restart
service rsyslog restart
```

Two things in there are worth knowing about before it runs:

- `COLLECTOR` in `31-forward-radacct.conf` is a word, not an address. Put
  the isemon machine's own name or address in it **before** pasting the
  block, or step 5 copies a file that forwards to a host that does not
  exist.
- the `perl -0pi -e` in step 2 puts the `update request` immediately after
  the first `authorize {` in `sites-enabled/default`, which is where it has
  to be: `auth_log` a few lines below it writes the request to the detail
  log, and an attribute set after that is not in what was written. On a
  configuration that has been edited by hand, check that it landed in the
  right one of them:

  ```bash
  grep -n -A4 "^authorize {" /etc/raddb/sites-enabled/default | head -20
  ```

`radiusd -XC` in step 7 is the one check that is in the block, because
`set -e` then stops it: it will not restart a server whose configuration
does not parse. If it does stop there, §2 has the way back — the whole of
`/etc/raddb` was copied in the first command.

## 7. Maintenance

The detail files rotate themselves — a new one per day and per NAS — but
nothing deletes them:

```bash
cat > /etc/cron.daily/radacct-cleanup <<'SCRIPT'
#!/bin/sh
find /var/log/radius/radacct -type f -mtime +180 -delete
find /var/log/radius/radacct -type d -empty -mtime +180 -delete
SCRIPT
chmod 755 /etc/cron.daily/radacct-cleanup
```

`acct-linelog` into logrotate (`/etc/logrotate.d/radiusd`), with
`copytruncate`, because FreeRADIUS 2.x holds the handle open:

```
/var/log/radius/acct-linelog {
    monthly
    rotate 12
    compress
    missingok
    notifempty
    copytruncate
    create 0600 radiusd radiusd
}
```

isemon keeps what it reads for a month and at most 400,000 packets, and tidies
the rest away by itself. Erasing them by hand is Settings → The database →
*Erase the collected data* → the token group, which takes them with the token
records they belong to.

## 8. Security notes

- `auth-detail-*` holds the attributes of authentication requests.
  `User-Password` is suppressed in RADIUS itself (`suppress`), again in the
  shipper (`SUPPRESS_ATTRS`), and a third time in isemon, which drops any
  attribute whose name says it is a secret before the record is ever written
  down. Three places, because a password reaching a log is not a thing to be
  careless about once.
- Accounting packets hold no passwords, so there is nothing to suppress
  there.
- `/etc/raddb/totpcgi-handler.yaml` has an LDAP bind password in it in the
  clear — check it is `0600 radiusd:radiusd`, and filter it out if you ever
  send that configuration anywhere.
- Syslog goes over UDP, unencrypted. If these records count as sensitive on
  your site, use TCP with TLS (`@@` plus `$DefaultNetstreamDriver gtls`) or
  rsync over SSH instead.

## 9. What is not forwarded, and why

The detail files cannot go through rsyslog's `imfile`: they are multi-line
and their names hold the day and the NAS's address. rsyslog 5.8 on CentOS 6
has neither wildcards in `$InputFileName` nor multi-line `readMode`. Hence
the shipper, which sends each record already assembled into one message. The
original files stay on the token server as a forensic archive.

If the far end should be a file archive rather than a collector, the
alternative is `rsync -a /var/log/radius/radacct/ user@host:/srv/radius-logs/otp/`
from cron over an SSH key — also without touching RADIUS.
