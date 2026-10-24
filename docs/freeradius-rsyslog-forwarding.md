# Forwarding FreeRADIUS Logs to a Remote Server via rsyslog + RELP/TLS

A complete, tested procedure for shipping all FreeRADIUS logs from a RADIUS
server to a central log server, **without modifying the FreeRADIUS
configuration**. Logs continue to be written locally exactly as before; the
remote server receives a second copy.

---

## 1. Overview

### Hosts in this guide

| Role | Hostname | Certificate CN | OS |
|---|---|---|---|
| Sender (RADIUS server) | `radius1.example.org` | `radius1.example.org` | AlmaLinux 10 |
| Receiver (log server) | `logsrv.example.lan` | `logsrv.example.lan` | RHEL/Alma 9 |

Substitute your own hostnames throughout. Example NAS addresses are given as
`10.0.0.0/8` addresses; substitute your own.

### What gets forwarded

FreeRADIUS produces two completely different kinds of log output, and they are
handled separately:

| Source | Content | Format | Facility used here |
|---|---|---|---|
| `/var/log/radius/radius.log` | Daemon log (auth results, errors) | Single-line | `local5` |
| `/var/log/radius/radacct/<NAS-IP>/detail-*` | Accounting detail records | **Multi-line** | `local6` |

`/var/log/radius/radwtmp` is a **binary** `utmp`-format file read by `radlast`.
It cannot be tailed as text and is deliberately excluded. The same data is
already present in the `detail-*` files in parsable form.

### Design decisions

- **`imfile` instead of native syslog output.** FreeRADIUS can log to syslog
  natively (`destination = syslog` in `radiusd.conf`), but that requires editing
  the RADIUS configuration and would stop `radius.log` from being written
  locally. Tailing the files with `imfile` leaves FreeRADIUS completely
  untouched.
- **RELP instead of plain TCP.** RELP provides application-level acknowledgement.
  Combined with a disk-assisted queue, no messages are lost if the log server or
  the network goes down.
- **TLS with cross-signed self-signed certificates.** Each host trusts the other
  host's self-signed certificate directly as a CA. See §3 for why fingerprint
  authentication was rejected.

### Trade-offs to be aware of

- Logs are stored in **two places**. Forwarding does not free disk space on the
  RADIUS server; local rotation still applies (see §9).
- All messages arrive with severity `info`, since `imfile` cannot infer severity
  from log content.
- Roughly a few hundred milliseconds of additional latency. Irrelevant for logs.
- Accounting records contain personal data (usernames, realms, MAC addresses, IP
  addresses). TLS on the transport is not optional, and the retention policy on
  the receiver should match whatever applies to the source.
- Files written by rsyslog are readable by root and nobody else until it is
  told otherwise, and the modes it is configured with are not the modes that
  reach the disk. If anything else is going to read these files, §5.1 is not
  optional either.

---

## 2. Prerequisites

On **both** hosts:

```bash
dnf install -y rsyslog rsyslog-relp rsyslog-openssl
```

On the **receiver** additionally:

```bash
dnf install -y policycoreutils-python-utils
```

Verify name resolution from the sender:

```bash
getent hosts logsrv.example.lan
```

If the name does not resolve (common with internal-only domains), use the IP
address as the target instead. With the authentication mode used here the
certificate CN is validated, not the name you connect to, so an IP target is
fine.

---

## 3. Certificates

### Why not fingerprint authentication

`tls.authMode="fingerprint"` looks attractive for a two-host link, but with
`librelp 1.10.0` (RHEL 9) and the OpenSSL driver it fails: the standard
certificate chain verification still runs, hits `err 18: self-signed
certificate`, and aborts the handshake before the fingerprint is ever compared.

The symptom is a log line on the receiver that complains about a *self-signed
certificate* rather than about a mismatched fingerprint:

```
authentication error 'Certificate error in verify_callback at depth: 0
issuer = /CN=radius1.example.org  subject = /CN=radius1.example.org
err 18:self-signed certificate'
```

A self-signed certificate is its own CA. Handing each host the peer's
certificate as `tls.caCert` makes chain validation succeed, works on any
librelp version, and is easier to maintain — replacing a host means copying one
`.pem` file instead of editing configuration on both sides.

### Generate the certificates

On the **sender**:

```bash
mkdir -p /etc/pki/rsyslog && cd /etc/pki/rsyslog

openssl req -x509 -newkey rsa:4096 -nodes -days 3650 \
  -keyout radius1.key -out radius1.pem \
  -subj "/CN=radius1.example.org" \
  -addext "subjectAltName=DNS:radius1.example.org" \
  -addext "extendedKeyUsage=clientAuth,serverAuth"

chmod 600 radius1.key
```

On the **receiver**:

```bash
mkdir -p /etc/pki/rsyslog && cd /etc/pki/rsyslog

openssl req -x509 -newkey rsa:4096 -nodes -days 3650 \
  -keyout logsrv.key -out logsrv.pem \
  -subj "/CN=logsrv.example.lan" \
  -addext "subjectAltName=DNS:logsrv.example.lan" \
  -addext "extendedKeyUsage=clientAuth,serverAuth"

chmod 600 logsrv.key
```

The `extendedKeyUsage` extension is required — without it the OpenSSL driver
rejects the certificate during verification.

> **Do not reuse `/etc/raddb/certs/`.** Those are either FreeRADIUS bootstrap
> snake-oil certificates (regenerated by any `make` in that directory, which
> would silently break this link) or a production EAP certificate issued for
> `serverAuth` only.

### Exchange the public certificates

Private keys are never copied.

```bash
# on the sender
scp /etc/pki/rsyslog/radius1.pem \
    root@logsrv.example.lan:/etc/pki/rsyslog/peer-radius1.pem

scp root@logsrv.example.lan:/etc/pki/rsyslog/logsrv.pem \
    /etc/pki/rsyslog/peer-logsrv.pem
```

Verify what arrived on each side:

```bash
openssl x509 -in /etc/pki/rsyslog/peer-radius1.pem -noout -subject -fingerprint -sha256
```

---

## 4. Sender configuration

### `/etc/rsyslog.d/10-radius-input.conf`

```
module(load="imfile" mode="inotify")

global(maxMessageSize="64k")
global(defaultNetstreamDriver="ossl")

# radiusd daemon log
input(type="imfile"
      File="/var/log/radius/radius.log"
      Tag="radius:"
      Facility="local5"
      Severity="info"
      reopenOnTruncate="on"
      freshStartTail="on")

# accounting detail files (multi-line records)
input(type="imfile"
      File="/var/log/radius/radacct/*/detail-*"
      Tag="radius-detail:"
      Facility="local6"
      Severity="info"
      startmsg.regex="^[[:alpha:]]{3} [[:alpha:]]{3} [ 0-9]{2} "
      escapeLF="on"
      reopenOnTruncate="on"
      freshStartTail="on")
```

Notes on the parameters that matter:

- **`maxMessageSize="64k"`** must be declared **before** anything that processes
  messages, which is why it lives in the `10-` file rather than the `90-` one.
  The 8 KB default truncates detail records. It may only be declared **once**
  across the whole configuration — a duplicate causes
  `parameter 'maxmessagesize' specified more than once`.
- **`startmsg.regex`** matches the record header (`Thu Sep 24 23:49:30 2026`).
  Everything until the next header is treated as one message.
- **`escapeLF="on"`** joins the multi-line record into a single syslog message,
  replacing line feeds with the two-character sequence `\n`. The receiver
  reverses this (§5).
- **`freshStartTail="on"`** starts at the end of file on first run. Without it,
  months of historical records would be shipped at once. Remove it later if you
  ever want a full replay.
- **`reopenOnTruncate="on"`** handles logrotate with `copytruncate`.

### `/etc/rsyslog.d/90-forward.conf`

```
module(load="omrelp")

ruleset(name="radius_remote") {
    action(type="omrelp"
           target="logsrv.example.lan"
           port="20514"
           tls="on"
           tls.authMode="name"
           tls.permittedPeer=["logsrv.example.lan"]
           tls.caCert="/etc/pki/rsyslog/peer-logsrv.pem"
           tls.myCert="/etc/pki/rsyslog/radius1.pem"
           tls.myPrivKey="/etc/pki/rsyslog/radius1.key"
           queue.type="LinkedList"
           queue.filename="q_radius_fwd"
           queue.spoolDirectory="/var/spool/rsyslog"
           queue.maxDiskSpace="2g"
           queue.size="100000"
           queue.saveOnShutdown="on"
           action.resumeRetryCount="-1"
           action.resumeInterval="10")
}

if ($syslogfacility-text == "local5" or $syslogfacility-text == "local6") then {
    call radius_remote
    stop
}
```

- **`tls.permittedPeer`** must match the **CN of the peer certificate**, not the
  DNS name or reverse lookup of the host you connect to.
- **`stop`** prevents these messages from also being duplicated into
  `/var/log/messages`. It has no effect on the original FreeRADIUS files.
- The **disk-assisted queue** buffers up to 2 GB on disk if the receiver is
  unreachable, and survives an rsyslog restart. `action.resumeRetryCount="-1"`
  means retry forever.

### Prepare and start

```bash
mkdir -p /var/spool/rsyslog && chmod 700 /var/spool/rsyslog
chmod 600 /etc/pki/rsyslog/radius1.key

rsyslogd -N1
systemctl restart rsyslog
```

---

## 5. Receiver configuration

### `/etc/rsyslog.d/05-radius-receiver.conf`

```
module(load="imrelp" tls.tlslib="openssl")

global(maxMessageSize="64k")
global(defaultNetstreamDriver="ossl")
global(parser.escapeControlCharactersOnReceive="off")

input(type="imrelp"
      port="20514"
      tls="on"
      tls.authMode="name"
      tls.permittedPeer=["radius1.example.org"]
      tls.caCert="/etc/pki/rsyslog/peer-radius1.pem"
      tls.myCert="/etc/pki/rsyslog/logsrv.pem"
      tls.myPrivKey="/etc/pki/rsyslog/logsrv.key"
      ruleset="radius_in")
```

`parser.escapeControlCharactersOnReceive="off"` stops rsyslog from escaping
control characters on its own — this is what preserves the tab indentation
inside detail records. It does **not** undo the sender's `escapeLF`; that is
handled below.

Only **one** `imrelp` input may listen on a given port. A leftover input from an
earlier attempt will silently win over the intended one.

### `/etc/rsyslog.d/06-radius-store.conf`

```
template(name="radiusDaemonFile" type="string"
         string="/var/log/remote/%HOSTNAME%/radius.log")

template(name="radiusDetailFile" type="string"
         string="/var/log/remote/%HOSTNAME%/detail-%$YEAR%%$MONTH%%$DAY%")

template(name="radiusDetailFormat" type="string"
         string="%$!detail%\n")

ruleset(name="radius_in") {

    if ($syslogfacility-text == "local6") then {
        set $!detail = replace(ltrim($msg), "\\n", "\n");
        action(type="omfile"
               dynaFile="radiusDetailFile"
               template="radiusDetailFormat"
               dirCreateMode="0750"  dirOwner="root"  dirGroup="logreader"
               fileCreateMode="0640" fileOwner="root" fileGroup="logreader"
               dynaFileCacheSize="50")
        stop
    }

    if ($syslogfacility-text == "local5") then {
        action(type="omfile"
               dynaFile="radiusDaemonFile"
               dirCreateMode="0750"  dirOwner="root"  dirGroup="logreader"
               fileCreateMode="0640" fileOwner="root" fileGroup="logreader")
        stop
    }
}
```

The critical line is:

```
set $!detail = replace(ltrim($msg), "\\n", "\n");
```

`"\\n"` is the literal two-character sequence produced by `escapeLF`; `"\n"` is a
real line feed. Without this, records land in the file as one long line with
visible `\n` sequences. `ltrim()` removes the single leading space that syslog
inserts.

The trailing `\n` in `radiusDetailFormat` produces the blank line between
records that the FreeRADIUS detail format uses.

> Escape sequences **inside** attribute values — such as
> `Cisco-AVPair = "dc-opaque=\001\000..."` — are written that way by FreeRADIUS
> itself and appear identically in the source file. Do not try to expand them.

`logreader` in that block stands for whatever account reads these files — a
log analyzer, a monitoring daemon, an operator group — and is used throughout
this guide both as that account's name and as its group. If nothing but root
ever reads them, drop the four `*Owner`/`*Group` parameters; the modes alone
are then enough, and the umask in §5.1 still applies.

## 5.1 File permissions on the receiver

Everything in §5 writes files that only `root` can read unless two further
things are dealt with. Both are silent: no error, no warning, and a reader
that simply sees nothing.

### The umask strips what `fileCreateMode` grants

`fileCreateMode` and `dirCreateMode` are passed to `open()` and `mkdir()`, and
the process umask is applied on top of them. The rsyslog unit shipped on
RHEL 9 and AlmaLinux 9 sets `UMask=0066`, which is why the files come out one
bit tighter than the configuration says:

```
0640 & ~0066 = 0600      -rw-------   the detail and radius.log files
0750 & ~0066 = 0710      drwx--x---   the per-host directory
```

The group-read bit is removed in both cases, so the `fileGroup` above has
nothing to read with. Check what the unit is using:

```bash
systemctl show rsyslog -p UMask
```

If it is anything tighter than `0027`, override it. Do it with a drop-in file
written directly — `systemctl edit` silently creates nothing if the editor is
closed with an empty buffer, which looks exactly like the change having had no
effect:

```bash
mkdir -p /etc/systemd/system/rsyslog.service.d
printf '[Service]\nUMask=0027\n' > /etc/systemd/system/rsyslog.service.d/umask.conf
systemctl daemon-reload
systemctl restart rsyslog
systemctl show rsyslog -p UMask        # must now say UMask=0027
```

`daemon-reload` is not optional: without it systemd keeps the old unit and
`systemctl show` goes on reporting the old value even though the file exists.

An `$umask` directive in `rsyslog.conf` can do the same job, but the unit wins
where both are set, so the drop-in is the reliable place.

### Files that already exist keep their old modes

A umask applies at creation. Everything written before the change stays as it
was, and so does the directory:

```bash
chgrp -R logreader /var/log/remote
find /var/log/remote -type d -exec chmod 750 {} +
find /var/log/remote -type f -exec chmod 640 {} +
```

`chmod 640 /var/log/remote/*/*.log` is **not** enough here — the accounting
files are called `detail-20260925`, not `*.log`, and a pattern that only
matches logs leaves exactly the larger half of the data unreadable.

### The directory needs `r-x`, not just `--x`

`0710` lets a member of the group open a file whose exact name it already
knows, but not list the directory. A reader that has to find today's
`detail-YYYYMMDD` for itself needs `0750`.

### Verify as the reader, not as root

Root can read everything and proves nothing:

```bash
sudo -u logreader ls /var/log/remote/radius1/
sudo -u logreader head -1 /var/log/remote/radius1/detail-$(date +%Y%m%d)
```

Both must succeed. If they do, tomorrow's file will be created correctly too —
that is the point of the two changes above.

### Prepare and start

```bash
mkdir -p /var/log/remote && chgrp logreader /var/log/remote && chmod 750 /var/log/remote
chmod 600 /etc/pki/rsyslog/logsrv.key

mkdir -p /etc/systemd/system/rsyslog.service.d
printf '[Service]\nUMask=0027\n' > /etc/systemd/system/rsyslog.service.d/umask.conf
systemctl daemon-reload

firewall-cmd --permanent --add-port=20514/tcp && firewall-cmd --reload
semanage port -a -t syslogd_port_t -p tcp 20514

rsyslogd -N1
systemctl restart rsyslog
```

If `semanage` reports the port is already defined under another type, use `-m`
instead of `-a`.

**Start the receiver before the sender** so the first connection attempt
succeeds.

---

## 6. Optional: preserve per-NAS directory structure

By default all records land in a single `detail-YYYYMMDD` file per day, merged
across every NAS. No data is lost — each record carries `NAS-IP-Address`
internally — but the source-side directory layout is flattened.

To restore it, add to the **receiver**'s `radius_in` ruleset, inside the
`local6` branch:

```
set $!nas = re_extract($msg, "NAS-IP-Address = ([0-9.]+)", 0, 1, "unknown");
```

and change the file template to:

```
template(name="radiusDetailFile" type="string"
         string="/var/log/remote/%HOSTNAME%/%$!nas%/detail-%$YEAR%%$MONTH%%$DAY%")
```

Raise `dynaFileCacheSize` to `200`, since many more files will be open
concurrently.

Records without a `NAS-IP-Address` attribute fall into `unknown/`.

**Alternative:** set `addMetadata="on"` on the sender's detail input and extract
the directory from the original path instead:

```
set $!nas = re_extract($!metadata!filename, "radacct/([^/]+)/", 0, 1, "unknown");
```

This reproduces the source layout exactly, including directories that are not
named after a NAS IP (e.g. `127.0.0.1`). Verify after restart that `$!nas` is
actually populated; if it comes out as `unknown`, fall back to the `$msg`
variant.

Consider whether you need the split at all. If the remote copy is consumed by an
analyzer or kept purely as an archive, one file per day is easier to process.

---

## 7. Verification

**Receiver is listening:**

```bash
ss -lntp | grep 20514
```

**Send a test message from the sender:**

```bash
logger -p local5.info "TEST $(date)"
```

**Queue is draining** (on the sender):

```bash
ls -l /var/spool/rsyslog/
```

Empty means everything is being delivered. Accumulating `q_radius_fwd.*` files
mean messages are buffered — nothing is lost, but the link is down.

**Data is arriving** (on the receiver):

```bash
ls -R /var/log/remote/
tail -f /var/log/remote/radius1/detail-$(date +%Y%m%d)
```

**Record counts match.** Compare today's totals; the sum across all source
directories should match the receiver (minus anything written before the
forwarder started, due to `freshStartTail`):

```bash
# sender
grep -c "^$(date '+%a %b %e')" /var/log/radius/radacct/*/detail-$(date +%Y%m%d)

# receiver
grep -c "^$(date '+%a %b %e')" /var/log/remote/radius1/detail-$(date +%Y%m%d)
```

A large discrepancy means the `radacct/*/detail-*` glob is not matching every
directory — that *would* be real data loss.

---

## 8. Troubleshooting

### `certificate verify failed` / `err 18: self-signed certificate`

The peer certificate is not trusted. Check that `tls.caCert` points at the
*peer's* `.pem` (not the host's own) and that the file actually contains the
expected certificate:

```bash
openssl x509 -in /etc/pki/rsyslog/peer-radius1.pem -noout -subject -fingerprint -sha256
```

Test the handshake directly from the sender, which gives clearer errors than
rsyslog:

```bash
openssl s_client -connect logsrv.example.lan:20514 \
  -CAfile /etc/pki/rsyslog/peer-logsrv.pem \
  -cert /etc/pki/rsyslog/radius1.pem \
  -key /etc/pki/rsyslog/radius1.key
```

`Verify return code: 0 (ok)` means TLS is fine and any remaining problem is in
the RELP layer or `permittedPeer`.

### Handshake succeeds but peer is rejected

`tls.permittedPeer` does not match the peer certificate's CN. Check both CN and
SAN:

```bash
openssl x509 -in /etc/pki/rsyslog/peer-radius1.pem -noout -subject -ext subjectAltName
```

Note that the receiver's log identifies the peer by **reverse DNS**, which often
differs from the certificate CN — compare against the CN, not against the name
in the log message. `permittedPeer` accepts a list, so several names can be
allowed at once: `["radius1.example.org", "radius1-alt.example.org"]`.

### `parameter 'maxmessagesize' specified more than once`

Declared in more than one file. Find all occurrences and keep exactly one, in
the file that loads first:

```bash
grep -rn "maxMessageSize" /etc/rsyslog.conf /etc/rsyslog.d/
```

The follow-up error `parameter 'maxMessageSize' not known` is a side effect of
the duplicate, not a separate problem.

### Records contain literal `\n` sequences

The `replace()` call in §5 is missing or was not applied. It belongs on the
**receiver**. Never remove `escapeLF="on"` from the sender — without it each
line becomes a separate syslog message and the records fall apart entirely.

Repair already-written files:

```bash
sed -i 's/\\n/\n/g' /var/log/remote/radius1/detail-YYYYMMDD
```

### Records arrive but nothing can read them

The files are there and growing, and the account that consumes them reports
permission denied — or, worse, reports nothing at all and simply stays empty.

Look at what is actually on disk, not at what the configuration asks for:

```bash
ls -ln /var/log/remote/radius1/
```

`-rw------- root root` against a `fileCreateMode="0640"` means the umask is
taking the group bit off; `-rw-r----- root root` means the mode survived but
`fileGroup` was never set, so the group that may read is root's. Both are
§5.1. `drwx--x--- root root` on the directory means a reader can open a file
by name but cannot list the directory to find today's.

Test as the reader rather than as root — root reads everything and tells you
nothing:

```bash
sudo -u logreader head -1 /var/log/remote/radius1/detail-$(date +%Y%m%d)
```

An ACL is the other way to do this, and works without touching the unit:

```bash
setfacl -R  -m u:logreader:rX /var/log/remote
setfacl -R -d -m u:logreader:r /var/log/remote
```

The default ACL (`-d`) is what makes it stick to files created later. It is a
smaller change than the umask override, but it is invisible in `ls` beyond a
trailing `+`, and it has to be re-applied to any directory made outside
`/var/log/remote`.

### Nothing arrives, no TLS errors

Check SELinux on **both** hosts — the most common silent failure:

```bash
ausearch -m avc -ts recent -c rsyslogd
```

If there are denials:

```bash
ausearch -m avc -ts recent -c rsyslogd | audit2allow -M rsyslog-radius
semodule -i rsyslog-radius.pp
```

Typical denials: reading `radiusd_log_t` on the sender, writing to the spool
directory, binding port 20514 on the receiver.

Also confirm the port is reachable at all:

```bash
tcpdump -i any port 20514
```

### Duplicate module loads

A leftover config file from an earlier attempt can load `omrelp`/`imrelp` twice,
with conflicting parameters. The second `module()` load silently overrides
parameters such as `tls.tlslib`. Check:

```bash
ls -l /etc/rsyslog.d/
grep -c omrelp /etc/rsyslog.d/*.conf
```

---

## 9. Operational notes

### Local retention is unchanged

Forwarding does **not** reduce disk usage on the RADIUS server. If detail files
are accumulating (they are often never rotated), age them out — but **do not
point logrotate at them**. They are already one file per day, and logrotate has
no "only throw the old ones away": it rotates the live file first, which is the
day still being written. With `rotate 0` it deletes it outright.

`/etc/cron.daily/radacct-tidy`, `chmod 755`:

```sh
#!/bin/sh
find /var/log/radius/radacct -type f -name 'detail-*' -mtime +90 -delete 2>/dev/null
exit 0
```

Leave them uncompressed while they are recent: `imfile` cannot read a gzip, so
a file compressed before it has been forwarded is a file that never arrives.
By ninety days they have long since gone.

### Remote retention

`/var/log/remote` grows at roughly the same rate as the source. Apply a
logrotate rule there as well, or monitor free space. Because these records
contain personal data, the remote retention period should be a deliberate
decision rather than a side effect of available disk space.

If anything other than root reads these files, have logrotate recreate them
the way rsyslog creates them, or the first rotation quietly undoes §5.1 — the
logs go on arriving, the reader goes on showing yesterday, and nothing says
so. One rule for the whole tree, because logrotate refuses two rules that
match the same file (`error: duplicate log entry`):

```
/var/log/remote/*/*.log {
    daily
    dateext
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root logreader
    sharedscripts
    postrotate
        /usr/bin/systemctl reload rsyslog > /dev/null 2>&1 || true
    endscript
}
```

`logreader` is the account that reads them. `delaycompress` is not decoration:
without it logrotate compresses a file rsyslog still has open.

The accounting files are **not** in that rule and must not be: `detail-*` has
no `.log` on the end, and pointing logrotate at it rotates the day being
written, exactly as on the sender. Age those out instead, and leave today's
and yesterday's alone:

```sh
#!/bin/sh
find /var/log/remote -type f -name 'detail-*' ! -name '*.gz' -mtime +2 \
     -exec gzip -9 {} + 2>/dev/null
find /var/log/remote -type f -name 'detail-*' -mtime +90 -delete 2>/dev/null
exit 0
```

Compressing the older ones is safe for a reader that follows the newest
uncompressed file by name, which is what isemon does: a `.gz` beside it is
skipped rather than followed and read as empty. A reader that does not work
that way wants `nocompress` here.

isemon ships all of this ready to copy — `deploy/remote-logs.logrotate`,
`deploy/isemon-logs-tidy`, `deploy/rsyslog-permissions.conf` — and
`docs/log-rotation-and-permissions.md` is the whole procedure, including how
to prove the rotation instead of waiting a day for it.

### Certificate lifetime

The certificates above are valid for 10 years. Treat replacement as part of host
reinstallation. If a private key is ever exposed, regenerate the pair and
re-copy the public certificate to the peer — there is no revocation mechanism in
this setup.

### Logrotate interaction on the sender

Check `/etc/logrotate.d/radiusd`. With `copytruncate`, `reopenOnTruncate="on"`
handles it. With `create`, inotify finds the new inode automatically, but a few
lines can be lost at the switch; adding `delaycompress` makes this practically
impossible.
