# acme's logs and the acme tab (1.10.287, 1.10.288)

*acme* here is the certificate manager: the application that orders the
site's certificates, renews them and deploys them to the F5s, the firewalls
and the servers. It is not this server's own **Automatic certificates**
(Settings → Automatic certificates, the `acme*` settings). Its settings here
are all called `acmelog*`.

acme sends isemon what happens to every certificate by syslog. isemon reads
those logs the way it reads the OTP logs, and shows them on an **acme** tab.
Nothing of it is ever judged: nobody is banned by what acme says.

## 1. In acme

Settings → isemon, or from the command line:

```bash
acme --set isemon=1
acme --set isemon_targets=isemon.example.cz:514/tcp      # or :6514/tls, see 4.
acme --set isemon_hostname=acme                          # HOST on every line
acme --set isemon_events=1                               # the rest of what acme does too
acme --isemon-test                                       # a test line
```

| Program (TAG) | What | When |
|---|---|---|
| `acme-certs` | what happened to a certificate: issued, renewed, a renewal failed, deployed, a deployment failed, runs out soon, ran out, revoked, imported, changed | always, while `isemon=1` |
| `acme` | everything else: sign-ins, accounts, settings, backups, the portal, mail, HA, … | with `isemon_events=1` |
| `acme-jobs` | every job step by step (start, steps, HTTPS requests, validations, end) and every run of a check (acme 1.0.44) | with `isemon_detail=1` (as it comes) |

Every node of an acme cluster sends its own lines, with its name in `node=`.
The HOST is the same for the whole cluster (`isemon_hostname`).

## 2. rsyslog on this machine

`deploy/rsyslog-acme.conf` (as `/etc/rsyslog.d/11-acme.conf`; acme ships the
same rule as `deploy/isemon/11-acme.conf` - one of them is enough) files
both programs as:

```
/var/log/remote/<HOST>/acme-certs.log
/var/log/remote/<HOST>/acme.log
/var/log/remote/<HOST>/acme-jobs.log
```

(acme 1.0.43's own rule left `acme-jobs` out.) An `acme-jobs` line runs to
900 bytes and more: over UDP raise `$MaxMessageSize`, or send over TCP or
TLS.

readable by the `isemon` group. The plain input (514) is the one the other
logs use already.

## 3. Settings → The acme logs

| Setting | Default | |
|---|---|---|
| `acmelog` | `0` | read acme's logs at all; off, not one file is opened and the tab is not there |
| `acmelog_paths` | `/var/log/remote/acme` | the folder per HOST; a path ending in `.log` is a file itself |
| `acmelog_certs_name` | `acme-certs.log` | the certificates' log in each folder |
| `acmelog_events` | `1` | read the other log too |
| `acmelog_events_name` | `acme.log` | what it is called |
| `retain_acmelog_days` | `400` | how long a line is kept |
| `acmelog_jobs` | `1` | read acme-jobs too |
| `acmelog_jobs_name` | `acme-jobs.log` | what it is called |
| `retain_acmelog_jobs_days` | `90` | how long a job's steps are kept (a renewal is 20-60 lines) |

```bash
isemon --set acmelog=1
isemon --get 'acmelog*'
```

A line is the envelope (RFC 3164: `<PRI>` or none, the BSD time or an ISO
one, HOST, TAG[PID]) and `key=value` - `level kind node who`, the other
fields by name, `msg` last. A value is bare where it is
`[A-Za-z0-9_.:@/+-]+`, else in quotes with `\"` and `\\`; a line cut at
acme's length ends `...TRUNCATED`, perhaps inside a quoted value, and is
marked cut. Fields with no column of their own (a module's) are kept beside
the line as they came; a kind never seen before is kept as it is. acme's
test lines that are not key=value (`acme --isemon-test`, its TLS wizard) are
kept as text. A line read twice - a file read again, a rotation - is kept
once.

The Logs tab shows the two files like every other log: how far they have
been read and whether anything is wrong with them.

## 4. Encrypted receiving (TLS)

Settings → The acme logs → **Encrypted receiving**: the receiver the OTP
logs have (see [otp-logs-over-tls.md](otp-logs-over-tls.md)), done again for
acme's nodes, by root's helper:

- its own rsyslog file, `/etc/rsyslog.d/99-tls-acme.conf` (a
  `10-acme-tls.conf` put in by hand from acme's ZIP is kept as
  `.isemon-before` and taken away - two inputs on one port and rsyslog
  refuses both);
- its own folder, `/etc/pki/rsyslog/acme` (0750, the key 0600);
- its own port - 6514 unless the OTP logs' receiver has it already;
- the certificate from the ZIP acme's wizard makes (Settings → isemon →
  Encrypted sending → Encrypt…, opened here with its passphrase: the key goes
  to root once and is kept nowhere else), made here by an authority of this
  machine's own, or pasted;
- mutual TLS: only acme's nodes may send, known by the name in each node's
  certificate - the node's name (`acme1`, `acme2`) - and acme's `ca.pem`.

What arrives over TLS is filed by the same rule as what arrives plain.
With both receivers set up, imtcp is loaded once, by the file rsyslog reads
first, and taken over by the other when that one is removed.

Then in acme: `isemon_targets=<this machine>:6514/tls` (and
`isemon_mtls=1` for mutual TLS), and *Try it on every node*.

`./install.sh --upgrade` from 1.10.287 puts in the path unit that watches
`acmetls.ask`; until then the card says root's half is not there.

## 5. The firewall

Where isemon's own firewall is on (Settings → Firewall and access), *What
isemon lets in by itself* has a tile **acme - the certificate manager**
while acme's logs are read or acme's encrypted receiving is set up: the TLS
port of that receiver and the plain syslog port (514) its nodes send to
until they are switched over - from anywhere, or only from acme's nodes
named there. The rules are put in by themselves (the firewall is compared
every minute with what it should be); turned off, the tile lets nothing in.

## 6. The acme tab

There only while the logs are read, for anybody signed in:

- **the counts** - certificates, those that run out within 30 days, those
  that have run out, those failing, the renewals and deployments of the
  period (7 days, 30, 90, a year);
- **wants looking at** - every certificate that has run out, runs out soon,
  fails to renew, or is not on a target it should be on; the tab's own count
  is how many;
- **certificates** - each as its last line says it is, with what earlier
  lines said where the last did not (its names, serial, end, issuer); the
  days it has left, its targets each with its last word; searched and
  filtered; opened, the whole story of one certificate;
- **when they run out** - on one line of time, and the next five in words;
- **day by day** - issued and renewed, deployed, warnings, failures, the
  rest;
- **targets** and **nodes** - each target with its certificates and the
  ones not deployed; each node with its last line and its last trouble
  ("certificates only" where `isemon_events` is off on it);
- **what went wrong**, **everything acme sent** by kind and by account;
- **every line**, newest first: searched, filtered by log, level, kind, node
  and action, each opened with every field it carried.

How a certificate stands, from its lines:

| State | When |
|---|---|
| Deleted | `action=deleted` after its last issue |
| Revoked | `action=revoked` after its last issue |
| Run out | its `not_after` has passed, or `action=expired` after its last issue |
| Renewal failing | a failed renewal (`action=renew`) after its last issue |
| Not deployed | its last word on a target is a failed deployment |
| Runs out soon | within 30 days, or its last line says `expiring` |
| Fine | everything else |

acme drops what it cannot send while isemon does not answer (it never sends
it again), so the tab is what arrived: the whole record is on the nodes
(`/var/log/acme/acme-certs.log`) and in acme's own Events.

### Jobs (acme-jobs)

- the counts - jobs, the share that succeeded, how long a renewal takes
  (half of them, 9 of 10), validations refused, requests that failed and
  were rate-limited, jobs interrupted (no `event=end` an hour after their
  last line: a node restarted; acme runs it again as a new job);
- jobs day by day, and every renewal's duration as a dot (on a logarithmic
  scale when they differ widely);
- by source, by kind of job, by target: how many, the share that succeeded,
  how long;
- validations by the provider that proved them (`via`, `challenge_type`):
  proved, refused, how long the CA took, the last refusal;
- requests by server (`host`, `module`): how many, the share answered well,
  how many 429, the time half and 9 of 10 answers came within, the last
  failure - never bodies, headers or query values (acme sends none);
- who began them (`acme` is its own schedule) and the wait in the queue;
- every job, searched and filtered; opened, a waterfall of its lines on the
  time since it began. A job's certificate fields on `start` are the
  certificate before, on `end` the new one.

### Checks (acme-jobs, `kind=check`)

Every test of a certificate (HTTPS, SMTP, IMAP, LDAP …): as it stands -
serves it, serves an older version, serves another certificate, answers
wrongly, cannot be reached - its last runs as a strip, the share that went
well, how many failed in a row; and when one began (`went=bad`) or stopped
(`went=back`) failing.

`[hidden]` is a value acme left out on purpose (a secret, a TXT value): it
is shown as such.

API: `GET /api/acmelog?days=30` (the tab), `GET /api/acmelog/events`
(`tag level kind node cert action result target who q before since limit`),
`GET /api/acmelog/jobs?days=30`, `GET /api/acmelog/job?job=&node=`,
`GET /api/acmelog/checks?days=30`.
