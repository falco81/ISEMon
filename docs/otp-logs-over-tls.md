# The otp logs over TLS

otp sends isemon its `totp.cgi` and `radius-detail` lines over syslog. Sent
plain (UDP or TCP on 514), anybody on the way can read who signs in, when,
from where and from which device. Since otp 1.0.172 the nodes can send them
over **TLS** (RFC 5425, 6514/tcp): encrypted, otp checks that it is isemon that
answers, and with **mutual TLS** isemon checks that it is one of otp's nodes
that sends.

The otp side is *Settings → isemon → Encrypted sending (TLS)* on otp. The
isemon side is **Settings → The OTP logs → Encrypted receiving (TLS)** on
isemon (1.10.245): it puts rsyslog's encrypted input in for you - the
certificate and its key, the rsyslog file, the TLS driver, the port in the
firewall - and says how it stands.

**Nothing of the plain receiving changes.** The input on 514 stays as it is,
and a node not switched over yet goes on sending there. What arrives over TLS
is filed by the same rule into the same files
(`/var/log/remote/<host>/totp.cgi.log`, `radius-detail.log`), so nothing
about reading them changes either: *The OTP logs* reads the same folders.

## Setting it up

1. **On otp:** *Settings → isemon → Encrypted sending → Encrypt…* - isemon's
   address, the port (6514), and where isemon's certificate comes from.
2. **On isemon:** *Settings → The OTP logs → Encrypted receiving → Set up…*,
   with the same choice:

   | otp's wizard says | on isemon choose |
   |---|---|
   | **otp makes isemon a certificate** - *Make the file for isemon…* saves `isemon-tls.zip` | **The file otp made**: choose the file and type its passphrase |
   | **isemon has one from its own CA** | **Made here** (isemon makes its own authority), then paste *isemon's authority* into otp - or **Paste a certificate** from a CA of your own, and paste that CA into otp |
   | **a public CA** | **Paste a certificate** (the certificate, its key, its chain) |

   then the port, whether isemon takes otp's nodes only (**mutual TLS**), and
   which nodes. *Set it up* - root puts it in within seconds (a minute when
   rsyslog's TLS driver has to be installed first).
3. **Back on otp:** *Try it on every node*, then *Switch over*. *Send a test
   line* on a node's card shows it arrive.

### The file otp made

`isemon-tls.zip` holds otp's authority (`ca.pem`), isemon's certificate and
key (`isemon.crt`, `isemon.key`), otp's `10-otp-tls.conf` and a README, every
entry locked with AES-256 - which `unzip` cannot open. isemon opens it itself,
in memory: no `7z`, no copy left in a folder, nothing to `shred`. It shows
what is in it - the names isemon's certificate is for, who issued it, until
when, and from otp's `10-otp-tls.conf` the port, the mode and the nodes - and
takes those as the settings, to change before *Set it up*.

The key goes from there to root once and is kept only where rsyslog reads it
(`/etc/pki/rsyslog/otp/isemon.key`, root's, 0600): not in the database, not in
a backup, not in a log or an event. The opened file is held for ten minutes,
then forgotten - open it again after that. otp does not keep isemon's key
either: a lost file is made again on otp (*Make the file for isemon…*) and
goes in the same way.

otp's `10-otp-tls.conf` is read, never put in as it is: root writes a file of
its own (below) from the port, the mode and the nodes, checked again there.

### Made here

isemon makes an authority of its own (RSA 3072, ten years, its key root's
alone in `/etc/pki/rsyslog/otp/isemon-ca.key`) and from it a certificate for
the names and addresses the nodes reach this machine by (825 days). The card
then shows **isemon's authority** - copy it, or download `isemon-ca.crt` - to
paste into otp's wizard as *isemon has one from its own CA*.

Made again (a name added, or the certificate near its end), it is the same
authority: otp trusts the new certificate as it is. For mutual TLS, otp's
authority is pasted beside it (otp: *High availability → the cluster's
authority*, or `ca.pem` from the file).

### Mutual TLS and the nodes

| Mutual TLS | Nodes | rsyslog's `AuthMode` | who may send |
|---|---|---|---|
| off | - | `anon` | anybody; otp still checks isemon |
| on | empty | `x509/certvalid` | any node with a certificate from otp's authority |
| on | `otp1 otp2` | `x509/name` | only those nodes, as their certificates name them |

With names, a node added on otp later is added here (*Change nodes…*); with
none, it is let in by its certificate alone.

## What root puts in

```
/etc/pki/rsyslog/otp/            root:root 0750
  ca.pem          the authorities the nodes are checked against (otp's)
  isemon.crt      isemon's certificate (with its chain)
  isemon.key      its key - 0600
  isemon-ca.*     the authority made here, when it was
/etc/rsyslog.d/10-otp-tls.conf
```

`10-otp-tls.conf` as isemon writes it (rsyslog 8.2108 and later, mutual TLS
with two nodes):

```
module(load="imtcp")            # only where no other file loads it
input(type="imtcp" port="6514" name="otp-tls"
      StreamDriver.Name="gtls"
      StreamDriver.Mode="1"
      StreamDriver.AuthMode="x509/name"
      StreamDriver.CAFile="/etc/pki/rsyslog/otp/ca.pem"
      StreamDriver.CertFile="/etc/pki/rsyslog/otp/isemon.crt"
      StreamDriver.KeyFile="/etc/pki/rsyslog/otp/isemon.key"
      PermittedPeer=["otp1", "otp2"])
```

- **The TLS files per input**, not in `global()`: a RELP or TLS input of the
  site's own keeps its own. rsyslog 8.2106 and 8.2107 take them only in
  `global()` - written there, unless another file sets them already (then it
  is refused, and said). Older rsyslog (RHEL / AlmaLinux 8, 8.2102) cannot
  have an encrypted input beside the plain one: refused, and said.
- **imtcp is loaded once**: where `/etc/rsyslog.conf` or another file loads it
  already (isemon's own `10-ise.conf` does, for TCP on 514), it is not loaded
  again.
- **The driver**: `gtls` (rsyslog-gnutls, which otp's README names) where it
  is installed, `ossl` (rsyslog-openssl, which install.sh puts in with the
  receiver) otherwise; with neither, rsyslog-gnutls is installed first. The
  installer adds rsyslog-gnutls too, where rsyslog is and it is not.
- **Checked before**: `rsyslogd -N1` is asked before rsyslog is restarted, and
  after the restart that it listens on the port. When either says no, every
  file is put back as it was, rsyslog restarted on the old ones, and the card
  says what rsyslog said.
- **A file set up by hand before** (from otp's README) is written over - kept
  once beside it as `10-otp-tls.conf.isemon-before`, which rsyslog does not
  load.
- **SELinux**: 6514/tcp is `syslog_tls_port_t` already; another port is added
  to it with `semanage` where SELinux is on. The files are labelled with
  `restorecon`.
- **The firewall**: with firewalld, the port is let in (and taken out again
  when switched off); with isemon's own firewall (*Settings → Firewall*), the
  port is one more that rsyslog listens on, let in by *The logs arriving
  (rsyslog)* from the log senders named there.

*Switch off…* takes `10-otp-tls.conf` away and restarts rsyslog; the
certificate and its key stay, to switch it on again (*Change nodes…*). The
plain input is as it was all along.

## From the command line

```
isemon --otp-tls                         how it stands (--json: the card's view)
isemon --otp-tls-import isemon-tls.zip   the file otp made (passphrase: --passphrase-file, ISEMON_ZIP_PASSPHRASE, or asked)
isemon --otp-tls-make isemon.example.net,192.0.2.10 [--otp-tls-ca otp-ca.pem]
isemon --otp-tls-set --otp-tls-nodes "otp1 otp2 otp3"
isemon --otp-tls-off
```

`--otp-tls-port`, `--otp-tls-nodes` and `--otp-tls-mutual yes|no` go with
`--otp-tls-import`, `--otp-tls-make` and `--otp-tls-set`. `isemon --console`
has them too.

## When nothing arrives

- The card: *Listening*, *Firewall* and rsyslog's own words about TLS from its
  journal (the last half hour) - `not permitted to talk to peer` (a node's
  name not among the nodes), `unknown CA` (`ca.pem` is not otp's authority),
  `certificate expired`.
- otp: *Settings → isemon*, each node's card - *trouble* says why from its side.
- From a node: `openssl s_client -connect isemon:6514 -CAfile ca.pem` shows the
  certificate isemon answers with.
- `journalctl -u rsyslog` on isemon.
