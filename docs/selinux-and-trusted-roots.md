# SELinux and the system's trusted roots (1.10.319)

Two things isemon now does for the operating system it runs on. Both were
first written for otp (1.0.233–1.0.265) and are built the same way here. Both
change the system, so root's helper does the work (`isemon_web.py`, started by
`isemon-web.path`). The daemon and the pages never run as root.

An installation from before 1.10.319 needs `./install.sh --upgrade` once. An
upgrade from the web runs it by itself. Until then, both say that root's half
is not installed.

## SELinux

**Settings → Server → SELinux** (full administrator) and `isemon --selinux`.

### What it shows

- The mode now (`getenforce`) and after the next restart (`/etc/selinux/config`).
- Whether every file is labelled at the next start (`/.autorelabel`).
- Whether the kernel's command line has `selinux=0`.
- A checklist of what isemon needs:

  | What | Why | How |
  |---|---|---|
  | `/run/isemon` and `/run/isemon/api-token` labelled `httpd_var_run_t` (`httpd_runtime_t` on newer policies) | php-fpm (`httpd_t`) reads the daemon's API token. systemd makes `/run/isemon` as `var_run_t`, which `httpd_t` may not read | `filecon` in isemon's module, for both `/run/isemon` and `/var/run/isemon` |
  | systemd may chown and chmod in `/run/isemon` | `systemctl reload isemon` (logrotate) hands the folder back to the account: `init_t → httpd_var_run_t { setattr }` | a narrow `allow` in an `optional` block |
  | `/var/www/isemon` labelled `httpd_sys_content_t` | the pages | the distribution's own label, `restorecon` |
  | `httpd_can_network_connect` on | the pages ask the daemon on `127.0.0.1:9851` | boolean |
  | a local PostgreSQL on a port other than 5432 labelled `postgresql_port_t` | the server itself is confined | `semanage port -a` |
  | a local MariaDB on a port other than 3306 labelled `mysqld_port_t` | the same | `semanage port -a` |
  | the ports rsyslog listens on that its policy does not give it: `syslog_tls_port_t` for the otp and acme inputs over TLS, `syslogd_port_t` for plain ones | rsyslog (`syslogd_t`) may bind only labelled ports | `semanage port -a`. Root reads them off rsyslog's own files; 514, 601, 6514, 10514 and 20514 are not asked |

- What SELinux refused (`ausearch -m AVC,USER_AVC -ts boot`), for the programs
  isemon works with: `httpd_t`, `syslogd_t`, `logrotate_t`, `postgresql_t`,
  `mysqld_t`, `chronyd_t`, `system_cronjob_t`, `init_t`, `unconfined_service_t`,
  and any line that names isemon. Refusals are grouped by source, target,
  class and permissions.
  - A refusal that `audit2why` says "would be allowed by active policy" (a
    newer module, a boolean put in since) is counted as settled.
  - Refusals are counted from the moment isemon's needs were last put in, kept
    in root's own folder (`/var/lib/isemon-root/selinux-applied`), so what was
    put right does not block enforcing. The time is never kept in the service's
    folder, where the service could write a time ahead and hide refusals.
- Whether auditd runs. Without it nothing is written down, and enforcing is refused.

### The steps

None of them is taken by itself. A machine with SELinux disabled stays
disabled, and isemon runs as it always did.

```
 absent (Debian, Ubuntu) ── nothing to do
 Disabled ──Make it ready──> SELINUX=permissive, /.autorelabel, selinux=0 taken off the
                             kernel's command line (grubby), the module put in.
                             The machine is NOT restarted: restart it when it suits.
 Permissive ──Put in what isemon needs──> module, boolean, ports, restorecon
            ──Switch to enforcing──> all of it again, checked, refused while anything is
                                     missing or refused or auditd is not running;
                                     then setenforce 1 + SELINUX=enforcing
 Enforcing ──Back to permissive──> setenforce 0 + SELINUX=permissive
```

Every step takes effect at once, without restarting a service. The one
restart is the first one from *disabled*. A step asked more than ten minutes
before root gets it is not done. Each step is written to Events with who
asked for it.

### What root does not do

- It never takes a port from another service. It only runs `semanage port -a`,
  never `-m`. "Already defined" means the port belongs to another type: the
  step is refused with "choose another port".
- It takes booleans and port types only from fixed lists in its own code. A
  port type it does not know (a newer daemon with an older helper during an
  upgrade) is left out with a message, not refused along with everything else.
- It never writes a confined domain for isemon itself. isemon's own programs
  run unconfined (`unconfined_service_t`), as anything started from
  `/usr/local` does.

### The module

`deploy/isemon_server.cil` is in CIL, so `semodule -i` needs no compiler on
the machine. Each `allow` sits in an `optional` block, so a policy missing one
of the types still loads the rest.

`install.sh` copies it to `/usr/local/lib/isemon/isemon_server.cil` on every
install and every upgrade. Where SELinux is on, it puts the module into the
policy when it changed. "Changed" is measured against
`isemon_server.cil.in-policy`, the copy written only after a successful
`semodule -i`. The installer also:

- runs `restorecon` on `/run/isemon`;
- warns when `matchpathcon /run/isemon` does not say `httpd_var_run_t`;
- on dnf systems, installs any missing tools (`policycoreutils`, `libselinux-utils`,
  `policycoreutils-python-utils`, `audit`, `selinux-policy-targeted`);
- starts auditd where SELinux is on.

The mode is never touched. `./install.sh --uninstall` runs
`semodule -r isemon_server`. The mode, the booleans and the ports belong to
the machine and stay.

### The report

*Download the report* (or `isemon --selinux-report [FILE]`) puts into one
`.tar.gz` everything someone needs to extend the module. Nothing is changed to
make it:

- the refusals, raw and readable;
- `audit2why`, and `audit2allow` output as a hint (never loaded);
- the card's state;
- the labels of isemon's files against what `matchpathcon` says;
- the domains the programs run in;
- ports and booleans;
- the system's and the policy's versions;
- isemon's switches and ports, with no password, key or token.

The audit log holds other programs' command lines: look through `avc*.txt`
before sending it on.

### Command line

```bash
isemon --selinux                 # how it is here; exit 1 when something is missing
isemon --selinux prepare --yes   # check | prepare | enforce | permissive
isemon --selinux-report /root/selinux.tar.gz
```

The console has the same items, under *Network, time and power → SELinux*.

## The system's trusted roots

**Settings → Certificates and TLS → Trusted roots of the system** and `isemon --os-roots`.

This card adds your own certificate authorities (a company root, an
intermediate) to the trust of the whole operating system. That covers curl,
dnf, LDAPS to a domain controller, mail, and isemon's own connections.

The distribution's list is never touched. It keeps coming with the system's
updates (`ca-certificates`). isemon's additions go beside it, through the
system's own way of taking local additions, which every run of the system
tool merges in:

| Family | Local additions | Tool | Resulting list |
|---|---|---|---|
| RHEL / AlmaLinux / Rocky | `/etc/pki/ca-trust/source/anchors/isemon-<sha256 16>.pem` | `update-ca-trust extract` | `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem` |
| Debian / Ubuntu | `/usr/local/share/ca-certificates/isemon-<sha256 16>.crt` | `update-ca-certificates` | `/etc/ssl/certs/ca-certificates.crt` |

Rules for the files:

- isemon writes and removes only files named `isemon-<16 hex>.pem|.crt`.
- Anything else in that folder was put there by someone else. It is listed
  and never changed.
- A link is never followed.
- The folder must be root's and not writable by group or others.

**Adding.** Paste PEM, or pick a `.pem`, `.crt` or `.cer` file (DER is
converted in the browser). A chain adds every authority in it.

- **Refused:** a private key, PKCS7, `TRUSTED CERTIFICATE`, a certificate
  without `basicConstraints CA:TRUE` (a server's own certificate), and a key
  usage without `keyCertSign`.
- **Taken with a warning:**
  - expired or not yet valid;
  - an intermediate signed with SHA-1 or MD5, or an RSA key under 2048 bits
    (the DEFAULT crypto policy refuses these);
  - an intermediate whose root is in neither the set nor the same paste.

At most 50 certificates are kept.

**Applying.** The set wanted is kept in the database (`oscerts:want`). Root's
helper brings the machine to it:

- right after a change, at the start, every half hour, and on *Read it again*;
- always as the whole set, so a run that changes nothing writes nothing;
- the system tool runs only when something changed.

It then reads back each of isemon's certificates and checks it is really in
the resulting list. The card shows:

- *as wanted*, *waiting* or *failed*;
- the system's own list (count, package, when it was made);
- the folder and the tool;
- what someone else added.

**isemon's own connections.** These use `ssl.create_default_context()`. When
this Python's OpenSSL looks where there is nothing (a Python built with its
own OpenSSL), the daemon points `SSL_CERT_FILE` at the system list at its
start. Only then: an `SSL_CERT_FILE` or `SSL_CERT_DIR` that is already given
stays. The card says whether isemon's own connections use the system list.

```bash
isemon --os-roots                          # the set and how the system is
isemon --os-roots-add company-root.pem     # asks first unless --yes
isemon --os-roots-remove 6433b38639c3      # by SHA-256, 12 characters at least
```

Read access to the card is given to anyone signed in, because certificates of
authorities are not secret. Changes are for a full administrator.

## Tests

`test/fixes319_selinux_osroots.py` runs root's helper against a pretend
machine: `getenforce`, `getsebool`, `setsebool`, `semodule`, `semanage`,
`ausearch`, `audit2why` and `setenforce` on `PATH`, plus `update-ca-trust`
pointed at a folder. It covers:

- every step and every refusal;
- ports left out, and ports belonging to another service;
- rsyslog's own ports;
- refusals counted since the needs were put in, and settled refusals;
- a stale request, and a link in the request's place;
- the report;
- sync, idempotence, someone else's files, a link, removal and the folder's rights;
- the daemon's half, the installer, the units and the page.
