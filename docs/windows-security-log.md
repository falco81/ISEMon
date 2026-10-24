# Forwarding a Windows Security Event Log with NXLog

A working NXLog configuration for shipping a Windows domain controller's
**Security** event log to the same rsyslog that already carries the ISE,
token and eduroam logs. The file is in this folder as
[`nxlog.conf`](nxlog.conf) and is included as it runs in production, with its
own comments; this page says what it does and what to change.

Since 1.10.43 isemon reads these files itself: switch **The domain
controllers** on in Settings, point it at the folders rsyslog files them into,
and the **Domain** page appears. A domain controller's Security log is the
thing an operator wants beside a VPN refusal when the question is *"was that
the same person?"*, and a lockout only says which account — which machine,
which program and which password are in the refusals around it. Nothing read
here is ever judged and nothing here can earn anybody a ban.

---

## 1. What it does

```
Windows Security log  →  NXLog  →  syslog UDP 514  →  rsyslog  →  /var/log/remote/<host>/<tag>.log
```

- **Input**: the whole Security channel, read from where it left off
  (`SavePos`), starting at the end on a first run (`ReadFromLast`).
- **Output**: RFC 3164 syslog over UDP, with the header built by
  `to_syslog_bsd()` out of `$EventTime`, `$Hostname` and `$SourceName` — so
  the time and the host are *not* also stuffed into the message.
- An `AUDIT_FAILURE` event is sent at severity `WARNING`; everything else at
  `INFO`. That is what lets a rule on the receiving side file the failures
  separately without parsing the text.

Every field is checked with `defined()` before it is used. In NXLog a
concatenation with an undefined field throws the **whole message** away, so
an event that happens not to carry `$Message` or `$EventID` would otherwise
vanish silently.

## 2. What to change

| Define | What it decides |
|---|---|
| `SYSLOGHOST` | the folder on the log server: `/var/log/remote/<SYSLOGHOST>/` |
| `SYSLOGTAG` | the file in it: `<SYSLOGTAG>.log` |
| `Host` / `Port` in `<Output>` | the rsyslog that receives it |

Nothing else normally needs touching. `ROOT` assumes the default install
path, `C:\Program Files\nxlog`.

## 3. Two things worth knowing

**Event 4662 is most of the volume.** On a busy domain controller, directory
access auditing can be a fifth of everything the Security log produces, and
none of it is anybody signing in. The `Exec` line in `<Input>` drops 4662 and
its neighbours; it ships commented out, so the log arrives whole until
somebody decides otherwise.

> **Careful with comments inside `<Exec>`.** Those blocks join their lines
> with `\` into one logical line, so a `#` anywhere inside cuts off
> everything after it — including the rest of the statement. Comment a whole
> `Exec` out line by line, as the file does, or not at all.

**UDP loses long events.** A 4624 or a 4662 can exceed 1500 bytes, and a
fragmented datagram that loses one fragment loses the entire event with no
trace on either side. The file carries a commented-out `om_tcp` output for
that: comment out `<Output out_syslog>`, uncomment the TCP block, and point
the `<Route>` at `out_syslog_tcp`.

## 4. The receiving side

Whatever rsyslog rule already files the ISE logs by host will file these the
same way — see
[log-rotation-and-permissions.md](log-rotation-and-permissions.md) for the
folder layout, the permissions isemon needs to read those files, and the
rotation that keeps them from filling the disk.

## 5. What the controllers should write: the audit policy

NXLog sends whatever the Security log holds (`<Select Path="Security">*`),
so what isemon can say is decided on the controllers, by their audit policy.
What is not audited is never written, and nothing downstream can bring it
back.

**Check what a controller writes now**, on each controller:

```
auditpol /get /category:*
```

**Set it** in a GPO linked to the *Domain Controllers* OU: *Computer
Configuration → Policies → Windows Settings → Security Settings → Advanced
Audit Policy Configuration → Audit Policies*. Also set *Security Options →
Audit: Force audit policy subcategory settings (Windows Vista or later) to
override audit policy category settings* to **Enabled**, or an old-style
category setting somewhere can silently win.

What one real site's two controllers wrote in five hours (1.10.100 was
checked against it) said which of these were on. Sign-ins, Kerberos, NTLM
and user account management were on. Special logons, computer accounts,
groups and directory changes were not, and nothing in those five hours could
have said whether an account had been locked or a group changed.

| Subcategory | Setting | Events | What it gives here |
|---|---|---|---|
| Account Logon → Credential Validation | Success, Failure | 4776 | NTLM checks: which workstation, which name form |
| Account Logon → Kerberos Authentication Service | Success, Failure | 4768, 4771 | sign-ins and wrong passwords **with the client's address** |
| Account Logon → Kerberos Service Ticket Operations | Success, Failure | 4769, 4770 | who works on which server (a terminal server, a share); RC4 tickets |
| Logon/Logoff → Logon | Success, Failure | 4624, 4625 | sign-ins at the controller; NPS's refusals (logon process IAS) |
| Logon/Logoff → **Special Logon** | Success | 4672 | an account with administrative rights signing in, and where |
| Account Management → User Account Management | Success, Failure | 4720–4726, 4738, **4740**, 4767 | lockouts, unlocks, password resets, accounts made and deleted |
| Account Management → **Computer Account Management** | Success | 4741–4743 | computers joined, changed and removed; a computer's password changing |
| Account Management → **Security Group Management** | Success | 4728, 4732, 4756, 4799 | somebody put into Domain Admins and the like; groups read in bulk |
| DS Access → **Directory Service Changes** | Success | 5136, 5137, 5141 | what was changed in the directory, and by whom (policies included) |
| DS Access → Directory Service Access | Success | 4662 | an account asking to replicate the directory (DCSync) — see below |
| Policy Change → Audit Policy Change | Success | 4719 | the audit policy itself being changed |
| Policy Change → Authentication Policy Change | Success | 4713, 4739 | the domain's password and Kerberos policy changed |
| System → Security System Extension | Success | 4697 | a service installed on a controller |

The Security log being cleared (1102) is written whatever the policy says.

**The ones in bold are the ones worth switching on first.** Each of them is
a card on the Domain page that stays empty until it is.

- **Computer Account Management** writes 4742 when a computer's own password
  changes. That is the missing half of *"a computer's own password is
  refused"*: it would show that the refusals began a few minutes after the
  password changed.
- **Special Logon** says where accounts with administrative rights sign in.
- **Security Group Management** feeds *"somebody was put into a group that
  runs the domain"*.
- **Directory Service Changes** needs the auditing entries on the directory
  objects themselves. The default ones on the domain cover users, groups and
  policies. It feeds the directory changes on the *Accounts and groups* and
  *The directory itself* tabs.

**Directory Service Access (4662)** is the loudest of all: a fifth of a busy
controller's log can be 4662. It is what the *"an account asked to replicate
the directory"* card is built on. The domain object needs an auditing entry
for *Replicating Directory Changes All*. Azure AD Connect (`MSOL_…`, run by
`ADSyncMSA…$`) will show up there doing its job. It is already on the list of
accounts expected to do that (`winsec_expected`, `MSOL_*,AAD_*` by default,
under **Settings → The domain controllers**), so it does not raise the card.
Anything else that legitimately replicates goes on the same list.

**The Security log's size.** At several thousand events an hour, the
default 128 MB holds a day or two. 1–4 GB on a controller keeps the local copy
long enough to look at when the forwarding stops. *Computer Configuration →
Policies → Administrative Templates → Windows Components → Event Log Service
→ Security → Specify the maximum log file size*.

**NTLM auditing** (*Network security: Restrict NTLM: Audit NTLM
authentication in this domain* = **Enable all**, on the controllers) writes
8004 to the **Microsoft-Windows-NTLM/Operational** log. It names the server
that passed an NTLM sign-in on, which is exactly what 4776 leaves out. It is a
different log from the Security one: NXLog would need a second `<Select>` for
it, and isemon does not read it yet.

**Beyond the controllers.** A controller sees *that* a password was wrong,
the machine it came from, and for Kerberos the address. It never sees
*which program* on that machine sent it. On the machine itself, the Security
log's 4625 carries the caller process. Forwarding the Security log of the
servers people sit on (terminal servers, the Exchange server) for a day is
the way to find the program an old password lives in when the Domain page
has narrowed it to one server.
