# Before Windows Server 2025: what to fix, tile by tile

This is the companion to *Domain → Before Windows Server 2025*. For every
tile on that page, it says:

- what the tile means;
- whether it blocks the move to Windows Server 2025 domain controllers;
- how to find who does it;
- how to fix it, with commands;
- how to check that the fix worked.

**Use the page as the to-do list:**

- A tile opens the machines or accounts behind it.
- A row opens the events behind it.
- A fix is done when its rows stop growing. Use *last day* in the window
  list for that.

## Order of work

Work through the tiles in this order:

| # | Tile | Blocks 2025? | Typical cause |
|---|---|---|---|
| 1 | LDAP simple bind in the clear | **yes** | an application reading AD over port 389 with a user and password |
| 2 | NTLMv1 | **yes** | an old device, or a machine with a low *LAN Manager authentication level* |
| 3 | SMB1 to a domain controller | **yes** | an old scanner, NAS, printer or OS |
| 4 | Kerberos with DES | **yes** | an account with *Use Kerberos DES encryption types* ticked |
| 5 | Kerberos with RC4 | **yes, from the 2026 Kerberos updates** | a service account or keytab without AES, a client that offers only RC4 |
| 6 | An account with no AES keys | **yes, together with 5** | a password older than AES in the domain |
| 6b | DES still allowed on an account | no (tidy up) | the policy *Configure encryption types allowed for Kerberos* with DES ticked |
| 7 | LDAP bind without signing | **yes** | an application doing NTLM/Kerberos LDAP without signing |
| 8 | LDAP channel binding failed | once channel binding is required | an LDAPS client without channel binding support |
| 9 | A password handed over as it is (logon type 8) | only where it is not over TLS | LDAP simple bind or basic authentication |
| 9b | Sign-ins with Digest (WDigest) | no (information) | a print server or an old web application using HTTP Digest |
| 10 | NTLM, and NTLM by the server it was for | **no** (information) | anything that uses an IP address or lacks an SPN |
| 11 | The controller's own daily count | — | a daily summary (event 2887) |

> **Why the LDAP tiles block.** A *new* Windows Server 2025 domain
> controller requires LDAP signing by default (*Domain controller: LDAP
> server signing requirements Enforcement*). It then refuses:
> - simple binds on port 389 without TLS;
> - NTLM/Kerberos binds without signing.
>
> Such a client gets `strongerAuthRequired` (LDAP result 8). Turning the
> policy off on a 2025 controller is possible, but it is a step backwards.
> Fix the clients first.

Before changing a client, prepare the controllers for LDAPS (step 0 below).
Most fixes rely on it.

---

## 0. Prerequisite: every domain controller offers LDAPS

LDAPS (port 636) and StartTLS (389) need a certificate on every controller.
With AD CS, the *Kerberos Authentication* (or *Domain Controller
Authentication*) template gives them one by autoenrolment.

Check from any machine:

```powershell
Get-ADDomainController -Filter * | ForEach-Object {
    $r = Test-NetConnection $_.HostName -Port 636 -WarningAction SilentlyContinue
    '{0,-30} 636 {1}' -f $_.HostName, $(if ($r.TcpTestSucceeded) {'open'} else {'CLOSED'})
}
```

Check the certificate from Linux. It must name the controller and chain to
your root CA:

```bash
openssl s_client -connect pvtcdcx01.kr-olomoucky.int:636 -showcerts </dev/null | openssl x509 -noout -subject -issuer -ext subjectAltName -dates
```

- **Clients connect by name, not by address.** Use the domain name
  (`kr-olomoucky.int`) or a controller's name. An IP address does not match
  the certificate.
- **Clients must trust the company root CA.** Export it once:

  ```powershell
  certutil -ca.cert C:\temp\root-ca.cer
  ```

  On Linux and appliances, import it as a trusted CA.

---

## 1. LDAP simple bind in the clear

**What it is.**
- Directory Service event 2889, *Binding Type 1*: a user name and password
  sent over port 389 **unencrypted**.
- Anyone on the path can read the password.
- A 2025 controller refuses it.

**Who.** Open the tile. The *Accounts from it* column names the service
account, which usually names the application. Examples from the page:

| Account (examples) | Usually | Where to change it |
|---|---|---|
| `nagios` | Nagios `check_ldap` / LDAP auth of the web UI | `check_ldap -H dc -p 636 -S` (LDAPS) or `-T` (StartTLS); `htpasswd`/Apache `AuthLDAPURL ldaps://…` |
| `vsphere`, `vspherewf` | vCenter identity source "Active Directory as an LDAP Server" | vCenter → Administration → Single Sign-On → Configuration → Identity Sources → edit: `ldaps://dc:636`, upload the DC certificate or root CA |
| `horizon_ldap`, `connection_server` | VMware Horizon | Horizon Console → LDAP/AD settings: LDAPS and the root CA |
| `appvol` | App Volumes Manager | Configuration → AD Domains → *Secure* (LDAPS) or *StartTLS*, with the root CA |
| `OneClickAD`, `SMA`, `wsa`, `IDMint-sync` | an appliance or sync tool | its LDAP/AD settings: port 636 / "use SSL/TLS" / StartTLS, the root CA imported |

In general: change `ldap://…:389` to `ldaps://…:636`, or turn on StartTLS.
Import the root CA. Use the controller's **name**.

**Check.**
- The machine's row on the page stops growing.
- On the controller, no new 2889 events with *Binding Type: 1* from that
  address:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Directory Service'; Id=2889; StartTime=(Get-Date).AddHours(-1)} |
  Where-Object Message -match 'Binding Type:\s+1' | Select-Object TimeCreated, Message -First 5
```

---

## 2. NTLMv1

**What it is.**
- A sign-in with an NTLMv1 response (event 4624, *Package Name (NTLM only):
  NTLM V1*).
- An NTLMv1 response can be turned back into the password hash.
- Windows Server 2025 and Windows 11 24H2 do not accept NTLMv1 at all.

**Who.** Open the tile. Each row is a machine (name and address) and the
account it signed in as. `LM` is counted here too, and it is even weaker.
*ANONYMOUS LOGON* is not counted. Windows writes it as "NTLM V1"
whatever the client can do, because a null session sends no password.

**Fix.**
- **On Windows machines,** the policy decides it. In a GPO for the
  computers, set:
  - `Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options`
  - **Network security: LAN Manager authentication level** =
    *Send NTLMv2 response only. Refuse LM & NTLM*
  - This is registry value `LmCompatibilityLevel` = 5.

  To check it on one machine:

  ```powershell
  Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LmCompatibilityLevel -ErrorAction SilentlyContinue
  ```

  Missing, or less than 3, means the machine can still send NTLMv1. Set 5.
  Windows Vista and newer handle 5 with no side effects; only very old
  devices notice.
- **On devices** (printers, scanners, NAS, old Linux/Samba):
  - update the firmware;
  - for Samba, set `client ntlmv2 auth = yes` and `ntlm auth = ntlmv2-only`;
  - or replace the device.

**Check.** The row stops growing. 4624 events with `NTLM V1` from that
machine stop.

---

## 3. SMB1 to a domain controller

**What it is.**
- SMBServer/Audit event 3000: a client opened SMB1 to a controller. SMB1 is
  the protocol EternalBlue/WannaCry used.
- Windows Server 2025 has no SMB1 at all, and it requires SMB signing.

**Who.** The tile lists addresses. Find the device by address in DHCP/DNS
or in the switch's MAC table.

**Fix.**
- Turn on SMB2/3 in the device (scanner "scan to folder", NAS, old Linux).
  Update its firmware, or replace it.
- The device must also be able to **sign** SMB. Windows Server 2025 requires
  signing.

**Once the tile has stayed at 0 for weeks,** turn SMB1 off on the current
controllers too:

```powershell
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
# on Windows Server 2016/2019/2022, to remove it completely (restart needed):
Uninstall-WindowsFeature FS-SMB1
```

---

## 4. Kerberos with DES

**What it is.** A Kerberos ticket in DES (type 0x1 or 0x3). DES is broken,
and Windows Server 2025 has none.

**Fix.** Find the accounts with DES on, and turn it off:

```powershell
Get-ADUser -Filter 'UserAccountControl -band 0x200000' -Properties UserAccountControl |
  Select-Object SamAccountName
# for each account found:
Set-ADAccountControl -Identity <account> -UseDESKeyOnly $false
```

In *Active Directory Users and Computers* this is: the account → *Account*
tab → untick **Use Kerberos DES encryption types for this account**.

---

## 5. Kerberos with RC4

**What it is.**
- A Kerberos ticket encrypted with RC4 (type 0x17), or a client that offers
  no AES at all.
- RC4 tickets for service accounts are what *Kerberoasting* cracks offline.
- From the Kerberos hardening updates of 2026 (KB5073381), controllers stop
  handing out RC4 to accounts that do not explicitly ask for it. A 2025
  controller under the new defaults does not hand it out either.
- In short: whatever still gets RC4 today **will fail**.

**Who.**
- *Machines* gives the client address and the account.
- *Accounts* gives the account the ticket was for. That is usually a
  **service account** (an account with an SPN), like `SPSInstallTest` in
  the page's example.
- The row's detail says which, for example *a ticket for svc-x in RC4*.

**Why an account gets RC4.** There are three usual reasons. Check them in
this order.

1. **The account has no AES keys.** Its password was last set before the
   domain had AES (domain functional level below 2008).

   ```powershell
   Get-ADUser <account> -Properties PasswordLastSet, msDS-SupportedEncryptionTypes |
     Select-Object Name, PasswordLastSet, msDS-SupportedEncryptionTypes
   ```

   A `PasswordLastSet` older than the move to 2008 functional level means no
   AES keys. **Fix: reset the password once.** For a service account, also
   update the password where the service uses it.

2. **The account allows only RC4.** `msDS-SupportedEncryptionTypes` is 4
   (RC4 only), or it is empty and the service is not a Windows machine.
   **Fix: set AES.**

   ```powershell
   # 24 = AES128 + AES256; 28 = + RC4 for a transition period
   Set-ADUser <account> -Replace @{'msDS-SupportedEncryptionTypes' = 24}
   ```

   In ADUC: *Account* tab → tick **This account supports Kerberos AES 128
   bit encryption** and **…AES 256 bit encryption**.

3. **The service uses a keytab with RC4 only.** This is common for Linux,
   Java, Apache/Tomcat SSO, SAP and appliances. **Fix: make the keytab again
   with AES**, after steps 1 and 2:

   ```cmd
   ktpass /princ HTTP/web.kr-olomoucky.int@KR-OLOMOUCKY.INT /mapuser KR-OLOMOUCKY\svc-web /crypto AES256-SHA1 /ptype KRB5_NT_PRINCIPAL /pass * /out web.keytab
   ```

   On the Linux side, check it with `klist -kte web.keytab`. It must show
   `aes256-cts-hmac-sha1-96`.

Clients that **offer** only RC4 (*the client offers only …*) are old Java,
old Samba or old appliances. Update them, or allow AES in their
`krb5.conf`:

```
permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
```

To list every account an RC4 ticket was issued for, by count, run on a
controller:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769; StartTime=(Get-Date).AddDays(-1)} -MaxEvents 200000 |
  Where-Object { $_.Properties[5].Value -eq 0x17 } |
  Group-Object { $_.Properties[2].Value } | Sort-Object Count -Descending | Select-Object Count, Name -First 30
```

`Properties[5]` is Ticket Encryption Type and `Properties[2]` is Service
Name. Both are as written by the 2025+ 4769 format; on older builds, look up
the field order in the event's XML.

**Check.** In `klist` on the client, after `klist purge`, the ticket for
that service shows `KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96`.
On the page, the account's RC4 rows stop growing.

> **Do not** set `DefaultDomainSupportedEncTypes` or a domain-wide "AES
> only" policy before this tile is clean. That is the step that breaks
> whatever is still on RC4.

---

## 6. An account with no AES keys

**What it is.**
- The controller reported that the account's keys contain no AES. This
  comes from *Available Keys* in 4768/4769, and from the KDC's events
  14/16/26/27.
- Such an account can only get RC4 tickets. Once RC4 is gone, it cannot
  sign in at all.
- `Available Keys: N/A` is not counted. It means the KDC did not look the
  keys up.
- A KDC event about an account that *has* AES keys (17/18) counts as the
  client's RC4, because the client asked for RC4 only.

**Fix.** Reset the account's password once. The new password gets AES keys.
For a service account, update the password where it is used, and make any
keytab again (see 5.3). Then check:

```powershell
Get-ADUser <account> -Properties PasswordLastSet | Select-Object Name, PasswordLastSet
```

The *krbtgt* account: if it ever shows up here, reset it **twice**, at
least 10 hours apart (replication and ticket lifetime). Microsoft's
`New-KrbtgtKeys.ps1` script does this safely.

---

## 6b. DES still allowed on an account

**What it is.**
- Since the January 2025 updates, events 4768/4769 write each account's own
  `msDS-SupportedEncryptionTypes`. This tile lists the accounts whose value
  still has the DES bits (0x1, 0x2), for example `0x1F (DES, RC4,
  AES128-SHA96, AES256-SHA96)`.
- It typically shows every domain controller, `krbtgt` and trust accounts.
  That is the domain policy **Network security: Configure encryption types
  allowed for Kerberos** with DES ticked. Windows writes that policy into
  each computer's own value.
- **Nothing breaks by itself.** DES is never used while AES is there, and
  Windows Server 2025 has no DES. It is a setting to tidy.

**Fix.**
- In the GPO that sets the policy (often *Default Domain Controllers
  Policy*), tick only **AES128_HMAC_SHA1**, **AES256_HMAC_SHA1** and, until
  the RC4 tile is clean, **RC4_HMAC_MD5**. The computers rewrite their own
  value at the next `gpupdate`.
- On a user or service account set by hand:

  ```powershell
  Set-ADUser <account> -Replace @{'msDS-SupportedEncryptionTypes' = 0x1C}   # RC4 + AES, no DES
  ```

---

## 7. LDAP bind without signing

**What it is.**
- Directory Service event 2889, *Binding Type 0*: an NTLM or Kerberos
  (SASL) bind on port 389 without signing.
- The traffic can be changed on the way, and an NTLM bind can be relayed.
- A 2025 controller refuses it.

**Fix,** depending on the client:

- **Windows:** the policy *Network security: LDAP client signing
  requirements* must be **Negotiate signing** (the default) or **Require
  signing**. Check that no GPO sets *None*.
- **.NET / PowerShell applications:** `AuthType.Negotiate` with
  `SessionOptions.Signing = true` and `Sealing = true`. Or use LDAPS.
- **Python ldap3:** `Connection(..., authentication=NTLM,
  session_security=ENCRYPT)`. Or use LDAPS.
- **Java (JNDI):** `javax.security.sasl.qop = auth-int` (or `auth-conf`).
  Or use LDAPS.
- **Linux sssd / Samba:** current versions sign by default. Update old ones.
- **Appliances:** the "LDAP signing" or "secure LDAP" option. Or use LDAPS.

**Check.** No more 2889 events with *Binding Type: 0* from that address.

---

## 8. LDAP channel binding failed

**What it is.**
- Directory Service event 3039: an NTLM or Kerberos bind **over LDAPS**
  without a channel binding token (CBT).
- It is refused once *LDAP server channel binding token requirements* =
  *Always*.
- A 2025 controller ships with *When supported*. A client that sends no CBT
  is refused only under *Always*, so this is the next step after signing.

**Fix.**
- Update the client library. For example, `ldap3` 2.9.1+ sends CBT.
  Windows has sent it since the 2020 updates.
- Or use a simple bind over LDAPS, which is not subject to CBT.

---

## 9. A password handed over as it is (logon type 8)

**What it is.**
- Event 4624, logon type 8 (*NetworkCleartext*): the controller received the
  password itself.
- This is typical of an LDAP simple bind or HTTP basic authentication.
- Over TLS (LDAPS) it is fine. Over plain 389 it is the same case as tile 1.

**Fix.**
- If the same machine is also in tile 1, fix it there.
- Otherwise, check that the application uses LDAPS, or better, Kerberos.

---

## 9b. Sign-ins with Digest (WDigest)

**What it is.**
- Event 4624 with `Authentication Package: WDigest`: a sign-in by HTTP
  Digest. It is typically a print server (MyQ, for example) or an old web
  application.
- It is not one of the things Windows Server 2025 is known to refuse.
- But Digest is an old protocol, and the controllers keep a digest form of
  every password for it.

**Fix.**
- In the application, switch to Kerberos (Negotiate) or at least NTLMv2.
- Then switch Digest off where the application offers it.

---

## 10. NTLM (information)

**What it is.**
- Any NTLM sign-in (4776, and 8004 from the NTLM audit).
- NTLMv2 still works on Windows Server 2025, so **this tile does not block
  the move**.
- Microsoft is phasing NTLM out, and members of *Protected Users* cannot use
  it.

**Reduce it where it is cheap.** The usual reasons for NTLM are:

- A connection to an **IP address** instead of a name. Kerberos needs a
  name. Fix the shortcut, the mapped drive or the application setting.
- A missing or duplicate **SPN**:

  ```powershell
  setspn -Q HTTP/web.kr-olomoucky.int
  setspn -X        # duplicates
  ```

- A machine outside the domain, or a local account.
- An application that only knows NTLM.

The tile **NTLM, by the server it was for** shows the same NTLM sign-ins
from the other side. It comes from NTLM/Operational 8004 on the
controllers. Fix the servers named most first. It is a separate tile so
that one sign-in is not counted twice.

---

## 11. The controller's own daily count

**What it is.**
- Directory Service event 2887, written by every controller once a day: the
  number of unsigned or clear-text LDAP binds in the last 24 hours.
- It is a check on tiles 1 and 7. When it says 0 on every controller for
  several days, LDAP is ready.
- If the controllers count binds but no tile names who, the top card says
  so and points to the detailed logging (2889).
- *Not said yet* means no 2887 has arrived in the window yet. The event
  comes once a day.

---

## When the page is clean

1. Every blocking tile stays at **0** for at least two weeks, including
   month-end jobs.
2. On the current controllers, require LDAP signing, as a dress rehearsal
   for 2025:
   - *Domain controller: LDAP server signing requirements* = **Require
     signing**;
   - watch the page and the help desk for a few days.
3. Turn SMB1 off on the controllers (see 3).
4. Promote the first Windows Server 2025 controller. The audit GPO from
   `docs/active-directory-logging.md` applies to it automatically. Run its
   per-controller script and set up NXLog on it.
5. After the last old controller is gone, take the extra logging back
   (`docs/active-directory-logging.md`, section 8).
