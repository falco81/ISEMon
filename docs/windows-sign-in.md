# Signing in with Windows (Kerberos)

isemon can sign an Active Directory administrator in to its pages **without a
password**: a browser on a computer in the domain sends a Kerberos ticket for
the name the page was opened by, and isemon checks it against a keytab put in
on the pages. Built after otp 1.0.274's Kerberos SSO.

## The rules it keeps

1. **Off by default.** Nothing changes until it is switched on, and nothing of
   it is offered while it is off.
2. **Never NTLM.** Only Kerberos 5. A token of NTLM, bare or inside SPNEGO, is
   refused, and so is any other SPNEGO mechanism. There is no setting for it.
3. **The second step stays.** With Face ID on, it is asked after a Windows
   sign-in exactly as after a password. Kerberos replaces the *password*,
   nothing more.
4. **Only people of the directory**, with the role their groups give: the same
   lookup as a sign-in with the directory's password. The account is kept
   under the person's short name (`sAMAccountName`), the same account as a
   password sign-in. A local account of isemon keeps its password.
5. **Nothing to install**: the system's GSS-API (`libgssapi_krb5`, part of
   `krb5-libs`) through Python's `ctypes`. No KDC is contacted: the ticket is
   decrypted with the service's key from the keytab.
6. **"Only Windows"** (optional): no password anywhere. It can be switched on
   only from a Windows sign-in, it is in effect only while Windows sign-in is
   on, and root always has a way back.

## Setting it up

### 1. In Active Directory (once)

On a domain controller, as a domain administrator:

1. A service account of its own (`svc-isemon-http`): a normal user,
   *Password never expires*, *This account supports Kerberos AES 256 bit
   encryption*.
2. An SPN for every name the pages are opened by:
   ```
   setspn -S HTTP/isemon.corp.example CORP\svc-isemon-http
   ```
3. The keytab (AES only):
   ```
   ktpass -princ HTTP/isemon.corp.example@CORP.EXAMPLE -mapuser CORP\svc-isemon-http ^
          -crypto AES256-SHA1 -ptype KRB5_NT_PRINCIPAL -pass * -out isemon-http.keytab
   ```
   Changing the account's password later makes a new key version: make the
   keytab again and put it in again.

One key serves every name: give the one account an SPN for each name, never a
keytab per name.

### 2. In isemon

*Settings → Active Directory*, with the directory set up for administrators:

- **Sign in with Windows (Kerberos)**: the switch.
- **...by itself when the sign-in page opens**: the page tries Windows at once
  and shows the form only when it did not work. After *Sign out* it is not
  tried by itself again in that tab, so signing out does not sign you
  straight back in.
- **Kerberos realm**: empty means it is taken from the directory's base DN
  (`DC=corp,DC=example` → `CORP.EXAMPLE`). A ticket of any other realm is
  refused.
- **...and no password at all - only Windows**: see below.

The card **Signing in with Windows (Kerberos)** below the settings shows:

- **the keytab**: its principals, key versions and kinds of key, never a key;
  **Put in a keytab… / Take the keytab away** (a full admin);
- **Try my browser's ticket**: asks this browser for its ticket and says who
  it would sign in and as what, without signing anybody in. Use it to find a
  wrong SPN before switching the sign-in on;
- **the name** the pages are opened by, its SPN, and whether the keytab has it
  by name;
- **the commands for AD** and **the browsers' settings**, filled in with this
  name and realm.

The keytab is kept in the database, sealed with the installation's key, and
written out by the daemon itself (`/var/lib/isemon/kerberos/http.keytab`,
0600, the service's own account) whenever it is needed.

### 3. In the browsers

- **Edge and Chrome on Windows** (group policy): `AuthServerAllowlist` = the
  name(s), comma separated. Or *Internet Options → Security → Local intranet →
  Sites*.
- **Firefox**: `network.negotiate-auth.trusted-uris` = the name(s), by policy
  or in about:config.
- Open the pages by the **name**, never an IP address. There is no SPN for an
  address, and Windows then offers NTLM, which is refused.

### 4. nginx

A ticket of a person in many AD groups is larger than nginx's 8 kB header
buffer. The shipped vhost has `large_client_header_buffers 4 32k;`. On an
older vhost, the root helper puts that line in when Windows sign-in is
switched on, if the file does not set it anywhere already. It is never taken
out or changed. PHP-FPM gets the header as `HTTP_AUTHORIZATION` by default.

## How it works

```
browser                   nginx + PHP (index.php)               isemon daemon
   │ POST ?api=kerberos-login   │                                    │
   │───────────────────────────►│ no Authorization                   │
   │◄── 401 WWW-Authenticate: Negotiate                              │
   │ (a ticket for HTTP/<name in the address bar>, from the          │
   │  person's Windows sign-in)                                      │
   │ POST, Authorization: Negotiate <SPNEGO base64>                  │
   │───────────────────────────►│── /api/auth/kerberos {token} ─────►│ NTLM? refused
   │                            │                                    │ gss_accept_sec_context (keytab)
   │                            │                                    │ Kerberos 5? user@REALM, the realm?
   │                            │                                    │ used once only?
   │                            │                                    │ AD by sAMAccountName: one entry,
   │                            │                                    │  on, not locked, not expired,
   │                            │                                    │  groups → role
   │                            │◄── {token, name, role, second} ────│ a session (the second step first)
   │◄── 200, Set-Cookie (HttpOnly, SameSite=Strict)                  │
   │ second step? → Face ID : reload                                 │
   │ refused → 403, never a second 401 (no retry, no NTLM, no browser password window)
```

What is refused, and said in *Events* as a warning: no group with a role, not
in the directory, switched off or locked out or expired in the directory,
switched off here, more than one entry answering to the name, a computer
account, a local account of the same name, another realm, a ticket for a name
not in the keytab, the same ticket again, NTLM, garbage.

## Only Windows

With **...and no password at all - only Windows** on:

- the sign-in page offers no name and password, only *Sign in with Windows*;
- a password sign-in is refused, local accounts' too;
- no password is set or changed on the pages (*Your account*, *Accounts*).

It can be switched on only from a session opened by Windows, so whoever does
it has shown that it works for them. It is in effect only while *Sign in with
Windows* is on and a keytab is in. **The way back**, as root on the server:

```bash
isemon --set password_off=0
```

or `isemon --set kerberos=0`, which turns off Windows sign-in as well.

## Testing without a domain

`test/fixes340_kerberos.py` makes an MIT Kerberos realm of its own
(`test/kdc_krb5.sh`, realm `CORPNET.LOC`) when `krb5-kdc` is installed. Its
tickets are real, made by the system's GSS-API as a browser on Linux makes
them. The test checks every case above, then the whole round through PHP with
`curl --negotiate`. In a real Chromium:
`--auth-server-allowlist=isemon.corpnet.loc`, `KRB5_CONFIG` and `KRB5CCNAME`
in its environment, and the name in `/etc/hosts`.
