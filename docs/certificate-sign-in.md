# Signing in with a certificate (a smart card, a YubiKey)

isemon can sign an administrator in with a certificate issued by the domain's
own authority (AD CS). The certificate can be on a smart card, on a YubiKey
(PIV), or in the computer. No password is typed: the browser offers the
certificate, and Windows asks for the card's PIN. Built after otp 1.0.275.

## The rules it keeps

1. **Off by default.** While it is off, nothing is offered and no port is
   opened.
2. **A port of its own** (8443). nginx asks for a certificate only there,
   never on 443. Nobody who opens the pages is asked for one, and nothing but
   the sign-in is served on that port.
3. **isemon checks the certificate**, not nginx:
   - the chain to the authorities put in;
   - the dates;
   - a key usage for signing in (Client Authentication or Smart Card Logon);
   - revocation, by the CRL at the certificate's CRL Distribution Point;
   - the person in AD, found by the UPN in the certificate, with the SID of
     KB5014754.
4. **The second step stays.** With Face ID on, it is asked after the
   certificate exactly as after a password.
5. **Only people of the directory**, with the role their groups give. One
   person is one account: the same `sAMAccountName` account as a password or
   Windows (Kerberos) sign-in. A local account of isemon keeps its password.
6. **"No password at all"** (optional): see below.

## Setting it up

### 1. AD CS (once)

1. A certificate template made from *Smartcard Logon* (or *User*):
   - *Subject Name* built from AD, with the *User principal name (UPN)* in the
     Subject Alternative Name;
   - the key usages *Client Authentication* and *Smart Card Logon*;
   - published on the issuing authority.
2. The authority's *Extensions*: a CRL Distribution Point over **http** that
   the isemon server can reach. The default `http://<server>/CertEnroll/...`
   is fine. The issuing authority's own certificate needs one too, for its
   root's CRL (isemon 1.10.347 checks every authority above a card but the
   root). The card says which authority put in has none.
3. A YubiKey (PIV): enrol it from Windows with the template (smart card
   enrolment, `certreq`), or with YubiKey Manager: a request from slot 9a,
   signed by the authority and imported back to 9a.

### 2. isemon

*Settings → Active Directory*, with the directory set up for administrators:

- **Sign in with a certificate (a smart card, a YubiKey)**: the switch.
- **The certificate's own port**: 8443 by default. SELinux already allows it
  as `http_port_t`. 80, 443 and the ports of the logs and databases are
  refused.
- **Which account a certificate is**:
  - `compat` (default): if the certificate carries the SID that AD CS writes
    since KB5014754, it must be the account's;
  - `strong`: the certificate must carry that SID (Microsoft's full
    enforcement);
  - `upn`: the UPN alone.
- **...by itself when the sign-in page opens**: the page goes to the
  certificate's port at once. The browser offers its certificate, the card
  asks for its PIN, and the form is shown only when that did not work. Off:
  a button "Sign in with a certificate" under the form.
- **Check that a certificate is not revoked (CRL)**: on by default. See
  [Revocation lists (CRL)](#revocation-lists-crl) below.
- **CRLs from the directory (LDAP) too**: off by default. See
  [CRLs from the directory](#crls-from-the-directory-ldap).
- **Ask an OCSP responder** (`off` by default) and **OCSP responder of its
  own**. See [OCSP](#ocsp-online-status).

The card **Signing in with a certificate** shows:

- **the authorities**: *Put in an authority…* takes PEM, `.cer` or `.p7b`. A
  person's certificate is refused. Each authority can be taken away again.
  Put in the issuing authority **and** its root.
- **Revocation lists (CRL)**: one row for each CRL, with **Fetch now** and
  **Clear all** (see below);
- **nginx**: whether its server on the port is in place;
- **Try my certificate**: goes to the port, where the browser offers its
  certificate, and says who it would sign in and as what. Nobody is signed in.
  This is the best way to find a wrong template before telling people.

When the sign-in is switched on and an authority is in, the root helper does
three things within a minute:

1. It adds a **server of isemon's own** at the end of the dashboard's nginx
   file, between two marked lines. It is taken away whole when the sign-in is
   switched off. Nothing else in the file is touched. The server:
   - listens on the certificate's port;
   - uses the dashboard's own name, certificate, PHP and *Who may reach which
     page* lines;
   - sends the authorities' names (`ssl_client_certificate`), so the browser
     offers only fitting certificates;
   - uses `ssl_verify_client optional_no_ca`: nginx asks, isemon checks;
   - serves only `index.php?api=cert-login` and `cert-check`, and 404 for
     everything else.
2. It writes the authorities to `/etc/nginx/certs/isemon-client-ca.pem`.
3. It opens the port in isemon's firewall from where the dashboard is reached
   (*Settings → Firewall and access*).

Run `./install.sh --upgrade` once, for the new root helper.

### 3. The browsers and the network

- The browsers need no setting. Edge and Chrome can pick the certificate by
  themselves with the policy `AutoSelectCertificateForUrls`.
- Behind a load balancer, the port must reach the server as plain TCP (TLS
  passthrough). A balancer that ends TLS cannot hand on the browser's
  certificate.

### A certificate for a person (1.10.352)

*A certificate for a person* on the card finds a person in the directory and
shows what their certificate must carry, each value with its own **Copy**:

- **Subject CN**: the account's `cn`.
- **SAN - UPN**: the `userPrincipalName`, as the other name *Principal name*
  (1.3.6.1.4.1.311.20.2.3). isemon finds the person by it, so an account
  without a UPN cannot sign in with a certificate.
- **SAN - URL**: `tag:microsoft.com,2022-09-14:sid:<SID>`, the SID of the
  account for strong mapping (KB5014754).
- **SID** and the account as Windows writes it (`NETBIOS\name`, with the
  domain's real NetBIOS name).

Type the name as `jnovak`, `DOMAIN\jnovak`, the UPN or the mail. More than one
match is refused rather than guessed. *The request as a file* gives the same
values as a `certreq` INF (`certreq -new request.inf request.req`) and an
openssl config (`openssl req -new -key key.pem -config req.cnf`).

A certificate issued online by AD CS from a template gets the SID extension
(1.3.6.1.4.1.311.25.2) by itself. One from an offline request, or one whose
Subject is supplied in the request, carries the SID only as the URL. Put the
URL in, or `strong` refuses the certificate.

It is read only (nothing is written in AD or here) and is for a full admin.

**Make a request (CSR)** in the same popup opens a form with these fields:

- **The key**: ECC P-256 (YubiKey, iPad, Windows), P-384, RSA 2048, 3072 or
  4096. An iPad does not sign with RSA 4096.
- **Subject**: the CN (from the account), and O, OU and C if wanted.
- **Subject Alternative Name**, each ticked or not: the UPN, the URL of the
  SID, the mail.
- **Key usage**: Client Authentication and Smart Card Logon. Digital
  signature (and key encipherment for RSA) is always set, as critical.

*Make and download* makes the key and the request **in the browser**
(WebCrypto). Two files are saved: `<name>.csr` (PKCS#10) and `<name>.key`
(PKCS#8, unencrypted). Nothing of the key is sent to isemon or kept anywhere;
it is only in the file saved. The page must be open over https (WebCrypto
needs a secure page). Then:

```
certreq -submit -attrib "CertificateTemplate:<template>" jnovak.csr jnovak.cer
ykman piv keys import 9a jnovak.key
ykman piv certificates import 9a jnovak.cer
```

To keep the key file encrypted:
`openssl pkcs8 -topk8 -v2 aes-256-cbc -in jnovak.key -out jnovak-enc.key`.
Where the template builds the Subject from AD, the authority replaces what the
request asks with what AD has, and the SID comes as its own extension.

### When the card is taken out (1.10.353)

A browser has no way of telling a page that a smart card or a YubiKey was
taken out. isemon finds out by asking the card. *When the card is taken out*
(Settings → Active Directory → Signing in with a certificate) chooses what
happens. It is off by default and only applies to a sign-in made with a
certificate (a password or Windows sign-in is never watched):

| Setting | What happens |
|---|---|
| `off` | Nothing: the session goes on until it runs out, as before. |
| `signout` | At the first check without the card the session ends and the sign-in page says why. |
| `grace` | A notice with a countdown; the session ends unless the card is back within *...put back within (seconds)* (default 30). |

In both modes, **another card** than the one the person signed in with ends
the session at once (the certificate's SHA-256 is compared; only that
fingerprint is kept, never the certificate).

**How it is checked.** Every *Checked every (seconds)* (default 15, 5-300)
the page loads a tiny picture from the certificate's port. That port asks for
a certificate and keeps no TLS session - and, while this is on, no
connection - open, so every check
is a new handshake **the card has to sign**:

- the card is there: answered, nothing happens;
- the card is out: the browser has no certificate to offer, or cannot sign;
  the check fails and the session ends (or the countdown starts);
- the page's policy (CSP) lets that one address in only for a watched
  session.

**The server's half (1.10.354).** The page only makes it visible at once.
The state is kept in the session's own row in the database (`card`,
`card_seen`, `card_out`), so a restart of the daemon forgets nothing.

- **The card out within the grace**: the session is **held**. Every question
  of it gets HTTP 423 (`code: card`) except whoami, sign out and the card's
  own checks, until a check finds the card again.
- **The card out longer than the grace + *late*** (three checks or 150 s,
  whichever is longer): the session is ended.
- **A page that stopped checking**, for *late* + grace + max(interval, 30 s),
  is **held, not ended**. iPadOS stops Safari's pages entirely while the
  screen is locked or another app is in front, so no timer runs. Before
  1.10.354 the person was signed out after ~3.5 minutes although the card
  never left. The page checks the moment it wakes (`visibilitychange`,
  `pageshow`, `focus`, `online`): the card there, it goes on; not there, it
  counts as a card taken out.
- **A failed handshake** never reaches the daemon. The page then says so on
  443 (`card-gone`), which can only end or hold its own session. Events say
  why, and in `grace` the server holds the session.

Events:

- *was signed out: the card they signed in with was taken out*
- *...was not put back in time*
- *...another certificate than the one signed in with was offered*
- *&lt;name&gt;: the card they signed in with is out - the session waits N s*
- *...is back*

**A browser that cannot be checked (1.10.355).** On an iPad the card is in,
yet the check in the background never finds it: Safari signs nothing for a
page in the background. A session therefore remembers whether a check in the
background has ever found its card in this browser (`sessions.card_ok`).

- Until one has, a check without the card does not count as the card taken
  out.
- With *A browser that cannot be checked* = `allow` (the default), that
  sign-in is simply **not watched**, and Events say so and why:
  - *no certificate came with the check*;
  - *the browser sent no cookie with the check*;
  - *the check got no answer at all*.
- With `signout`, it is signed out as if the card were out: such a browser
  cannot stay signed in while watching is on.
- Once a check has found the card, a later one without it is a card taken
  out, whatever the setting says.
- The picture's answer tells the page which case it is: 3 px wide means no
  cookie came, 4 px wide means this browser cannot be checked.

**Kind to the card (1.10.354).** The page is careful not to make the card
sign more than it has to:

- one check at a time;
- one check for all the tabs of a browser (`localStorage`);
- a picture that failed is asked once more after 1.5 s before it counts;
- while the card is out, a check every 5 s, or 10 s after a check that waited
  on a window of the card's ("Insert a smart card", a PIN);
- the first check 1.5 s after the page loads;
- the countdown drawn every second;
- switched on while pages are open, they learn of it within a minute and load
  again.

The reason for a sign-out is a word in the tab's own `sessionStorage`, never
text from the address.

**Things to know:**

- **No PIN while the card stays in.** Windows and the card's minidriver keep
  the PIN for the browser; a YubiKey's slot 9a asks it once (PIN policy
  `once`, the default).
- **Touch or PIN every time.** A YubiKey with *touch policy* or *PIN policy*
  `always` would ask at every check. Leave the setting off for one.
- **Windows may ask for the card.** Depending on the driver, Windows may show
  "Insert a smart card" when the card is out. Cancelling it ends the session
  as well.
- **Off, nothing changes.** Switched on, root's helper adds two lines to the
  port's nginx server (`keepalive_timeout 0`, the check let through) within
  a few seconds. Switched off, it takes them out again.
- **With it**, set Windows' own *Interactive logon: Smart card removal
  behavior* = **Lock Workstation** by group policy. It locks the computer at
  once, and isemon ends the session.

## How it works

```
browser (443)                    browser (:8443)                       isemon
 │ "Sign in with a certificate"
 │ POST ?api=cert-nonce ──► a nonce in an HttpOnly SameSite=Strict cookie, the port's address
 │ location.href = https://name:8443/index.php?api=cert-login&n=<nonce>
 │                               │ TLS: nginx sends the authorities' names; the browser offers a
 │                               │ certificate of them - the card's PIN
 │                               │ nginx (optional_no_ca) ─► PHP: SSL_CLIENT_CERT (escaped PEM)
 │                               │ PHP: the nonce == its cookie? ─► /api/auth/cert {cert} ──────► │
 │                               │                       chain to the authorities, dates, key usage
 │                               │                       the CRL at its CDP (kept until next update)
 │                               │                       UPN ─► AD: one entry, on, not locked,
 │                               │                       not expired, SID == objectSid, groups
 │                               │ ◄─────────────────────────── {token, second} │ a session
 │                               │ Set-Cookie session (cookies are not kept apart by port)
 │ ◄──── 303 https://name/ (signed in, or ?certsaid=<why>)
 │ second step owed? → Face ID
```

- **Why the nonce**: it stops a page of somebody else's from signing a
  browser in with whatever certificate the browser has (login CSRF). It is
  used once, lasts five minutes, and is HttpOnly and SameSite=Strict.
- **Why the CRL comes after the chain**: the CRL's address is read only from
  a certificate that one of the authorities signed.
- **Why the SID**: a UPN can be given to somebody else; the SID in the
  certificate cannot be moved.

What is refused, written to *Events* as a warning with the reason. The
person is told little (1.10.347): *Certificate sign-in refused: revoked*,
*run out*, *not available just now* or *certificate not accepted*. *Try my
certificate* shows an administrator the whole reason.

- the certificate: of an authority, of another authority, run out, revoked,
  not for signing in, with no UPN, or whose CRL cannot be fetched;
- the person: not in the directory, more than one entry, switched off, locked
  out or expired in the directory, or in no group with a role;
- the SID: another account's SID (`compat`, `strong`), or no SID at all
  (`strong`);
- here: an account switched off here, or a local account of the same name;
- the request: no nonce or a nonce of another browser, or no certificate
  offered.

## With Windows (Kerberos) as well

Both can be on together. Each is a button under the form, or is tried by
itself when the page opens. When both are tried by themselves:

1. Windows goes first, silently.
2. The certificate is tried only when this computer has no Windows ticket -
   a computer outside the domain with a smart card.
3. A refusal of either stops there and says why.

Nothing is tried by itself again in that tab after *Sign out* or after a
refusal. The card *The sign-in page* shows what a person meets.

## No password at all

**...and no password at all - only Windows or a certificate**:

- the sign-in page offers no name and password;
- a password sign-in is refused, local accounts' too;
- no password is set or changed on the pages.

It can be switched on only from a session opened by Windows or by a
certificate, and it is in effect only while one of the two is on. The last
authority cannot be taken away while it alone signs people in. **The way
back**, as root on the server:

```bash
isemon --set password_off=0
```

or `isemon --set certlogin=0`.

## iPad and iPhone

Safari on iPadOS and iOS uses a YubiKey's certificate only through a smart card extension. With
Yubico Authenticator, open *Smart card extension*, enable it, and add the certificate of slot 9A
to the device.

- **Key type**: use **ECC P-256** (template: Purpose *Signature*, algorithm *ECDSA_P256*,
  provider *Microsoft Smart Card Key Storage Provider*), or RSA 2048. With an **RSA 4096** key,
  Safari closes the connection before it asks for the PIN, and says "could not establish a secure
  connection". Windows, with the same token, works. On the server, `tcpdump` shows the iPad
  closing the connection right after the server's certificate request, with nothing sent.
- **Generate the key in slot 9A** and import the certificate:
  `ykman piv keys generate --algorithm ECCP256 9a pubkey.pem`, then
  `ykman piv certificates request ...`, `certreq -submit -attrib "CertificateTemplate:<name>" ...`,
  `ykman piv certificates import 9a cert.cer`. Then remove the old certificate in the
  extension and add the new one.
- The iPad does not need to trust the internal CA for this. Only isemon checks the client
  certificate. The server certificate on the port is the dashboard's.
- nginx writes a failed TLS handshake to its error log only at level `info`
  (`error_log /var/log/nginx/error.log info;`).

## Revocation lists (CRL)

From the CRL kit of acme 1.0.104 (1.10.347).

**The rules**

1. **No CRL, no sign-in (fail closed).** When a CRL cannot be had and no good
   copy is kept, nobody signs in with a certificate it covers.
2. **The certificate's CRL, its delta, and those of the authorities above it.**
   The root is skipped: it is its own anchor. Up to three `http://` URIs of the
   CRL Distribution Point are tried in turn. A delta CRL (*Freshest CRL*, named
   by the certificate or by its base CRL) is applied. A delta that is named but
   cannot be had means no sign-in: without it, a card revoked since the weekly
   base would still pass. An issuing authority with no http CDP is refused, the
   same as a person's certificate.
3. **Fetched only for a certificate whose chain is already good.** The chain
   is checked without CRLs first, so an address written into just anybody's
   certificate is never fetched.
4. **Ten minutes at most.** A CRL is kept for ten minutes, or until its next
   update if that comes sooner. A fetch that failed less than a minute ago is
   not tried again at every sign-in. If the address does not answer, the last
   good CRL is kept until its next update, then nothing. A CRL already past its
   next update when fetched counts as not had. One with no next update is kept
   for an hour.
5. **http only, with SSRF guards.** No https, ldap, user or password in the
   address, and no name of a cloud's metadata service. The machine's own DNS,
   and no proxy. **Every** address the name resolves to is checked: no
   loopback, link-local, multicast, unspecified, reserved, or metadata address
   (169.254.169.254, 169.254.170.2, fd00:ec2::254, 100.100.100.200), in any
   spelling (`2852039166`, `0251.0376.0251.0376`, `127.1`). Private addresses
   are fine: AD CS's CDPs live inside. The connection goes to the address
   checked, with a `Host:` header, so the name is never looked up again. No
   redirect is followed. 8 MB at most, 15 s for the whole fetch.
6. **Checked by openssl** (`verify -crl_check_all [-use_deltas]`) against the
   authorities put in, never the system's store.
7. **Only a full administrator** can press Fetch now or Clear, and both are
   written to *Events*.

**The lag**: a revoked card stops signing in once the authority has
**published** a CRL listing it, plus up to ten minutes. With AD CS's defaults
(base weekly, delta daily) that can be a day. After revoking a lost card,
publish by hand (`certutil -CRL`), then press **Fetch now**.

**The table** on the card *Signing in with a certificate*: one row for each
CRL kept, and one for each CRL an authority names that has not been fetched
yet. The columns are address (with a copy button), issued by, type (`base` or
`delta`), next update, revoked entries, when fetched, and the row's own Fetch
now / Clear. The pill reads, in this order:

| Pill | When |
|---|---|
| **not fetched yet** (grey) | no copy yet; the first sign-in that needs it, or Fetch now, fetches it |
| **run out** (red) | no good copy, its next update has passed, and no error was recorded |
| **not had** (red) | no good copy: nobody signs in with a certificate it covers |
| **within a day** (amber) | good, but its next update is less than 24 h away (AD CS's delta CRLs always are) |
| **last fetch failed** (amber) | good: the last good copy is kept until its next update, but the latest fetch failed |
| **good** (green) | everything else |

A row opens (click, Enter or Space) to this update, next update, CRL number,
size, revoked entries, its signature (*verified* by `openssl crl -CAfile`
against the authorities put in, *bad*, or *not verified* when its authority is
not put in), the issuer's whole DN, the authority that names it, the last error
and when, and the address with *Copy*. **Fetch now** fetches every CRL again at
once: those kept, those the authorities name, and the delta CRLs these name.
**Clear all** asks first: every CRL kept is forgotten, and the next sign-in
fetches them again. A box above the table shows the answer. The card is
redrawn off the page and swapped in one step, holding the row that was
clicked where it was on the screen.

**From the command line**, the same as the page:

```
isemon --cert-login-crl [--json]        the table as text
isemon --cert-login-crl-fetch [URL]     Fetch now - every CRL, or one; exit 1 if one failed
isemon --cert-login-crl-clear [URL]     Clear - one, or all (asks first; --yes)
```

An unknown URL is refused: *no CRL at that address is known here*.

## OCSP (online status)

From 1.10.348. *Ask an OCSP responder* (`certlogin_ocsp`):

| Mode | What happens |
|---|---|
| `off` (default) | the CRLs alone, as before |
| `first` | the responder is asked; only when it gives no answer, the CRL decides |
| `only` | the responder alone: no answer, no sign-in |
| `both` | the responder **and** the CRL, both must say good |

The card shows the order as steps, for example *OCSP → no answer → CRL →
none to be had → no sign-in*.

- **Which responder**: the one each certificate names (*Authority Information
  Access*, OCSP), or one set for all (*OCSP responder of its own*,
  `certlogin_ocsp_url`, an http address). The setting refuses https, a user or
  password in the address, and loopback, link-local or metadata addresses.
- **What is asked**: the certificate and every authority above it but the
  root, each of its own issuer. With `first`, an authority whose certificate
  names no responder is checked by its CRL. With `only`, it is refused.
- **How**: the request is made by `openssl ocsp -reqout` (no nonce, as Windows
  asks). It is POSTed by the same guarded http as a CRL: every address of the
  name is checked, the connection goes to the address checked, no redirect is
  followed, 1 MB and 15 s at most. The answer is checked by `openssl ocsp
  -respin -CAfile <the authorities put in>`, never against the system's store.
  It must be signed by the authority, or by a responder certificate the
  authority issued with *OCSP Signing* (AD CS's Online Responder). It must be
  within its this/next update.
- **The answer**:
  - *good* lets the person in;
  - *revoked* refuses (*revoked* for the person; reason and time in Events);
  - *unknown* refuses (*certificate not accepted*);
  - a forged answer, no answer, or one out of date counts as *no answer*.
- **Kept ten minutes at most**, or until its next update if that is sooner. A
  responder that failed less than a minute ago is not asked again at every
  sign-in. While it does not answer, a last *good* answer is used until its
  next update.

**The table "Online status (OCSP)"** has one row for each answer kept:

- the certificate, its issuer, a status pill, the next update, the serial,
  and when it was asked;
- the pill reads *good*, *revoked*, *unknown*, *no answer*, *run out* or
  *last answer kept*;
- a row opens to the revocation time and reason, this and next update, the
  responder that signed, the size, the last error, and the responder's
  address with *Copy*;
- **Ask again** and **Clear all** (also per row) are for a full administrator
  and are written to Events. Clear all asks first.

```
isemon --cert-login-ocsp [--json]     the answers kept
isemon --cert-login-ocsp-fetch        ask every responder again
isemon --cert-login-ocsp-clear        forget them (asks first; --yes)
```

AD CS: install the *Online Responder* role, add a *Revocation Configuration*
for the issuing authority (and one on the root's side for the authority above
it), and put its URL in the authority's *Extensions* → *Authority Information
Access* with *Include in the online certificate status protocol (OCSP)
extension*. Certificates issued before that name no responder. For those, set
*OCSP responder of its own*.

## CRLs from the directory (LDAP)

From 1.10.348. AD CS publishes its CRLs into the directory as well:
`ldap:///CN=<CA>,CN=<server>,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,DC=...?certificateRevocationList?base?objectClass=cRLDistributionPoint`.
With *CRLs from the directory (LDAP) too* on:

- such a CDP (and the delta's, `deltaRevocationList`) is read when no http
  address of the certificate answers, or when it names none;
- it is read with the **directory connection set above**, never with the host
  written in the address;
- only a `cRLDistributionPoint` object under `CN=CDP,CN=Public Key
  Services,CN=Services,CN=Configuration,...` is read, base scope, and only its
  `certificateRevocationList` or `deltaRevocationList`. Any other DN or
  attribute in a certificate is ignored;
- the same rules as an http CRL apply: ten minutes, the last good copy,
  openssl's check, fail closed;
- the table shows such a row with an **LDAP** tag and the CA's name, and in
  its details *Read from: the directory (LDAP)*.

The account the directory is read with needs read access to the
configuration partition, which every domain account has by default.

## Testing without a domain

`test/fixes341_certlogin.py` makes an AD CS of its own with openssl
(`test/pki_certlogin.sh`): a root, an issuing authority, its CRL served over
http, and a person's certificate for every case. It checks every refusal
above, the authorities, `compat`/`strong`/`upn`, the CRL switched off, the
second step, and "no password". It then checks nginx's server as the root
helper writes it, put in and taken away. Where nginx and php-fpm are
installed, it also makes the whole round through them with a client
certificate: the nonce on 443, the sign-in on the port, the session back on
443, the refusals, and nothing else served on the port. In Playwright:
`newContext({clientCertificates: [{origin: 'https://name:8443', certPath,
keyPath}]})`.

`test/fixes347_crl.py` makes the CRL kit's PKI (`test/pki_crl.sh`): a root,
an issuing authority naming the root's CRL, a base CRL, a delta CRL, and an
authority the root revoked. It checks every SSRF guard, alice (good), bob
(revoked in the base), carol (run out), dave (CRL not to be had), erin
(revoked in the delta only) and frank (his authority revoked by the root), the
ten-minute cache and the last good copy, a delta not to be had, the card's
rows, Fetch now and Clear (refused to read-only), the events, what the person
is told, and the command line. The test CRLs are on 127.0.0.1, which only the
tests' switch `ISEMON_CDP_LOOPBACK_OK=1` allows. isemon never sets it.

`test/fixes348_ocsp.py` makes a PKI with two OCSP responders (`test/pki_ocsp.sh`,
`openssl ocsp` as the server). It checks `off`, `first`, `only` and `both`
with alice (good), bob (revoked), dan (responder dead), eve (no AIA), hal
(revoked in the CRL only), ida (unknown to the responder), the authority above,
a forged answer, a responder of its own, the cache and the last good answer,
the setting's guards, gina's CRL read from the directory (and nothing else read
there), the card, Ask again and Clear, the events, and the command line.
