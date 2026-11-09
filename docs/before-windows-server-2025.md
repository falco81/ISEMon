# Before Windows Server 2025 (1.10.321)

**Domain → Before Windows Server 2025** lists what a domain controller of
Windows Server 2025 refuses that a 2016 one still lets through, and which
machines and accounts here still do it.

It is off unless switched on, under **Settings → The domain controllers →
Look for what Windows Server 2025 will refuse** (`winsec_ad2025`). While it is
off, nothing is counted and the page is not there.

## What it finds, and in which log

| Kind | How bad | Log | Events | What breaks on 2025 | Fix |
|---|---|---|---|---|---|
| LDAP simple bind in the clear | refused | Directory Service | 2889 (binding type 1) | simple bind on 389 without TLS: `strongerAuthRequired`, result 8 | LDAPS on 636 or StartTLS; the controller by FQDN; trust the root CA |
| LDAP bind without signing | refused | Directory Service | 2889 (binding type 0) | SASL (NTLM/Kerberos) bind on 389 without signing | signing/sealing in the library, or LDAPS |
| LDAP channel binding failed | refused | Directory Service | 3039 | NTLM/Kerberos over LDAPS without a channel binding token, once required | a library that sends the token, or a simple bind over LDAPS |
| NTLMv1 | refused | Security | 4624 `Package Name (NTLM only): NTLM V1` | NTLMv1 is gone | LmCompatibilityLevel 5, or a newer device |
| Kerberos with DES | refused | Security | 4768/4769, ticket type 0x1/0x3 | DES is not there | take DES off the account |
| Kerberos with RC4 | from July 2026 | Security, System (KDC) | 4768/4769 type 0x17/0x18; a client offering no AES; KDC 201–209 | no RC4 for accounts that do not ask for it (KB5073381) | `msDS-SupportedEncryptionTypes` 24, password reset, AES keytabs |
| An account with no AES keys | from July 2026 | Security, System (KDC) | 4768/4769 `Available Keys` without AES; KDC 14/16/26/27 | its tickets fail without RC4 | reset its password |
| SMB1 to a controller | refused | SMBServer/Audit | 3000 | SMB1 is not on 2025 | SMB 2/3 |
| A password handed over as it is | info | Security | 4624 logon type 8 | in the clear it is refused (2889 says which) | LDAPS |
| NTLM | info | Security, NTLM/Operational | 4776, 8004 | still works (NTLMv2), on its way out; Protected Users cannot use it | Kerberos: names, SPNs |
| The controller's daily count | info | Directory Service | 2887, 3040, 3041 | — | the detailed logging names the clients |

## How it is counted

The rules are matched when each line is read, and only for the event numbers
above. Only a few words of each line are read, never the whole of it.
Matching happens before any event the site has switched off (sign-ins,
directory reads) is dropped, so it works either way.

Each finding is counted in `ad25_seen`: one row per day, kind of trouble,
client, account and controller, holding how many times it was seen and when
it was first and last seen. Rows are kept for 90 days (NTLM for 31).

A line read again is not counted again. This covers a rotated file, the pass
back over every log, and the same line arriving in two files. One
controller's lines arrive in order, so anything no newer than a row's newest
moment has already been counted.

What isemon counted before this was switched on is not on the page. *Go back
over the logs* (Settings → Go back over the logs) reads the files that are
still on disk and fills in the days they cover.

The page shows each kind as a tile, then the trouble listed by machine, by
account, or row by row. It also shows which of the logs are arriving at all.
Pressing a row opens the events behind it.

## What the controllers have to send

The Security log is sent already and covers Kerberos, NTLMv1 and NTLM. The rest
need two steps.

### 1. On every domain controller

LDAP, so that the controller names who does it (2889, 3039). This takes effect
at once. At level 2 every such bind is an event, so on a busy controller keep
it on only for the weeks before the change:

```
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics" /v "16 LDAP Interface Events" /t REG_DWORD /d 2 /f
```

SMB1 to the controller (SMBServer/Audit, 3000):

```
Set-SmbServerConfiguration -AuditSmb1Access $true -Force
```

NTLM by server (NTLM/Operational, 8004): set a group policy on the Domain
Controllers OU. The path is Computer Configuration → Policies → Windows
Settings → Security Settings → Local Policies → Security Options. Set
*Network security: Restrict NTLM: Audit NTLM authentication in this domain*
to **Enable all**.

The Security log has to audit Kerberos and the logons, Success and Failure:

```
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

### 2. In nxlog.conf, beside the Security input

Add one input per log, so that a log a controller does not have does not
stop the others. All of them use the same output, so everything lands in the
file isemon already reads. Then run `Restart-Service nxlog`.

```
<Input eventlog_ds>
    Module          im_msvistalog
    SavePos         TRUE
    ReadFromLast    TRUE
    <QueryXML>
        <QueryList>
            <Query Id="0">
                <Select Path="Directory Service">*[System[(EventID=2886 or EventID=2887 or EventID=2888 or EventID=2889 or EventID=3039 or EventID=3040 or EventID=3041)]]</Select>
            </Query>
        </QueryList>
    </QueryXML>
</Input>

<Input eventlog_kdc>
    Module          im_msvistalog
    SavePos         TRUE
    ReadFromLast    TRUE
    <QueryXML>
        <QueryList>
            <Query Id="0">
                <Select Path="System">*[System[Provider[@Name='Microsoft-Windows-Kerberos-Key-Distribution-Center'] and (EventID=14 or EventID=16 or EventID=26 or EventID=27 or (EventID &gt;= 201 and EventID &lt;= 209))]]</Select>
            </Query>
        </QueryList>
    </QueryXML>
</Input>

<Input eventlog_smb1>
    Module          im_msvistalog
    SavePos         TRUE
    ReadFromLast    TRUE
    <QueryXML>
        <QueryList>
            <Query Id="0">
                <Select Path="Microsoft-Windows-SMBServer/Audit">*[System[(EventID=3000)]]</Select>
            </Query>
        </QueryList>
    </QueryXML>
</Input>

<Input eventlog_ntlm>
    Module          im_msvistalog
    SavePos         TRUE
    ReadFromLast    TRUE
    <QueryXML>
        <QueryList>
            <Query Id="0">
                <Select Path="Microsoft-Windows-NTLM/Operational">*[System[(EventID=8004)]]</Select>
            </Query>
        </QueryList>
    </QueryXML>
</Input>

<Route security_to_syslog>
    Path        eventlog_security, eventlog_ds, eventlog_kdc, eventlog_smb1, eventlog_ntlm => out_syslog
</Route>
```

The 2889 and 4769 events are often longer than 1500 bytes. Over UDP, losing
one fragment loses the whole event, so the TCP output already in the
configuration (port 514) is safer.
