# Active Directory logging for isemon

This guide covers everything to set up on the domain controllers so that
isemon receives complete logs. That means the Domain tab as a whole, and in
particular **Domain → Before Windows Server 2025**: who still does what a
Windows Server 2025 controller will refuse.

It covers the domain policy (GPO), what has to be done on each controller,
the whole NXLog configuration, how to check the result, whether any of it is
risky, and how to take it back afterwards.

Where PowerShell can do a step in a supported way, the script is given. Where
it cannot, the exact clicks are given.

## Contents

1. [What isemon needs, and from which log](#1-what-isemon-needs-and-from-which-log)
2. [Before you start](#2-before-you-start)
3. [The domain policy (GPO)](#3-the-domain-policy-gpo)
4. [On every domain controller](#4-on-every-domain-controller)
5. [NXLog](#5-nxlog)
6. [Check it](#6-check-it)
7. [Is any of this risky?](#7-is-any-of-this-risky)
8. [After the migration: taking it back](#8-after-the-migration-taking-it-back)
9. [Event reference](#9-event-reference)

---

## 1. What isemon needs, and from which log

| Log on the controller | Events | What isemon learns | What writes it |
|---|---|---|---|
| **Security** | 4768, 4769 | Kerberos tickets: RC4 or DES, accounts with no AES keys (`Available Keys`) | Advanced audit: *Kerberos Authentication Service*, *Kerberos Service Ticket Operations* |
| **Security** | 4776 | NTLM: which machine, which account | Advanced audit: *Credential Validation* |
| **Security** | 4624, 4625, 4740 | sign-ins, NTLMv1 (`Package Name (NTLM only): NTLM V1`), passwords handed over in clear (logon type 8), lockouts | Advanced audit: *Logon*, *Account Lockout*, *User Account Management* |
| **Directory Service** | 2889 | **who** binds to LDAP in the clear or unsigned (address, account, bind type) | Registry: `16 LDAP Interface Events` = 2 |
| **Directory Service** | 2887, 3039–3041 | the daily count of such binds; LDAP channel binding | written by the controller itself |
| **System** (source *KDC*) | 14, 16, 26, 27, 201–209 | the KDC's own warnings: missing keys, RC4 (KB5073381) | written by the controller itself |
| **Microsoft-Windows-SMBServer/Audit** | 3000 | who connects to the controller over SMB1 | `Set-SmbServerConfiguration -AuditSmb1Access $true` |
| **Microsoft-Windows-NTLM/Operational** | 8004 (8001–8003) | NTLM by the server it was used for | Policy: *Audit NTLM authentication in this domain* = Enable all |

Three of these logs are written to only when something happens: the KDC part
of System, SMBServer/Audit and NTLM/Operational. If nothing arrives from one
of them, there may simply have been nothing to say. isemon shows such a log
in grey, not red.

---

## 2. Before you start

- **Who:** a member of *Domain Admins*, on a controller or on a management
  machine with RSAT. RSAT provides the `GroupPolicy` and `ActiveDirectory`
  PowerShell modules.
- **Save the audit policy as it is now**, on one controller. It is the
  baseline to compare against, and the way back:

  ```powershell
  New-Item -ItemType Directory -Force C:\temp | Out-Null
  auditpol /get /category:* > C:\temp\audit-before.txt
  auditpol /backup /file:C:\temp\audit-before.csv
  gpresult /scope computer /h C:\temp\gpo-before.html
  ```

- **Check which audit policy is in use.** Open `C:\temp\gpo-before.html` and
  look for *Advanced Audit Configuration*.
  - If it is there, the domain already uses the advanced audit policy, and
    the settings in section 3.1 go into that same kind of policy.
  - If only *Audit Policy* (the basic one) is there, read the warning in
    section 7 before you switch on *Force audit policy subcategory settings*.

---

## 3. The domain policy (GPO)

Everything in this section goes into **one new GPO linked to the
Domain Controllers OU**. A separate GPO is clearer than changing *Default
Domain Controllers Policy*: once the migration is over, you unlink it in one
step, and a new Windows Server 2025 controller picks it up the moment it is
promoted.

### 3.0 Create the GPO and link it (PowerShell)

```powershell
Import-Module GroupPolicy, ActiveDirectory
$name = 'isemon - DC logging before Windows Server 2025'
$ou   = 'OU=Domain Controllers,' + (Get-ADDomain).DistinguishedName
$gpo  = Get-GPO -Name $name -ErrorAction SilentlyContinue
if (-not $gpo) { $gpo = New-GPO -Name $name -Comment 'Audit only: Kerberos, NTLM, LDAP, SMB1 - for isemon' }
if (-not ((Get-GPInheritance -Target $ou).GpoLinks.DisplayName -contains $name)) {
    New-GPLink -Name $name -Target $ou -LinkEnabled Yes | Out-Null
}
"GPO: $($gpo.DisplayName)  {$($gpo.Id)}  linked to $ou"
```

### 3.1 Advanced audit policy (click it in GPMC)

There is no supported PowerShell cmdlet that writes advanced audit
subcategories into a GPO. `auditpol` changes only the machine it runs on, and
a GPO overwrites that at its next refresh. So this part is done in the editor.

Open `gpmc.msc`, right-click the GPO from 3.0 and choose **Edit**. Every path
starts here:

`Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy Configuration → Audit Policies`

| Under | Policy | Tick | Events |
|---|---|---|---|
| Account Logon | **Audit Credential Validation** | Success, Failure | 4776 |
| Account Logon | **Audit Kerberos Authentication Service** | Success, Failure | 4768 (shows the encryption type, so RC4 is found) |
| Account Logon | **Audit Kerberos Service Ticket Operations** | Success, Failure | 4769 |
| Logon/Logoff | **Audit Logon** | Success, Failure | 4624, 4625 |
| Logon/Logoff | **Audit Account Lockout** | Failure | 4625 with the status *account locked out* |
| Account Management | **Audit User Account Management** | Success, Failure | 4740 (the lockout itself), 4720–4738 |

For each policy, tick **Configure the following audit events**, then the
boxes in the table.

> If the domain already has an advanced audit policy in another GPO (for
> example in *Default Domain Controllers Policy*), the GPO with the higher
> precedence wins for each subcategory. Keep the settings in one place, or
> make sure both GPOs agree.

### 3.2 Security options and log size (PowerShell)

These are registry-backed settings, so `Set-GPRegistryValue` writes them into
the same GPO.

```powershell
$name = 'isemon - DC logging before Windows Server 2025'

# Audit: Force audit policy subcategory settings (Windows Vista or later) to override
# audit policy category settings = Enabled. Without it, the basic audit policy can
# override the advanced one from 3.1 and the events are not written.
Set-GPRegistryValue -Name $name -Key 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' `
    -ValueName 'SCENoApplyLegacyAuditPolicy' -Type DWord -Value 1 | Out-Null

# Network security: Restrict NTLM: Audit NTLM authentication in this domain = Enable all
# (7). Audit only: NTLM/Operational 8004 on the controller.
Set-GPRegistryValue -Name $name -Key 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' `
    -ValueName 'AuditNTLMInDomain' -Type DWord -Value 7 | Out-Null

# Network security: Restrict NTLM: Audit Incoming NTLM Traffic = Enable auditing for all
# accounts (2). Audit only: NTLM/Operational 8001-8003. Optional.
Set-GPRegistryValue -Name $name -Key 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' `
    -ValueName 'AuditReceivingNTLMTraffic' -Type DWord -Value 2 | Out-Null

# Event Log Service - Security - Maximum log size (KB): 4 GB, the largest Windows takes.
Set-GPRegistryValue -Name $name -Key 'HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security' `
    -ValueName 'MaxSize' -Type DWord -Value 4194240 | Out-Null

Get-GPRegistryValue -Name $name -Key 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
```

If you would rather click these, the same settings are here. Each path
starts at `Computer Configuration → Policies`:

- `… → Windows Settings → Security Settings → Local Policies → Security Options`:
  - **Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings** = *Enabled*
  - **Network security: Restrict NTLM: Audit NTLM authentication in this domain** = *Enable all*.
    Its events do not go to the Security log; they go to
    `Applications and Services Logs → Microsoft → Windows → NTLM → Operational`
    (on a controller, mostly 8004).
  - **Network security: Restrict NTLM: Audit Incoming NTLM Traffic** = *Enable auditing for all accounts* (8001–8003)
- `… → Administrative Templates → Windows Components → Event Log Service → Security`:
  - **Specify the maximum log file size (KB)** = *Enabled*, *4194240*

> Settings written with `Set-GPRegistryValue` outside the `…\Policies\…` keys
> appear in the GPO editor under *Extra Registry Settings*, not under
> *Security Options*. They act the same. They stay on the controller when the
> GPO is unlinked, so section 8 takes them back explicitly.

> **Leave these unconfigured.** They are in the same list and are named
> almost the same, but they **block** NTLM rather than audit it:
> - *Network security: Restrict NTLM: NTLM authentication in this domain* (the *Deny …* values)
> - *Network security: Restrict NTLM: Incoming NTLM traffic* (*Deny all …*)
>
> Both must stay *Not Defined*.

### 3.3 LDAP logging and SMB1 audit through the same GPO (optional)

Both are plain registry values with no policy of their own, so Group Policy
Preferences can carry them to every controller, including new ones:

```powershell
$name = 'isemon - DC logging before Windows Server 2025'

# Directory Service 2889: who binds in the clear or unsigned.
Set-GPPrefRegistryValue -Name $name -Context Computer -Action Update `
    -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' `
    -ValueName '16 LDAP Interface Events' -Type DWord -Value 2 | Out-Null

# SMBServer/Audit 3000: who connects over SMB1 (what Set-SmbServerConfiguration
# -AuditSmb1Access $true writes).
Set-GPPrefRegistryValue -Name $name -Context Computer -Action Update `
    -Key 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' `
    -ValueName 'AuditSmb1Access' -Type DWord -Value 1 | Out-Null
```

In the editor the same is at `Computer Configuration → Preferences → Windows
Settings → Registry → New → Registry Item`: action *Update*, hive
*HKEY_LOCAL_MACHINE*, then the key, the value name, *REG_DWORD* and the value
from above.

If you leave this out, section 4 sets both on each controller instead.

### 3.4 Apply it

On each controller (or wait up to 90 minutes):

```powershell
gpupdate /target:computer /force
```

---

## 4. On every domain controller

Run this as administrator on each controller, and again on every new one
after it is promoted. It is safe to run more than once. It changes only
logging:

- LDAP diagnostics for event 2889;
- the SMB1 audit;
- the sizes of the logs;
- it then refreshes Group Policy.

```powershell
& {
    # LDAP: who binds in the clear or unsigned (Directory Service 2889). Takes effect at once.
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' `
        -Name '16 LDAP Interface Events' -PropertyType DWord -Value 2 -Force | Out-Null

    # SMB1: who connects to this controller over SMB1 (SMBServer/Audit 3000). Audit only -
    # SMB1 itself is not switched on by this.
    Set-SmbServerConfiguration -AuditSmb1Access $true -Force

    # Room in the logs, so that nothing is overwritten before NXLog sends it.
    wevtutil sl "Security" /ms:4294901760                            # 4 GB, the largest allowed
    wevtutil sl "Directory Service" /ms:268435456                    # 256 MB - 2889 can be many
    wevtutil sl "Microsoft-Windows-NTLM/Operational" /e:true /ms:104857600   # 100 MB
    wevtutil sl "Microsoft-Windows-SMBServer/Audit" /ms:16777216     # 16 MB

    # The GPO from section 3, now rather than within 90 minutes.
    gpupdate /target:computer /force | Out-Null
    'done on ' + $env:COMPUTERNAME
}
```

> Check that drive C: has room for a 4 GB Security log (`Get-PSDrive C`). The
> file grows to that size; it is not taken at once. If space is short, use
> `wevtutil sl "Security" /ms:2147483648` (2 GB).

The KDC writes 14, 16, 26, 27 and 201–209 by itself: there is nothing to
switch on. 201–209 come with the Kerberos updates of 2026 (KB5073381). A
controller patched later than January 2026 writes them when there is
something to say.

---

## 5. NXLog

isemon reads one file per controller: `/var/log/remote/<SYSLOGHOST>/WinSecurity.log`.
NXLog sends the Security log plus the four logs above, all through the same
output and so into the same file. isemon tells them apart by the event
number.

The configuration below has one input per log. If a log is missing on a
controller, only that input fails; the others go on.

Install NXLog Community Edition. Then put this into
`C:\Program Files\nxlog\conf\nxlog.conf` on each controller, with
**`SYSLOGHOST` set to that controller's own name**, and restart NXLog:

```powershell
Restart-Service nxlog
```

```
########################################################################
## NXLog Community Edition 3.2
## Domain controller - forward Security Event Log
##                   + Directory Service (LDAP signing, channel binding)
##                   + System / KDC (RC4, missing AES keys)
##                   + SMBServer/Audit (SMB1)
##                   + NTLM/Operational (NTLM audit)
## To: syslog 172.29.14.92:514 (rsyslog / isemon)
##
## NOTE: no '#' comments inside <Exec> blocks - the lines are joined by '\'
## into one logical line, and a comment would cut off the rest of it.
##
## Everything goes through the same output into the same file isemon reads
## (/var/log/remote/<SYSLOGHOST>/<SYSLOGTAG>.log); isemon tells the events
## apart by their EventID.
########################################################################

define ROOT      C:\Program Files\nxlog
define LOGDIR    %ROOT%\data

## syslog hostname -> /var/log/remote/<THIS>/
define SYSLOGHOST   pftcdcx02
## syslog tag -> <THIS>.log
define SYSLOGTAG    WinSecurity

Moduledir    %ROOT%\modules
CacheDir     %ROOT%\data
Pidfile      %ROOT%\data\nxlog.pid
SpoolDir     %ROOT%\data
LogFile      %LOGDIR%\nxlog.log
LogLevel     INFO

<Extension _syslog>
    Module      xm_syslog
</Extension>

<Extension _charconv>
    Module              xm_charconv
    AutodetectCharsets  utf-8, windows-1250, iso8859-2, utf-16, utf-32
</Extension>

########################################################################
## Security log
## 4624, 4768, 4769 and 4776 must not be dropped: Kerberos RC4/DES,
## accounts without AES, NTLMv1 and NTLM are read from them.
## Optional noise filter: uncomment the Exec line (4662 was ~18 % on one DC).
########################################################################
<Input eventlog_security>
    Module          im_msvistalog
    SavePos         TRUE
    ReadFromLast    TRUE
    <QueryXML>
        <QueryList>
            <Query Id="0">
                <Select Path="Security">*</Select>
            </Query>
        </QueryList>
    </QueryXML>
#    Exec  if $EventID IN (4656, 4658, 4662, 4663, 4670, 4690, 5145, \
#                          5152, 5154, 5156, 5157, 5158, 5447) drop();
</Input>

########################################################################
## Directory Service (LDAP)
## 2889 = a simple bind without TLS (Binding Type 1) or a SASL bind without
##        signing (Binding Type 0), with address and account - only with
##        "16 LDAP Interface Events" = 2.
## 2887 = the daily count; 3039 = channel binding failed; 3040/3041 summaries.
########################################################################
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

########################################################################
## System log, the KDC only
## 14, 16, 26, 27 = an account without a suitable key (typically RC4 only).
## 201-209       = the KDC's RC4 warnings (KB5073381, 2026).
########################################################################
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

########################################################################
## SMB1 audit: 3000 = a client connected over SMB1.
## Only with Set-SmbServerConfiguration -AuditSmb1Access $true
########################################################################
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

########################################################################
## NTLM audit: 8004 = NTLM through the controller (user, workstation, server).
## Only with "Audit NTLM authentication in this domain" = Enable all.
########################################################################
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

########################################################################
## Output - syslog over UDP. The RFC 3164 header comes from to_syslog_bsd();
## every field is checked with defined() first, because joining an
## undefined field throws the whole message away.
########################################################################
<Output out_syslog>
    Module      om_udp
    Host        172.29.14.92
    Port        514

    Exec        $Hostname = '%SYSLOGHOST%';                              \
                $SourceName = '%SYSLOGTAG%';                             \
                delete($ProcessID);                                      \
                $SyslogFacility = 'SECURITY';                            \
                $SyslogSeverity = 'INFO';                                \
                if defined($EventType) and $EventType == 'AUDIT_FAILURE' \
                    $SyslogSeverity = 'WARNING';                         \
                if not defined($Message) $Message = '';                  \
                $Message = replace($Message, "\r\n", " ");               \
                $Message = replace($Message, "\n", " ");                 \
                $Message = replace($Message, "\r", " ");                 \
                $Message = replace($Message, "\t", " ");                 \
                if defined($EventID)                                     \
                    $Message = 'EventID=' + string($EventID) + ' | ' +   \
                               $Message;                                 \
                to_syslog_bsd();
</Output>

## --- TCP instead (recommended) -------------------------------------------
## Over UDP a message above 1500 bytes is fragmented (4624, 4662, 4769 and 2889
## often are), and one lost fragment loses the whole event without a trace.
## rsyslog on isemon listens on TCP 514 too. To switch: comment out
## <Output out_syslog> above, uncomment this block, and point the Route at
## out_syslog_tcp.
# <Output out_syslog_tcp>
#     Module      om_tcp
#     Host        172.29.14.92
#     Port        514
#
#     Exec        $Hostname = '%SYSLOGHOST%';                            \
#                 $SourceName = '%SYSLOGTAG%';                           \
#                 delete($ProcessID);                                    \
#                 $SyslogFacility = 'SECURITY';                          \
#                 $SyslogSeverity = 'INFO';                              \
#                 if defined($EventType) and $EventType == 'AUDIT_FAILURE' \
#                     $SyslogSeverity = 'WARNING';                       \
#                 if not defined($Message) $Message = '';                \
#                 $Message = replace($Message, "\r\n", " ");             \
#                 $Message = replace($Message, "\n", " ");               \
#                 $Message = replace($Message, "\r", " ");               \
#                 $Message = replace($Message, "\t", " ");               \
#                 if defined($EventID)                                   \
#                     $Message = 'EventID=' + string($EventID) + ' | ' + \
#                                $Message;                               \
#                 to_syslog_bsd();
# </Output>

########################################################################
## Route. If nxlog.log says a log does not exist on this controller,
## comment out its <Input> and take it out of the Path line - the other
## inputs go on.
########################################################################
<Route security_to_syslog>
    Path        eventlog_security, eventlog_ds, eventlog_kdc, eventlog_smb1, eventlog_ntlm => out_syslog
</Route>
```

On the isemon side, switch the page on under *Settings → The domain
controllers → Look for what Windows Server 2025 will refuse*. The same page
lists the folders the controllers write to.

---

## 6. Check it

### 6.1 One controller, everything at once

Paste this whole block into a PowerShell window as administrator. It changes
nothing, and every line says OK, WARN or FAIL. It checks:

- the audit policy;
- the LDAP logging;
- the SMB1 and NTLM audit;
- the sizes of the logs;
- what each log wrote in the last seven days;
- NXLog: its service, its configuration and its errors.

The same script is on isemon's page: *Domain → Before Windows Server 2025 →
The logs and how to send them*, step 3. There, isemon's own address is
already filled in.

```powershell
& {
    $n = @{ok = 0; bad = 0}
    function Say($state, $what, $more) {
        $colour = @{OK='Green'; WARN='Yellow'; FAIL='Red'; INFO='Gray'}[$state]
        Write-Host ('{0,-5} {1}' -f $state, $what) -ForegroundColor $colour -NoNewline
        if ($more) { Write-Host "  - $more" -ForegroundColor DarkGray } else { Write-Host '' }
        if ($state -eq 'OK') { $n.ok++ } elseif ($state -ne 'INFO') { $n.bad++ }
    }

    Write-Host "`n== Audit policy (Security log) ==" -ForegroundColor Cyan
    $want = [ordered]@{
        'Credential Validation'              = 'Success and Failure'
        'Kerberos Authentication Service'    = 'Success and Failure'
        'Kerberos Service Ticket Operations' = 'Success and Failure'
        'Logon'                              = 'Success and Failure'
        'Account Lockout'                    = 'Failure'
        'User Account Management'            = 'Success'
    }
    foreach ($sub in $want.Keys) {
        $line = (auditpol /get /subcategory:"$sub" /r | ConvertFrom-Csv | Select-Object -First 1)
        $has = $line.'Inclusion Setting'
        $need = $want[$sub]
        $good = ($has -eq 'Success and Failure') -or ($need -eq 'Failure' -and $has -match 'Failure') -or ($need -eq 'Success' -and $has -match 'Success')
        if ($good) { Say OK "$sub" $has } else { Say FAIL "$sub" "is '$has', wants '$need'" }
    }
    $force = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue).SCENoApplyLegacyAuditPolicy
    if ($force -eq 1) { Say OK 'Advanced audit policy overrides the basic one' } else { Say WARN 'Advanced audit policy may be overridden by the basic one' 'GPO: Audit: Force audit policy subcategory settings = Enabled' }

    Write-Host "`n== LDAP (Directory Service log) ==" -ForegroundColor Cyan
    $ldap = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -ErrorAction SilentlyContinue).'16 LDAP Interface Events'
    if ($ldap -ge 2) { Say OK '16 LDAP Interface Events' "= $ldap (2889 names who binds in the clear or unsigned)" } else { Say FAIL '16 LDAP Interface Events' "= $ldap, wants 2" }
    $sign = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ErrorAction SilentlyContinue).LDAPServerIntegrity
    $cbt  = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ErrorAction SilentlyContinue).LdapEnforceChannelBinding
    Say INFO 'LDAP signing required (LDAPServerIntegrity)' "$(if ($sign -eq 2) {'2 - required'} elseif ($null -eq $sign) {'not set - not required'} else {"$sign - not required"})"
    Say INFO 'LDAP channel binding (LdapEnforceChannelBinding)' "$(if ($null -eq $cbt) {'not set - never'} else {$cbt}) (0 never, 1 when supported, 2 always)"

    Write-Host "`n== SMB1 and NTLM audit ==" -ForegroundColor Cyan
    $smb = Get-SmbServerConfiguration
    if ($smb.AuditSmb1Access) { Say OK 'SMB1 access audited (SMBServer/Audit 3000)' } else { Say FAIL 'SMB1 access not audited' 'Set-SmbServerConfiguration -AuditSmb1Access $true -Force' }
    if ($smb.EnableSMB1Protocol) { Say WARN 'SMB1 server is ON on this controller' 'Windows Server 2025 has none: what uses it shows on the SMB1 tile' } else { Say OK 'SMB1 server is off' }
    $ntlm = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -ErrorAction SilentlyContinue).AuditNTLMInDomain
    if ($ntlm -eq 7) { Say OK 'Audit NTLM authentication in this domain' 'Enable all (NTLM/Operational 8004)' } else { Say FAIL 'Audit NTLM authentication in this domain' "is '$ntlm', wants 7 (GPO: Network security: Restrict NTLM: Audit NTLM authentication in this domain = Enable all)" }
    $inc = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -ErrorAction SilentlyContinue).AuditReceivingNTLMTraffic
    if ($inc -eq 2) { Say OK 'Audit Incoming NTLM Traffic' 'for all accounts' } else { Say WARN 'Audit Incoming NTLM Traffic' "is '$inc', wants 2 (optional)" }
    $block = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -ErrorAction SilentlyContinue).RestrictNTLMInDomain
    if ($block -and $block -ne 0) { Say WARN 'NTLM is RESTRICTED in this domain (RestrictNTLMInDomain)' "= $block - that blocks, not audits" }

    Write-Host "`n== Log sizes ==" -ForegroundColor Cyan
    foreach ($l in @(@('Security', 1024), @('Directory Service', 256), @('System', 20),
                     @('Microsoft-Windows-SMBServer/Audit', 8), @('Microsoft-Windows-NTLM/Operational', 64))) {
        $log = Get-WinEvent -ListLog $l[0] -ErrorAction SilentlyContinue
        if (-not $log) { Say FAIL $l[0] 'this log is not on this controller'; continue }
        $mb = [int]($log.MaximumSizeInBytes / 1MB)
        if (-not $log.IsEnabled) { Say FAIL $l[0] 'switched off' } elseif ($mb -ge $l[1]) { Say OK $l[0] "$mb MB" } else { Say WARN $l[0] "$mb MB, wants $($l[1]) MB or more: wevtutil sl `"$($l[0])`" /ms:$($l[1] * 1MB)" }
    }

    Write-Host "`n== What each log wrote in the last 7 days ==" -ForegroundColor Cyan
    $since = (Get-Date).AddDays(-7)
    foreach ($q in @(
        @{N='Security 4768 (TGT)';           Log='Security'; Id=4768; Need=$true}
        @{N='Security 4769 (service ticket)'; Log='Security'; Id=4769; Need=$true}
        @{N='Security 4776 (NTLM)';          Log='Security'; Id=4776; Need=$true}
        @{N='Directory Service 2887 (daily)'; Log='Directory Service'; Id=2887; Need=$false}
        @{N='Directory Service 2889 (who)';  Log='Directory Service'; Id=2889; Need=$false}
        @{N='Directory Service 3039-3041';   Log='Directory Service'; Id=3039,3040,3041; Need=$false}
        @{N='System KDC 14/16/26/27';        Log='System'; P='Microsoft-Windows-Kerberos-Key-Distribution-Center'; Id=14,16,26,27; Need=$false}
        @{N='System KDC 201-209 (RC4)';      Log='System'; P='Microsoft-Windows-Kerberos-Key-Distribution-Center'; Id=201,202,203,204,205,206,207,208,209; Need=$false}
        @{N='SMBServer/Audit 3000 (SMB1)';   Log='Microsoft-Windows-SMBServer/Audit'; Id=3000; Need=$false}
        @{N='NTLM/Operational 8004';         Log='Microsoft-Windows-NTLM/Operational'; Id=8004; Need=$false})) {
        # The KDC's own events only: other programs write 14 and 16 into the System log too.
        $f = @{LogName=$q.Log; Id=$q.Id; StartTime=$since}
        if ($q.P) { $f.ProviderName = $q.P }
        $got = (Get-WinEvent -FilterHashtable $f -ErrorAction SilentlyContinue | Measure-Object).Count
        if ($got -gt 0) { Say OK $q.N "$got" } elseif ($q.Need) { Say FAIL $q.N '0 - the audit above that writes it is off' } else { Say INFO $q.N '0 - nothing happened, or its switch above is off' }
    }
    $e = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($e) {
        if ($e.Message -match 'Available Keys') { Say OK '4769 names the keys an account has' 'accounts with no AES keys can be seen' } else { Say WARN '4769 does not name the keys an account has' 'the January 2025 updates (or later) add it' }
    }

    Write-Host "`n== NXLog ==" -ForegroundColor Cyan
    $svc = Get-Service nxlog -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') { Say OK 'nxlog service running' } else { Say FAIL 'nxlog service' "$(if ($svc) {$svc.Status} else {'not installed'})" }
    $conf = 'C:\Program Files\nxlog\conf\nxlog.conf'
    if (Test-Path $conf) {
        $text = Get-Content $conf -Raw
        foreach ($i in 'eventlog_security','eventlog_ds','eventlog_kdc','eventlog_smb1','eventlog_ntlm') {
            $in = $text -match "(?m)^\s*<Input $i>"
            $routed = $text -match "(?m)^\s*Path\s+.*\b$i\b"
            if ($in -and $routed) { Say OK "nxlog.conf: $i" 'an input, and in the Route' } elseif ($in) { Say FAIL "nxlog.conf: $i" 'an input, but not in the Route Path' } else { Say FAIL "nxlog.conf: $i" 'missing' }
        }
        $host_ = ([regex]::Match($text, '(?m)^\s*define\s+SYSLOGHOST\s+(\S+)')).Groups[1].Value
        if ($host_ -and $host_ -ieq $env:COMPUTERNAME) { Say OK 'SYSLOGHOST' "$host_ - this controller's name" } else { Say WARN 'SYSLOGHOST' "'$host_' but this controller is $env:COMPUTERNAME - its logs land in that folder" }
    } else { Say FAIL 'nxlog.conf' "not at $conf" }
    $nlog = 'C:\Program Files\nxlog\data\nxlog.log'
    if (Test-Path $nlog) {
        $errs = Select-String -Path $nlog -Pattern 'ERROR' | Select-Object -Last 5
        if ($errs) { Say WARN 'nxlog.log has errors' 'the last ones:'; $errs | ForEach-Object { Write-Host "      $($_.Line)" -ForegroundColor DarkYellow } } else { Say OK 'nxlog.log has no errors' }
    }
    $dest = '172.29.14.92'
    $tcp = Test-NetConnection $dest -Port 514 -WarningAction SilentlyContinue
    Say INFO "TCP 514 to isemon ($dest)" "$(if ($tcp.TcpTestSucceeded) {'open - the TCP output would work'} else {'closed - stay on UDP, or open it'})"

    Write-Host ("`n{0} OK, {1} to look at" -f $n.ok, $n.bad) -ForegroundColor $(if ($n.bad) {'Yellow'} else {'Green'})
}
```

What a good result looks like:

- everything OK except possibly:
  - *Audit Incoming NTLM Traffic*, which is optional;
  - *SMB1 server is ON*, which is worth knowing but is not a logging problem;
- INFO lines with 0 for Directory Service 3039–3041, the KDC, and SMB1 3000.
  These logs write only when something happens.

### 6.2 All controllers from one machine

Run this on a machine with RSAT. It checks whether every controller has the
key settings, without logging on to each one:

```powershell
Get-ADDomainController -Filter * | ForEach-Object {
    $dc = $_.HostName
    Invoke-Command -ComputerName $dc -ScriptBlock {
        [pscustomobject]@{
            DC          = $env:COMPUTERNAME
            TicketAudit = ((auditpol /get /subcategory:"Kerberos Service Ticket Operations" /r | ConvertFrom-Csv).'Inclusion Setting')
            LdapDiag    = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics').'16 LDAP Interface Events'
            Smb1Audit   = (Get-SmbServerConfiguration).AuditSmb1Access
            NtlmAudit   = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -ErrorAction SilentlyContinue).AuditNTLMInDomain
            NXLog       = (Get-Service nxlog -ErrorAction SilentlyContinue).Status
        }
    }
} | Format-Table DC, TicketAudit, LdapDiag, Smb1Audit, NtlmAudit, NXLog -AutoSize
```

Wanted: `Success and Failure`, `2`, `True`, `7` and `Running` on every row.

### 6.3 In isemon

Open *Domain → Before Windows Server 2025 → The logs and how to send them*.
Within a few minutes:

- *Security log* and *Directory Service log* should be green, each listing
  every controller.
- *Directory Service log* should also show *who did it (2889)*.
- *NTLM/Operational* turns green with the first NTLM through a controller.
- *System log – the KDC* and *SMBServer/Audit* stay grey until there is
  something to say.

---

## 7. Is any of this risky?

**Authentication is not affected.** Every setting in this guide is audit
only: the controller writes down what happens, and allows and refuses
exactly what it did before. Specifically:

- *Audit NTLM authentication in this domain* only writes NTLM/Operational.
  NTLM is blocked by two other policies with almost the same names, which
  must stay *Not Defined* (see 3.2).
- `AuditSmb1Access` only writes SMBServer/Audit. It does not switch SMB1 on.
- `16 LDAP Interface Events = 2` only writes Directory Service 2889/3039.
- LDAP signing and channel binding are **not** enforced by anything here
  (`LDAPServerIntegrity`, `LdapEnforceChannelBinding` are left as they are).
  Enforcing them is what would cut clients off, and the point of all this is
  to see who they are first.

What to keep an eye on:

- **Volume.**
  - *Kerberos Service Ticket Operations* (4769) can be a very large number of
    events on a busy controller. The Security log then turns over quickly, and
    the volume to isemon or to a SIEM grows.
  - The log sizes in section 4 give NXLog time to send everything.
  - If the volume to isemon is too much, this NXLog filter sends only the 4769
    events that matter for the migration (RC4, DES, refusals) and drops the
    ordinary AES tickets on the controller. Put it into `<Input
    eventlog_security>`:

    ```
    Exec  if ($EventID == 4769) and ($TicketEncryptionType == '0x12' or $TicketEncryptionType == '0x11') and ($Status == '0x0') drop();
    ```

  - LDAP level 2 writes one 2889 for every bind in the clear or unsigned. Keep
    it on for the weeks before the change, then set it back to 0 (section 8).
- **Performance.** The extra CPU and disk load is negligible; it matters only
  on a controller that is already very busy.
- **Switching to the advanced audit policy.** The one setting here that can
  change what is audited is *Force audit policy subcategory settings*:
  - If the domain still configures auditing only through the **basic** audit
    policy (*Local Policies → Audit Policy*), only the advanced subcategories
    count once this is on. Anything audited only by the basic policy stops
    being audited, possibly something a SIEM relies on.
  - Compare before and after with the files from section 2:
    `auditpol /get /category:* > C:\temp\audit-after.txt`, then
    `Compare-Object (Get-Content C:\temp\audit-before.txt) (Get-Content C:\temp\audit-after.txt)`.
  - If the advanced policy is already in use, which `gpresult` shows as
    *Advanced Audit Configuration*, nothing changes.
- **Disk.** A 4 GB Security log needs 4 GB on C:. Check with `Get-PSDrive C`
  first.

---

## 8. After the migration: taking it back

Once every controller is Windows Server 2025 and the tiles on isemon's page
have stayed empty for a while:

1. **LDAP diagnostics back to 0**, on each controller (or change the GPP item
   from 3.3 to the value 0):

   ```powershell
   Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -Name '16 LDAP Interface Events' -Value 0
   ```

2. **The GPO from section 3.** Keep it if the audit is to stay. That is
   reasonable: it costs only log volume, and isemon's Domain tab uses the same
   events. To stop:
   - Set the registry-backed values back to their defaults **before**
     unlinking. `Set-GPRegistryValue` values stay on the controller after the
     GPO is gone.

     ```powershell
     $name = 'isemon - DC logging before Windows Server 2025'
     Set-GPRegistryValue -Name $name -Key 'HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -ValueName 'AuditNTLMInDomain' -Type DWord -Value 0 | Out-Null
     Set-GPRegistryValue -Name $name -Key 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -ValueName 'AuditReceivingNTLMTraffic' -Type DWord -Value 0 | Out-Null
     # wait for gpupdate on every controller, then:
     Remove-GPLink -Name $name -Target ('OU=Domain Controllers,' + (Get-ADDomain).DistinguishedName)
     ```

   - Leave `SCENoApplyLegacyAuditPolicy` at 1 if the domain uses the advanced
     audit policy elsewhere. It is the recommended setting anyway.

3. **SMB1 audit:** `Set-SmbServerConfiguration -AuditSmb1Access $false -Force`.
   Or keep it: it writes nothing while nobody uses SMB1. Windows Server 2025
   has no SMB1 server at all.
4. **isemon:** switch *Look for what Windows Server 2025 will refuse* off
   under *Settings → The domain controllers*. What it counted stays for 90
   days, then goes.

---

## 9. Event reference

| Event | Log | Meaning for the migration | isemon tile |
|---|---|---|---|
| 2889 (Binding Type 1) | Directory Service | simple bind on 389 without TLS - **refused by 2025** | LDAP simple bind in the clear |
| 2889 (Binding Type 0) | Directory Service | SASL (NTLM/Kerberos) bind without signing - **refused by 2025** | LDAP bind without signing |
| 2887 | Directory Service | the daily count of the above | The controller's own daily count |
| 3039 | Directory Service | LDAPS bind without a valid channel binding token | LDAP channel binding failed |
| 3040, 3041 | Directory Service | channel binding: daily count / not enforced | The controller's own daily count |
| 4624 with `NTLM V1` | Security | NTLMv1 - **gone in 2025** | NTLMv1 |
| 4624 with logon type 8 | Security | a password handed over as it is (LDAP simple bind, basic auth) | A password handed over as it is |
| 4768, 4769 with type 0x17/0x18 | Security | a Kerberos ticket in RC4 - **from July 2026** only where the account asks for it | Kerberos with RC4 |
| 4768, 4769 with type 0x1/0x3 | Security | DES - **gone** | Kerberos with DES |
| 4768, 4769 `Available Keys` without AES | Security | an account with no AES keys - its tickets fail without RC4 | An account with no AES keys |
| 14, 16, 26, 27 (KDC) | System | the KDC found no suitable key for an account | An account with no AES keys |
| 201–209 (KDC) | System | the KDC's RC4 warnings (KB5073381) | Kerberos with RC4 |
| 3000 | SMBServer/Audit | a client connected over SMB1 - **gone in 2025** | SMB1 to a domain controller |
| 4776 | Security | NTLM through the controller, by workstation | NTLM |
| 8004 | NTLM/Operational | NTLM through the controller, by the server it was for | NTLM |

isemon's page has a fix for every tile, and **Export for analysis** gives all
of it as one file.
