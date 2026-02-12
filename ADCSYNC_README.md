# ADCSync (Execution Corrections & Bug Fixes)

## Attribution
**Original Author:** JPG0mez  
**Original Repository:** https://github.com/JPG0mez/ADCSync  

All credit for the original tool design belongs to the author.  
This version strictly corrects implementation defects discovered during controlled lab testing. No functional changes were made to the underlying attack technique.

**Execution Corrections:** Osher Jacobs (with debugging assistance from Claude/Anthropic AI)  
**Date:** February 2026


## Purpose

This repository documents execution corrections applied to ADCSync after identifying multiple implementation bugs during ADCS ESC1 lab research. These fixes address three critical issues that prevented reliable operation with current versions of Certipy.

The objective of this work is research-oriented: improving tool reliability to better study attack telemetry, detection opportunities, and enterprise control visibility.


## What is ADCSync?

ADCSync is a Python wrapper around Certipy that automates ESC1 (Active Directory Certificate Services abuse) at scale by:

1. Parsing a BloodHound JSON file containing domain users  
2. Requesting certificates via a vulnerable ESC1 template  
3. Authenticating with certificates using PKINIT  
4. Extracting NT hashes from Kerberos authentication  
5. Outputting hashes in hashcat/john-compatible format  

**Concept:** *DCSync via ADCS certificates.*


## Bugs Corrected

### Bug 1 — Hash Parsing (Lines 110–126)

**Problem:**  
The original implementation assumed the NT hash would appear on the final line of Certipy output using a simple `: ` delimiter:

```python
# Original (broken)
output_lines = stdout.strip().split('\n')
nt_hash = output_lines[-1].split(': ')[1]
```

**Actual Certipy Output:**
```
Got hash for 'administrator@lab.local': aad3b435b51404eeaad3b435b51404ee:3c02b6b6fb6b3b17242dc33a31bc011f
```

**Correction:**
```python
hash_line = [line for line in output_lines if 'Got hash for' in line]
if not hash_line:
    print(f"Warning: Could not extract hash for {username}, skipping")
    continue

full_hash = hash_line[0].split(': ')[1]  # LM:NT
nt_hash = full_hash.split(':')[1]        # NT only
```


### Bug 2 — Domain Lookup Logic (Lines 67, 73, 106–114)

**Problem:**  
The script reused the loop variable `domain`, resulting in invalid dictionary lookups.

```python
# Original (broken)
domain = name.split('@')[-1]
domain = usernames_with_domains.get(f'{username}@{domain}')  # Incorrect key
```

**Correction:**
```python
# Store using full UPN as the key
usernames_with_domains[name] = domain

# Lookup with full UPN
domain = usernames_with_domains.get(name)

# Reconstruct full UPN when required
full_name = None
for name in names:
    if name.split('@')[0].lower() == username:
        full_name = name
        break

domain = usernames_with_domains.get(full_name)
```


### Bug 3 — Error Handling

**Problem:**  
The script terminated on first failure, preventing batch processing.

**Correction:**  
Added structured error handling:

- Warns if hash extraction fails and continues  
- Warns if domain lookup fails and skips that user  
- Completes processing even when individual requests fail  


## Usage

```bash
python3 adcsync_fixed.py \
  -u lowpriv@lab.local \
  -p Password123! \
  -ca LAB-CA \
  -template ESC1-Vulnerable \
  -target-ip 192.168.1.10 \
  -dc-ip 192.168.1.10 \
  -f bloodhound_users.json \
  -o ntlm_hashes.txt
```

**Requirements:**
- Certipy (`pip install certipy-ad`)
- Python 3.x
- tqdm, pyfiglet, click, ldap3

**Input:** BloodHound JSON export of domain users  
**Output:** `DOMAIN/username::NT_HASH:::`


## Research Context

These defects were identified while:

1. Building an ADCS ESC1 lab for detection research  
2. Testing offensive tooling to understand attack behavior  
3. Analyzing Windows Event ID 4887 for certificate abuse detection  


## Detection Insight

Even when functioning correctly, ADCSync generates highly visible signals in Event ID 4887:

- Low-privilege users requesting certificates for privileged principals  
- High request volume within short time windows  
- Subject/SAN mismatches (e.g., `CN=lowpriv`, `SAN=administrator@domain`)  

A properly instrumented SOC should detect this behavior quickly.


## Responsible Use

**Intended for:**

- Authorized penetration testing  
- Security research in isolated lab environments  
- Understanding ADCS attack paths for defensive engineering  
- Developing detection logic and SIEM rules  

**Not intended for:**

- Unauthorized system access  
- Malicious activity  
- Testing against production environments without explicit authorization  


## License

This project inherits the license of the original ADCSync repository. Refer to the upstream project for details.


## Detection Recommendations

If you are defending against ESC1-style abuse:

- Monitor Event ID 4887 for subject/SAN mismatches  
- Alert when non-privileged users request certificates for privileged accounts  
- Track certificate request frequency per identity  
- Implement Sigma or equivalent detection rules for ADCS abuse patterns  


## Contributing

If you identify additional defects or improvements:

1. Validate findings in a controlled lab  
2. Document the issue and correction clearly  
3. Consider submitting a PR to the original repository  
4. Share any detection insights derived from testing  


## Acknowledgments

- **JPG0mez** — Original ADCSync tool and concept  
- **Claude (Anthropic)** — Debugging assistance and code analysis  
- **Will Schroeder & Lee Christensen** — ESC research (Certified Pre-Owned)  
- **Oliver Lyak** — Certipy development



---

**Key Takeaway:** Understanding why tools fail — and how their behavior appears in telemetry — is more valuable than simply executing them. The primary lesson is detection, not exploitation.
