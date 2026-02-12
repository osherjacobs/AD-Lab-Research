# ADCSync - Fixed Version

## Attribution

**Original Author:** JPG0mez  
**Original Repository:** https://github.com/JPG0mez/ADCSync  
**Bug Fixes:** Osher Jacobs (with debugging assistance from Claude/Anthropic AI)  
**Date:** February 2026

## Purpose

This is a corrected version of ADCSync created during ADCS ESC1 lab testing and security research. The fixes address three critical bugs that prevented the tool from functioning with current versions of Certipy.

## What is ADCSync?

ADCSync is a Python wrapper around Certipy that automates ESC1 (ADCS certificate abuse) exploitation at scale:

1. Takes a BloodHound JSON file containing domain users
2. Requests certificates for each user via a vulnerable ESC1 template
3. Authenticates with each certificate using PKINIT
4. Extracts NT hashes from the Kerberos authentication
5. Outputs hashes in hashcat/john compatible format

**Concept:** "DCSync but via ADCS certificates"

## Bugs Fixed

### Bug 1: Hash Parsing (Lines 110-126)

**Problem:**  
Original code assumed the NT hash would be on the last line of certipy's output with a simple `: ` separator:

```python
# Original (broken)
output_lines = stdout.strip().split('\n')
nt_hash = output_lines[-1].split(': ')[1]
```

**Reality:**  
Certipy actually outputs:
```
Got hash for 'administrator@lab.local': aad3b435b51404eeaad3b435b51404ee:3c02b6b6fb6b3b17242dc33a31bc011f
```

**Fix:**
```python
# Fixed version
hash_line = [line for line in output_lines if 'Got hash for' in line]
if not hash_line:
    print(f"Warning: Could not extract hash for {username}, skipping")
    continue

full_hash = hash_line[0].split(': ')[1]  # Gets "LM:NT"
nt_hash = full_hash.split(':')[1]  # Gets just NT portion
```

### Bug 2: Domain Lookup (Lines 67, 73, 106-114)

**Problem:**  
Original code reused the loop variable `domain` incorrectly and performed dictionary lookups with wrong keys:

```python
# Original (broken)
domain = name.split('@')[-1]
# ... later ...
domain = usernames_with_domains.get(f'{username}@{domain}')  # Wrong!
```

**Fix:**
```python
# Line 67 - Store with full UPN as key
usernames_with_domains[name] = domain

# Line 73 - Lookup with full UPN
domain = usernames_with_domains.get(name)

# Lines 106-114 - Reconstruct full UPN to get domain
full_name = None
for name in names:
    if name.split('@')[0].lower() == username:
        full_name = name
        break

domain = usernames_with_domains.get(full_name)
```

### Bug 3: Error Handling

**Problem:**  
Zero error handling - script would crash on first failure instead of processing remaining users.

**Fix:**  
Added proper error checking:
- Warns if hash extraction fails and continues
- Warns if domain lookup fails and skips that user
- Script completes processing all users even if some fail

## Usage

```bash
# Same as original
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
**Output:** File with format: `DOMAIN/username::NT_HASH:::`

## Educational Context

These fixes were discovered while:
1. Setting up an ADCS ESC1 lab for detection research
2. Testing offensive tools to understand attack patterns
3. Analyzing Windows Event 4887 for certificate abuse detection

**Detection Lesson:**  
Even when ADCSync works perfectly, it generates extremely obvious signatures in Event 4887:
- Low-privilege user requesting certificates for Domain Admins
- Multiple certificate requests in short timeframe
- Subject/SAN mismatch (CN=lowpriv, SAN=administrator@domain)

Any competent SOC should detect this immediately.

## Responsible Use

**This tool is for:**
- ✅ Authorized penetration testing
- ✅ Security research in isolated lab environments
- ✅ Understanding ADCS attack chains for defense
- ✅ Developing detection logic and SIEM rules

**This tool is NOT for:**
- ❌ Unauthorized access to systems
- ❌ Malicious activity
- ❌ Production environments without explicit authorization

## License

Inherits license from original ADCSync repository (check original for details).

## Detection Resources

If you're defending against ESC1 attacks:
- Monitor Event ID 4887 for subject/SAN mismatches
- Alert on privileged users being requested by non-privileged accounts
- Track certificate request volume per user
- Implement Sigma rules for ADCS abuse patterns

## Contributing

If you find additional bugs or improvements:
1. Test in your lab environment
2. Document the issue and fix clearly
3. Consider submitting a PR to the original repository
4. Share detection lessons from your testing

## Acknowledgments

- **JPG0mez** - Original ADCSync tool and concept
- **Claude (Anthropic)** - Debugging assistance and code analysis
- **Will Schroeder & Lee Christensen** - ESC1 research (Certified Pre-Owned)
- **Oliver Lyak** - Certipy tool development

---

**Remember:** Understanding why tools break is more valuable than just running them. The real lesson here is about detection, not exploitation.
