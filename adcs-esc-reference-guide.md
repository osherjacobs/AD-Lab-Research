# ADCS ESC Vulnerabilities - Reference Guide

**Last Updated:** January 2026  
**Source:** Research notes and conceptual groupings

---

## ESC Vulnerabilities by Discovery Order

The Active Directory Certificate Services (ADCS) exploitation techniques were discovered and documented across multiple research efforts:

### Original SpecterOps Research (2021)
**"Certified Pre-Owned" whitepaper introduced:**

1. **ESC1** - Client authentication with SAN impersonation
2. **ESC2** - Any Purpose/Subordinate CA templates
3. **ESC3** - Enrollment agent abuse
4. **ESC4** - Vulnerable ACLs on certificate templates
5. **ESC5** - Vulnerable ACLs on CA/PKI objects
6. **ESC6** - EDITF_ATTRIBUTESUBJECTALTNAME2 flag
7. **ESC7** - Vulnerable CA ACLs (ManageCA/ManageCertificates)
8. **ESC8** - NTLM relay to HTTP enrollment endpoints

### Extended Research (2022+)

**Ly4k discoveries:**
9. **ESC9** - No security extension (CT_FLAG_NO_SECURITY_EXTENSION)
10. **ESC10** - Weak certificate-to-account mappings
11. **ESC11** - IF_ENFORCEENCRYPTICERTREQUEST relay bypass

**Compass Security (2024):**
12. **ESC12** - ADCS on IIS with NTLM authentication
13. **ESC13** - Issuance policy with group linking abuse

---

## Conceptual Grouping

### Template Misconfigurations (Direct Exploitation)
**ESC1, ESC2, ESC9** - Dangerous certificate template settings

**ESC1 - Enrollee Supplies Subject:**
- Template allows subject alternative name (SAN) specification
- Client authentication enabled
- Low-privilege users can enroll
- **Impact:** Impersonate any domain user including DAs

**ESC2 - Any Purpose EKU:**
- Template has "Any Purpose" extended key usage
- Can be used as subordinate CA certificate
- **Impact:** Issue arbitrary certificates, including for authentication

**ESC9 - No Security Extension:**
- Template missing CT_FLAG_NO_SECURITY_EXTENSION
- Allows certificate mapping manipulation
- **Impact:** Authentication bypass via UPN spoofing

---

### Access Control Issues
**ESC4, ESC5, ESC7** - Weak ACLs enabling privilege escalation

**ESC4 - Vulnerable Template ACLs:**
- WriteDacl/WriteOwner permissions on certificate template
- Attacker can modify template to make it vulnerable
- **Impact:** Convert secure template into ESC1/ESC2 exploit

**ESC5 - Vulnerable PKI Object ACLs:**
- WriteDacl/WriteOwner on CA server, Certificate Templates container, etc.
- **Impact:** Modify CA configuration, create vulnerable templates

**ESC7 - Vulnerable CA ACLs:**
- ManageCA or ManageCertificates rights on Certificate Authority
- **Impact:** Approve pending requests, enable vulnerable flags (ESC6)

---

### Certificate Request Manipulation
**ESC3, ESC6** - Exploiting certificate request handling

**ESC3 - Enrollment Agent Abuse:**
- Template with Certificate Request Agent EKU
- Can request certificates on behalf of other users
- **Impact:** Request certificate for any user if enrollment agent template exists

**ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2:**
- CA flag allowing SAN specification in certificate requests
- Works even if template doesn't allow enrollee-supplied subject
- **Impact:** Similar to ESC1 but via CA misconfiguration

---

### Authentication & Certificate Mapping
**ESC10, ESC13, Certificate Mapping** - How certificates authenticate users

**ESC10 - Weak Certificate Mappings:**
- Strong certificate mapping disabled
- Allows authentication with certificates not explicitly mapped
- **Impact:** Certificate from one account authenticates as another

**ESC13 - Issuance Policy Group Linking:**
- Issuance policies linked to AD groups
- Weak access controls on policy objects
- **Impact:** Privilege escalation via policy manipulation

**Certificate Mapping Context:**
- Pre-2022: UPN in certificate → authentication as that user
- Post-KB5014754: Stronger certificate mapping requirements
- ESC9/ESC10 exploit weaknesses in new mapping logic

---

### Network/Relay Attacks
**ESC8, ESC11, ESC12** - NTLM relay to certificate enrollment

**ESC8 - HTTP Enrollment NTLM Relay:**
- Certificate enrollment web interface uses NTLM over HTTP
- No EPA (Extended Protection for Authentication)
- **Impact:** Relay NTLM to enroll certificate as victim

**ESC11 - NTLM Relay with IF_ENFORCEENCRYPTICERTREQUEST:**
- Bypasses the IF_ENFORCEENCRYPTICERTREQUEST flag
- Exploits RPC interface weakness
- **Impact:** Relay despite encryption requirements

**ESC12 - ADCS on IIS NTLM:**
- ADCS web enrollment on IIS with NTLM auth
- Similar to ESC8 but IIS-specific implementation
- **Impact:** Certificate enrollment via relayed credentials

---

## HTB Academy Grouping Logic

HTB's module progression follows pedagogical flow rather than chronology:

1. **Core Template Exploits** (ESC1, ESC2, ESC3)
   - Most common, direct exploitation
   - Foundation for understanding ADCS abuse

2. **Authentication/Mapping Layer** (Certificate Mapping, ESC9, ESC10)
   - How certificates map to accounts
   - Understanding authentication mechanics

3. **Configuration Weaknesses** (ESC6)
   - CA-level flags and settings
   - Broader misconfigurations

4. **Access Control Exploits** (ESC4, ESC7, ESC5)
   - Privilege escalation through permissions
   - Template → CA → broader PKI objects

5. **Network/Relay Attacks** (ESC8, ESC11)
   - NTLM relay techniques
   - Network-based attack vectors

**Rationale:** Attack-path progression for learning. Start with exploitation, understand mechanisms, then escalate through permissions and network attacks.

---

## Microsoft's Certificate Mapping Changes (KB5014754)

### What Microsoft Did

**May 2022:** Released KB5014754 changing how certificates map to user accounts

**Old Behavior:**
- Certificate with UPN → automatically authenticates as that user
- "Weak" certificate mapping (SAN-based only)

**New Behavior:**
- Certificate must be explicitly linked to user account
- Stronger certificate mapping requirements
- SID extension in certificate
- Certificate hash stored in user object

### Why Microsoft Did It

**Problem:** ESC1-style attacks allow arbitrary user impersonation
- Request cert with `administrator@domain.com` in SAN
- Certificate authenticates as Administrator
- No actual link to Administrator account required

**Goal:** Prevent certificate impersonation by requiring explicit account binding

### The Vulnerability (ESC9/ESC10)

**It didn't fully work.**

**ESC9 - No Security Extension:**
- Templates without `CT_FLAG_NO_SECURITY_EXTENSION` 
- Can still bypass strong mapping under certain conditions
- UPN-based mapping still possible

**ESC10 - Weak Mapping Still Enabled:**
- Strong mapping can be disabled at CA level
- `CertificateMappingMethods` registry key configuration
- If weak mapping enabled: old attacks still work

**Bottom line:** The fix is bypassable if:
1. Templates lack proper flags (ESC9)
2. CA doesn't enforce strong mapping (ESC10)
3. Backwards compatibility enabled for legacy systems

---

## ESC Viability Under Modern Defenses

### VBS/Credential Guard Impact: None

**Why ESCs remain viable:**
- ADCS attacks exploit **certificate issuance logic**, not credential storage
- VBS/Credential Guard protect LSASS memory, not PKI trust chains
- Certificate-based authentication bypasses traditional credential theft

### NTLM Deprecation Impact: Minimal

**ESC8/ESC11/ESC12 affected:**
- These rely on NTLM relay to HTTP enrollment
- NTLM deprecation would kill these specific techniques

**ESC1-7, ESC9-10, ESC13 unaffected:**
- Use Kerberos PKINIT authentication
- Certificate enrollment via RPC/DCOM (not NTLM)
- Authentication happens via Kerberos after cert issuance

**Net result:** 10+ of 13 ESCs remain viable even with NTLM disabled

---

## Detection & Mitigation

### Detection Events

**Event 4887** - Certificate Services issued a certificate
- Monitor for Subject/SAN mismatches (ESC1 indicator)
- Track enrollment by low-privilege accounts
- Alert on privileged account impersonation

**Event 4768** - Kerberos TGT request (PKINIT)
- Certificate-based authentication attempts
- Unusual certificate auth for accounts

**Event 4769** - Kerberos service ticket request
- Post-authentication activity from cert-based sessions

### Mitigation Strategies

**Template Hardening:**
- Remove Enrollee Supplies Subject where not needed
- Restrict enrollment permissions to specific groups
- Require manager approval for sensitive templates
- Enable `CT_FLAG_NO_SECURITY_EXTENSION` on all templates

**CA Configuration:**
- Disable EDITF_ATTRIBUTESUBJECTALTNAME2 flag
- Enable strong certificate mapping
- Restrict ManageCA/ManageCertificates permissions
- Disable HTTP enrollment or enable EPA

**Monitoring:**
- SIEM rules for Event 4887 anomalies
- Alert on certificate enrollment spikes
- Monitor template/CA permission changes
- Track certificate-based authentication patterns

**Access Control:**
- Audit template and CA ACLs regularly
- Restrict WriteDacl/WriteOwner permissions
- Implement least privilege for PKI administrators
- Monitor Certificate Templates container modifications

---

## Learning Resources

### Primary Research
- **Certified Pre-Owned** (SpecterOps, 2021) - Original ESC1-8 research
- **Certipy** (ly4k) - ESC9-11 discoveries and exploitation tool
- **ADCS Exploit Primitives** (Compass Security, 2024) - ESC12-13

### Tools
- **Certipy** - ADCS enumeration and exploitation
- **Certify** - .NET tool for ADCS abuse
- **ForgeCert** - Certificate forging after compromise
- **ADCSTemplate** - PowerShell template manipulation

### HTB Academy
- ADCS module progression: ESC1 → ESC2 → ESC3 → Mapping → ESC9/10 → ESC6 → ESC4/7/5 → ESC8/11
- Hands-on labs for each exploitation scenario
- Detection and defense sections

---

## Key Takeaways

1. **ESC techniques target PKI trust infrastructure** - fundamentally different from credential theft
2. **Modern security controls (VBS, NTLM deprecation) don't mitigate most ESCs** - they operate at different layers
3. **Microsoft's certificate mapping fixes are bypassable** - ESC9/ESC10 exploit implementation weaknesses
4. **ADCS remains a critical attack surface** - especially as traditional techniques get harder
5. **Detection requires specific ADCS monitoring** - standard EDR/AV won't catch these attacks

---

## The "Mint" Analogy

Think of ADCS as a **mint that produces identity tokens**:

- **ESC1-3:** Tricking the mint into printing tokens with wrong names (template flaws)
- **ESC4-7:** Breaking into the mint's security office to change the printing rules (ACL abuse)
- **ESC6:** Finding a backdoor where the mint accepts custom token requests (CA flag)
- **ESC8-12:** Intercepting delivery trucks to steal token printing authority (relay attacks)
- **ESC9-10:** Exploiting how tokens get matched to real people (mapping weaknesses)

The mint (PKI infrastructure) issues tokens (certificates) that the kingdom (domain) trusts. Compromise the mint, you can forge any identity.

---

**Tags:** #ADCS #ActiveDirectory #PKI #ESC1 #CertificateAbuse #Kerberos #PKINIT #SecurityResearch

