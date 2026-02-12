# ADCS Abuse - ESC4: The Attack That Requires Reading the Fine Print

Just completed an ESC4 module and discovered why certificate authentication kept failing despite "successful" template modification.

## The Issue

The version of Certipy (v5.0.4+) I'm using removed automated template modification which the module relied on for completion. So there I was stuck with no flag / administrator's hash...

You must manually edit JSON configs - but documentation doesn't tell you explicitly about the hidden second field.

## The Gotcha

Two separate AD attributes control certificate EKUs:

- **pKIExtendedKeyUsage** (what tools display)
- **msPKI-Certificate-Application-Policy** (what the CA actually uses)

Miss the second one? Your cert gets issued without Client Authentication EKU. Authentication fails. Template looks correct in AD. Time wasted.

## The Fix

```json
"msPKI-Certificate-Application-Policy": [
  "1.3.6.1.4.1.311.10.3.4",
  "1.3.6.1.5.5.7.3.4",
  "1.3.6.1.5.5.7.3.2"  // Don't forget this - Client Authentication
]
```

Plus restart CA services - template changes are cached. Or wait 5-10 mins.

## Verification

Check the actual cert, not the template:

```bash
openssl pkcs12 -in cert.pfx -nokeys -clcerts | \
  openssl x509 -noout -text | grep -A 5 "Extended Key Usage"
```

## ESC4 vs ESC1

**ESC1** = template already broken, exploit directly  
**ESC4** = use Full Control permissions to break it first, then exploit

## Real-World Lesson

Tool output ≠ ground truth. When auth fails, inspect the artifact.

<img width="800" height="374" alt="image" src="https://github.com/user-attachments/assets/6b04fb1c-4fb7-4ed8-8c43-996f0cf6d32e" />


---

**Tags:** #ActiveDirectory #CertificateServices #ADCS #PenetrationTesting #InfoSec
