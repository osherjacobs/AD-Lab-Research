# Quick Sysmon Setup for Domain Controller Monitoring

A minimal guide to get Sysmon running on a Windows Domain Controller with SwiftOnSecurity's proven config.

## Prerequisites

- Windows Server (Domain Controller)
- Administrator access
- Internet connection (for downloads)

## Step 1: Download Sysmon

Download Sysmon from Microsoft Sysinternals:

```powershell
# Download Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"

# Extract
Expand-Archive -Path "$env:TEMP\Sysmon.zip" -DestinationPath "$env:TEMP\Sysmon" -Force
```

**Manual alternative:** Download from https://docs.microsoft.com/sysinternals/downloads/sysmon

## Step 2: Download SwiftOnSecurity Config

```powershell
# Download SwiftOnSecurity's config
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "$env:TEMP\sysmonconfig.xml"
```

**Manual alternative:** Download from https://github.com/SwiftOnSecurity/sysmon-config

## Step 3: Install Sysmon

```powershell
# Navigate to Sysmon directory
cd "$env:TEMP\Sysmon"

# Install with config (use 64-bit version for modern DCs)
.\Sysmon64.exe -accepteula -i "$env:TEMP\sysmonconfig.xml"
```

**You should see:**
```
Sysmon64 v15.x - System Monitor
Copyright (C) 2014-2024 Mark Russinovich and Thomas Garnier
Sysinternals - www.sysinternals.com

Sysmon64 installed.
SysmonDrv installed.
Starting SysmonDrv.
Starting Sysmon64..
Installation complete.
```

## Step 4: Verify Installation

```powershell
# Check service is running
Get-Service Sysmon64

# Check event log exists
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

## Step 5: Update Config (Optional)

To update Sysmon with a new config later:

```powershell
.\Sysmon64.exe -c new-config.xml
```

## What You're Now Monitoring

SwiftOnSecurity's config tracks:
- **Process creation** (Event ID 1) - what's executing
- **Network connections** (Event ID 3) - C2 beaconing, lateral movement
- **File creation** (Event ID 11) - malware drops, tool staging
- **Registry modifications** (Event ID 12/13) - persistence mechanisms
- **Image loads** (Event ID 7) - DLL injection, reflective loading
- **DNS queries** (Event ID 22) - C2 domains
- **Pipe events** (Event ID 17/18) - named pipe abuse (common in AD attacks)

## View Logs

**Event Viewer:**
```
Applications and Services Logs > Microsoft > Windows > Sysmon > Operational
```

**PowerShell:**
```powershell
# Recent process creation events
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=1} -MaxEvents 10 | Format-List

# Network connections
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=3} -MaxEvents 10 | Format-List
```

## Critical Events for ADCS/AD Security

Focus on these for detecting ADCS abuse and AD attacks:

- **Event ID 1** (Process Creation): Look for `certipy`, `certutil`, `Rubeus`, suspicious PowerShell
- **Event ID 3** (Network Connection): Connections to CA on port 445 (SMB relay), LDAP enumeration
- **Event ID 11** (File Create): `.pfx` files, certificate drops in unusual locations
- **Event ID 17/18** (Pipe Events): Named pipe abuse for Kerberos relay

## Forwarding to SIEM (Optional)

If you have a SIEM or log collector:

**Windows Event Forwarding:**
```powershell
# Enable WinRM
winrm quickconfig

# Configure subscription on collector (not covered here)
```

**For Splunk/ELK/etc:** Configure forwarder to collect from `Microsoft-Windows-Sysmon/Operational`

## Performance Considerations

Sysmon adds ~5-10% CPU overhead on a busy DC. SwiftOnSecurity's config is optimized to reduce noise while maintaining visibility.

**If performance is critical:**
- Disable DNS logging (Event ID 22) - very noisy
- Reduce network connection logging scope
- Use `sysmonconfig-export-reduced.xml` variant

## Uninstall (if needed)

```powershell
.\Sysmon64.exe -u
```

## Next Steps

1. **Test detection** - run `whoami`, `net user`, check logs
2. **Baseline normal activity** - identify legitimate admin tools
3. **Build alerts** - focus on anomalies (unusual process trees, rare network connections)
4. **Integrate with detection** - forward to SIEM or use Sigma rules

## Resources

- **Sysmon Documentation:** https://docs.microsoft.com/sysinternals/downloads/sysmon
- **SwiftOnSecurity Config:** https://github.com/SwiftOnSecurity/sysmon-config
- **Event ID Reference:** https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/
- **Sigma Rules for Sysmon:** https://github.com/SigmaHQ/sigma/tree/master/rules/windows/sysmon

---

**Pro tip:** Combine Sysmon with Windows Event ID 4887 (ADCS certificate requests) for comprehensive ADCS attack detection.
