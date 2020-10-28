# PsExec IOC Analysis

[Sysinternals Page](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec)

PsExec is a sysinternals utility that allows for the execution of commands on a remote endpoint without requiring additional software on that endpoint. It also allows for the execution to occur as another user. It functions by installing a service embedded in its binary on the remote endpoint and using DCE/RPC to trigger it. While it is a legitimate program, it is often a key indicator of lateral movement by threat actors.

Test was run from a domain-joined Windows 10 host (W10-01, 10.100.0.10), targeting a Windows Server 2012 Domain Controller (DC-01, 10.100.0.2). Remote binary executed was powershell.exe.

```
	PsExec64.exe  \\dc-01 -accepteula -u HOMELAB\Administrator -p "Password!" powershell.exe
```

## System Event Log Artifacts - Target Endpoint

Event ID 7045 - Service installed

* Service Name: PSEXESVC
* Service File Name:  %SystemRoot%\PSEXESVC.exe
* Service Type:  user mode service
* Service Start Type:  demand start
* Service Account:  LocalSystem

Event ID 7036 - The PSEXESVC service entered the running state.

[Raw Artifacts](psexec_dc01_system.evtx)

## Sysmon Event Log Artifacts - Target Endpoint

Event ID 11 - File Create

* TargetFilename: C:\Windows\PSEXESVC.exe

Event ID 13 - Registry Value Set  (2x)

1. TargetObject: HKLM\System\CurrentControlSet\Services\PSEXESVC\Start
2. TargetObject: HKLM\System\CurrentControlSet\Services\PSEXESVC\ImagePath

Event ID 1 - Process Created

* Image: C:\Windows\PSEXESVC.exe
* Description: PsExec Service
* Hashes: IMPHASH=09D5553D2AA2F39BDE811B88883DE7D5

*There will be additional Event ID 1 artifacts for whatever program was spawned by psexec afterwards.*

[Raw Artifacts](psexec_dc01_sysmon.evtx)
