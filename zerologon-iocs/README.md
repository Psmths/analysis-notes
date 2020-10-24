# Zerologon IOC Analysis

[MS CVE Page](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1472)

[Whitepaper](https://www.secura.com/pathtoimg.php?id=2055)

Test was run from a domain-joined Windows 10 host (W10-01, 10.100.0.10), targeting a Windows Server 2012 Domain Controller (DC-01, 10.100.0.2). Exploit was executed via Mimikatz module using commands:

```
lsadump::Zerologon /target:dc-01 /account:dc-01$ /null /ntlm /exploit
```

## Security Event Log Artifacts

Event ID 4742 with Subject > Security ID as ANONYMOUS, Subject > Account Name as ANONYMOUS, domain as NT AUTHORITY. Computer Account That Was Changed > Account Name should be the domain controller computer account (i.e DC-01$).

## Network Traffic Artifacts

Large amount of NetrServerReqChallenge and NetrServerAuthenticate2 request/response pairs, followed by one NetrServerPasswordSet2 request/response.
