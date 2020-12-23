Sunburst Cracked
-----------------

[Sunburst](https://en.wikipedia.org/wiki/2020_United_States_federal_government_data_breach) is the trojaned version of SolarWinds Orion that contains a malicious backdoor in a class named `OrionImprovementBusinessLayer`. 

The following repository contains a modified version of this decompiled class with the following modifications:

 - Deobfuscated Strings 
 - Inline comments with the cracked values per each FNV-1a hash
 - Additional inline comments

An examples of inline comments:

```csharp
private static readonly ulong[] assemblyTimeStamps = new ulong[]
{
    2597124982561782591UL	/* apimonitor-x64 (Rohitab - RE/Malware analysis) */,
    2600364143812063535UL	/* apimonitor-x86 (Rohitab - RE/Malware analysis) */,
    13464308873961738403UL	/* autopsy64 (Autopsy - Forensics) */,
    4821863173800309721UL	/* autopsy (Autopsy - Forensics) */,
    ...
    ...
```

The decompiled class was extracted from the following sample: `ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6`

## Acknowledgements
The analysis and comments in the modified class are based on work conducted by the community and I. Specifically, I want to refer and thank to these works:
- The entire community who worked on cracking these hashes - The cracked hashes can be found on [FireEye's repository](https://github.com/fireeye/sunburst_countermeasures/blob/main/fnv1a_xor_hashes.txt)
- The Hashcat team and Royce Williams for their [detailed work](https://docs.google.com/spreadsheets/d/1u0_Df5OMsdzZcTkBDiaAtObbIOkMa5xbeXdKk_k0vWs/edit?usp=sharing) on these hashes
