# PSHiveNightmare

**PSHiveNightmare**
CVE-2021–36934. Exploit allowing you to read any registry hives as non-admin.

**What is this?**
An zero day exploit for HiveNightmare, which allows you to retrieve all registry hives in Windows 10 as a non-administrator user. For example, this includes hashes in SAM, which can be used to execute code as SYSTEM.

**Why PS this?**
The HiveNightmware was easily detected by AV tool and can't inject into memory, PS does. 

老外那个不改改，落地就被杀了，绕绕虽然容易，但不如注入内存运行方便。

**Authors**
Code by wolf@0x

**Scope**
Works on all supported versions of Windows 10, where System Protection is enabled (should be enabled by default in most configurations).

**How does this work?**
The permissions on key registry hives are set to allow all non-admin users to read the files by default, in most Windows 10 configurations. This is an error.

**What does the exploit do?**
Allows you to read SAM data (sensitive) in Windows 10, as well as the SYSTEM and SECURITY hives.

This exploit uses VSC to extract the SAM, SYSTEM, and SECURITY hives even when in use, and saves them in current directory as HIVENAME, for use with whatever cracking tools, or whatever, you want.

![image](https://user-images.githubusercontent.com/15625431/127021995-b396742e-087d-4ff6-9067-2c614dbceaab.png)


**Pulling Credentials out**
python3 secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL

![image](https://user-images.githubusercontent.com/15625431/127021883-2730c098-17a9-4405-9fca-76801d5e7314.png)

