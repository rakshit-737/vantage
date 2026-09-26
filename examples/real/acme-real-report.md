# VANTAGE audit report: Acme Corp (synthetic, real catalog)

> Generated from a declared posture file. Treat as SENSITIVE: this document is a map of blind spots.

## Summary

- Techniques in scope: 697
- Claimed (paper) coverage: **53.9%**
- True (defended) coverage: **17.6%**
- Paper-only techniques: 253  |  Blind: 291  |  Detected without control: 30
- Deployed-but-dead detections (log source not ingested): 2132
- Zero-Trust posture score: **53.2/100**

## Compliant but undetectable

| Technique | Name | Claimed by | Why undetectable |
| --- | --- | --- | --- |
| T1001 | Data Obfuscation | CIS-13.3 | no detection deployed |
| T1001.001 | Data Obfuscation: Junk Data | CIS-13.3 | no detection deployed |
| T1001.002 | Data Obfuscation: Steganography | CIS-13.3 | no detection deployed |
| T1003.007 | OS Credential Dumping: Proc Filesystem | CIS-3.3, CIS-4.7, CIS-5.2, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2 | no detection deployed |
| T1003.008 | OS Credential Dumping: /etc/passwd and /etc/shadow | CIS-3.3, CIS-4.7, CIS-5.2, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2 | no detection deployed |
| T1008 | Fallback Channels | CIS-13.3 | 4 rule(s) deployed but dead (117d3d3a-755c-4a61-b23e-9171146d094c, 396ae3eb-4174-4b9b-880e-dc0364d78a19, 8c31f563-f9a7-450c-bfa8-35f8f32f1f61 (+1 more)); missing log source: windows/file_event, windows/registry_set |
| T1011 | Exfiltration Over Other Network Medium | CIS-18.3, CIS-4.1 | no detection deployed |
| T1011.001 | Exfiltration Over Other Network Medium: Exfiltration Over Bluetooth | CIS-18.3, CIS-2.3, CIS-2.5, CIS-4.1, CIS-4.8 | no detection deployed |
| T1020.001 | Automated Exfiltration: Traffic Duplication | CIS-3.10, CIS-4.2, CIS-4.6 | no detection deployed |
| T1021 | Remote Services | CIS-4.7, CIS-5.3, CIS-6.1, CIS-6.2, CIS-6.4, CIS-6.5 | 9 rule(s) deployed but dead (22777c9e-873a-4b49-855f-6072ab861a52, 6991bc2b-ae2e-447f-bc55-3a1ba04c14e5, 730fc21b-eaff-474b-ad23-90fd265d4988 (+6 more)); missing log source: opencanary/application, windows/process_creation |
| T1021.004 | Remote Services: SSH | CIS-16.10, CIS-18.3, CIS-2.3, CIS-2.5, CIS-4.1, CIS-4.7, CIS-4.8, CIS-5.3, CIS-6.1, CIS-6.2, CIS-6.4, CIS-6.5, CIS-7.6 | 4 rule(s) deployed but dead (16ab6143-510a-44e2-a615-bdb80b8317fc, 327f48c1-a6db-4eb8-875a-f6981f1b0183, 3ce8e9a4-bc61-4c9b-8e69-d7e2492a8781 (+1 more)); missing log source: bitbucket/audit, windows/openssh, windows/process_creation |
| T1021.005 | Remote Services: VNC | CIS-13.4, CIS-18.2, CIS-18.3, CIS-2.1, CIS-2.2, CIS-2.3, CIS-2.4, CIS-2.5, CIS-4.2, CIS-4.4, CIS-4.5, CIS-4.8, CIS-7.6, CIS-7.7 | 1 rule(s) deployed but dead (871b9555-69ca-4993-99d3-35a59f9f3599); missing log source: windows/process_creation |
| T1021.006 | Remote Services: Windows Remote Management | CIS-12.2, CIS-18.3, CIS-2.3, CIS-2.5, CIS-3.12, CIS-4.1, CIS-4.4, CIS-4.5, CIS-4.7, CIS-4.8, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2, CIS-7.6, CIS-7.7 | 8 rule(s) deployed but dead (734f8d9b-42b8-41b2-bcf5-abaf49d5a3c8, 7b836d7f-179c-4ba4-90a7-a7e60afb48e6, 96b9f619-aa91-478f-bacb-c3e50f8df575 (+5 more)); missing log source: windows/network_connection, windows/process_access, windows/process_creation, windows/ps_module, windows/ps_script, zeek/http |
| T1027.002 | Obfuscated Files or Information: Software Packing | CIS-10.1, CIS-10.2, CIS-10.7, CIS-13.2 | no detection deployed |
| T1029 | Scheduled Transfer | CIS-13.3 | no detection deployed |
| T1030 | Data Transfer Size Limits | CIS-13.3 | no detection deployed |
| T1036.001 | Masquerading: Invalid Code Signature | CIS-4.1 | no detection deployed |
| T1036.003 | Masquerading: Rename Legitimate Utilities | CIS-3.3, CIS-4.1, CIS-6.1, CIS-6.2 | 22 rule(s) deployed but dead (0718cd72-f316-4aa2-988f-838ea8533277, 0b0cd537-fc77-4e6e-a973-e53495c1083d, 0ba1da6d-b6ce-4366-828c-18826c9de23e (+19 more)); missing log source: linux/auditd, windows/file_event, windows/process_creation, windows/ps_script, windows/registry_set |
| T1037 | Boot or Logon Initialization Scripts | CIS-3.3, CIS-4.1, CIS-5.4, CIS-6.1, CIS-6.2 | no detection deployed |
| T1037.001 | Boot or Logon Initialization Scripts: Logon Script (Windows) | CIS-4.1 | 3 rule(s) deployed but dead (0a98a10c-685d-4ab0-bddc-b6bdd1d48458, 21d856f9-9281-4ded-9377-51a1a6e2a432, 9ace0707-b560-49b8-b6ca-5148b42f39fb); missing log source: windows/process_creation, windows/registry_set |
| T1037.002 | Boot or Logon Initialization Scripts: Login Hook | CIS-3.3, CIS-4.1, CIS-5.4, CIS-6.1, CIS-6.2 | no detection deployed |
| T1037.003 | Boot or Logon Initialization Scripts: Network Logon Script | CIS-3.3, CIS-4.1, CIS-5.4, CIS-6.1, CIS-6.2 | no detection deployed |
| T1037.004 | Boot or Logon Initialization Scripts: RC Scripts | CIS-3.3, CIS-4.1, CIS-5.4, CIS-6.1, CIS-6.2 | no detection deployed |
| T1037.005 | Boot or Logon Initialization Scripts: Startup Items | CIS-3.3, CIS-4.1, CIS-6.1, CIS-6.2 | no detection deployed |
| T1041 | Exfiltration Over C2 Channel | CIS-13.3 | 3 rule(s) deployed but dead (07837ab9-60e1-481f-a74d-c31fb496a94c, 881834a4-6659-4773-821e-1c151789d873, b4e6b016-a2ac-4759-ad85-8000b300d61e); missing log source: firewall, opencanary/application, windows/network_connection |
| T1046 | Network Service Discovery | CIS-12.2, CIS-13.3, CIS-16.10, CIS-16.8, CIS-18.2, CIS-18.3, CIS-3.12, CIS-4.4, CIS-4.8, CIS-7.6, CIS-7.7 | 11 rule(s) deployed but dead (4fd6b1c7-19b8-4488-97f6-00f0924991a3, 54773c5f-f1cc-4703-9126-2f797d96a69d, 851fd622-b675-4d26-b803-14bc7baa517a (+8 more)); missing log source: linux/process_creation, windows/file_event, windows/network_connection, windows/process_creation, windows/ps_script |
| T1048.001 | Exfiltration Over Alternative Protocol: Exfiltration Over Symmetric Encrypted Non-C2 Protocol | CIS-12.2, CIS-13.3, CIS-13.4, CIS-4.2, CIS-4.4, CIS-7.6, CIS-7.7, CIS-9.2 | 1 rule(s) deployed but dead (98a96a5a-64a0-4c42-92c5-489da3866cb0); missing log source: windows/process_creation |
| T1048.002 | Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | CIS-12.2, CIS-13.3, CIS-13.4, CIS-4.2, CIS-4.4, CIS-7.6, CIS-7.7, CIS-9.2 | no detection deployed |
| T1048.003 | Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol | CIS-12.2, CIS-13.3, CIS-13.4, CIS-4.2, CIS-4.4, CIS-7.6, CIS-7.7, CIS-9.2 | 6 rule(s) deployed but dead (2dbd9d3d-9e27-42a8-b8df-f13825c6c3d5, 4153a907-2451-4e4f-a578-c52bb6881432, 4c4af3cd-2115-479c-8193-6b8bfce9001c (+3 more)); missing log source: dns, linux/auditd, windows/network_connection, windows/process_creation, windows/ps_script |
| T1052 | Exfiltration Over Physical Medium | CIS-10.3, CIS-18.3, CIS-2.3, CIS-2.5, CIS-4.1 | no detection deployed |
| T1052.001 | Exfiltration Over Physical Medium: Exfiltration over USB | CIS-10.3, CIS-18.3, CIS-2.3, CIS-2.5, CIS-4.1 | no detection deployed |
| T1053.006 | Scheduled Task/Job: Systemd Timers | CIS-3.3, CIS-4.1, CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2 | no detection deployed |
| T1055 | Process Injection | CIS-13.2, CIS-4.1, CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2 | 29 rule(s) deployed but dead (02d1d718-dd13-41af-989d-ea85c7fab93f, 0e7163d4-9e19-4fa7-9be6-000c61aad77a, 0fa66f66-e3f6-4a9c-93f8-4f2610b00171 (+26 more)); missing log source: antivirus, windows/create_remote_thread, windows/file_event, windows/image_load, windows/network_connection, windows/pipe_created, windows/process_access, windows/process_creation, windows/ps_script |
| T1055.001 | Process Injection: Dynamic-link Library Injection | CIS-13.2, CIS-4.1 | 7 rule(s) deployed but dead (148431ce-4b70-403d-8525-fcc2993f29ea, 340a090b-c4e9-412e-bb36-b4b16fe96f9b, 4f73421b-5a0b-4bbf-a892-5a7fb99bea66 (+4 more)); missing log source: windows/create_remote_thread, windows/process_creation |
| T1055.002 | Process Injection: Portable Executable Injection | CIS-13.2, CIS-4.1 | no detection deployed |
| T1055.003 | Process Injection: Thread Execution Hijacking | CIS-13.2, CIS-4.1 | 2 rule(s) deployed but dead (7bdde3bf-2a42-4c39-aa31-a92b3e17afac, a1a144b7-5c9b-4853-a559-2172be8d4a03); missing log source: windows/create_remote_thread, windows/process_access |
| T1055.004 | Process Injection: Asynchronous Procedure Call | CIS-13.2, CIS-4.1 | no detection deployed |
| T1055.005 | Process Injection: Thread Local Storage | CIS-13.2, CIS-4.1 | no detection deployed |
| T1055.008 | Process Injection: Ptrace System Calls | CIS-13.2, CIS-4.1, CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2 | no detection deployed |
| T1055.009 | Process Injection: Proc Memory | CIS-13.2, CIS-3.3, CIS-4.1, CIS-6.1, CIS-6.2 | 1 rule(s) deployed but dead (4cad6c64-d6df-42d6-8dae-eb78defdc415); missing log source: linux/process_creation |
| T1055.011 | Process Injection: Extra Window Memory Injection | CIS-13.2, CIS-4.1 | no detection deployed |
| T1055.012 | Process Injection: Process Hollowing | CIS-13.2, CIS-4.1 | 3 rule(s) deployed but dead (2e4e488a-6164-4811-9ea1-f960c7359c40, c4b890e5-8d8c-4496-8c66-c805753817cd, d8937fe7-42d5-4b4d-8178-e089c908f63f); missing log source: windows/create_remote_thread, windows/process_creation, windows/process_tampering |
| T1055.013 | Process Injection: Process Doppelgänging | CIS-13.2, CIS-4.1 | no detection deployed |
| T1055.014 | Process Injection: VDSO Hijacking | CIS-13.2, CIS-4.1 | no detection deployed |
| T1056.002 | Input Capture: GUI Input Capture | CIS-14.1, CIS-14.2, CIS-14.6 | 2 rule(s) deployed but dead (9ae01559-cf7e-4f8e-8e14-4c290a1b4784, c9192ad9-75e5-43eb-8647-82a0a5b493e3); missing log source: windows/image_load, windows/process_creation |
| T1056.003 | Input Capture: Web Portal Capture | CIS-12.2, CIS-4.1, CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2 | no detection deployed |
| T1059.002 | Command and Scripting Interpreter: AppleScript | CIS-2.5, CIS-4.1 | 7 rule(s) deployed but dead (1bc2e6c5-0885-472b-bed6-be5ea8eace55, 69483748-1525-4a6c-95ca-90dc8d431b68, 6e4dcdd1-e48b-42f7-b2d8-3b413fc58cb4 (+4 more)); missing log source: macos/process_creation |
| T1059.005 | Command and Scripting Interpreter: Visual Basic | CIS-10.1, CIS-10.2, CIS-10.7, CIS-13.2, CIS-16.10, CIS-18.3, CIS-2.3, CIS-2.5, CIS-4.1, CIS-4.8, CIS-9.3, CIS-9.6 | 21 rule(s) deployed but dead (002bdb95-0cf1-46a6-9e08-d38c128a6127, 05c36dd6-79d6-4a9a-97da-3db20298ab2d, 07aa184a-870d-413d-893a-157f317f6f58 (+18 more)); missing log source: windows/applocker, windows/create_remote_thread, windows/file_event, windows/process_creation, windows/wmi_event |
| T1059.006 | Command and Scripting Interpreter: Python | CIS-10.1, CIS-10.2, CIS-10.7, CIS-13.2, CIS-18.3, CIS-2.1, CIS-2.2, CIS-2.3, CIS-2.4, CIS-2.5, CIS-4.1 | 5 rule(s) deployed but dead (1f32d820-1d5c-43fe-8fe2-feef0c952eb7, 401e5d00-b944-11ea-8f9a-00163ecd60ae, 5660d8db-6e25-411f-b92f-094420168a5d (+2 more)); missing log source: windows/applocker, windows/process_creation |
| T1059.007 | Command and Scripting Interpreter: JavaScript | CIS-16.10, CIS-18.3, CIS-2.3, CIS-2.5, CIS-4.1, CIS-4.8, CIS-9.3, CIS-9.6 | 18 rule(s) deployed but dead (002bdb95-0cf1-46a6-9e08-d38c128a6127, 05c36dd6-79d6-4a9a-97da-3db20298ab2d, 0bcfabcb-7929-47f4-93d6-b33fb67d34d1 (+15 more)); missing log source: macos/process_creation, windows/applocker, windows/create_remote_thread, windows/file_event, windows/process_creation |
| T1059.008 | Command and Scripting Interpreter: Network Device CLI | CIS-12.2, CIS-12.5, CIS-4.1, CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2 | no detection deployed |
| T1070.003 | Indicator Removal: Clear Command History | CIS-3.3, CIS-4.1, CIS-5.4, CIS-6.1, CIS-6.2 | 7 rule(s) deployed but dead (26b692dc-1722-49b2-b496-a8258aa6371d, 602f5669-6927-4688-84db-0d4b7afb2150, 70ad982f-67c8-40e0-a955-b920c2fa05cb (+4 more)); missing log source: cisco/aaa, linux, windows/ps_module, windows/ps_script |
| T1071 | Application Layer Protocol | CIS-13.3 | 7 rule(s) deployed but dead (03552375-cc2c-4883-bbe4-7958d5a980be, 0ea52357-cd59-4340-9981-c46c7e900428, 3db10f25-2527-4b79-8d4b-471eb900ee29 (+4 more)); missing log source: macos/process_creation, windows/dns-server-analytic, windows/image_load, windows/process_creation |
| T1071.002 | Application Layer Protocol: File Transfer Protocols | CIS-13.3 | no detection deployed |
| T1071.003 | Application Layer Protocol: Mail Protocols | CIS-13.3 | no detection deployed |
| T1078.001 | Valid Accounts: Default Accounts | CIS-4.7, CIS-5.2 | 1 rule(s) deployed but dead (821bcf4d-46c7-4b87-bc57-9509d3ba7c11); missing log source: macos/process_creation |
| T1078.003 | Valid Accounts: Local Accounts | CIS-4.1, CIS-4.7, CIS-5.1, CIS-5.2, CIS-5.3, CIS-5.4, CIS-5.5, CIS-6.1, CIS-6.2 | 4 rule(s) deployed but dead (5d0fdb62-f225-42fb-8402-3dfe64da468a, 652c098d-dc11-4ba6-8566-c20e89042f2b, 821bcf4d-46c7-4b87-bc57-9509d3ba7c11 (+1 more)); missing log source: macos/process_creation |
| T1080 | Taint Shared Content | CIS-10.5, CIS-2.5, CIS-3.3, CIS-4.1, CIS-6.1, CIS-6.2 | no detection deployed |
| T1087.001 | Account Discovery: Local Account | CIS-18.3, CIS-4.1, CIS-4.8 | 8 rule(s) deployed but dead (02030f2f-6199-49ec-b258-ea71b07e03dc, 02773bed-83bf-469f-b7ff-e676e7d78bab, 7d0d0329-0ef1-4e84-a9f5-49500f9d7c6c (+5 more)); missing log source: windows/file_event, windows/process_creation, windows/ps_module, windows/ps_script |
| T1090.003 | Proxy: Multi-hop Proxy | CIS-13.4, CIS-4.2, CIS-4.4, CIS-9.3 | 3 rule(s) deployed but dead (62f7c9bf-9135-49b2-8aeb-1e54a6ecc13c, 8384bd26-bde6-4da9-8e5d-4174a7a47ca2, b55ca2a3-7cff-4dda-8bdd-c7bfa63bf544); missing log source: windows/dns-client, windows/dns_query, windows/process_creation |
| T1091 | Replication Through Removable Media | CIS-10.3, CIS-18.3, CIS-2.3, CIS-2.5, CIS-4.1, CIS-7.7 | no detection deployed |
| T1092 | Communication Through Removable Media | CIS-10.3, CIS-18.3, CIS-2.3, CIS-2.5, CIS-4.1, CIS-4.8 | no detection deployed |
| T1095 | Non-Application Layer Protocol | CIS-12.2, CIS-13.3, CIS-13.4, CIS-18.2, CIS-18.3, CIS-4.2, CIS-4.4, CIS-4.5, CIS-7.6, CIS-7.7 | 3 rule(s) deployed but dead (c5b20776-639a-49bf-94c7-84f912b91c15, e31033fc-33f0-4020-9a16-faf9b31cbf08, ede05abc-2c9e-4624-9944-9ff17fdc0bf5); missing log source: windows/process_creation, windows/ps_classic_start, zeek/dns |
| T1098.002 | Account Manipulation: Additional Email Delegate Permissions | CIS-3.3, CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2, CIS-6.3, CIS-6.4, CIS-6.5 | no detection deployed |
| T1098.004 | Account Manipulation: SSH Authorized Keys | CIS-16.10, CIS-18.3, CIS-2.3, CIS-2.5, CIS-3.3, CIS-4.1, CIS-4.8, CIS-5.4, CIS-6.1, CIS-6.2, CIS-7.6 | no detection deployed |
| T1102 | Web Service | CIS-13.3, CIS-2.3, CIS-2.5, CIS-9.3 | 11 rule(s) deployed but dead (18249279-932f-45e2-b37a-8925f2597670, 19bf6fdb-7721-4f3d-867f-53467f6a5db6, 1d08ac94-400d-4469-a82f-daee9a908849 (+8 more)); missing log source: linux/network_connection, windows/network_connection, windows/process_creation |
| T1104 | Multi-Stage Channels | CIS-13.3 | no detection deployed |
| T1106 | Native API | CIS-2.5 | 12 rule(s) deployed but dead (03d83090-8cba-44a0-b02f-0b756a050306, 09706624-b7f6-455d-9d02-adee024cee1d, 3f3f3506-1895-401b-9cc3-e86b16e630d0 (+9 more)); missing log source: linux/auditd, windows/pipe_created, windows/process_access, windows/process_creation, windows/ps_script |
| T1110.001 | Brute Force: Password Guessing | CIS-4.1, CIS-4.10, CIS-4.7, CIS-5.2, CIS-6.3, CIS-6.4, CIS-6.5 | 2 rule(s) deployed but dead (71886b70-d7b4-4dbf-acce-87d2ca135262, aaafa146-074c-11eb-adc1-0242ac120002); missing log source: windows/process_creation, windows/smbclient-security |
| T1110.002 | Brute Force: Password Cracking | CIS-4.7, CIS-5.2, CIS-6.3, CIS-6.4, CIS-6.5 | 1 rule(s) deployed but dead (39b31e81-5f5f-4898-9c0e-2160cfc0f9bf); missing log source: windows/process_creation |
| T1110.003 | Brute Force: Password Spraying | CIS-4.1, CIS-4.10, CIS-4.7, CIS-5.2, CIS-6.3, CIS-6.4, CIS-6.5 | no detection deployed |
| T1110.004 | Brute Force: Credential Stuffing | CIS-4.1, CIS-4.10, CIS-4.7, CIS-5.2, CIS-5.3, CIS-6.3, CIS-6.4, CIS-6.5 | no detection deployed |
| T1111 | Multi-Factor Authentication Interception | CIS-14.1, CIS-14.3 | no detection deployed |
| T1114.001 | Email Collection: Local Email Collection | CIS-3.10 | 1 rule(s) deployed but dead (2837e152-93c8-43d2-85ba-c3cd3c2ae614); missing log source: windows/ps_script |
| T1114.002 | Email Collection: Remote Email Collection | CIS-3.10, CIS-6.3, CIS-6.4, CIS-6.5 | no detection deployed |
| T1119 | Automated Collection | CIS-11.4, CIS-3.11 | 4 rule(s) deployed but dead (a9723fcc-881c-424c-8709-fd61442ab3c3, aa2efee7-34dd-446e-8a37-40790a66efd7, c1dda054-d638-4c16-afc8-53e007f3fbc5 (+1 more)); missing log source: windows/process_creation, windows/ps_script |
| T1127 | Trusted Developer Utilities Proxy Execution | CIS-16.10, CIS-18.3, CIS-2.3, CIS-2.5, CIS-4.1, CIS-4.8 | 17 rule(s) deployed but dead (0152550d-3a26-4efd-9f0e-54a0b28ae2f3, 18749301-f1c5-4efc-a4c3-276ff1f5b6f8, 3d48c9d3-1aa6-418d-98d3-8fd3c01a564e (+14 more)); missing log source: windows/create_remote_thread, windows/process_creation |
| T1127.001 | Trusted Developer Utilities Proxy Execution: MSBuild | CIS-18.3, CIS-2.3, CIS-2.5, CIS-4.1, CIS-4.8 | 1 rule(s) deployed but dead (50e54b8d-ad73-43f8-96a1-5191685b17a4); missing log source: windows/network_connection |
| T1129 | Shared Modules | CIS-2.5, CIS-2.6 | no detection deployed |
| T1132 | Data Encoding | CIS-13.3 | no detection deployed |
| T1132.001 | Data Encoding: Standard Encoding | CIS-13.3 | 4 rule(s) deployed but dead (98767d61-b2e8-4d71-b661-e36783ee24c1, 98a96a5a-64a0-4c42-92c5-489da3866cb0, d75d6b6b-adb9-48f7-824b-ac2e786efe1f (+1 more)); missing log source: windows/process_creation, windows/ps_script |
| T1132.002 | Data Encoding: Non-Standard Encoding | CIS-13.3 | no detection deployed |
| T1134.003 | Access Token Manipulation: Make and Impersonate Token | CIS-4.1, CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2 | 3 rule(s) deployed but dead (c7d33b50-f690-4b51-8cfb-0fb912a31e57, cf0c254b-22f1-4b2b-8221-e137b3c0af94, f89b08d0-77ad-4728-817b-9b16c5a69c7a); missing log source: windows/process_creation |
| T1135 | Network Share Discovery | CIS-18.3, CIS-4.1 | 6 rule(s) deployed but dead (54773c5f-f1cc-4703-9126-2f797d96a69d, b2317cfa-4a47-4ead-b3ff-297438c0bc2d, bef37fa2-f205-4a7b-b484-0759bfd5f86f (+3 more)); missing log source: windows/process_creation |
| T1136 | Create Account | CIS-11.3, CIS-11.4, CIS-12.2, CIS-18.3, CIS-3.12, CIS-4.1, CIS-4.2, CIS-4.4, CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2, CIS-6.3, CIS-6.4, CIS-6.5 | 1 rule(s) deployed but dead (b28e4eb3-8bbc-4f0c-819f-edfe8e2f25db); missing log source: linux/process_creation |
| T1137 | Office Application Startup | CIS-18.3, CIS-2.3, CIS-4.1, CIS-4.8, CIS-7.1, CIS-7.2, CIS-7.3, CIS-7.4, CIS-7.5, CIS-7.7, CIS-9.4 | 8 rule(s) deployed but dead (0e20c89d-2264-44ae-8238-aeeaba609ece, 117d3d3a-755c-4a61-b23e-9171146d094c, 396ae3eb-4174-4b9b-880e-dc0364d78a19 (+5 more)); missing log source: windows/file_event, windows/registry_set |
| T1137.001 | Office Application Startup: Office Template Macros | CIS-18.3, CIS-2.3, CIS-4.1, CIS-4.8, CIS-9.4 | no detection deployed |
| T1137.002 | Office Application Startup: Office Test | CIS-18.3, CIS-4.1 | 2 rule(s) deployed but dead (3d27f6dd-1c74-4687-b4fa-ca849d128d1c, 69483748-1525-4a6c-95ca-90dc8d431b68); missing log source: macos/process_creation, windows/registry_event |
| T1137.003 | Office Application Startup: Outlook Forms | CIS-18.3, CIS-7.1, CIS-7.2, CIS-7.3, CIS-7.4, CIS-7.5 | 1 rule(s) deployed but dead (c3edc6a5-d9d4-48d8-930e-aab518390917); missing log source: windows/file_event |
| T1137.004 | Office Application Startup: Outlook Home Page | CIS-18.3, CIS-7.1, CIS-7.2, CIS-7.3, CIS-7.4, CIS-7.5 | no detection deployed |
| T1137.005 | Office Application Startup: Outlook Rules | CIS-18.3, CIS-7.1, CIS-7.2, CIS-7.3, CIS-7.4, CIS-7.5 | no detection deployed |
| T1176 | Software Extensions | CIS-14.4, CIS-18.3, CIS-2.3, CIS-2.5, CIS-4.1, CIS-9.4 | 1 rule(s) deployed but dead (0a74c5a9-1b71-4475-9af2-7829d320d5c2); missing log source: windows/process_creation |
| T1185 | Browser Session Hijacking | CIS-14.4, CIS-3.3, CIS-4.7, CIS-5.3, CIS-6.1, CIS-6.2 | 2 rule(s) deployed but dead (3e8207c5-fcd2-4ea6-9418-15d45b4890e4, b3d34dc5-2efd-4ae3-845f-8ec14921f449); missing log source: windows/process_creation |
| T1195 | Supply Chain Compromise | CIS-16.1, CIS-16.11, CIS-16.2, CIS-16.3, CIS-16.4, CIS-16.5, CIS-18.3, CIS-7.1, CIS-7.2, CIS-7.3, CIS-7.4, CIS-7.5 | 1 rule(s) deployed but dead (805c55d9-31e6-4846-9878-c34c75054fe9); missing log source: windows/file_event |
| T1195.001 | Supply Chain Compromise: Compromise Software Dependencies and Development Tools | CIS-16.1, CIS-16.11, CIS-16.2, CIS-16.3, CIS-16.4, CIS-16.5, CIS-18.3, CIS-7.1, CIS-7.2, CIS-7.3, CIS-7.4, CIS-7.5 | 2 rule(s) deployed but dead (34e1c7d4-0cd5-419d-9f1b-1dad3f61018d, 805c55d9-31e6-4846-9878-c34c75054fe9); missing log source: github/audit, windows/file_event |
| T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | CIS-16.1, CIS-16.11, CIS-16.2, CIS-16.3, CIS-16.4, CIS-16.5, CIS-18.3, CIS-7.1, CIS-7.2, CIS-7.3, CIS-7.4, CIS-7.5 | no detection deployed |
| T1195.003 | Supply Chain Compromise: Compromise Hardware Supply Chain | CIS-3.6, CIS-4.1 | no detection deployed |
| T1204 | User Execution | CIS-13.3, CIS-14.1, CIS-14.2, CIS-14.6, CIS-2.3, CIS-2.5, CIS-9.3, CIS-9.6 | 8 rule(s) deployed but dead (1412aa78-a24c-4abd-83df-767dfb2c5bbe, 234dc5df-40b5-49d1-bf53-0d44ce778eca, 24de4f3b-804c-4165-b442-5a06a2302c7e (+5 more)); missing log source: antivirus, macos/process_creation, windows/process_creation, windows/registry_event |
| T1204.001 | User Execution: Malicious Link | CIS-13.3, CIS-14.1, CIS-14.2, CIS-14.6, CIS-2.3, CIS-2.5, CIS-9.3, CIS-9.6 | 2 rule(s) deployed but dead (6e4dcdd1-e48b-42f7-b2d8-3b413fc58cb4, c67fc22a-0be5-4b4f-aad5-2b32c4b69523); missing log source: linux, macos/process_creation |
| T1205 | Traffic Signaling | CIS-13.4, CIS-4.2, CIS-4.4, CIS-7.7 | no detection deployed |
| T1205.001 | Traffic Signaling: Port Knocking | CIS-13.4, CIS-4.2, CIS-4.4 | no detection deployed |
| T1213 | Data from Information Repositories | CIS-14.1, CIS-14.4, CIS-14.5, CIS-16.1, CIS-16.9, CIS-18.3, CIS-3.1, CIS-3.2, CIS-3.3, CIS-4.7, CIS-5.3, CIS-6.1, CIS-6.2 | 7 rule(s) deployed but dead (3ec9a16d-0b4f-4967-9542-ebf38ceac7dd, 4fe17521-aef3-4e6a-9d6b-4a7c8de155a8, 5259cbf2-0a75-48bf-b57a-c54d6fabaef3 (+4 more)); missing log source: bitbucket/audit, opencanary/application |
| T1213.001 | Data from Information Repositories: Confluence | CIS-14.1, CIS-14.4, CIS-14.5, CIS-16.1, CIS-16.9, CIS-18.3, CIS-3.1, CIS-3.2, CIS-3.3, CIS-4.7, CIS-5.3, CIS-6.1, CIS-6.2 | no detection deployed |
| T1213.002 | Data from Information Repositories: Sharepoint | CIS-14.1, CIS-14.4, CIS-14.5, CIS-16.1, CIS-16.9, CIS-18.3, CIS-3.1, CIS-3.2, CIS-3.3, CIS-4.7, CIS-5.3, CIS-6.1, CIS-6.2 | no detection deployed |
| T1218.001 | System Binary Proxy Execution: Compiled HTML File | CIS-2.3, CIS-2.5, CIS-9.3, CIS-9.6 | 4 rule(s) deployed but dead (52cad028-0ff0-4854-8f67-d25dfcbc78b4, 84b1706c-932a-44c4-ae28-892b28a25b94, e8a95b5e-c891-46e2-b33a-93937d3abc31 (+1 more)); missing log source: windows/process_creation |
| T1218.002 | System Binary Proxy Execution: Control Panel | CIS-2.5, CIS-4.1, CIS-6.1, CIS-6.2 | 1 rule(s) deployed but dead (0ba863e6-def5-4e50-9cea-4dd8c7dc46a4); missing log source: windows/process_creation |
| T1218.003 | System Binary Proxy Execution: CMSTP | CIS-18.3, CIS-2.3, CIS-2.5, CIS-4.1, CIS-4.8 | 7 rule(s) deployed but dead (3b4b232a-af90-427c-a22f-30b0c0837b95, 4b60e6f2-bf39-47b4-b4ea-398e33cfe253, 75e508f7-932d-4ebc-af77-269237a84ce1 (+4 more)); missing log source: windows/image_load, windows/network_connection, windows/process_access, windows/process_creation, windows/registry_event |
| T1218.004 | System Binary Proxy Execution: InstallUtil | CIS-18.3, CIS-2.3, CIS-2.5, CIS-4.1, CIS-4.8 | no detection deployed |
| T1218.005 | System Binary Proxy Execution: Mshta | CIS-18.3, CIS-2.3, CIS-2.5, CIS-4.1, CIS-4.8 | 8 rule(s) deployed but dead (03cc0c25-389f-4bf8-b48d-11878079f1ca, 2b30fa36-3a18-402f-a22d-bf4ce2189f35, 2e4e488a-6164-4811-9ea1-f960c7359c40 (+5 more)); missing log source: windows/create_remote_thread, windows/process_creation |
| T1218.008 | System Binary Proxy Execution: Odbcconf | CIS-18.3, CIS-2.3, CIS-2.5, CIS-4.1, CIS-4.8 | 8 rule(s) deployed but dead (2d32dd6f-3196-4093-b9eb-1ad8ab088ca5, 3f5491e2-8db8-496b-9e95-1029fce852d4, 5f03babb-12db-4eec-8c82-7b4cb5580868 (+5 more)); missing log source: windows/process_creation |
| T1218.009 | System Binary Proxy Execution: Regsvcs/Regasm | CIS-18.3, CIS-2.3, CIS-2.5, CIS-4.1, CIS-4.8 | 3 rule(s) deployed but dead (0531e43a-d77d-47c2-b89f-5fe50321c805, cc368ed0-2411-45dc-a222-510ace303cb2, e9f8f8cc-07cc-4e81-b724-f387db9175e4); missing log source: windows/network_connection, windows/process_creation |
| T1218.010 | System Binary Proxy Execution: Regsvr32 | CIS-10.5 | 19 rule(s) deployed but dead (089fc3d2-71e8-4763-a8a5-c97fbb0a403e, 10152a7b-b566-438f-a33c-390b607d1c8d, 2dd2c217-bf68-437a-b57c-fe9fd01d5de8 (+16 more)); missing log source: windows/dns_query, windows/image_load, windows/network_connection, windows/process_creation |
| T1218.011 | System Binary Proxy Execution: Rundll32 | CIS-10.5 | 42 rule(s) deployed but dead (0ea52357-cd59-4340-9981-c46c7e900428, 15bd98ea-55f4-4d37-b09a-e7caa0fa2221, 285b85b1-a555-4095-8652-a8a4106af63f (+39 more)); missing log source: windows/create_remote_thread, windows/file_event, windows/image_load, windows/network_connection, windows/process_creation, windows/registry_set |
| T1218.012 | System Binary Proxy Execution: Verclsid | CIS-13.4, CIS-18.2, CIS-18.3, CIS-2.3, CIS-2.5, CIS-4.1, CIS-4.2, CIS-4.4, CIS-4.5, CIS-4.8, CIS-7.6, CIS-7.7 | no detection deployed |
| T1219 | Remote Access Tools | CIS-13.3, CIS-13.4, CIS-18.2, CIS-18.3, CIS-2.5, CIS-4.2, CIS-4.4, CIS-7.6, CIS-9.3 | 2 rule(s) deployed but dead (2cf29f11-e356-4f61-98c0-1bdb9393d6da, 90d6bd71-dffb-4989-8d86-a827fedd6624); missing log source: windows/process_creation |
| T1220 | XSL Script Processing | CIS-2.5 | 5 rule(s) deployed but dead (05c36dd6-79d6-4a9a-97da-3db20298ab2d, 06ce37c2-61ab-4f05-9ff5-b1a96d18ae32, 75d0a94e-6252-448d-a7be-d953dff527bb (+2 more)); missing log source: windows/image_load, windows/process_creation |
| T1222 | File and Directory Permissions Modification | CIS-3.3, CIS-4.1, CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2 | 1 rule(s) deployed but dead (3bf1d859-3a7e-44cb-8809-a99e066d3478); missing log source: windows/ps_script |
| T1222.002 | File and Directory Permissions Modification: Linux and Mac Permissions | CIS-3.3, CIS-4.1, CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2 | 3 rule(s) deployed but dead (34979410-e4b5-4e5d-8cfb-389fdff05c12, 6419afd1-3742-47a5-a7e6-b50386cd15f8, a5b977d6-8a81-4475-91b9-49dbfcd941f7); missing log source: linux/auditd, linux/process_creation |
| T1482 | Domain Trust Discovery | CIS-11.3, CIS-11.4, CIS-12.2, CIS-18.3, CIS-3.12, CIS-4.1, CIS-4.4 | 14 rule(s) deployed but dead (02030f2f-6199-49ec-b258-ea71b07e03dc, 02773bed-83bf-469f-b7ff-e676e7d78bab, 31d68132-4038-47c7-8f8e-635a39a7c174 (+11 more)); missing log source: windows/file_event, windows/ldap, windows/process_creation, windows/ps_module, windows/ps_script |
| T1491 | Defacement | CIS-11.1, CIS-11.2, CIS-11.3, CIS-11.4, CIS-11.5 | no detection deployed |
| T1491.001 | Defacement: Internal Defacement | CIS-11.1, CIS-11.2, CIS-11.3, CIS-11.4, CIS-11.5 | 3 rule(s) deployed but dead (85b88e05-dadc-430b-8a9e-53ff1cd30aae, 8b9606c9-28be-4a38-b146-0e313cc232c1, 8cbc9475-8d05-4e27-9c32-df960716c701); missing log source: windows/process_creation, windows/registry_set |
| T1491.002 | Defacement: External Defacement | CIS-11.1, CIS-11.2, CIS-11.3, CIS-11.4, CIS-11.5 | no detection deployed |
| T1495 | Firmware Corruption | CIS-18.3, CIS-4.1, CIS-4.7, CIS-5.3, CIS-5.4, CIS-7.1, CIS-7.2, CIS-7.3, CIS-7.5 | 1 rule(s) deployed but dead (d94a35f0-7a29-45f6-90a0-80df6159967c); missing log source: cisco/aaa |
| T1498 | Network Denial of Service | CIS-7.6 | 2 rule(s) deployed but dead (7cded4b3-f09e-405a-b96f-24248433ba44, 999e8307-a775-4d5f-addc-4855632335be); missing log source: opencanary/application, windows/process_creation |
| T1498.001 | Network Denial of Service: Direct Network Flood | CIS-7.6, CIS-7.7 | no detection deployed |
| T1498.002 | Network Denial of Service: Reflection Amplification | CIS-7.6, CIS-7.7 | no detection deployed |
| T1499 | Endpoint Denial of Service | CIS-4.2, CIS-7.6, CIS-7.7 | no detection deployed |
| T1499.002 | Endpoint Denial of Service: Service Exhaustion Flood | CIS-4.2, CIS-7.6, CIS-7.7 | no detection deployed |
| T1499.003 | Endpoint Denial of Service: Application Exhaustion Flood | CIS-4.2, CIS-7.6, CIS-7.7 | no detection deployed |
| T1505 | Server Software Component | CIS-18.3, CIS-4.1, CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2 | 1 rule(s) deployed but dead (671ffc77-50a7-464f-9e3d-9ea2b493b26b); missing log source: cisco/aaa |
| T1505.001 | Server Software Component: SQL Stored Procedures | CIS-18.3, CIS-4.1, CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2 | 2 rule(s) deployed but dead (9cae055f-e1d2-4f81-b8a5-1986a68cdd84, d84c0ded-edd7-4123-80ed-348bb3ccc4d5); missing log source: database, windows/file_event |
| T1505.002 | Server Software Component: Transport Agent | CIS-18.3, CIS-4.1, CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2 | 3 rule(s) deployed but dead (4fe151c2-ecf9-4fae-95ae-b88ec9c2fca6, 83809e84-4475-4b69-bc3e-4aad8568612f, c7d16cae-aaf3-42e5-9c1c-fb8553faa6fa); missing log source: windows/msexchange-management, windows/process_creation |
| T1530 | Data from Cloud Storage | CIS-11.3, CIS-13.4, CIS-18.2, CIS-18.3, CIS-3.11, CIS-3.3, CIS-4.1, CIS-4.2, CIS-4.4, CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2, CIS-6.3, CIS-6.4, CIS-6.5 | no detection deployed |
| T1535 | Unused/Unsupported Cloud Regions | CIS-18.3, CIS-4.1 | no detection deployed |
| T1538 | Cloud Service Dashboard | CIS-3.3, CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2 | no detection deployed |
| T1539 | Steal Web Session Cookie | CIS-14.1, CIS-14.2, CIS-14.3, CIS-14.6, CIS-18.3, CIS-4.1, CIS-6.3 | 2 rule(s) deployed but dead (24c77512-782b-448a-8950-eddb0785fc71, 4833155a-4053-4c9c-a997-777fcea0baa7); missing log source: windows/process_creation |
| T1542 | Pre-OS Boot | CIS-18.3, CIS-3.6, CIS-4.1, CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2, CIS-7.1, CIS-7.2, CIS-7.3, CIS-7.5 | no detection deployed |
| T1542.001 | Pre-OS Boot: System Firmware | CIS-18.3, CIS-4.1, CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2, CIS-7.1, CIS-7.2, CIS-7.3, CIS-7.5 | 2 rule(s) deployed but dead (4abc0ec4-db5a-412f-9632-26659cddf145, e94b9ddc-eec5-4bb8-8a58-b9dc5f4e185f); missing log source: windows/file_event, windows/process_creation |
| T1542.003 | Pre-OS Boot: Bootkit | CIS-3.6, CIS-4.1, CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2 | 1 rule(s) deployed but dead (c9fbe8e9-119d-40a6-9b59-dd58a5d84429); missing log source: windows/process_creation |
| T1542.004 | Pre-OS Boot: ROMMONkit | CIS-13.3, CIS-18.3, CIS-4.1 | no detection deployed |
| T1542.005 | Pre-OS Boot: TFTP Boot | CIS-12.2, CIS-12.5, CIS-13.3, CIS-18.3, CIS-4.1, CIS-4.2, CIS-4.7, CIS-4.8, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2, CIS-8.1, CIS-8.2, CIS-8.3 | no detection deployed |
| T1543.001 | Create or Modify System Process: Launch Agent | CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2 | 2 rule(s) deployed but dead (65d506d3-fcfe-4071-b4b2-bcefe721bbbb, ae9d710f-dcd1-4f75-a0a5-93a73b5dda0e); missing log source: macos/process_creation |
| T1543.002 | Create or Modify System Process: Systemd Service | CIS-2.3, CIS-2.5, CIS-3.3, CIS-4.1, CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2 | 1 rule(s) deployed but dead (1bac86ba-41aa-4f62-9d6b-405eac99b485); missing log source: linux/auditd |
| T1543.004 | Create or Modify System Process: Launch Daemon | CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2 | 2 rule(s) deployed but dead (65d506d3-fcfe-4071-b4b2-bcefe721bbbb, ae9d710f-dcd1-4f75-a0a5-93a73b5dda0e); missing log source: macos/process_creation |
| T1546.002 | Event Triggered Execution: Screensaver | CIS-18.3, CIS-2.3, CIS-2.5, CIS-4.1, CIS-4.8 | 4 rule(s) deployed but dead (0fc35fc3-efe6-4898-8a37-0b233339524f, 4aafb0fa-bff5-4b9d-b99e-8093e659c65f, 67a6c006-3fbe-46a7-9074-2ba3b82c3000 (+1 more)); missing log source: windows/file_event, windows/process_creation, windows/registry_event |
| T1546.004 | Event Triggered Execution: Unix Shell Configuration Modification | CIS-3.3, CIS-4.1, CIS-5.4, CIS-6.1, CIS-6.2 | 1 rule(s) deployed but dead (a94cdd87-6c54-4678-a6cc-2814ffe5a13d); missing log source: linux/auditd |
| T1546.006 | Event Triggered Execution: LC_LOAD_DYLIB Addition | CIS-18.3, CIS-2.5, CIS-2.6, CIS-4.1 | no detection deployed |
| T1546.008 | Event Triggered Execution: Accessibility Features | CIS-12.2, CIS-12.7, CIS-13.5, CIS-18.3, CIS-2.5, CIS-4.1, CIS-4.2 | 6 rule(s) deployed but dead (1070db9a-3e5d-412e-8e7b-7183b616e1b3, 2fdefcb3-dbda-401e-ae23-f0db027628bc, ae215552-081e-44c7-805f-be16f975c8a2 (+3 more)); missing log source: windows/process_creation, windows/registry_event |
| T1546.009 | Event Triggered Execution: AppCert DLLs | CIS-2.6 | 2 rule(s) deployed but dead (046218bd-e0d8-4113-a3c3-895a12b2b298, 6aa1d992-5925-4e9f-a49b-845e51d1de01); missing log source: windows/registry_event, windows/registry_set |
| T1546.010 | Event Triggered Execution: AppInit DLLs | CIS-18.3, CIS-2.6, CIS-7.1, CIS-7.2, CIS-7.3, CIS-7.5 | 1 rule(s) deployed but dead (4f84b697-c9ed-4420-8ab5-e09af5b2345d); missing log source: windows/registry_event |
| T1546.011 | Event Triggered Execution: Application Shimming | CIS-18.3, CIS-4.1, CIS-7.1, CIS-7.2, CIS-7.3, CIS-7.5 | 6 rule(s) deployed but dead (18ee686c-38a3-4f65-9f44-48a077141f42, 517490a7-115a-48c6-8862-1a481504d5a8, 6b6976a3-b0e6-4723-ac24-ae38a737af41 (+3 more)); missing log source: windows/process_creation, windows/registry_set |
| T1546.013 | Event Triggered Execution: PowerShell Profile | CIS-18.3, CIS-4.1, CIS-5.4, CIS-6.1, CIS-6.2 | 3 rule(s) deployed but dead (05b3e303-faf0-4f4a-9b30-46cc13e69152, 3a9fa2ec-30bc-4ebd-b49e-7c9cff225502, b5b78988-486d-4a80-b991-930eff3ff8bf); missing log source: windows/file_event, windows/ps_script |
| T1546.014 | Event Triggered Execution: Emond | CIS-18.3, CIS-2.3, CIS-2.5, CIS-4.1, CIS-4.8 | 1 rule(s) deployed but dead (23c43900-e732-45a4-8354-63e4a6c187ce); missing log source: macos/file_event |
| T1547.002 | Boot or Logon Autostart Execution: Authentication Package | CIS-2.6, CIS-4.1 | 1 rule(s) deployed but dead (c2c76b77-32be-4d1f-82c9-7e544bdfe0eb); missing log source: windows/process_creation |
| T1547.003 | Boot or Logon Autostart Execution: Time Providers | CIS-3.3, CIS-4.1, CIS-5.4, CIS-6.1, CIS-6.2 | 1 rule(s) deployed but dead (e88a6ddc-74f7-463b-9b26-f69fc0d2ce85); missing log source: windows/registry_set |
| T1547.004 | Boot or Logon Autostart Execution: Winlogon Helper DLL | CIS-2.5, CIS-2.6, CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2 | 3 rule(s) deployed but dead (53389db6-ba46-48e3-a94c-e0f2cefe1583, 851c506b-6b7c-4ce2-8802-c703009d03c0, bbf59793-6efb-4fa1-95ca-a7d288e52c88); missing log source: windows/ps_script, windows/registry_set, zeek/dce_rpc |
| T1547.005 | Boot or Logon Autostart Execution: Security Support Provider | CIS-2.6, CIS-4.1 | 1 rule(s) deployed but dead (eeb30123-9fbd-4ee8-aaa0-2e545bbed6dc); missing log source: windows/registry_event |
| T1547.006 | Boot or Logon Autostart Execution: Kernel Modules and Extensions | CIS-10.1, CIS-10.2, CIS-10.7, CIS-13.2, CIS-2.5, CIS-2.6, CIS-4.1, CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2 | 1 rule(s) deployed but dead (106d7cbd-80ff-4985-b682-a7043e5acb72); missing log source: linux/auditd |
| T1547.007 | Boot or Logon Autostart Execution: Re-opened Applications | CIS-14.3, CIS-14.4, CIS-18.3, CIS-2.3, CIS-4.1, CIS-4.8, CIS-7.7 | no detection deployed |
| T1547.008 | Boot or Logon Autostart Execution: LSASS Driver | CIS-2.6, CIS-4.1 | 1 rule(s) deployed but dead (b3503044-60ce-4bf4-bbcb-e3db98788823); missing log source: windows/registry_event |
| T1547.012 | Boot or Logon Autostart Execution: Print Processors | CIS-4.7, CIS-5.3, CIS-5.4 | no detection deployed |
| T1548.001 | Abuse Elevation Control Mechanism: Setuid and Setgid | CIS-18.3, CIS-4.1 | 1 rule(s) deployed but dead (0506a799-698b-43b4-85a1-ac4c84c720e9); missing log source: linux/auth |
| T1548.002 | Abuse Elevation Control Mechanism: Bypass User Account Control | CIS-18.3, CIS-4.1, CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2, CIS-7.1, CIS-7.2, CIS-7.3, CIS-7.5 | 54 rule(s) deployed but dead (0058b9e5-bcd7-40d4-9205-95ca5a16d7b2, 0d7ceeef-3539-4392-8953-3dc664912714, 152f3630-77c1-4284-bcc0-4cc68ab2f6e7 (+51 more)); missing log source: windows/file_event, windows/image_load, windows/process_access, windows/process_creation, windows/ps_script, windows/registry_event, windows/registry_set |
| T1548.003 | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | CIS-18.3, CIS-3.3, CIS-4.1, CIS-5.4, CIS-6.1, CIS-6.2 | 3 rule(s) deployed but dead (7fcc54cb-f27d-4684-84b7-436af096f858, ddb26b76-4447-4807-871f-1b035b2bfa5d, f74107df-b6c6-4e80-bf00-4170b658162b); missing log source: linux/file_event, linux/process_creation, linux/sudo |
| T1548.004 | Abuse Elevation Control Mechanism: Elevated Execution with Prompt | CIS-2.5 | no detection deployed |
| T1550.003 | Use Alternate Authentication Material: Pass the Ticket | CIS-18.3, CIS-4.1, CIS-4.7, CIS-5.2, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2 | 4 rule(s) deployed but dead (12827a56-61a4-476a-a9cb-f3068f191073, 3245cd30-e015-40ff-a31d-5cadd5f377ec, 7ec2c172-dceb-4c10-92c9-87c1881b7e18 (+1 more)); missing log source: windows/network_connection, windows/process_creation, windows/ps_script |
| T1550.004 | Use Alternate Authentication Material: Web Session Cookie | CIS-18.3, CIS-4.1 | no detection deployed |
| T1552.003 | Unsecured Credentials: Shell History | CIS-18.3, CIS-4.1 | 3 rule(s) deployed but dead (508a9374-ad52-4789-b568-fc358def2c65, b094d9fb-b1ad-4650-9f1a-fb7be9f1d34b, eae8ce9f-bde9-47a6-8e79-f20d18419910); missing log source: cisco/aaa, linux/auditd, macos/process_creation |
| T1552.004 | Unsecured Credentials: Private Keys | CIS-11.3, CIS-18.3, CIS-3.1, CIS-3.11, CIS-3.12, CIS-3.2, CIS-3.3, CIS-5.2, CIS-5.4, CIS-6.1, CIS-6.2 | 6 rule(s) deployed but dead (1f978c6a-4415-47fb-aca5-736a44d7ca3d, 213d6a77-3d55-4ce8-ba74-fcfef741974e, 7892ec59-c5bb-496d-8968-e5d210ca3ac4 (+3 more)); missing log source: cisco/aaa, windows/file_event, windows/process_creation, windows/ps_script |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | CIS-13.4, CIS-18.3, CIS-2.3, CIS-2.5, CIS-4.1, CIS-4.2, CIS-4.5, CIS-4.8 | no detection deployed |
| T1552.006 | Unsecured Credentials: Group Policy Preferences | CIS-18.3, CIS-3.1, CIS-3.2, CIS-4.1, CIS-7.1, CIS-7.2, CIS-7.3, CIS-7.5 | 5 rule(s) deployed but dead (05f3c945-dcc8-4393-9f3d-af65077a8f86, 47e4bab7-c626-47dc-967b-255608c9a920, 91a2c315-9ee6-4052-a853-6f6a8238f90d (+2 more)); missing log source: windows/file_access, windows/process_creation |
| T1553 | Subvert Trust Controls | CIS-18.3, CIS-2.5, CIS-2.6, CIS-4.1, CIS-4.8 | 3 rule(s) deployed but dead (30d07da2-83ab-45d8-ae75-ec7c0edcaffc, 6e4dcdd1-e48b-42f7-b2d8-3b413fc58cb4, a4eaf250-7dc1-4842-862a-5e71cd59a167); missing log source: macos/process_creation, windows/process_creation |
| T1553.001 | Subvert Trust Controls: Gatekeeper Bypass | CIS-2.5 | no detection deployed |
| T1553.003 | Subvert Trust Controls: SIP and Trust Provider Hijacking | CIS-2.6, CIS-3.3, CIS-4.1, CIS-6.1, CIS-6.2 | 2 rule(s) deployed but dead (5a2b21ee-6aaa-4234-ac9d-59a59edf90a1, cbaa3ef3-07a9-4c8e-82d1-9e40578da7fd); missing log source: windows/registry_set |
| T1553.004 | Subvert Trust Controls: Install Root Certificate | CIS-18.3, CIS-4.1, CIS-4.8 | 8 rule(s) deployed but dead (114de787-4eb2-48cc-abdb-c0b449f93ea4, 1f978c6a-4415-47fb-aca5-736a44d7ca3d, 42821614-9264-4761-acfc-5772c3286f76 (+5 more)); missing log source: cisco/aaa, linux/process_creation, windows/process_creation, windows/ps_script |
| T1555 | Credentials from Password Stores | CIS-5.2 | 7 rule(s) deployed but dead (58f4ea09-0fc2-4520-ba18-b85c540b0eaf, 603c6630-5225-49c1-8047-26c964553e0e, 7679d464-4f74-45e2-9e01-ac66c5eb041a (+4 more)); missing log source: windows/file_event, windows/process_creation, windows/ps_script |
| T1555.001 | Credentials from Password Stores: Keychain | CIS-5.2 | 1 rule(s) deployed but dead (b120b587-a4c2-4b94-875d-99c9807d6955); missing log source: macos/process_creation |
| T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | CIS-14.3 | 6 rule(s) deployed but dead (24c77512-782b-448a-8950-eddb0785fc71, 47147b5b-9e17-4d76-b8d2-7bac24c5ce1b, 851fd622-b675-4d26-b803-14bc7baa517a (+3 more)); missing log source: windows/process_creation, windows/ps_script |
| T1556.001 | Modify Authentication Process: Domain Controller Authentication | CIS-2.6, CIS-4.1, CIS-4.7, CIS-5.1, CIS-5.3, CIS-5.4, CIS-5.5, CIS-6.1, CIS-6.2, CIS-6.4, CIS-6.5 | no detection deployed |
| T1556.002 | Modify Authentication Process: Password Filter DLL | CIS-18.3, CIS-4.1 | 3 rule(s) deployed but dead (63bf8794-9917-45bc-88dd-e1b5abc0ecfd, b7966f4a-b333-455b-8370-8ca53c229762, c2c76b77-32be-4d1f-82c9-7e544bdfe0eb); missing log source: windows/process_creation, windows/ps_script |
| T1556.003 | Modify Authentication Process: Pluggable Authentication Modules | CIS-4.1, CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2, CIS-6.4, CIS-6.5 | no detection deployed |
| T1556.004 | Modify Authentication Process: Network Device Authentication | CIS-12.2, CIS-4.1, CIS-4.7, CIS-5.2, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2, CIS-6.4, CIS-6.5 | no detection deployed |
| T1557 | Adversary-in-the-Middle | CIS-12.2, CIS-13.3, CIS-13.4, CIS-14.2, CIS-14.6, CIS-16.10, CIS-16.8, CIS-18.2, CIS-18.3, CIS-3.10, CIS-3.12, CIS-4.1, CIS-4.2, CIS-4.4, CIS-4.6, CIS-4.8, CIS-7.6, CIS-7.7 | 1 rule(s) deployed but dead (c2c76b77-32be-4d1f-82c9-7e544bdfe0eb); missing log source: windows/process_creation |
| T1557.002 | Adversary-in-the-Middle: ARP Cache Poisoning | CIS-12.2, CIS-13.3, CIS-14.2, CIS-14.6, CIS-18.2, CIS-18.3, CIS-3.10, CIS-4.1, CIS-4.2, CIS-4.4, CIS-4.8, CIS-7.6, CIS-7.7 | no detection deployed |
| T1558.001 | Steal or Forge Kerberos Tickets: Golden Ticket | CIS-18.3, CIS-4.1, CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2 | no detection deployed |
| T1558.002 | Steal or Forge Kerberos Tickets: Silver Ticket | CIS-3.10, CIS-4.1, CIS-4.7, CIS-5.2, CIS-5.3, CIS-5.4, CIS-5.5 | no detection deployed |
| T1558.004 | Steal or Forge Kerberos Tickets: AS-REP Roasting | CIS-18.3, CIS-3.10, CIS-4.1, CIS-4.7, CIS-5.2 | no detection deployed |
| T1559 | Inter-Process Communication | CIS-18.3, CIS-2.5, CIS-2.6, CIS-4.1, CIS-4.8 | 1 rule(s) deployed but dead (58bf96d9-ff5f-44bd-8dcc-1c4f79bf3a27); missing log source: windows/process_creation |
| T1559.001 | Inter-Process Communication: Component Object Model | CIS-4.1 | 3 rule(s) deployed but dead (36e037c4-c228-4866-b6a3-48eb292b9955, 3b4b232a-af90-427c-a22f-30b0c0837b95, c7e91a02-d771-4a6d-a700-42587e0b1095); missing log source: windows/dns_query, windows/network_connection, windows/process_access |
| T1559.002 | Inter-Process Communication: Dynamic Data Exchange | CIS-18.3, CIS-2.5, CIS-2.6, CIS-4.1, CIS-4.8 | 1 rule(s) deployed but dead (63647769-326d-4dde-a419-b925cc0caf42); missing log source: windows/registry_set |
| T1560 | Archive Collected Data | CIS-18.3, CIS-2.1, CIS-2.2, CIS-2.3, CIS-2.4 | 1 rule(s) deployed but dead (aa92fd02-09f2-48b0-8a93-864813fb8f41); missing log source: windows/process_creation |
| T1560.001 | Archive Collected Data: Archive via Utility | CIS-18.3, CIS-2.1, CIS-2.2, CIS-2.3, CIS-2.4 | 9 rule(s) deployed but dead (03e2746e-2b31-42f1-ab7a-eb39365b2422, 1ac14d38-3dfc-4635-92c7-e3fd1c5f5bfc, 4ede543c-e098-43d9-a28f-dd784a13132f (+6 more)); missing log source: macos/process_creation, windows/process_creation |
| T1561 | Disk Wipe | CIS-11.1, CIS-11.2, CIS-11.3, CIS-11.4, CIS-11.5 | no detection deployed |
| T1561.001 | Disk Wipe: Disk Content Wipe | CIS-11.1, CIS-11.2, CIS-11.3, CIS-11.4, CIS-11.5 | 1 rule(s) deployed but dead (71d65515-c436-43c0-841b-236b1f32c21e); missing log source: cisco/aaa |
| T1561.002 | Disk Wipe: Disk Structure Wipe | CIS-11.1, CIS-11.2, CIS-11.3, CIS-11.4, CIS-11.5 | 1 rule(s) deployed but dead (71d65515-c436-43c0-841b-236b1f32c21e); missing log source: cisco/aaa |
| T1563 | Remote Service Session Hijacking | CIS-12.2, CIS-16.10, CIS-18.3, CIS-2.3, CIS-2.5, CIS-3.12, CIS-4.1, CIS-4.2, CIS-4.4, CIS-4.7, CIS-4.8, CIS-5.3, CIS-6.1, CIS-6.2, CIS-7.6 | no detection deployed |
| T1563.001 | Remote Service Session Hijacking: SSH Hijacking | CIS-16.10, CIS-18.3, CIS-2.3, CIS-2.5, CIS-4.1, CIS-4.7, CIS-4.8, CIS-5.2, CIS-5.3, CIS-6.1, CIS-6.2, CIS-7.7 | no detection deployed |
| T1563.002 | Remote Service Session Hijacking: RDP Hijacking | CIS-12.2, CIS-12.7, CIS-13.5, CIS-16.10, CIS-18.3, CIS-2.3, CIS-2.5, CIS-3.12, CIS-4.1, CIS-4.2, CIS-4.4, CIS-4.7, CIS-4.8, CIS-5.1, CIS-5.3, CIS-5.5, CIS-6.1, CIS-6.2, CIS-7.6 | 2 rule(s) deployed but dead (6ba5a05f-b095-4f0a-8654-b825f4f16334, f72aa3e8-49f9-4c7d-bd74-f8ab84ff9bbb); missing log source: windows/process_creation |
| T1564.002 | Hide Artifacts: Hidden Users | CIS-18.3, CIS-4.1 | 4 rule(s) deployed but dead (9ec9fb1b-e059-4489-9642-f270c207923d, b22a5b36-2431-493a-8be1-0bae56c28ef3, c2c76b77-32be-4d1f-82c9-7e544bdfe0eb (+1 more)); missing log source: macos/process_creation, windows/process_creation, windows/registry_set |
| T1564.003 | Hide Artifacts: Hidden Window | CIS-2.5 | 6 rule(s) deployed but dead (056c7317-9a09-4bd4-9067-d051312752ea, 0e8cfe08-02c9-4815-a2f8-0d157b7ed33e, 313fbb0a-a341-4682-848d-6d6f8c4fab7c (+3 more)); missing log source: windows/process_creation, windows/ps_script |
| T1564.004 | Hide Artifacts: NTFS File Attributes | CIS-3.3, CIS-4.1, CIS-6.1, CIS-6.2 | 21 rule(s) deployed but dead (025bd229-fd1f-4fdb-97ab-20006e1a5368, 0900463c-b33b-49a8-be1d-552a3b553dae, 0d7a9363-af70-4e7b-a3b7-1a176b7fbe84 (+18 more)); missing log source: macos/process_creation, windows/create_stream_hash, windows/file_event, windows/process_creation, windows/ps_script |
| T1564.006 | Hide Artifacts: Run Virtual Instance | CIS-18.3, CIS-2.3, CIS-2.5, CIS-4.1, CIS-4.8, CIS-7.7 | 1 rule(s) deployed but dead (42d36aa1-3240-4db0-8257-e0118dcdd9cd); missing log source: windows/ps_script |
| T1564.007 | Hide Artifacts: VBA Stomping | CIS-16.10, CIS-18.3, CIS-2.3, CIS-2.5, CIS-4.1, CIS-4.8 | no detection deployed |
| T1565.002 | Data Manipulation: Transmitted Data Manipulation | CIS-11.3, CIS-3.10 | 1 rule(s) deployed but dead (671ffc77-50a7-464f-9e3d-9ea2b493b26b); missing log source: cisco/aaa |
| T1565.003 | Data Manipulation: Runtime Data Manipulation | CIS-11.3, CIS-11.4, CIS-12.2, CIS-16.8, CIS-3.12, CIS-3.3, CIS-4.4, CIS-5.4, CIS-6.1, CIS-6.2 | no detection deployed |
| T1566.003 | Phishing: Spearphishing via Service | CIS-14.1, CIS-14.2, CIS-14.6, CIS-2.3, CIS-2.5, CIS-9.3 | no detection deployed |
| T1567 | Exfiltration Over Web Service | CIS-2.3, CIS-2.5, CIS-9.3 | 11 rule(s) deployed but dead (00b90cc1-17ec-402c-96ad-3a8117d7a582, 18249279-932f-45e2-b37a-8925f2597670, 19bf6fdb-7721-4f3d-867f-53467f6a5db6 (+8 more)); missing log source: dns, linux/network_connection, linux/process_creation, windows/network_connection, windows/process_creation |
| T1567.001 | Exfiltration Over Web Service: Exfiltration to Code Repository | CIS-2.3, CIS-2.5, CIS-9.3 | 1 rule(s) deployed but dead (9501f8e6-8e3d-48fc-a8a6-1089dd5d7ef4); missing log source: windows/network_connection |
| T1568.002 | Dynamic Resolution: Domain Generation Algorithms | CIS-13.3, CIS-9.2 | 2 rule(s) deployed but dead (19bf6fdb-7721-4f3d-867f-53467f6a5db6, 1d08ac94-400d-4469-a82f-daee9a908849); missing log source: linux/network_connection, windows/network_connection |
| T1569.001 | System Services: Launchctl | CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2 | 1 rule(s) deployed but dead (ae9d710f-dcd1-4f75-a0a5-93a73b5dda0e); missing log source: macos/process_creation |
| T1571 | Non-Standard Port | CIS-12.2, CIS-13.3, CIS-4.2, CIS-4.4 | 5 rule(s) deployed but dead (4b89abaa-99fe-4232-afdd-8f9aa4d20382, 6d8c3d20-a5e1-494f-8412-4571d716cf5c, adf876b3-f1f8-4aa9-a4e4-a64106feec06 (+2 more)); missing log source: linux/network_connection, windows/network_connection, windows/ps_script, zeek/dns |
| T1572 | Protocol Tunneling | CIS-13.3, CIS-13.4, CIS-4.2, CIS-4.4, CIS-7.7, CIS-9.3 | 23 rule(s) deployed but dead (18249279-932f-45e2-b37a-8925f2597670, 19bf6fdb-7721-4f3d-867f-53467f6a5db6, 1cb0c6ce-3d00-44fc-ab9c-6d6d577bf20b (+20 more)); missing log source: linux/network_connection, windows/dns_query, windows/network_connection, windows/process_creation, windows/ps_script |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | CIS-13.3 | no detection deployed |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | CIS-13.3 | no detection deployed |
| T1574 | Hijack Execution Flow | CIS-18.3, CIS-2.5, CIS-2.6, CIS-4.1, CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2, CIS-7.1, CIS-7.2, CIS-7.3, CIS-7.4, CIS-7.5 | 7 rule(s) deployed but dead (1c373b6d-76ce-4553-997d-8c1da9a6b5f5, 50919691-7302-437f-8e10-1fe088afa145, 5b2bbc47-dead-4ef7-8908-0cf73fcbecbf (+4 more)); missing log source: windows/file_delete, windows/file_event, windows/process_creation, windows/registry_set |
| T1574.004 | Hijack Execution Flow: Dylib Hijacking | CIS-4.1, CIS-6.1, CIS-6.2 | no detection deployed |
| T1574.005 | Hijack Execution Flow: Executable Installer File Permissions Weakness | CIS-18.3, CIS-4.1, CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2 | 2 rule(s) deployed but dead (99c8be4f-3087-4f9f-9c24-8c7e257b442e, c484e533-ee16-4a93-b6ac-f0ea4868b2f1); missing log source: windows/process_creation |
| T1574.006 | Hijack Execution Flow: Dynamic Linker Hijacking | CIS-2.5, CIS-2.6 | 2 rule(s) deployed but dead (4b3cb710-5e83-4715-8c45-8b2b5b3e5751, 7e3c4651-c347-40c4-b1d4-d48590fdf684); missing log source: linux, linux/auditd |
| T1574.007 | Hijack Execution Flow: Path Interception by PATH Environment Variable | CIS-18.3, CIS-2.5, CIS-2.6, CIS-4.1, CIS-6.1, CIS-6.2 | 1 rule(s) deployed but dead (c2c76b77-32be-4d1f-82c9-7e544bdfe0eb); missing log source: windows/process_creation |
| T1574.008 | Hijack Execution Flow: Path Interception by Search Order Hijacking | CIS-18.3, CIS-2.5, CIS-2.6, CIS-4.1, CIS-6.1, CIS-6.2 | 1 rule(s) deployed but dead (b2ddd389-f676-4ac4-845a-e00781a48e5f); missing log source: windows/process_creation |
| T1574.009 | Hijack Execution Flow: Path Interception by Unquoted Path | CIS-18.3, CIS-2.5, CIS-2.6, CIS-4.1, CIS-6.1, CIS-6.2 | no detection deployed |
| T1574.010 | Hijack Execution Flow: Services File Permissions Weakness | CIS-18.3, CIS-4.1, CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2 | no detection deployed |
| T1574.011 | Hijack Execution Flow: Services Registry Permissions Weakness | CIS-4.1 | 10 rule(s) deployed but dead (0f9c21f1-6a73-4b0e-9809-cb562cb8d981, 22d80745-6f2c-46da-826b-77adaededd74, 38879043-7e1e-47a9-8d46-6bec88e201df (+7 more)); missing log source: windows/process_creation, windows/ps_script |
| T1574.012 | Hijack Execution Flow: COR_PROFILER | CIS-2.5, CIS-2.6, CIS-4.1, CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2 | 2 rule(s) deployed but dead (23590215-4702-4a70-8805-8dc9e58314a2, ad89044a-8f49-4673-9a55-cbd88a1b374f); missing log source: windows/ps_script, windows/registry_set |
| T1578.001 | Modify Cloud Compute Infrastructure: Create Snapshot | CIS-18.3, CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2 | no detection deployed |
| T1578.002 | Modify Cloud Compute Infrastructure: Create Cloud Instance | CIS-18.3, CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2 | no detection deployed |
| T1580 | Cloud Infrastructure Discovery | CIS-3.3, CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2 | no detection deployed |
| T1590.001 | Gather Victim Network Information: Domain Properties | CIS-18.2, CIS-18.3 | 1 rule(s) deployed but dead (2c32b543-1058-4808-91c6-5b31b8bed6c5); missing log source: windows/process_creation |
| T1590.002 | Gather Victim Network Information: DNS | CIS-18.2, CIS-18.3 | 1 rule(s) deployed but dead (6d444368-6da1-43fe-b2fc-44202430480e); missing log source: windows/dns-server |
| T1590.004 | Gather Victim Network Information: Network Topology | CIS-18.2, CIS-18.3 | no detection deployed |
| T1590.005 | Gather Victim Network Information: IP Addresses | CIS-18.2, CIS-18.3 | no detection deployed |
| T1590.006 | Gather Victim Network Information: Network Security Appliances | CIS-18.2, CIS-18.3 | no detection deployed |
| T1595 | Active Scanning | CIS-18.2, CIS-18.3 | 2 rule(s) deployed but dead (b1cb4ab6-ac31-43f4-adf1-d9d08957419c, b37998de-a70b-4f33-b219-ec36bf433dc0); missing log source: windows/process_creation |
| T1595.001 | Active Scanning: Scanning IP Blocks | CIS-18.2, CIS-18.3 | no detection deployed |
| T1595.002 | Active Scanning: Vulnerability Scanning | CIS-18.2, CIS-18.3 | 1 rule(s) deployed but dead (aff715fa-4dd5-497a-8db3-910bea555566); missing log source: dns |
| T1598 | Phishing for Information | CIS-14.1, CIS-14.2, CIS-14.6 | no detection deployed |
| T1598.001 | Phishing for Information: Spearphishing Service | CIS-14.1, CIS-14.2, CIS-14.6 | no detection deployed |
| T1598.002 | Phishing for Information: Spearphishing Attachment | CIS-14.1, CIS-14.2, CIS-14.6 | no detection deployed |
| T1598.003 | Phishing for Information: Spearphishing Link | CIS-14.1, CIS-14.2, CIS-14.6 | no detection deployed |
| T1599 | Network Boundary Bridging | CIS-12.2, CIS-13.4, CIS-4.1, CIS-4.2, CIS-4.4, CIS-4.7, CIS-5.2, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2, CIS-6.4, CIS-6.5 | no detection deployed |
| T1599.001 | Network Boundary Bridging: Network Address Translation Traversal | CIS-12.2, CIS-13.4, CIS-4.1, CIS-4.2, CIS-4.4, CIS-4.7, CIS-5.2, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2, CIS-6.4, CIS-6.5 | 1 rule(s) deployed but dead (679085d5-f427-4484-9f58-1dc30a7c426d); missing log source: windows/driver_load |
| T1601 | Modify System Image | CIS-12.2, CIS-3.6, CIS-4.1, CIS-4.7, CIS-5.2, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2, CIS-6.4, CIS-6.5 | no detection deployed |
| T1601.001 | Modify System Image: Patch System Image | CIS-12.2, CIS-3.6, CIS-4.1, CIS-4.7, CIS-5.2, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2, CIS-6.4, CIS-6.5 | no detection deployed |
| T1601.002 | Modify System Image: Downgrade System Image | CIS-12.2, CIS-3.6, CIS-4.1, CIS-4.7, CIS-5.2, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2, CIS-6.4, CIS-6.5 | no detection deployed |
| T1602 | Data from Configuration Repository | CIS-12.1, CIS-12.2, CIS-13.3, CIS-13.4, CIS-18.2, CIS-18.3, CIS-3.10, CIS-3.12, CIS-4.1, CIS-4.2, CIS-4.4, CIS-4.6, CIS-7.6 | no detection deployed |
| T1602.001 | Data from Configuration Repository: SNMP (MIB Dump) | CIS-12.1, CIS-12.2, CIS-13.3, CIS-13.4, CIS-18.2, CIS-18.3, CIS-3.10, CIS-3.12, CIS-4.1, CIS-4.2, CIS-4.4, CIS-4.6, CIS-7.6, CIS-7.7 | no detection deployed |
| T1602.002 | Data from Configuration Repository: Network Device Configuration Dump | CIS-12.1, CIS-12.2, CIS-13.3, CIS-13.4, CIS-18.2, CIS-18.3, CIS-3.10, CIS-3.12, CIS-4.1, CIS-4.2, CIS-4.4, CIS-4.6, CIS-7.6, CIS-7.7 | no detection deployed |
| T1606.001 | Forge Web Credentials: Web Cookies | CIS-18.3, CIS-4.1, CIS-6.1, CIS-6.2 | no detection deployed |
| T1606.002 | Forge Web Credentials: SAML Tokens | CIS-18.3, CIS-4.1, CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2 | no detection deployed |
| T1647 | Plist File Modification | CIS-14.3, CIS-14.4, CIS-3.3, CIS-4.1, CIS-5.4, CIS-6.1, CIS-6.2 | no detection deployed |
| T1685.006 | Disable or Modify Tools: Clear Linux or Mac System Logs | CIS-3.1, CIS-3.10, CIS-3.11, CIS-3.12, CIS-3.3, CIS-3.4, CIS-4.1, CIS-5.4, CIS-6.1, CIS-6.2, CIS-8.1, CIS-8.10, CIS-8.2, CIS-8.3 | 3 rule(s) deployed but dead (3fcc9b35-39e4-44c0-a2ad-9e82b6902b31, 80915f59-9b56-4616-9de0-fd0dea6c12fe, acf61bd8-d814-4272-81f0-a7a269aa69aa); missing log source: linux/process_creation, macos/process_creation |
| T1686 | Disable or Modify System Firewall | CIS-3.3, CIS-4.1, CIS-4.7, CIS-5.3, CIS-5.4, CIS-6.1, CIS-6.2 | 7 rule(s) deployed but dead (323ff3f5-0013-4847-bbd4-250b5edb62cc, 3be619f4-d9ec-4ea8-a173-18fdd01996ab, 49f5dfc1-f92e-4d34-96fa-feba3f6acf36 (+4 more)); missing log source: linux/auditd, linux/process_creation, linux/syslog |
| T1690 | Prevent Command History Logging | CIS-18.3, CIS-4.1 | 1 rule(s) deployed but dead (38eb1dbb-011f-40b1-a126-cf03a0210563); missing log source: linux/process_creation |

## Heatmap

```
tactic                  defended  paper  det-only  blind  total  true%
reconnaissance                 1     12         1     32     46    2.2 
resource-development           0      0         3     47     50    0.0 
initial-access                11      8         0      3     22   50.0 ##########
execution                     16     26         1     21     64   25.0 #####
persistence                   23     53         5     32    113   20.4 ####
privilege-escalation          23     48         3     22     96   24.0 #####
stealth                       17     55         4     72    148   11.5 ##
defense-impairment            13     21         3     19     56   23.2 #####
credential-access             20     28         3     16     67   29.9 ######
discovery                      5      6         5     33     49   10.2 ##
lateral-movement               9     11         1      2     23   39.1 ########
collection                     3     17         2     19     41    7.3 #
command-and-control           12     23         1      9     45   26.7 #####
exfiltration                   3     13         1      2     19   15.8 ###
impact                         8     15         2      8     33   24.2 #####
```

## Single points of failure

- log_source `windows/security` -> 39 techniques dark (5.6% of matrix)
- log_source `aws/cloudtrail` -> 14 techniques dark (2.0% of matrix)
- log_source `proxy` -> 11 techniques dark (1.6% of matrix)
- log_source `windows/application` -> 9 techniques dark (1.3% of matrix)
- log_source `azure/activitylogs` -> 7 techniques dark (1.0% of matrix)

## Recommended next actions (greedy set cover)

1. onboard_log_source `windows/ps_script` (cost 1.15) -> +51 techniques: T1018, T1021.006, T1033, T1036.003, T1046, T1048.003, T1055, T1056.001, T1059.005, T1069, T1069.001, T1070.003, T1070.005, T1070.006, T1074.001, T1082, T1087.001, T1106, T1113, T1114.001, T1119, T1132.001, T1137.006, T1202, T1222, T1482, T1497.001, T1518, T1518.001, T1529, T1546.013, T1546.015, T1547.004, T1548.002, T1550.003, T1552.004, T1553.004, T1553.005, T1555, T1555.003, T1556.002, T1564.003, T1564.004, T1564.006, T1571, T1572, T1574.011, T1574.012, T1589.002, T1620, T1686.003
2. deploy_detection `d22df9cd-2aee-4089-93c7-9dc4eae77f2c` (cost 0.05) -> +2 techniques: T1557, T1565.002
3. deploy_detection `f8a66a02-4a16-46e5-b7fd-a42c8a93d137` (cost 0.05) -> +1 techniques: T1499
4. deploy_detection `b07e58cf-cacc-4135-8473-ccb2eba63dd2` (cost 0.05) -> +1 techniques: T1557.003
5. deploy_detection `882fbe50-d8d7-4e29-ae80-0648a8556866` (cost 0.05) -> +1 techniques: T1005

## Zero-Trust components

- segmentation: 0.692
- mfa: 0.6
- privileged_access: 0.25
- device_posture: 0.0
- account_hygiene: 0.9
- Lateral/discovery techniques exposed by open flows into critical segments: T1007, T1010, T1012, T1016, T1016.001, T1016.002, T1018, T1021, T1021.001, T1021.002, T1021.003, T1021.004, T1021.005, T1021.006, T1021.007, T1021.008, T1033, T1040, T1046, T1049, T1057, T1069, T1069.001, T1069.002, T1069.003, T1072, T1080, T1082, T1083, T1087, T1087.001, T1087.002, T1087.003, T1087.004, T1091, T1120, T1124, T1135, T1201, T1210, T1217, T1482, T1497, T1497.001, T1497.002, T1497.003, T1518, T1518.001, T1518.002, T1526, T1534, T1538, T1550, T1550.001, T1550.002, T1550.003, T1550.004, T1563, T1563.001, T1563.002, T1570, T1580, T1613, T1614, T1614.001, T1615, T1619, T1622, T1652, T1654, T1673, T1680
