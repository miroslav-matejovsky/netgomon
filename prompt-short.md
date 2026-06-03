Build a Windows-only Go CLI tool called netwinmon.exe for monitoring network activity of one executable.

Constraints:
- Monitoring only.
- No firewall changes.
- No WFP programming for rules.
- No packet capture.
- No tshark, Wireshark, Npcap, PowerShell, Sysmon, Procmon, or external CLI tools.
- Use only built-in Windows capabilities and Go libraries/packages.
- Tool runs as Administrator.
- Input is only the path to the target executable.
- Tool waits for the next process instance matching that path, monitors it until exit, then writes report.json.

Data to collect:
- Process metadata: PID, path, start time, end time.
- TCP connections belonging to PID.
- UDP endpoints belonging to PID.
- Use first seen / last seen tracking.
- Aggregate unique remote IPs, ports, states, counts.
- Reverse DNS is optional, but IP remains source of truth.
- If HTTP is mentioned in report, it must be inferred only from port/endpoint metadata, never from payload.

Required output:
1. chosen approach paragraph
2. architecture
3. project layout
4. full Go code
5. JSON schema
6. build instructions
7. sample report
8. limitations
9. v2 roadmap

Prioritize simplicity and maintainability.
If ETW is too heavy for v1, choose the simplest fallback and explain the tradeoff.
No pseudocode.