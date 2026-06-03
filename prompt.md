You are designing and implementing a Windows-only Go command-line tool for SIMPLE NETWORK MONITORING of one executable.

Goal
- Produce a maintainable first version of a monitoring-only tool.
- No enforcement, no firewall rule changes, no WFP filter programming.
- No external tools.
- No tshark, no Wireshark, no Npcap, no Sysmon, no Procmon, no PowerShell dependency at runtime.
- Use only what is already in Windows and normal Go libraries / Go packages.
- Prefer the simplest approach that can work reliably enough for a first version.

Primary use case
- The user runs the tool as Administrator.
- The tool receives ONLY the path to the executable to monitor.
- Example:
    netwinmon.exe "C:\Apps\myapp.exe"
- The tool waits for the NEXT process instance whose image path matches the supplied executable path.
- When that process starts, the tool begins monitoring its network activity.
- When that process exits, the tool stops and writes a clear report.

Important design constraints
- Focus on monitoring only.
- Start with the simplest possible implementation.
- Avoid advanced WFP coding and avoid packet capture.
- Do not require starting the target process through the tool.
- Do not elevate or modify the target process.
- The tool itself runs elevated and observes the system.
- The report must be clear and useful for TCP, UDP, and higher-level HTTP-ish visibility only when inferable from endpoints / ports / hostnames; do not pretend packet contents are available.
- Be explicit about limitations.

Windows-native capabilities to use
1. Process lifecycle detection:
   - Use ETW or another Windows-native mechanism to detect process start/stop and match by executable path.
   - ETW is preferred if practical in Go.
2. TCP monitoring:
   - Use Windows TCP connection information with owning PID.
   - Equivalent concept: Get-NetTCPConnection exposes OwningProcess.
3. UDP monitoring:
   - Use Windows UDP endpoint information with owning PID.
   - Equivalent concept: Get-NetUDPEndpoint exposes OwningProcess.
4. Optional hostname resolution:
   - Reverse-resolve remote IPs for readability, but keep IPs as the source of truth.
5. Reporting:
   - Produce JSON report first.
   - Optional human-readable text summary is acceptable as a second output.

Expected CLI behavior
- Minimal form:
    netwinmon.exe "C:\Path\Target.exe"
- Optional flags:
    --out report.json
    --timeout 300
    --poll-ms 1000
    --include-children=false
    --attach-pid 1234
- Default behavior:
    - If attach-pid is absent, wait for the next process matching the path.
    - If timeout expires before process start, exit with a useful message.
    - Once attached to a PID, monitor until process exit.
    - Then write report and exit.

First-version monitoring model
- Poll-based collection is acceptable for v1.
- For the monitored PID:
  - periodically enumerate current TCP connections
  - periodically enumerate current UDP endpoints
  - record first seen / last seen timestamps
  - record unique tuples:
      protocol
      local address
      local port
      remote address
      remote port
      state (for TCP)
  - capture process metadata:
      pid
      image path
      start time
      end time
      exit code if obtainable
- Report aggregate statistics:
  - list of unique TCP connections observed
  - list of unique UDP endpoints observed
  - counts by protocol
  - unique remote IPs
  - unique remote ports
  - optional reverse DNS names
- If include-children=true, also monitor child PIDs discovered after target start.

Do NOT over-engineer
- No database.
- No GUI.
- No background service.
- No packet capture.
- No kernel driver.
- No firewall changes.
- No dependency on external CLI tools.
- No HTML frontend in v1 unless very small and generated from JSON.
- No complicated plugin architecture.

Implementation preferences
- Use Go.
- Organize as a small clean CLI project.
- Keep code readable and modular.
- Separate packages/modules for:
  - process detection
  - TCP/UDP collection
  - model/report schema
  - CLI
- Favor correctness and clarity over cleverness.
- If ETW in Go is too heavy for v1, propose the simplest acceptable fallback for process start detection, but explain the tradeoff.
- If ETW is used, keep the session minimal and focused.

Required output from you
1. A short architecture explanation.
2. Proposed project structure.
3. Clear explanation of why this is the simplest viable first version.
4. A complete JSON report schema.
5. The full Go source code for v1.
6. Build instructions.
7. Example run output.
8. A limitations section.
9. Suggested v2 improvements.

Important technical assumptions to reflect
- TCP and UDP ownership must be tied to PID.
- Packet contents are not available in this design.
- “HTTP” means only inferred traffic based on port 80/443 or endpoint metadata unless stronger native evidence is available.
- Report must never claim payload-level HTTP visibility without packet capture.
- The tool should work on modern Windows with administrator rights.
- All monitoring should use built-in Windows facilities and direct APIs or acceptable Go bindings, not shelling out to PowerShell.

Quality bar
- Production-style code quality for a small internal tool.
- Strong error handling.
- Explicit comments around Windows-specific behavior.
- No placeholder pseudocode.
- If a certain part cannot be implemented cleanly in pure Go, state that directly and provide the best minimal practical alternative.

Before writing code, first state the chosen approach in one concise paragraph:
- whether ETW is used or not,
- how process start is detected,
- how TCP/UDP ownership is collected,
- and why this is the simplest maintainable v1.
