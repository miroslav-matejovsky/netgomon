# Network Monitor Output

This directory contains output files from the network monitor.

## Querying Logs with jq

The `monitor.log` file is formatted as structured JSON lines using Go's `log/slog` library. You can query and filter the logs using `jq`.

### 1. Show all errors
```bash
jq 'select(.level == "ERROR")' monitor.log
```

### 2. Show warnings
```bash
jq 'select(.level == "WARN")' monitor.log
```

### 3. Print messages with level and timestamp
```bash
jq -r '[.time, .level, .msg] | @tsv' monitor.log
```
