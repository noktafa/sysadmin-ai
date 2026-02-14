# SysAdmin AI

LLM-powered system administration assistant that runs locally on your machine.

## Usage

```bash
python3 sysadmin_ai.py [OPTIONS]
```

### Options

| Flag | Description |
|------|-------------|
| `--provider {openai,vllm}` | LLM provider (default: `vllm`) |
| `--api-base URL` | Override API base URL |
| `--api-key KEY` | Override API key |
| `--model NAME` | Override model name |
| `--log-dir DIR` | Override log directory (default: `~/.sysadmin-ai/logs/`) |

### Environment Variables

- `SYSADMIN_AI_API_KEY` / `OPENAI_API_KEY` — API key
- `SYSADMIN_AI_API_BASE` — API base URL override
- `SYSADMIN_AI_MODEL` — Model name override

## Command Safety Filter

Every command the LLM requests goes through a two-tier safety check before execution:

- **Blocklist** — 30+ regex patterns that unconditionally reject dangerous commands (destructive ops like `rm -rf /`, reverse shells, credential exfiltration, privilege escalation, kernel tampering). Blocked commands are never executed.
- **Graylist** — commands that are risky but sometimes legitimate (`reboot`, `rm -r`, `apt remove`, `systemctl stop`, `iptables -F`, etc.) prompt the user for `y/N` confirmation before running.

Safety rules from `soul.md` (if present in the script directory) are also loaded into the LLM's system prompt so the AI is aware of the constraints at runtime.

## Structured JSON Logging

Every session automatically writes a structured log file in JSONL format (one JSON object per line) to `~/.sysadmin-ai/logs/session_<YYYYMMDD_HHMMSS>.jsonl`.

Override the log directory with `--log-dir`:

```bash
python3 sysadmin_ai.py --log-dir /tmp/ai-logs
```

### Log event types

| Event | Description |
|-------|-------------|
| `session_start` | Provider, model, base URL, OS, user |
| `user_input` | The user's message |
| `tool_call` | Command the LLM wants to run, plus its reasoning |
| `tool_result` | Command output and exit status |
| `llm_final_response` | The LLM's response after processing tool results |
| `command_blocked` | Command rejected by the safety blocklist |
| `command_denied` | Command rejected by the user (graylist prompt) |
| `error` | API failures or other exceptions |

### Example log entry

```json
{
  "timestamp": "2026-02-14T15:30:00.123456+00:00",
  "session_id": "20260214_153000",
  "event": "tool_call",
  "data": {
    "command": "df -h",
    "reasoning": "Checking disk usage as requested by user",
    "tool_call_id": "call_abc123"
  }
}
```

## Release Notes

### v0.5.0

- **Command safety filter** — two-tier blocklist/graylist system with 30+ regex patterns that intercepts dangerous commands before execution
- **Graylist user confirmation** — risky-but-legitimate commands (`reboot`, `rm -r`, `apt remove`, etc.) prompt `y/N` before running
- **soul.md loaded into system prompt** — safety rules are now visible to the LLM at runtime, not just a static document
- **New log events** — `command_blocked` and `command_denied` for safety audit trail

### v0.4.0

- **Structured JSON logging** — every session now writes a JSONL audit log to `~/.sysadmin-ai/logs/`, capturing commands executed, LLM reasoning, tool output, and errors
- **`--log-dir` CLI flag** — override the default log directory
- **Exit status tracking** — `run_shell_command` now returns exit status (`success`, `exit_N`, `timeout`, `error`) alongside output

### v0.3.0

- **Safety rules** — added `soul.md` guardrails to prevent harmful commands

### v0.2.0

- **Cross-platform compatibility** — fixes for Windows, Linux, and macOS

### v0.1.0

- **Initial release** — LLM-powered sysadmin assistant with OpenAI and vLLM provider support, interactive shell command execution, and multi-step tool-call reasoning

---

### Parsing logs

Since logs are JSONL, you can use standard tools:

```bash
# Pretty-print all events
cat ~/.sysadmin-ai/logs/session_*.jsonl | python3 -m json.tool

# Filter to only tool_call events
cat ~/.sysadmin-ai/logs/session_*.jsonl | python3 -c "
import sys, json
for line in sys.stdin:
    obj = json.loads(line)
    if obj['event'] == 'tool_call':
        print(json.dumps(obj, indent=2))
"
```
