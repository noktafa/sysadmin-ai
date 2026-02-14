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

## Persistent Shell State

By default, each command the AI runs executes in an isolated subprocess — meaning `cd`, `export`, and other stateful shell operations would be lost between turns. SysAdmin AI solves this with **Python-side CWD tracking** that gives the AI the feel of a persistent shell without the security risks of a live PTY.

### How it works

1. The session maintains a `shell_state` dictionary (starting `cwd` at `$HOME`).
2. Every command is executed via `subprocess.run(command, cwd=shell_state["cwd"])`, so the working directory carries over between commands.
3. After each command, a hidden sentinel + `pwd` is appended to capture the resulting directory. If the command includes `cd /some/path`, the new directory is detected and stored for the next command.
4. The sentinel and `pwd` output are stripped — they never appear in the AI's or user's view.
5. On timeout or error, the last known `cwd` is preserved.

### Example multi-turn session

```
You: list files in /var/log
AI:  [runs: ls /var/log]  →  cwd is now /var/log (if command cd'd there)

You: now check disk usage here
AI:  [runs: du -sh *]     →  runs in /var/log, not $HOME
```

### What is NOT tracked

- **Environment variables** — `export FOO=bar` in one command will not persist to the next. This is intentional; tracking arbitrary env mutations requires shell-level parsing and opens attack surface.
- **Shell aliases, functions, and traps** — each command still runs in a fresh shell process.
- **Background jobs** — no job control is carried between commands.

### Why not a persistent PTY?

A persistent shell (via `pexpect` or PTY) accumulates hidden state, makes timeout handling fragile, and allows multi-step safety filter bypasses (e.g., setting an alias in turn 1, exploiting it in turn 2). The CWD-tracking approach covers the most common use case (`cd` persistence) with none of these risks.

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
| `tool_result` | Command output, exit status, and current working directory |
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

### v0.6.0

- **Persistent working directory** — the AI's shell now remembers `cd` across commands via Python-side CWD tracking. Each command runs with `subprocess.run(cwd=tracked_cwd)` and a post-command `pwd` sentinel captures directory changes.
- **`shell_state` tracking** — session maintains a state dict starting at `$HOME`. The tracked `cwd` is passed in every user message and logged in `tool_result` events.
- **Sentinel-based pwd capture** — a hidden `__SYSADMIN_AI_PWD__` marker is appended after each command to detect directory changes. The sentinel and its output are stripped from all visible output.
- **`run_shell_command` returns 3-tuple** — now returns `(output, status, new_cwd)` instead of `(output, status)`. `new_cwd` is `None` on timeout/error, preserving the last known directory.

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
