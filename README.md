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
| `--safe-mode` | Run commands inside a Docker container instead of directly on the host |

### Environment Variables

- `SYSADMIN_AI_API_KEY` / `OPENAI_API_KEY` — API key
- `SYSADMIN_AI_API_BASE` — API base URL override
- `SYSADMIN_AI_MODEL` — Model name override

## Persistent Shell State

By default, each command the AI runs executes in an isolated subprocess — meaning `cd`, `export`, and other stateful shell operations would be lost between turns. SysAdmin AI solves this with **Python-side CWD tracking** (implemented in `HostExecutor`) that gives the AI the feel of a persistent shell without the security risks of a live PTY.

### How it works

1. The session maintains a `shell_state` dictionary (starting `cwd` at `$HOME`).
2. Every command is executed via `subprocess.run(command, cwd=shell_state["cwd"])`, so the working directory carries over between commands.
3. After each command, a hidden sentinel is appended to capture the resulting directory. On Linux/macOS it uses `pwd`; on Windows it uses `cd` (via `&` chaining — see below).
4. The sentinel output is stripped — it never appears in the AI's or user's view.
5. On timeout or error, the last known `cwd` is preserved.

### Windows command chaining

On Windows, `subprocess.run(shell=True)` invokes `cmd.exe /c`. Newline (`\r\n`) chaining does **not** work under `cmd.exe /c` — only the first line executes. SysAdmin AI uses `&` chaining with `&&`/`||` to run the sentinel commands and preserve the original command's exit status:

```
{command} && (echo SENTINEL_0 & cd) || (echo SENTINEL_1 & cd)
```

The `_0` / `_1` suffix encodes success or failure, since `result.returncode` would otherwise always reflect the last chained command (`cd`), not the user's command.

### Auto-wrapping PowerShell cmdlets

On Windows, `shell=True` runs commands through `cmd.exe`, not PowerShell. If the LLM sends a bare PowerShell cmdlet like `Get-Process`, it will fail with "not recognized". SysAdmin AI auto-detects bare cmdlets using the `Verb-Noun` naming pattern and wraps them:

```
Get-Process | Sort-Object CPU   →   powershell -NoProfile -Command "Get-Process | Sort-Object CPU"
```

Commands already prefixed with `powershell` or `pwsh` are left untouched.

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

## Executor Abstraction (Strategy Pattern)

Command execution is decoupled from the chat loop via an `Executor` ABC. This enables swapping execution backends without touching the LLM orchestration logic.

| Executor | Backend | When used |
|----------|---------|-----------|
| `HostExecutor` | `subprocess.run(shell=True)` on the host | Default (no flags) |
| `DockerExecutor` | `docker exec` inside a disposable container | `--safe-mode` |

Both executors implement the same interface: `execute(command, cwd=None) → (output, status, new_cwd)` and `cleanup()`.

### Safe Mode (Docker Sandbox)

Pass `--safe-mode` to run all commands inside an isolated Docker container instead of directly on the host:

```bash
python3 sysadmin_ai.py --safe-mode
```

This starts a disposable `ubuntu:22.04` container named `sysadmin-ai-<SESSION_ID>` that is automatically removed when the session ends. Requires Docker to be installed and running.

- Commands execute via `docker exec` — the host filesystem is never touched
- CWD tracking works via appended `pwd` (Linux-only containers)
- The safety filter still runs on the host side before any command reaches the container
- If Docker is not installed or not running, a clear `RuntimeError` is raised at startup

## Command Safety Filter

Every command the LLM requests goes through a two-tier safety check before execution:

- **Blocklist** — 40+ regex patterns that unconditionally reject dangerous commands. Blocked commands are never executed.
- **Graylist** — commands that are risky but sometimes legitimate prompt the user for `y/N` confirmation before running.

Both tiers include OS-specific patterns:

| Category | Linux / macOS | Windows |
|----------|--------------|---------|
| Destructive ops | `rm -rf /`, `mkfs`, `dd`, `shred` | `format C:`, `del /s`, `rd /s`, `diskpart`, `Remove-Item -Recurse` |
| System sabotage | `chmod 000`, `kill -9 1`, `shutdown` | `Stop-Computer`, `bcdedit`, `reg delete HKLM` |
| Credential access | `cat /etc/shadow`, SSH keys | SAM/NTDS dump, `mimikatz`, Wi-Fi passwords |
| Privilege escalation | `sudo su`, SUID/SGID | Admin account creation, UAC bypass |
| Network attacks | `curl \| bash`, reverse shells | `Invoke-WebRequest \| Invoke-Expression` |
| Firewall | `iptables -F`, `ufw disable` | `netsh advfirewall ... off`, Defender disable |
| Kernel/boot | `modprobe`, `grub-install` | `bcdedit` |
| macOS-specific | `csrutil disable`, `nvram` | — |

### soul.md

Safety rules from `soul.md` (if present in the script directory) are loaded into the LLM's system prompt so the AI is aware of the constraints at runtime. The file is organized into sections:

- **All Platforms** — network attacks, credential exfiltration
- **Linux / macOS** — destructive ops, system sabotage, firewall, privilege escalation, kernel/boot
- **macOS-Specific** — SIP, nvram, `/System` protections
- **Windows** — format, diskpart, registry, SAM, Defender, UAC, firewall
- **File I/O Tools** — prefer `read_file`/`write_file` over shell, blocked write paths, read-before-write
- **Required Behavior** — OS-appropriate safe practices (`--dry-run` on Unix, `-WhatIf` on PowerShell)

## Native File I/O Tools

In addition to shell commands, the AI has dedicated `read_file` and `write_file` tools that use Python I/O directly. These bypass the shell entirely, eliminating quoting/escaping issues that plague `echo "content" > file.conf` and `cat` with unusual encodings.

| Tool | What it does | Why it's better than shell |
|------|-------------|---------------------------|
| `read_file` | Reads a file via Python `open()` | No encoding crashes, handles binary detection, truncates large files |
| `write_file` | Writes content via Python `open()` | No shell escaping — quotes, backticks, and backslashes are written verbatim |

Both tools resolve relative paths against the tracked CWD (`shell_state["cwd"]`), so `cd /etc` followed by `read_file nginx/nginx.conf` reads `/etc/nginx/nginx.conf`.

The system prompt instructs the AI to prefer these tools over `cat`/`echo >` for file operations.

### File I/O safety

File tools have their own safety checks, mirroring the shell command safety filter:

**Read safety** — blocks reading credential files that the shell blocklist also protects:
- `/etc/shadow`, `/etc/gshadow` (password hashes)
- `.ssh/id_*` (SSH private keys)
- `/etc/ssh/ssh_host_*` (SSH host keys)
- SAM database paths (Windows)
- Keychain files (macOS)

**Write safety** — two-tier blocked/confirm system:

| Tier | Paths | Action |
|------|-------|--------|
| Blocked | `/bin/`, `/sbin/`, `/usr/bin/`, `/boot/`, `/proc/`, `/sys/`, `/dev/`, `C:\Windows\`, `C:\Program Files\`, `/System/` (macOS), `/Library/Keychains/` (macOS) | Write rejected unconditionally |
| Blocked | `/etc/passwd`, `/etc/shadow`, `/etc/fstab`, `/etc/gshadow`, `/etc/sudoers` | Write rejected unconditionally |
| Confirm | `/etc/*`, `C:\ProgramData\*`, `/Library/*` (macOS), `/Applications/*` (macOS) | User prompted `y/N` before write |
| Confirm | Any existing file (overwrite) | User prompted `y/N` before write |
| Safe | New files in non-system paths | Write proceeds immediately |

## Structured JSON Logging

Every session automatically writes a structured log file in JSONL format (one JSON object per line) to `~/.sysadmin-ai/logs/session_<YYYYMMDD_HHMMSS>.jsonl`.

### Log redaction

All log entries pass through a redaction filter before being written to disk. Secrets matching known patterns are replaced with `[REDACTED]` so they never appear in plaintext log files.

Redacted patterns include:
- **API keys** — OpenAI (`sk-`), AWS (`AKIA`), Google (`AIza`), GitHub (`ghp_`, `gho_`, `ghs_`, `github_pat_`), GitLab (`glpat-`), Slack (`xoxb-`), Stripe (`sk_live_`, `rk_live_`), Square (`sq0atp-`), HuggingFace (`hf_`), SendGrid (`SG.`)
- **Authorization headers** — `Bearer <token>`
- **Shell secret assignments** — `export PASSWORD=...`, `set API_KEY=...`, `$env:SECRET_TOKEN=...`
- **Private key blocks** — `-----BEGIN RSA PRIVATE KEY-----` (all key types)
- **AWS secret access keys** — `aws_secret_access_key = ...`

Override the log directory with `--log-dir`:

```bash
python3 sysadmin_ai.py --log-dir /tmp/ai-logs
```

### Log event types

| Event | Description |
|-------|-------------|
| `session_start` | Provider, model, base URL, OS, user, executor type, safe_mode flag |
| `user_input` | The user's message |
| `tool_call` | Command the LLM wants to run, plus its reasoning |
| `tool_result` | Command output, exit status, and current working directory |
| `llm_final_response` | The LLM's response after processing tool results |
| `command_blocked` | Command rejected by the safety blocklist |
| `command_denied` | Command rejected by the user (graylist prompt) |
| `read_blocked` | File read rejected by the read safety filter |
| `write_blocked` | File write rejected by the write safety filter |
| `write_denied` | File write rejected by the user (graylist prompt) |
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

## Testing

Run the full test suite:

```bash
python -m pytest tests/ -v
```

54 tests across 8 classes: safety filter, shell execution, PowerShell wrapping, Windows execution, CWD tracking, encoding, message history trimming, and log redaction. One test (Unix `cd` tracking) is automatically skipped on Windows.

## Release Notes

### v0.12.0

- **Native file I/O tools** — new `read_file` and `write_file` tools give the AI safe file operations via Python I/O, bypassing the shell entirely. No more quoting/escaping issues when editing config files. The system prompt instructs the LLM to prefer these over `cat`/`echo >`.
- **Read safety filter** — `read_file` blocks access to credential files (`/etc/shadow`, SSH private keys, SAM database), mirroring the shell blocklist's credential access protections so `read_file` cannot bypass them.
- **Write safety filter** — `write_file` uses the same blocked/confirm/safe pattern as shell commands. Writes to system binaries (`/bin/`, `C:\Windows\`) are unconditionally blocked. Writes to `/etc/` config and overwrites of existing files require `y/N` confirmation. New files in non-system paths proceed immediately.
- **New log events** — `read_blocked`, `write_blocked`, and `write_denied` events for file I/O safety audit trail.

### v0.11.0

- **Executor abstraction layer** — command execution is decoupled from the chat loop via an `Executor` ABC (Strategy Pattern). `HostExecutor` wraps the existing `subprocess.run` logic; `DockerExecutor` runs commands inside a disposable Docker container. The chat loop selects the executor based on CLI flags, with no changes to safety filtering or LLM orchestration.
- **`--safe-mode` CLI flag** — pass `--safe-mode` to run all commands inside an isolated `ubuntu:22.04` Docker container instead of directly on the host. The container is automatically created at startup and removed on exit. Prints a `[SAFE MODE]` banner when active.
- **`DockerExecutor` skeleton** — uses Docker CLI (`docker run -d`, `docker exec`, `docker rm -f`) with no new Python dependencies. CWD tracking via appended `pwd`. Raises `RuntimeError` with a clear message if Docker is not installed or not running.
- **Backward-compatible wrappers** — module-level `run_shell_command()`, `_needs_powershell_wrap()`, and `CWD_SENTINEL` delegate to `HostExecutor`, preserving all existing test imports. Zero test changes required.
- **Extended session logging** — `session_start` event now includes `executor` (class name) and `safe_mode` (boolean) fields.

### v0.10.1

- **Log redaction** — all log entries are now scrubbed for secrets before writing to JSONL. `redact_text()` / `redact_data()` filter 18 regex patterns covering API keys (OpenAI, AWS, Google, GitHub, GitLab, Slack, Stripe, Square, HuggingFace, SendGrid), Bearer tokens, shell secret assignments (`export`/`set`/`$env:`), PEM private key blocks, and AWS secret access keys. Integrated at the `log_event()` chokepoint so every event is filtered.
- **24 new redaction tests** — `TestRedaction` class covers all 18 patterns plus safe-text passthrough and recursive `redact_data()` on dicts/lists. Total: 54 tests across 8 classes.

### v0.10.0

- **Persistent test suite** — 30 tests across 7 classes (`TestSafetyFilter`, `TestRunShellCommand`, `TestNeedsPowershellWrap`, `TestWindowsExecution`, `TestCWDTracking`, `TestEncoding`, `TestTrimMessageHistory`) covering all core functionality. Run with `python -m pytest tests/ -v`.
- **Message history trimming** — new `trim_message_history()` function caps the conversation at `MAX_HISTORY_MESSAGES = 80` messages to prevent context window overflow on long sessions. The system prompt is always preserved, and a trim notice is injected so the LLM knows earlier context was dropped.

### v0.9.0

- **Fix Windows encoding crash** — `systeminfo`, `Get-WinEvent`, and other commands that produce locale-specific output would crash with `argument of type 'NoneType' is not iterable`. Replaced `text=True` with explicit `encoding="utf-8", errors="replace"` and added null guards on `stdout`/`stderr`.
- **Auto-wrap bare PowerShell cmdlets** — added `_needs_powershell_wrap()` to detect the `Verb-Noun` pattern (e.g. `Get-Process`, `Set-ExecutionPolicy`) and automatically wrap with `powershell -NoProfile -Command`. Skips commands already prefixed with `powershell` or `pwsh`. No-op on Linux/macOS.
- **Fix Windows CWD tracking** — `\r\n` command chaining does not work under `cmd.exe /c` (only the first line runs). Replaced with `&` chaining using `&&`/`||` to encode the command's exit status in the sentinel output.
- **Fix Windows exit code tracking** — with `&` chaining, `result.returncode` always reflects the last command (`cd`), not the user's command. Exit status is now parsed from the sentinel (`_0` for success, `_1` for failure).
- **Improved Windows system prompt** — updated to instruct the LLM to always use `powershell -command` prefix for PowerShell cmdlets, with explicit warning that bare cmdlets don't work under cmd.exe.

### v0.8.0

- **OS-aware system prompt** — the LLM is now told which OS it's running on and given platform-appropriate command examples (PowerShell/cmd on Windows, shell on Unix)
- **OS-aware tool description** — tool examples adapt to the OS (`systeminfo`, `Get-Process` on Windows vs `df -h`, `ps aux` on Unix)
- **Windows CWD sentinel** — uses `cd` (cmd.exe built-in) instead of `pwd` on Windows for directory tracking
- **Windows safety patterns** — blocklist adds `format`, `del /s`, `rd /s`, `bcdedit`, `diskpart`, `Stop-Computer`, `Remove-Item -Recurse`, `reg delete HKLM`; graylist adds `Restart-Computer`, `Stop-Service`, `Restart-Service`, `net stop`, `reg delete`
- **Restructured soul.md** — safety rules organized into cross-platform, Linux/macOS, macOS-specific, and Windows sections with OS-appropriate guidance (e.g., `-WhatIf` for PowerShell, `--dry-run` for Unix)
- **macOS rules in soul.md** — `csrutil disable`, `nvram` tampering, `/System` and `/Library` protections
- **Windows rules in soul.md** — SAM/NTDS credential dumping, UAC bypass, Defender disable, firewall disable, admin account creation

### v0.7.0

- **Persistent working directory** — the AI's shell now remembers `cd` across commands via Python-side CWD tracking. Each command runs with `subprocess.run(cwd=tracked_cwd)` and a post-command `pwd` sentinel captures directory changes.
- **`shell_state` tracking** — session maintains a state dict starting at `$HOME`. The tracked `cwd` is passed in every user message and logged in `tool_result` events.
- **Sentinel-based pwd capture** — a hidden `__SYSADMIN_AI_PWD__` marker is appended after each command to detect directory changes. The sentinel and its output are stripped from all visible output.
- **`run_shell_command` returns 3-tuple** — now returns `(output, status, new_cwd)` instead of `(output, status)`. `new_cwd` is `None` on timeout/error, preserving the last known directory.

### v0.6.0

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
