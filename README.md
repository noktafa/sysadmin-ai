<div align="center">

<img src="logo.png" alt="SysAdmin AI" width="256">

# SysAdmin AI

**Stateless Executor / Context-Aware Administration Interface**

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)](#)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-informational)](#)
[![License](https://img.shields.io/badge/License-MIT-green)](#)

</div>

---

> **TR** &mdash; SysAdmin AI; tasarımında operasyonel güvenliği ve sunucu bütünlüğünü otonom yeteneklerin önünde tutan, durumsuz yürütücü (stateless executor) tabanlı bir yönetim arayüzüdür. Bu yapısına rağmen sahip olduğu bağlam farkındalığı (context-aware) sayesinde; her komutu bağımsız bir yalıtılmış alan (sandbox) veya ana makine süreci (host process) içerisinde yürüterek öngörülebilir bir yönetim katmanı sağlar.

> **EN** &mdash; SysAdmin AI is a stateless-executor-based administration interface that prioritizes operational safety and server integrity over autonomous capabilities. Despite this stateless architecture, its context-aware design executes every command within an independent sandbox or host process, providing a predictable and auditable management layer.

### Key Design Principles

| Principle | Implementation |
|-----------|---------------|
| **Stateless execution** | Each command runs in an isolated `subprocess` &mdash; no persistent shell, no accumulated hidden state |
| **Context awareness** | Python-side CWD tracking + session state gives the feel of a persistent shell without the risks |
| **Safety-first** | Two-tier blocklist/graylist filter with 96 regex patterns intercepts dangerous commands before execution |
| **Triple execution backends** | `HostExecutor` (direct subprocess), `DockerExecutor` (disposable container), or `KubernetesExecutor` (ephemeral K8s pod) via Strategy Pattern |
| **Native file I/O** | Dedicated `read_file` / `write_file` tools bypass the shell entirely &mdash; no escaping issues |
| **Audit trail** | Structured JSONL logging with automatic secret redaction (19 patterns), optional stderr output for K8s log aggregators |
| **Kubernetes-ready** | Health endpoints (`/healthz`, `/readyz`), SIGTERM graceful shutdown, K8s-specific security filters, deployment manifests |
| **Cross-platform** | OS-aware safety rules, prompts, and command wrapping for Linux, macOS, and Windows |

### Architecture Overview

```
User ──> LLM (OpenAI / vLLM) ──> Safety Filter ──> Executor ──> OS
              │                     │                  │
              │                     │           ┌──────┼──────────────┐
              │                     │      HostExecutor │    KubernetesExecutor
              │                     │      (subprocess) │    (K8s pod exec)
              │                     │            DockerExecutor
              │                     │            (docker exec)
              │               Blocklist (reject)
              │               Graylist  (confirm)
              │
         read_file / write_file ──> Python I/O (no shell)

Health: /healthz + /readyz (background thread, port 8080)
Logs:   JSONL file + stderr (auto in K8s)
```

---

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
| `--safe-mode` | Run commands inside a Docker container (or K8s pod if running in Kubernetes) instead of directly on the host |
| `--log-stdout` | Also emit structured JSON logs to stderr (auto-enabled in K8s) |
| `--health-port PORT` | Port for `/healthz` and `/readyz` endpoints (default: `8080`, `0` to disable) |

### Environment Variables

- `SYSADMIN_AI_API_KEY` / `OPENAI_API_KEY` — API key
- `SYSADMIN_AI_API_BASE` — API base URL override
- `SYSADMIN_AI_MODEL` — Model name override
- `KUBERNETES_SERVICE_HOST` — Auto-detected in K8s pods; enables stderr logging and health endpoint

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
| `DockerExecutor` | `docker exec` inside a disposable container | `--safe-mode` on bare host |
| `KubernetesExecutor` | `kubernetes.stream` exec into ephemeral pod | `--safe-mode` inside a K8s pod |

All executors implement the same interface: `execute(command, cwd=None) → (output, status, new_cwd)` and `cleanup()`. When `--safe-mode` is used, the executor is auto-selected based on the environment: `KubernetesExecutor` if `/var/run/secrets/kubernetes.io/serviceaccount` exists, otherwise `DockerExecutor`.

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

### Safe Mode in Kubernetes

When `--safe-mode` is used inside a Kubernetes pod, `KubernetesExecutor` is automatically selected instead of `DockerExecutor`. It creates an ephemeral sandbox pod with:

- Non-root execution (UID 1000), all capabilities dropped
- `automountServiceAccountToken: false` — no access to K8s API
- Auto-detected namespace from the service account mount
- Cleanup: sandbox pod is deleted on exit or SIGTERM

## Command Safety Filter

Every command the LLM requests goes through a two-tier safety check before execution:

- **Blocklist** — 71 regex patterns that unconditionally reject dangerous commands. Blocked commands are never executed.
- **Graylist** — commands that are risky but sometimes legitimate prompt the user for `y/N` confirmation before running.

Both tiers include OS-specific patterns:

| Category | Linux / macOS | Windows |
|----------|--------------|---------|
| Destructive ops | `rm -rf /`, `mkfs`, `dd`, `shred` | `format C:`, `del /s`, `rd /s`, `diskpart`, `Remove-Item -Recurse` |
| System sabotage | `chmod 000`, `kill -9 1`, `shutdown` (command-start only) | `Stop-Computer`, `bcdedit`, `reg delete HKLM` |
| Credential access | `cat /etc/shadow`, SSH keys | SAM/NTDS dump, `mimikatz`, Wi-Fi passwords |
| Privilege escalation | `sudo su`, SUID/SGID | Admin account creation, UAC bypass |
| Network attacks | `curl \| bash`, reverse shells | `Invoke-WebRequest \| Invoke-Expression` |
| Firewall | `iptables -F`, `ufw disable` | `netsh advfirewall ... off`, Defender disable |
| Kernel/boot | `modprobe`, `grub-install` | `bcdedit` |
| Kubernetes | `kubectl delete/drain/exec`, `kubectl get secret`, service account tokens, K8s API curl, `helm delete/uninstall` | — |
| Container escape | Docker socket mount/read, `/proc/*/environ` | — |
| macOS-specific | `csrutil disable`, `nvram` | — |

### soul.md

Safety rules from `soul.md` (if present in the script directory) are loaded into the LLM's system prompt so the AI is aware of the constraints at runtime. The file is organized into sections:

- **All Platforms** — network attacks, credential exfiltration
- **Linux / macOS** — destructive ops, system sabotage, firewall, privilege escalation, kernel/boot
- **macOS-Specific** — SIP, nvram, `/System` protections
- **Windows** — format, diskpart, registry, SAM, Defender, UAC, firewall
- **File I/O Tools** — prefer `read_file`/`write_file` over shell, blocked write paths, read-before-write
- **Domain-Specific Behavioral Guardrails** — 11 sections covering safe approaches to service management, database operations, network configuration, package management, log & disk management, backup & recovery, SSL/TLS certificates, containers & orchestration, Kubernetes environments, cron & scheduled tasks, and user & permission management
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
- `/var/run/secrets/kubernetes.io/` (K8s service account tokens)
- `/proc/self/environ`, `/proc/1/environ` (process environment variables)
- SAM database, NTDS.dit (Windows)
- Keychain files (macOS)

All path matching is case-insensitive and drive-letter-agnostic on Windows (e.g., `D:\WINDOWS\` is caught, not just `C:\Windows\`). On macOS, `/private/etc` is normalized to `/etc` after `realpath` resolution so symlink-based bypasses are prevented.

**Write safety** — two-tier blocked/confirm system:

| Tier | Paths | Action |
|------|-------|--------|
| Blocked | `/bin/`, `/sbin/`, `/usr/bin/`, `/boot/`, `/proc/`, `/sys/`, `/dev/`, `<drive>:\Windows\`, `<drive>:\Program Files\` (any drive letter, case-insensitive), `/System/` (macOS), `/Library/Keychains/` (macOS) | Write rejected unconditionally |
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

When running in Kubernetes (detected via `KUBERNETES_SERVICE_HOST`), logs are also emitted to stderr in JSONL format for integration with Fluentd, Loki, CloudWatch, or other log aggregators. This can also be enabled manually with `--log-stdout`.

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

## Health Endpoints

SysAdmin AI runs a lightweight HTTP server in a background daemon thread for Kubernetes liveness and readiness probes:

| Endpoint | Behavior |
|----------|----------|
| `GET /healthz` | Always returns `200 ok` (liveness) |
| `GET /readyz` | Returns `200 ok` after initialization, `503 not ready` before (readiness) |

The health server starts on port 8080 by default. Disable with `--health-port 0`. Auto-enabled when running in Kubernetes.

## Graceful Shutdown

SysAdmin AI handles `SIGTERM` (sent by Kubernetes on pod eviction) by:

1. Printing a shutdown notice
2. Raising `SystemExit(0)` to trigger the `finally` block
3. Cleaning up the executor (removing sandbox containers/pods)
4. Flushing and closing all log handlers

This ensures no orphaned sandbox pods and complete log capture during rolling updates or node drains.

## Kubernetes Deployment

A complete set of Kubernetes manifests is provided in `k8s/`:

| Manifest | Description |
|----------|-------------|
| `k8s/deployment.yaml` | Deployment with non-root security context, resource limits, health probes, secret envFrom |
| `k8s/service.yaml` | ClusterIP service exposing health port |
| `k8s/networkpolicy.yaml` | Egress restricted to DNS (53), vLLM (8000), HTTPS (443) |
| `k8s/rbac.yaml` | ServiceAccount with `automountServiceAccountToken: false` |
| `k8s/pdb.yaml` | PodDisruptionBudget (minAvailable: 1) |
| `k8s/secret.yaml` | Template for API keys |

### Quick Start

```bash
# Build the image
docker build -t sysadmin-ai .

# Configure your API key
kubectl create secret generic sysadmin-ai-secrets \
  --from-literal=SYSADMIN_AI_API_KEY=your-key-here

# Deploy
kubectl apply -f k8s/
```

### Security Context

The pod runs with a hardened security context:
- `runAsNonRoot: true`, `runAsUser: 1000`
- All capabilities dropped
- No privilege escalation
- Seccomp profile: `RuntimeDefault`
- No service account token mounted
- Network egress restricted via NetworkPolicy

## Testing

Run the full test suite:

```bash
python -m pytest tests/ -v
```

133 tests across 27 classes covering safety filters, shell execution, PowerShell wrapping, Windows execution, CWD tracking, encoding, message history trimming, log redaction, executor abstraction, file I/O, path traversal, symlink safety, platform constants, interpreter evasion blocking, script execution graylist, write content scanning, prompt injection delimiters, and script execution tracking. Windows-only and macOS-only tests are automatically skipped on other platforms.

## Release Notes

### v0.16.0

- **Security hardening layer** — comprehensive defense-in-depth additions to block interpreter evasion, scan file content for dangerous payloads, mitigate prompt injection, and detect write-then-execute attack patterns.
- **Interpreter evasion blocking** — 17 new blocked patterns for `bash -c`, `sh -c`, `python3 -c`, `perl -e`, `ruby -e`, `node -e`, `eval`, base64 pipe to shell/python, PowerShell `Invoke-Expression`/`iex`, `crontab -r`/`-e`, and destructive indirection (`find -exec rm`, `xargs rm`, `find -delete`).
- **Script execution graylist** — 9 new graylist patterns requiring user confirmation for `bash *.sh`, `sh *.sh`, `python3 *.py`, `perl *.pl`, `ruby *.rb`, `node *.js`, `powershell -File`, `source`, and dot-sourcing commands.
- **Write content scanning** — new `_check_write_content_safety()` function with 25 regex patterns that scan file content before writing. Blocks reverse shells, `curl | bash`, credential theft (shadow/SSH/mimikatz/LSASS), destructive operations, fork bombs, SUID escalation, data exfiltration, cron persistence, and PowerShell evasion payloads.
- **Prompt injection delimiters** — `_wrap_tool_output()` wraps all tool output in `[BEGIN/END]` delimiters with system prompt instructions telling the LLM to treat delimited content strictly as data, preventing injected instructions in command output from hijacking the conversation.
- **Write-then-execute detection** — tracks files written via `write_file` during the session. If a subsequent `run_shell_command` attempts to execute a recently-written file, it is escalated to user confirmation. `_extract_script_path()` parses script paths from bash, sh, python, perl, ruby, node, powershell, source, and dot commands.
- **133 tests passing** — 27 test classes, up from 110/16 in v0.15.0. New classes: `TestInterpreterEvasionBlocked`, `TestScriptExecutionGraylist`, `TestWriteContentSafety`, `TestPromptInjectionDelimiters`, `TestScriptExecutionTracking`, `TestSafeCommandsNotBroken`.

### v0.15.0

- **Kubernetes-ready production hardening** — complete K8s deployment support with security filters, sandboxed execution, lifecycle management, observability, and deployment manifests.
- **K8s security filters** — 14 new blocked patterns for `kubectl` destructive operations (`delete`, `drain`, `exec`, `get secret`), Helm destructive ops, service account token reads, Docker socket access, and `/proc/*/environ` reads. 2 new graylist patterns for `kubectl scale` and `kubectl rollout restart`. Read safety filter extended to block `/var/run/secrets/kubernetes.io/`, `/proc/self/environ`, and `/proc/1/environ`.
- **KubernetesExecutor** — new `Executor` subclass that creates an ephemeral sandbox pod using the `kubernetes` Python client. The pod runs as non-root (UID 1000), drops all capabilities, and disables service account token mounting. Commands execute via `kubernetes.stream` exec. Auto-selected when `--safe-mode` is used inside a K8s pod.
- **SIGTERM graceful shutdown** — signal handler raises `SystemExit(0)` on `SIGTERM`, triggering executor cleanup and log flush via the existing `finally` block. Ensures clean pod eviction during rolling updates or node drains.
- **Structured stderr logging** — when running in Kubernetes (auto-detected via `KUBERNETES_SERVICE_HOST`) or with `--log-stdout`, structured JSONL logs are also emitted to stderr for integration with Fluentd, Loki, CloudWatch, and other log aggregators. Existing file logging is preserved.
- **Health endpoints** — lightweight HTTP server in a daemon thread serves `/healthz` (liveness, always 200) and `/readyz` (readiness, 200 after init). Configurable via `--health-port` (default: 8080, 0 to disable).
- **Dockerfile** — minimal `python:3.12-slim` image, non-root user, no kubectl/docker/curl binaries. Exposes port 8080 for health probes.
- **Kubernetes manifests** — `k8s/` directory with Deployment (hardened security context, resource limits, probes), Service, NetworkPolicy (egress restricted to DNS/vLLM/HTTPS), RBAC (no service account token), PDB, and Secret template.
- **soul.md K8s guardrails** — new "Kubernetes Environment" section with behavioral rules for service account tokens, K8s API access, `kubectl` operations, resource limits, and ConfigMap/Secret safety.
- **New CLI flags** — `--log-stdout`, `--health-port`
- **New dependency** — `kubernetes>=28.0.0` (required only for K8s executor)

### v0.14.0

- **Domain-specific behavioral guardrails** — 10 new sections in `soul.md` encoding safe approaches to common sysadmin tasks. These go beyond command blocklists to define *how* the AI should approach service management, database operations, network changes, package management, log/disk cleanup, backups, SSL/TLS certificates, containers, cron jobs, and user/permission management. Examples: check dependent services before stopping one, ask about backups before destructive operations, validate config syntax before restarting services, warn about session disconnection before network changes.

### v0.13.0

- **Fix subshell CWD bug in both executors** — `HostExecutor` and `DockerExecutor` wrapped commands in a subshell `(command)`, which discarded `cd` side-effects before `pwd` ran. Commands now run without subshell wrapping, using `$?` to capture exit status instead.
- **Case-insensitive path safety on Windows** — `_check_read_safety` and `_check_write_safety` now compare paths case-insensitively. `D:\WINDOWS\system32` and `c:\windows\System32` are both correctly blocked.
- **Drive-letter-agnostic write safety** — Windows write safety no longer hardcodes `C:`. Any drive letter (`D:\Windows\`, `E:\Program Files\`) is caught by stripping the drive prefix before matching.
- **NTDS.dit added to read blocklist** — the Windows Active Directory credential database is now blocked alongside SAM.
- **macOS `/private/etc` normalization** — after `realpath` resolves `/etc` → `/private/etc` on macOS, both safety checkers strip the `/private` prefix so rules for `/etc/shadow`, `/etc/passwd` etc. still match.
- **Shutdown pattern narrowed** — `shutdown`, `poweroff`, `halt` are now only blocked when they appear at the start of a command (with optional `sudo` prefix). `grep shutdown /var/log/syslog` and `journalctl | grep halt` are no longer false-positived.
- **110 tests passing** — test suite updated to match new sentinel format; all symlink, path traversal, and safety tests pass on Linux, macOS, and Windows.

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
