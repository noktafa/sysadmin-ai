# SysAdmin AI - Documentation

A CLI chatbot that connects to a cloud LLM (OpenAI) or self-hosted LLM (vLLM) and can execute shell commands on the local machine using function calling (tool use).

## Requirements

- Python 3.8+
- `openai` Python package (`pip install openai`)
- One of:
  - An OpenAI API key (for cloud usage)
  - A running vLLM (or any OpenAI-compatible) API endpoint

## Configuration

The script supports two providers via `--provider`:

| Provider | API Endpoint | Default Model | API Key |
|----------|-------------|---------------|---------|
| `openai` | `https://api.openai.com/v1` | `gpt-4o` | Required (`OPENAI_API_KEY`) |
| `vllm`   | `http://vllm-service-address:8000/v1` | `sysadmin-ai` | `dummy` (no auth) |

### CLI Arguments

```
--provider {openai,vllm}   LLM provider (default: vllm)
--api-base URL              Override API base URL
--api-key KEY               Override API key
--model NAME                Override model name
```

All settings can also be set via environment variables:

| Environment Variable       | Description                          |
|----------------------------|--------------------------------------|
| `SYSADMIN_AI_API_BASE`     | Override base URL for any provider   |
| `SYSADMIN_AI_API_KEY`      | Fallback API key                     |
| `SYSADMIN_AI_MODEL`        | Override model name                  |
| `OPENAI_API_KEY`           | OpenAI API key (used when `--provider openai`) |

Priority: CLI flag > environment variable > provider default.

## Usage

### OpenAI Cloud

```bash
# Using environment variable
export OPENAI_API_KEY="sk-..."
python3 sysadmin_ai.py --provider openai

# Using CLI flag
python3 sysadmin_ai.py --provider openai --api-key sk-...

# With a specific model
python3 sysadmin_ai.py --provider openai --model gpt-4o-mini
```

### Self-hosted vLLM

```bash
# Default vLLM
python3 sysadmin_ai.py

# Custom endpoint
python3 sysadmin_ai.py --api-base http://10.0.0.5:8000/v1 --model Qwen2.5-72B-Instruct
```

- Type natural language queries. The AI will decide whether to run shell commands to answer.
- Type `exit` or `quit` to stop. `Ctrl+C` also works.

### Example Session

```
[SysAdmin AI Connected] provider=openai model=gpt-4o
  endpoint: https://api.openai.com/v1
You: What's the disk usage on this machine?
[EXEC] df -h
AI: Your root partition is 63% full with 45GB free...

You: Show me the last 10 lines of the system log
[EXEC] tail -10 /var/log/syslog
AI: Here are the last 10 log entries...

You: exit
```

## Architecture

```
User Input
    │
    ▼
┌──────────────────────┐  tool_calls  ┌────────────────┐
│  LLM                 │ ──────────►  │ run_shell_cmd  │
│  (OpenAI / vLLM)     │              │ (subprocess)   │
│                      │ ◄────────── │                │
└──────────────────────┘ tool results └────────────────┘
    │
    ▼
 AI Response
```

1. User types a question.
2. The script sends the conversation + system context to the LLM with tool definitions.
3. If the LLM decides it needs to run a command, it returns a `tool_calls` response.
4. The script executes the command(s) locally and feeds results back to the LLM.
5. Steps 3-4 repeat if the LLM needs to chain multiple commands (multi-step reasoning).
6. The LLM produces a final text answer.

## Features

- **Multi-provider Support**: Switch between OpenAI cloud and self-hosted vLLM with `--provider`.
- **Tool/Function Calling**: The LLM autonomously decides when to run shell commands.
- **Multi-step Reasoning**: The tool loop supports chained calls — the LLM can run one command, inspect the result, then run another.
- **Parallel Tool Calls**: If the LLM emits multiple tool calls in one turn, all are executed before the next LLM call.
- **Output Truncation**: Command output is capped at 8000 characters to prevent context window overflow.
- **Timeout Protection**: Commands are killed after 30 seconds.
- **System Context**: The LLM is seeded with OS, user, and directory info on startup.
- **Graceful Exit**: Handles `Ctrl+C`, `EOF`, and `exit`/`quit` commands.
- **CLI Interface**: Full `argparse` support with `--help`, provider selection, and override flags.

## Security Considerations

- **No confirmation prompt by default.** The LLM can run arbitrary commands. To enable user confirmation before each command, uncomment the confirmation block in the source (lines with `confirm = input(...)`).
- **`shell=True`** is used for command execution, which allows shell features (pipes, redirects) but also shell injection. This is by design since the LLM is the only caller.
- **30-second timeout** prevents runaway commands but won't stop a `rm -rf` from completing quickly. Consider running in a sandboxed environment or as a non-privileged user.
- For production use, consider adding a command allowlist/blocklist.

## Release Notes

### v1.2.0 — Safety Layer

- Added `soul.md` — a safety rules file that is loaded into the LLM system prompt on startup
- Blocks destructive commands (`rm -rf /`, `mkfs`, `dd`, fork bombs)
- Blocks credential/data exfiltration (`/etc/shadow`, SSH keys, secrets)
- Blocks privilege escalation (`sudo su`, sudoers modification, SUID bits)
- Blocks network attacks (reverse shells, `curl | bash`, firewall flushing)
- Blocks kernel/boot tampering (`modprobe`, `/boot`, `/sys` writes)
- Enforces read-before-write, explain-before-execute behavior
- Refuses social engineering attempts to bypass rules
- Script exits with error if `soul.md` is missing

### v1.1.0 — Multi-Provider & Cross-Platform

- Added OpenAI cloud API as a provider (`--provider openai`)
- Added CLI arguments via `argparse`: `--provider`, `--api-base`, `--api-key`, `--model`
- Config priority: CLI flag > environment variable > provider default
- API key validation: exits with clear error if OpenAI provider has no key
- Cross-platform support: replaced `uname -sr` with `platform` module
- Added `USERNAME` env var fallback for Windows compatibility
- Fixed variable shadowing bug: `args` was reused for both argparse and tool call JSON

### v1.0.0 — Initial Release

- Interactive CLI chatbot connecting to vLLM (OpenAI-compatible API)
- LLM-driven shell command execution via function calling (tool use)
- Multi-step reasoning: LLM can chain multiple commands in one turn
- Parallel tool call support: multiple tool calls processed before next LLM call
- Output truncation at 8000 characters to protect context window
- 30-second command timeout
- System context injection (OS, user, working directory)
- Graceful exit handling (`Ctrl+C`, `EOF`, `exit`/`quit`)
- Error recovery: API failures print error and continue the session

## Bugs Fixed (from original version)

| # | Bug | Fix |
|---|-----|-----|
| 1 | **Follow-up inside tool loop**: When multiple tool calls were returned, a follow-up API call was made after *each* tool call instead of after *all* were processed. This caused incomplete tool results and duplicate AI responses. | Moved the follow-up API call outside the `for tool_call` loop. |
| 2 | **No multi-step tool chaining**: The follow-up API call did not pass `tools`, so the LLM could not request additional commands after seeing results. | Changed to a `while msg.tool_calls` loop that always passes `tools` to the API. |
| 3 | **No output truncation**: Large command outputs (e.g., `cat` on a big file) could overflow the context window. | Added `MAX_OUTPUT_CHARS = 8000` truncation. |
| 4 | **`EOFError` crash**: Piped input or closed stdin would crash with an unhandled `EOFError`. | Added `EOFError` to the `except` clause on `input()`. |
| 5 | **Hardcoded config**: API base, key, and model were hardcoded with no override mechanism. | Config now reads from environment variables with defaults. |
| 6 | **Generic timeout exception**: `subprocess.TimeoutExpired` was caught by the generic `Exception` handler, giving a less informative message. | Added a specific `except subprocess.TimeoutExpired` handler. |
| 7 | **No API error handling**: Network errors or API failures would crash the loop and kill the session. | Wrapped the API call block in `try/except` to print the error and continue. |
| 8 | **Variable shadowing**: `args` was used for both `argparse` namespace and `json.loads()` tool arguments, which would overwrite CLI args on first tool call. | Renamed tool argument variable to `tool_args`. |
