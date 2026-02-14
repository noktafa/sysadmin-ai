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
