import os
import sys
import platform
import argparse
import subprocess
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from openai import OpenAI

# --- SETTINGS ---
MAX_OUTPUT_CHARS = 8000  # Truncate long command output to protect context window
DEFAULT_LOG_DIR = os.path.join(Path.home(), ".sysadmin-ai", "logs")

# Provider presets: (base_url, default_model, env_key_var)
PROVIDERS = {
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "default_model": "gpt-4o",
        "api_key_env": "OPENAI_API_KEY",
    },
    "vllm": {
        "base_url": "http://vllm-service-address:8000/v1",
        "default_model": "sysadmin-ai",
        "api_key_env": "SYSADMIN_AI_API_KEY",
    },
}


SESSION_ID = datetime.now().strftime("%Y%m%d_%H%M%S")


class JSONLFormatter(logging.Formatter):
    """Formats log records as single-line JSON objects (JSONL)."""

    def format(self, record):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": SESSION_ID,
            "event": record.msg if isinstance(record.msg, str) else "unknown",
            "data": record.__dict__.get("data", {}),
        }
        return json.dumps(entry, default=str)


def setup_logging(log_dir=None):
    """Configure a JSONL file logger for the session.

    Returns the logger instance. Each session writes to a separate file:
    ``<log_dir>/session_<YYYYMMDD_HHMMSS>.jsonl``
    """
    log_dir = log_dir or DEFAULT_LOG_DIR
    os.makedirs(log_dir, exist_ok=True)

    log_file = os.path.join(log_dir, f"session_{SESSION_ID}.jsonl")

    logger = logging.getLogger("sysadmin_ai")
    logger.setLevel(logging.INFO)
    logger.propagate = False  # Don't send to root / stdout

    handler = logging.FileHandler(log_file, encoding="utf-8")
    handler.setFormatter(JSONLFormatter())
    logger.addHandler(handler)

    return logger


def log_event(logger, event, data=None):
    """Emit a structured log entry."""
    record = logger.makeRecord(
        name="sysadmin_ai",
        level=logging.INFO,
        fn="",
        lno=0,
        msg=event,
        args=(),
        exc_info=None,
    )
    record.data = data or {}
    logger.handle(record)


def build_client(args):
    """Build the OpenAI client from CLI args, env vars, and provider defaults."""
    provider = args.provider
    preset = PROVIDERS.get(provider, PROVIDERS["vllm"])

    api_key = args.api_key or os.environ.get(preset["api_key_env"]) or os.environ.get("SYSADMIN_AI_API_KEY", "dummy")
    base_url = args.api_base or os.environ.get("SYSADMIN_AI_API_BASE", preset["base_url"])
    model = args.model or os.environ.get("SYSADMIN_AI_MODEL", preset["default_model"])

    # OpenAI cloud requires a real key
    if provider == "openai" and api_key == "dummy":
        print("\033[91m[ERROR]\033[0m OpenAI provider requires an API key.")
        print("Set OPENAI_API_KEY or pass --api-key.")
        sys.exit(1)

    client = OpenAI(base_url=base_url, api_key=api_key)
    return client, model, base_url


def parse_args():
    parser = argparse.ArgumentParser(
        description="SysAdmin AI - LLM-powered system administration assistant"
    )
    parser.add_argument(
        "--provider", choices=list(PROVIDERS.keys()), default="vllm",
        help="LLM provider: 'openai' for OpenAI cloud API, 'vllm' for self-hosted vLLM (default: vllm)"
    )
    parser.add_argument("--api-base", help="Override API base URL")
    parser.add_argument("--api-key", help="Override API key")
    parser.add_argument("--model", help="Override model name")
    parser.add_argument("--log-dir", help=f"Override log directory (default: {DEFAULT_LOG_DIR})")
    return parser.parse_args()

# --- SYSTEM CONTEXT ---
def get_system_context():
    """Gathers current system info to feed the LLM."""
    return (
        "SYSTEM CONTEXT:\n"
        f"- OS: {platform.system()} {platform.release()}\n"
        f"- User: {os.environ.get('USER') or os.environ.get('USERNAME', 'unknown')}\n"
        f"- Current Dir: {os.getcwd()}\n"
        f"- Files in Dir: {str(os.listdir('.'))[:500]} ... (truncated)"
    )

# --- TOOLS ---
tools = [
    {
        "type": "function",
        "function": {
            "name": "run_shell_command",
            "description": "Executes a shell command on the local machine and returns the output. Use this to inspect files, check processes, or fix issues.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute (e.g., 'cat /var/log/syslog', 'grep error', 'ls -la')"
                    }
                },
                "required": ["command"]
            }
        }
    }
]

def run_shell_command(command):
    """Executes a command and returns (output, status) where status is
    'success', 'timeout', or 'error'."""
    print(f"\033[93m[EXEC]\033[0m {command}")
    try:
        result = subprocess.run(
            command, shell=True, text=True, capture_output=True, timeout=30
        )
        output = result.stdout + result.stderr
        if not output.strip():
            output = "(No output)"
        elif len(output) > MAX_OUTPUT_CHARS:
            output = output[:MAX_OUTPUT_CHARS] + f"\n... (truncated, {len(output)} chars total)"
        return output, "success" if result.returncode == 0 else f"exit_{result.returncode}"
    except subprocess.TimeoutExpired:
        return "Error: Command timed out after 30 seconds.", "timeout"
    except Exception as e:
        return f"Error executing command: {str(e)}", "error"

# --- CHAT LOOP ---
def chat_loop():
    args = parse_args()
    client, model_name, base_url = build_client(args)
    logger = setup_logging(args.log_dir)

    log_event(logger, "session_start", {
        "provider": args.provider,
        "model": model_name,
        "base_url": base_url,
        "os": f"{platform.system()} {platform.release()}",
        "user": os.environ.get("USER") or os.environ.get("USERNAME", "unknown"),
    })

    messages = [
        {
            "role": "system",
            "content": (
                "You are an expert Linux System Administrator AI. "
                "You are running LOCALLY on the user's machine. "
                "You have access to a 'run_shell_command' tool. "
                "When asked to analyze or fix something, USE THE TOOL to inspect the system state first. "
                "Do not hallucinate file contents. Run commands to read them."
            )
        },
        {"role": "user", "content": "I am ready. " + get_system_context()}
    ]

    print(f"\033[92m[SysAdmin AI Connected]\033[0m provider=\033[96m{args.provider}\033[0m model=\033[96m{model_name}\033[0m")
    print(f"\033[90m  endpoint: {base_url}\033[0m")

    while True:
        try:
            user_input = input("\033[94mYou:\033[0m ")
        except (KeyboardInterrupt, EOFError):
            print("\nExiting...")
            break

        if user_input.lower() in ['exit', 'quit']:
            break

        log_event(logger, "user_input", {"message": user_input})
        messages.append({"role": "user", "content": f"(CWD: {os.getcwd()}) {user_input}"})

        try:
            # Request completion with tool support
            response = client.chat.completions.create(
                model=model_name,
                messages=messages,
                tools=tools,
                tool_choice="auto"
            )
            msg = response.choices[0].message
            messages.append(msg)

            # Process tool calls in a loop to support multi-step reasoning
            while msg.tool_calls:
                # Extract reasoning text that may precede tool calls
                reasoning = msg.content or ""

                for tool_call in msg.tool_calls:
                    if tool_call.function.name == "run_shell_command":
                        tool_args = json.loads(tool_call.function.arguments)
                        cmd = tool_args.get("command", "")

                        log_event(logger, "tool_call", {
                            "command": cmd,
                            "reasoning": reasoning,
                            "tool_call_id": tool_call.id,
                        })

                        cmd_result, status = run_shell_command(cmd)

                        log_event(logger, "tool_result", {
                            "command": cmd,
                            "output": cmd_result,
                            "status": status,
                            "tool_call_id": tool_call.id,
                        })
                    else:
                        cmd_result = f"Error: Unknown tool '{tool_call.function.name}'"
                        status = "error"

                    messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": cmd_result
                    })

                # Let the LLM process all tool results and decide next action
                response = client.chat.completions.create(
                    model=model_name,
                    messages=messages,
                    tools=tools,
                    tool_choice="auto"
                )
                msg = response.choices[0].message
                messages.append(msg)

            # Print the final text response
            if msg.content:
                print(f"\033[92mAI:\033[0m {msg.content}")
                log_event(logger, "llm_final_response", {"content": msg.content})
            else:
                log_event(logger, "llm_response", {"content": None})

        except Exception as e:
            print(f"\033[91m[ERROR]\033[0m API call failed: {e}")
            log_event(logger, "error", {"error": str(e), "type": type(e).__name__})

if __name__ == "__main__":
    chat_loop()
