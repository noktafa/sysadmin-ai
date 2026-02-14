import os
import sys
import platform
import argparse
import subprocess
import json
from openai import OpenAI

# --- SETTINGS ---
MAX_OUTPUT_CHARS = 8000  # Truncate long command output to protect context window

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
    """Executes a command and returns its output (truncated if too long)."""
    print(f"\033[93m[EXEC]\033[0m {command}")
    try:
        result = subprocess.run(
            command, shell=True, text=True, capture_output=True, timeout=30
        )
        output = result.stdout + result.stderr
        if not output.strip():
            return "(No output)"
        if len(output) > MAX_OUTPUT_CHARS:
            return output[:MAX_OUTPUT_CHARS] + f"\n... (truncated, {len(output)} chars total)"
        return output
    except subprocess.TimeoutExpired:
        return "Error: Command timed out after 30 seconds."
    except Exception as e:
        return f"Error executing command: {str(e)}"

# --- CHAT LOOP ---
def chat_loop():
    args = parse_args()
    client, model_name, base_url = build_client(args)

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
                for tool_call in msg.tool_calls:
                    if tool_call.function.name == "run_shell_command":
                        tool_args = json.loads(tool_call.function.arguments)
                        cmd = tool_args.get("command", "")
                        cmd_result = run_shell_command(cmd)
                    else:
                        cmd_result = f"Error: Unknown tool '{tool_call.function.name}'"

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

        except Exception as e:
            print(f"\033[91m[ERROR]\033[0m API call failed: {e}")

if __name__ == "__main__":
    chat_loop()
