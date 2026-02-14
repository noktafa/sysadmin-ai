import os
import sys
import re
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

# --- COMMAND SAFETY ---

# Commands that are ALWAYS blocked (never executed)
BLOCKED_PATTERNS = [
    # Destructive operations
    (r"rm\s+(-[a-zA-Z]*)?r[a-zA-Z]*\s+/(\s|$|etc|usr|var|home|boot|sys|proc|dev)", "Recursive deletion of system directory"),
    (r"\bmkfs\b", "Disk format operation"),
    (r"\bdd\s+", "Raw disk write operation"),
    (r"\bshred\b", "File shredding operation"),
    (r"\bwipefs\b", "Filesystem signature wipe"),
    (r"sgdisk\s+--zap", "Partition table destruction"),
    (r":\(\)\s*\{.*\|.*&\s*\}\s*;", "Fork bomb"),
    # System sabotage
    (r"chmod\s+(-[a-zA-Z]*\s+)*(000|777)\s+.*(\/etc|\/usr|\/var|\/boot|\/sys|\/proc|\s+\/\s*$)", "Dangerous permission change on system directory"),
    (r"chown\s+(-[a-zA-Z]*\s+)*\S+\s+/(etc|usr|var|boot|sys|proc)(\s|/|$)", "Ownership change on system directory"),
    (r">\s*/etc/(passwd|shadow|fstab|hosts)", "Overwriting critical system file"),
    (r"kill\s+(-[0-9]*\s+)?-?1$", "Killing init or all processes"),
    (r"\b(shutdown|poweroff|halt)\b", "System shutdown/poweroff"),
    (r"\binit\s+[06]\b", "System halt/reboot via init"),
    # Network attacks
    (r"curl\s+.*\|\s*(ba)?sh", "Remote script execution via curl"),
    (r"wget\s+.*\|\s*(ba)?sh", "Remote script execution via wget"),
    (r"bash\s+-i\s+.*>/dev/tcp", "Reverse shell attempt"),
    (r"\bnc\s+.*-[a-zA-Z]*e\s+/(bin/)?(ba)?sh", "Netcat reverse shell"),
    (r"mkfifo.*nc\s+", "Named pipe reverse shell"),
    # Credential / data exfiltration
    (r"cat\s+.*/etc/(shadow|gshadow)", "Reading password shadow file"),
    (r"cat\s+.*\.ssh/id_", "Reading SSH private key"),
    (r"cat\s+.*/etc/ssh/ssh_host_.*_key(\s|$)", "Reading SSH host private key"),
    # Privilege escalation
    (r"sudo\s+su(\s|$)", "Unrestricted root shell via sudo su"),
    (r"sudo\s+(-\w+\s+)*bash", "Unrestricted root shell via sudo bash"),
    (r"sudo\s+-i", "Unrestricted root shell via sudo -i"),
    (r"chmod\s+[a-zA-Z]*u\+s", "Setting SUID bit"),
    (r"chmod\s+[a-zA-Z]*g\+s", "Setting SGID bit"),
    (r"visudo|.*>/etc/sudoers", "Modifying sudoers"),
    # Kernel / boot tampering
    (r"\b(modprobe|insmod|rmmod)\b", "Kernel module manipulation"),
    (r">\s*/(boot|sys|proc)/", "Writing to boot/sys/proc"),
    (r"\bgrub-install\b", "Bootloader modification"),
    # --- Windows-specific ---
    (r"\bformat\s+[A-Za-z]:", "Disk format operation"),
    (r"\bdel\s+(/[a-zA-Z]+\s+)*[A-Za-z]:[\\\/](Windows|Program Files|Users)", "Recursive deletion of system directory"),
    (r"\brd\s+(/[a-zA-Z]+\s+)*[A-Za-z]:[\\\/](Windows|Program Files|Users)", "Recursive deletion of system directory"),
    (r"\breg\s+delete\s+HKLM", "Registry deletion of machine keys"),
    (r"\bbcdedit\b", "Boot configuration modification"),
    (r"\bdiskpart\b", "Disk partition manipulation"),
    (r"Remove-Item\s+.*[\\\/](Windows|Program Files|Users).*-Recurse|Remove-Item\s+.*-Recurse.*[\\\/](Windows|Program Files|Users)", "Recursive deletion of system directory"),
    (r"\bStop-Computer\b", "System shutdown via PowerShell"),
]

# Commands that require user confirmation before execution
GRAYLIST_PATTERNS = [
    (r"\breboot\b", "System reboot"),
    (r"\bapt\s+(remove|purge)\b", "Package removal"),
    (r"\byum\s+(remove|erase)\b", "Package removal"),
    (r"\bsystemctl\s+(stop|disable|mask)\b", "Service stop/disable"),
    (r"\brm\s+(-[a-zA-Z]*)?r", "Recursive file deletion"),
    (r"\biptables\s+(-[a-zA-Z]*\s+)*-F", "Firewall rule flush"),
    (r"\bufw\s+disable\b", "Firewall disable"),
    (r"\bmv\s+/etc/", "Moving system config file"),
    # --- Windows-specific ---
    (r"\bRestart-Computer\b", "System restart via PowerShell"),
    (r"\bRestart-Service\b", "Service restart via PowerShell"),
    (r"\bStop-Service\b", "Service stop via PowerShell"),
    (r"\bnet\s+stop\b", "Service stop via net"),
    (r"\breg\s+delete\b", "Registry key deletion"),
]


def check_command_safety(command):
    """Check a command against blocklist and graylist.

    Returns:
        ("blocked", reason) - command must not run
        ("confirm", reason) - command needs user confirmation
        ("safe", None)      - command can run freely
    """
    for pattern, reason in BLOCKED_PATTERNS:
        if re.search(pattern, command):
            return "blocked", reason
    for pattern, reason in GRAYLIST_PATTERNS:
        if re.search(pattern, command):
            return "confirm", reason
    return "safe", None


def load_safety_rules():
    """Load soul.md safety rules to include in the system prompt."""
    soul_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "soul.md")
    try:
        with open(soul_path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return ""


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
_IS_WINDOWS = platform.system() == "Windows"

_TOOL_EXAMPLES = (
    "e.g., 'systeminfo', 'Get-Process', 'dir', 'tasklist'"
    if _IS_WINDOWS
    else "e.g., 'cat /var/log/syslog', 'grep error', 'ls -la', 'df -h'"
)

tools = [
    {
        "type": "function",
        "function": {
            "name": "run_shell_command",
            "description": (
                "Executes a shell command on the local machine and returns the output. "
                "Use this to inspect files, check processes, or fix issues."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": f"The shell command to execute ({_TOOL_EXAMPLES})"
                    }
                },
                "required": ["command"]
            }
        }
    }
]

CWD_SENTINEL = "__SYSADMIN_AI_PWD__"


def _needs_powershell_wrap(command):
    """Detect bare PowerShell cmdlets that need wrapping for cmd.exe.

    On Windows, shell=True runs through cmd.exe. PowerShell cmdlets like
    Get-Process, Get-Service, etc. must be wrapped with 'powershell -command'
    to execute correctly.  Commands already prefixed with 'powershell' or
    'pwsh' are left untouched.
    """
    if not _IS_WINDOWS:
        return False
    stripped = command.strip()
    # Already wrapped — nothing to do
    if re.match(r"(?i)^(powershell|pwsh)\b", stripped):
        return False
    # Heuristic: line starts with a known Verb-Noun PowerShell cmdlet pattern
    if re.match(r"^[A-Z][a-z]+-[A-Z][a-zA-Z]+", stripped):
        return True
    return False


def run_shell_command(command, cwd=None):
    """Executes a command and returns (output, status, new_cwd).

    Appends a pwd sentinel after the command to track directory changes.
    ``new_cwd`` is the working directory after the command ran, or None if
    it could not be determined.
    """
    # Auto-wrap bare PowerShell cmdlets so they work under cmd.exe
    if _needs_powershell_wrap(command):
        command = f'powershell -NoProfile -Command "{command}"'

    print(f"\033[93m[EXEC]\033[0m {command}")
    # Append a sentinel + pwd so we can capture the cwd after the command,
    # even if the command itself calls cd.
    if _IS_WINDOWS:
        # On Windows, \r\n chaining does NOT work under cmd.exe /c — only
        # the first line runs.  Use & (unconditional chaining) instead.
        # To preserve the command's exit status we use && / || to encode
        # success (0) or failure (1) in the sentinel output.
        wrapped = (
            f"{command} "
            f"&& (echo {CWD_SENTINEL}_0 & cd) "
            f"|| (echo {CWD_SENTINEL}_1 & cd)"
        )
    else:
        wrapped = f"{command}\n__exit=$?\necho {CWD_SENTINEL}\npwd\nexit $__exit"
    try:
        result = subprocess.run(
            wrapped, shell=True, capture_output=True, timeout=30,
            cwd=cwd, encoding="utf-8", errors="replace",
        )
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        new_cwd = None
        cmd_failed = False

        # Extract the post-command cwd and exit status from the sentinel
        if CWD_SENTINEL in stdout:
            before, _, after = stdout.partition(CWD_SENTINEL)
            lines = after.strip().split("\n")
            # First token after sentinel is _0 (success) or _1 (failure)
            status_token = lines[0].strip() if lines else ""
            if status_token == "_1":
                cmd_failed = True
            # Next line is the cwd from the 'cd' / 'pwd' command
            if len(lines) > 1:
                pwd_line = lines[1].strip()
                if pwd_line and os.path.isabs(pwd_line):
                    new_cwd = pwd_line
            stdout = before  # Remove the sentinel and pwd from visible output

        output = stdout + stderr
        if not output.strip():
            output = "(No output)"
        elif len(output) > MAX_OUTPUT_CHARS:
            output = output[:MAX_OUTPUT_CHARS] + f"\n... (truncated, {len(output)} chars total)"

        if _IS_WINDOWS:
            # Use the sentinel-encoded exit status (more reliable than
            # result.returncode which reflects the last chained command).
            status = "exit_1" if cmd_failed else "success"
        else:
            status = "success" if result.returncode == 0 else f"exit_{result.returncode}"
        return output, status, new_cwd
    except subprocess.TimeoutExpired:
        return "Error: Command timed out after 30 seconds.", "timeout", None
    except Exception as e:
        return f"Error executing command: {str(e)}", "error", None

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

    safety_rules = load_safety_rules()
    os_name = platform.system()
    system_prompt = (
        "You are an expert System Administrator AI. "
        "You are running LOCALLY on the user's machine. "
        f"The operating system is {os_name}. "
        "You have access to a 'run_shell_command' tool that executes shell commands. "
    )
    if os_name == "Windows":
        system_prompt += (
            "Use Windows commands (cmd.exe and PowerShell). "
            "IMPORTANT: For PowerShell cmdlets, always prefix with 'powershell -command', "
            "e.g. 'powershell -command \"Get-Process\"'. "
            "Bare cmdlets like 'Get-Process' will NOT work because the shell is cmd.exe. "
            "Examples: 'systeminfo', 'powershell -command \"Get-Process\"', "
            "'powershell -command \"Get-Service\"', 'tasklist', 'wmic cpu get loadpercentage'. "
        )
    else:
        system_prompt += (
            "Use appropriate shell commands for the OS. "
            "Examples: 'top -bn1', 'df -h', 'ps aux', 'cat /var/log/syslog'. "
        )
    system_prompt += (
        "When asked to analyze or fix something, USE THE TOOL to inspect the system state first. "
        "Do not hallucinate file contents. Run commands to read them."
    )
    if safety_rules:
        system_prompt += "\n\n" + safety_rules

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": "I am ready. " + get_system_context()}
    ]

    # Shell state tracking — cwd persists across commands
    shell_state = {"cwd": str(Path.home())}

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
        messages.append({"role": "user", "content": f"(CWD: {shell_state['cwd']}) {user_input}"})

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

                        # --- Safety check ---
                        safety, reason = check_command_safety(cmd)

                        if safety == "blocked":
                            cmd_result = f"BLOCKED: Command rejected by safety filter — {reason}. Do NOT attempt this command again."
                            status = "blocked"
                            print(f"\033[91m[BLOCKED]\033[0m {cmd}  ({reason})")
                            log_event(logger, "command_blocked", {
                                "command": cmd, "reason": reason,
                                "tool_call_id": tool_call.id,
                            })
                        elif safety == "confirm":
                            print(f"\033[93m[WARNING]\033[0m {cmd}")
                            print(f"  Reason: {reason}")
                            try:
                                answer = input("  Allow this command? (y/N): ").strip().lower()
                            except (KeyboardInterrupt, EOFError):
                                answer = "n"
                            if answer == "y":
                                cmd_result, status, new_cwd = run_shell_command(cmd, cwd=shell_state["cwd"])
                                if new_cwd:
                                    shell_state["cwd"] = new_cwd
                                log_event(logger, "tool_result", {
                                    "command": cmd, "output": cmd_result,
                                    "status": status, "cwd": shell_state["cwd"],
                                    "tool_call_id": tool_call.id,
                                })
                            else:
                                cmd_result = f"DENIED: User rejected this command — {reason}."
                                status = "denied"
                                print(f"\033[91m[DENIED]\033[0m Command rejected by user.")
                                log_event(logger, "command_denied", {
                                    "command": cmd, "reason": reason,
                                    "tool_call_id": tool_call.id,
                                })
                        else:
                            cmd_result, status, new_cwd = run_shell_command(cmd, cwd=shell_state["cwd"])
                            if new_cwd:
                                shell_state["cwd"] = new_cwd
                            log_event(logger, "tool_result", {
                                "command": cmd, "output": cmd_result,
                                "status": status, "cwd": shell_state["cwd"],
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
