import os
import sys
import re
import platform
import argparse
import subprocess
import json
import logging
from datetime import datetime, timezone
from abc import ABC, abstractmethod
from pathlib import Path
from openai import OpenAI

# --- SETTINGS ---
MAX_OUTPUT_CHARS = 8000  # Truncate long command output to protect context window
MAX_HISTORY_MESSAGES = 80  # Trim older messages to stay within context limits
DEFAULT_LOG_DIR = os.path.join(Path.home(), ".sysadmin-ai", "logs")
_IS_WINDOWS = platform.system() == "Windows"
_IS_MACOS = platform.system() == "Darwin"

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


REDACT_PLACEHOLDER = "[REDACTED]"

# Patterns that match secrets/credentials in free text.
# Each tuple: (compiled_regex, description_for_testing).
_REDACT_PATTERNS = [
    # --- API keys / tokens (known prefixes) ---
    (re.compile(r"sk-[A-Za-z0-9_-]{20,}"),            "OpenAI API key"),
    (re.compile(r"sk-proj-[A-Za-z0-9_-]{20,}"),       "OpenAI project key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"),                  "AWS Access Key ID"),
    (re.compile(r"AIza[A-Za-z0-9_-]{35}"),             "Google API key"),
    (re.compile(r"ghp_[A-Za-z0-9]{36,}"),              "GitHub PAT"),
    (re.compile(r"gho_[A-Za-z0-9]{36,}"),              "GitHub OAuth token"),
    (re.compile(r"ghs_[A-Za-z0-9]{36,}"),              "GitHub App token"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),      "GitHub fine-grained PAT"),
    (re.compile(r"glpat-[A-Za-z0-9_-]{20,}"),          "GitLab PAT"),
    (re.compile(r"xox[bpors]-[A-Za-z0-9-]{10,}"),     "Slack token"),
    (re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"), "SendGrid API key"),
    (re.compile(r"sk_live_[A-Za-z0-9]{24,}"),          "Stripe secret key"),
    (re.compile(r"rk_live_[A-Za-z0-9]{24,}"),          "Stripe restricted key"),
    (re.compile(r"sq0atp-[A-Za-z0-9_-]{22,}"),         "Square access token"),
    (re.compile(r"hf_[A-Za-z0-9]{34,}"),               "HuggingFace token"),
    # --- Generic high-entropy tokens (Bearer, Authorization headers) ---
    (re.compile(r"(?i)(Bearer\s+)[A-Za-z0-9_\-.]{20,}"), "Bearer token"),
    # --- Shell variable assignments with secret-looking names ---
    (re.compile(
        r"(?i)(?:export\s+|set\s+|\$env:)"           # export / set / $env:
        r"[A-Za-z_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|APIKEY|CREDENTIALS?|AUTH)"
        r"[A-Za-z_]*"
        r"\s*=\s*"
        r"""('[^']*'|"[^"]*"|\S+)"""                  # the value
    ), "shell secret assignment"),
    # --- Private key blocks ---
    (re.compile(
        r"-----BEGIN[ A-Z]*PRIVATE KEY-----"
        r"[\s\S]*?"
        r"-----END[ A-Z]*PRIVATE KEY-----"
    ), "private key block"),
    # --- AWS Secret Access Key (40-char base64 after known label) ---
    (re.compile(
        r"(?i)(?:aws_secret_access_key|secret_access_key)\s*[=:]\s*[A-Za-z0-9/+=]{40}"
    ), "AWS Secret Access Key"),
]


def redact_text(text):
    """Replace secrets/credentials in *text* with a placeholder."""
    for pattern, _ in _REDACT_PATTERNS:
        text = pattern.sub(REDACT_PLACEHOLDER, text)
    return text


def redact_data(obj):
    """Recursively redact secret values in a dict/list/string."""
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        return {k: redact_data(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_data(item) for item in obj]
    return obj


def log_event(logger, event, data=None):
    """Emit a structured log entry (with secret redaction)."""
    record = logger.makeRecord(
        name="sysadmin_ai",
        level=logging.INFO,
        fn="",
        lno=0,
        msg=event,
        args=(),
        exc_info=None,
    )
    record.data = redact_data(data or {})
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
    parser.add_argument("--safe-mode", action="store_true", default=False,
        help="Run commands inside a Docker container instead of directly on the host")
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
    (r"^\s*(sudo\s+)?(shutdown|poweroff|halt)\b", "System shutdown/poweroff"),
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


# --- EXECUTOR ABSTRACTION ---

class Executor(ABC):
    """Strategy interface for command execution."""

    @abstractmethod
    def execute(self, command, cwd=None):
        """Returns (output, status, new_cwd)."""
        ...

    def cleanup(self):
        pass


class HostExecutor(Executor):
    """Executes commands directly on the host via subprocess."""

    _SENTINEL = "__SYSADMIN_AI_PWD__"

    @staticmethod
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

    def execute(self, command, cwd=None):
        """Executes a command and returns (output, status, new_cwd).

        Appends a pwd sentinel after the command to track directory changes.
        ``new_cwd`` is the working directory after the command ran, or None if
        it could not be determined.
        """
        # Auto-wrap bare PowerShell cmdlets so they work under cmd.exe
        if self._needs_powershell_wrap(command):
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
                f"&& (echo {self._SENTINEL}_0 & cd) "
                f"|| (echo {self._SENTINEL}_1 & cd)"
            )
        else:
            # Use a variable to capture the command's exit status, then
            # emit the sentinel and pwd.  The command must NOT run in a
            # subshell so that 'cd' side-effects are visible to 'pwd'.
            wrapped = (
                f"{command}\n"
                f"__sa_exit=$?\n"
                f'if [ "$__sa_exit" -eq 0 ]; then echo {self._SENTINEL}_0; else echo {self._SENTINEL}_1; fi\n'
                f"pwd\n"
                f"exit $__sa_exit"
            )
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
            if self._SENTINEL in stdout:
                before, _, after = stdout.partition(self._SENTINEL)
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

            # Both platforms encode exit status in the sentinel (_0 / _1),
            # which is more reliable than result.returncode (always reflects
            # the last chained command, not the user's command).
            status = "exit_1" if cmd_failed else "success"
            return output, status, new_cwd
        except subprocess.TimeoutExpired:
            return "Error: Command timed out after 30 seconds.", "timeout", None
        except Exception as e:
            return f"Error executing command: {str(e)}", "error", None


class DockerExecutor(Executor):
    """Runs commands inside a disposable Docker container (--safe-mode)."""

    _SENTINEL = "__DOCKER_PWD__"

    def __init__(self):
        # Verify Docker is available
        try:
            subprocess.run(
                ["docker", "info"], capture_output=True, check=True, timeout=10,
            )
        except FileNotFoundError:
            raise RuntimeError(
                "Docker is not installed. Install Docker to use --safe-mode."
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(
                f"Docker is not running or not accessible: {e.stderr or e}"
            )

        self._container = f"sysadmin-ai-{SESSION_ID}"
        subprocess.run(
            ["docker", "run", "-d", "--name", self._container,
             "ubuntu:22.04", "sleep", "infinity"],
            capture_output=True, check=True, timeout=60,
        )

    def execute(self, command, cwd=None):
        """Executes a command inside the Docker container."""
        cwd = cwd or "/root"
        # Append pwd to track directory changes.
        # Do NOT wrap in a subshell — cd must be visible to pwd.
        wrapped = (
            f"{command}\n"
            f"__sa_exit=$?\n"
            f"echo {self._SENTINEL}\n"
            f"pwd\n"
            f"exit $__sa_exit"
        )
        print(f"\033[93m[EXEC container]\033[0m {command}")
        try:
            result = subprocess.run(
                ["docker", "exec", "--workdir", cwd, self._container,
                 "sh", "-c", wrapped],
                capture_output=True, timeout=30,
                encoding="utf-8", errors="replace",
            )
            stdout = result.stdout or ""
            stderr = result.stderr or ""
            new_cwd = None

            if self._SENTINEL in stdout:
                before, _, after = stdout.partition(self._SENTINEL)
                pwd_line = after.strip().split("\n")[0].strip()
                if pwd_line and os.path.isabs(pwd_line):
                    new_cwd = pwd_line
                stdout = before

            output = stdout + stderr
            if not output.strip():
                output = "(No output)"
            elif len(output) > MAX_OUTPUT_CHARS:
                output = output[:MAX_OUTPUT_CHARS] + f"\n... (truncated, {len(output)} chars total)"

            status = "exit_1" if result.returncode != 0 else "success"
            return output, status, new_cwd
        except subprocess.TimeoutExpired:
            return "Error: Command timed out after 30 seconds.", "timeout", None
        except Exception as e:
            return f"Error executing command: {str(e)}", "error", None

    def cleanup(self):
        """Remove the Docker container."""
        try:
            subprocess.run(
                ["docker", "rm", "-f", self._container],
                capture_output=True, timeout=15,
            )
        except Exception:
            pass


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
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": (
                "Read the contents of a file using Python I/O. "
                "More reliable than 'cat' — handles encoding safely. "
                "Use for reading config files, logs, and scripts."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "The file path to read (absolute or relative to CWD)."
                    }
                },
                "required": ["path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": (
                "Write content to a file using Python I/O. "
                "More reliable than 'echo >' — no shell escaping issues. "
                "Use for editing config files and creating scripts."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "The destination file path (absolute or relative to CWD)."
                    },
                    "content": {
                        "type": "string",
                        "description": "The exact content to write to the file."
                    }
                },
                "required": ["path", "content"]
            }
        }
    },
]

# --- Backward-compatible wrappers (preserve test imports) ---
CWD_SENTINEL = HostExecutor._SENTINEL


def _needs_powershell_wrap(command):
    return HostExecutor._needs_powershell_wrap(command)


_host_executor = HostExecutor()


def run_shell_command(command, cwd=None):
    return _host_executor.execute(command, cwd=cwd)


# --- FILE I/O TOOLS ---

def _check_read_safety(full_path):
    """Check if a file path is safe to read.

    IMPORTANT: Callers must resolve symlinks (os.path.realpath) BEFORE calling
    this function.  This function is a pure string matcher — no filesystem access.

    Returns:
        ("blocked", reason) - read must not proceed
        ("safe", None)      - read can proceed
    """
    normalized = full_path.replace("\\", "/")
    # On macOS, /etc -> /private/etc after realpath resolution
    if _IS_MACOS and normalized.startswith("/private/etc/"):
        normalized = normalized[len("/private"):]
    # Case-insensitive comparison for Windows paths
    norm_lower = normalized.lower()
    blocked_exact = ["/etc/shadow", "/etc/gshadow"]
    blocked_fragments = [".ssh/id_", "/etc/ssh/ssh_host_"]
    if _IS_WINDOWS:
        blocked_fragments += ["/sam", "/ntds.dit"]
    if _IS_MACOS:
        blocked_fragments += ["/library/keychains/", "keychains/login.keychain"]

    for exact in blocked_exact:
        if norm_lower == exact:
            return "blocked", f"Reading {exact} is blocked for safety"
    for frag in blocked_fragments:
        if frag in norm_lower:
            return "blocked", f"Reading sensitive file matching '{frag}'"
    return "safe", None


def _check_write_safety(full_path):
    """Check if a file path is safe to write to.

    IMPORTANT: Callers must resolve symlinks (os.path.realpath) BEFORE calling
    this function.  This function is a pure string matcher — no filesystem access.

    Returns:
        ("blocked", reason) - write must not proceed
        ("confirm", reason) - write needs user confirmation
        ("safe", None)      - write can proceed
    """
    normalized = full_path.replace("\\", "/")
    # On macOS, /etc -> /private/etc after realpath resolution
    if _IS_MACOS and normalized.startswith("/private/etc/"):
        normalized = normalized[len("/private"):]
    # Case-insensitive + drive-letter-agnostic for Windows
    norm_lower = normalized.lower()
    blocked_prefixes = [
        "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/",
        "/boot/", "/proc/", "/sys/", "/dev/",
    ]
    blocked_exact = [
        "/etc/passwd", "/etc/shadow", "/etc/fstab",
        "/etc/gshadow", "/etc/sudoers",
    ]
    if _IS_WINDOWS:
        # Strip drive letter for prefix matching (C:/Windows -> /windows)
        path_no_drive = re.sub(r"^[a-z]:", "", norm_lower)
        blocked_prefixes += ["/windows/", "/program files/", "/program files (x86)/"]
    else:
        path_no_drive = norm_lower
    if _IS_MACOS:
        blocked_prefixes += ["/system/", "/library/keychains/"]

    for prefix in blocked_prefixes:
        if path_no_drive.startswith(prefix):
            return "blocked", f"Writing to system path {prefix}"
    for exact in blocked_exact:
        if norm_lower == exact:
            return "blocked", f"Writing to critical system file {exact}"

    confirm_prefixes = ["/etc/"]
    if _IS_WINDOWS:
        confirm_prefixes += ["/programdata/"]
    if _IS_MACOS:
        confirm_prefixes += ["/library/", "/applications/"]
    for prefix in confirm_prefixes:
        check_path = path_no_drive if _IS_WINDOWS else norm_lower
        if check_path.startswith(prefix):
            return "confirm", f"Writing to system config directory ({prefix})"

    if os.path.exists(full_path):
        return "confirm", f"Overwriting existing file: {full_path}"

    return "safe", None


def read_file_content(path, cwd):
    """Read a file using Python I/O.  Returns (content_or_error, status)."""
    try:
        full_path = os.path.realpath(os.path.join(cwd, os.path.expanduser(path)))

        if not os.path.exists(full_path):
            return f"Error: File not found: {full_path}", "error"
        if os.path.isdir(full_path):
            return f"Error: {full_path} is a directory, not a file.", "error"

        try:
            with open(full_path, "r", encoding="utf-8") as f:
                content = f.read()
        except UnicodeDecodeError:
            return f"Error: File appears to be binary: {full_path}", "error"

        if not content:
            content = "(Empty file)"
        elif len(content) > MAX_OUTPUT_CHARS:
            content = content[:MAX_OUTPUT_CHARS] + f"\n... (truncated, {len(content)} chars total)"

        return content, "success"
    except PermissionError:
        return f"Error: Permission denied: {full_path}", "error"
    except Exception as e:
        return f"Error reading file: {e}", "error"


def write_file_content(path, content, cwd):
    """Write content to a file using Python I/O.  Returns (message_or_error, status)."""
    try:
        full_path = os.path.realpath(os.path.join(cwd, os.path.expanduser(path)))

        parent = os.path.dirname(full_path)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)

        with open(full_path, "w", encoding="utf-8") as f:
            f.write(content)

        return f"Successfully wrote {len(content)} chars to {full_path}", "success"
    except PermissionError:
        return f"Error: Permission denied: {full_path}", "error"
    except Exception as e:
        return f"Error writing file: {e}", "error"


def trim_message_history(messages):
    """Trim old messages to stay within context limits.

    Keeps:
      - messages[0]: system prompt (always)
      - The most recent MAX_HISTORY_MESSAGES messages

    When messages are trimmed a short notice is injected so the LLM
    knows prior context was dropped.
    """
    if len(messages) <= MAX_HISTORY_MESSAGES + 1:  # +1 for system prompt
        return messages

    system = messages[0]
    recent = messages[-(MAX_HISTORY_MESSAGES):]

    trimmed_count = len(messages) - 1 - MAX_HISTORY_MESSAGES
    notice = {
        "role": "user",
        "content": (
            f"[Note: {trimmed_count} older messages were trimmed to stay "
            "within context limits. Recent conversation follows.]"
        ),
    }
    return [system, notice] + recent


# --- CHAT LOOP ---
def chat_loop():
    args = parse_args()
    client, model_name, base_url = build_client(args)
    logger = setup_logging(args.log_dir)

    if args.safe_mode:
        executor = DockerExecutor()
    else:
        executor = HostExecutor()

    log_event(logger, "session_start", {
        "provider": args.provider,
        "model": model_name,
        "base_url": base_url,
        "os": f"{platform.system()} {platform.release()}",
        "user": os.environ.get("USER") or os.environ.get("USERNAME", "unknown"),
        "executor": type(executor).__name__,
        "safe_mode": args.safe_mode,
    })

    safety_rules = load_safety_rules()
    os_name = platform.system()
    # In safe mode, commands run inside a Linux container regardless of host OS
    effective_os = "Linux" if args.safe_mode else os_name
    system_prompt = (
        "You are an expert System Administrator AI. "
    )
    if args.safe_mode:
        system_prompt += (
            "You are running commands inside an Ubuntu Linux Docker container on the user's machine. "
            f"The HOST operating system is {os_name}, but your commands execute in Linux. "
            "You have access to a 'run_shell_command' tool that executes shell commands. "
        )
    else:
        system_prompt += (
            "You are running LOCALLY on the user's machine. "
            f"The operating system is {os_name}. "
            "You have access to a 'run_shell_command' tool that executes shell commands. "
        )
    if effective_os == "Windows":
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
        "You also have 'read_file' and 'write_file' tools for safe file I/O. "
        "Prefer these over shell commands (cat, echo >) for reading and writing files — "
        "they handle encoding and escaping correctly. "
        "When asked to analyze or fix something, USE THE TOOLS to inspect the system state first. "
        "Do not hallucinate file contents. Read them with read_file or shell commands."
    )
    if safety_rules:
        system_prompt += "\n\n" + safety_rules

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": "I am ready. " + get_system_context()}
    ]

    # Shell state tracking — cwd persists across commands
    # In safe mode, start in the container's home dir, not the host's
    shell_state = {"cwd": "/root" if args.safe_mode else str(Path.home())}

    print(f"\033[92m[SysAdmin AI Connected]\033[0m provider=\033[96m{args.provider}\033[0m model=\033[96m{model_name}\033[0m")
    print(f"\033[90m  endpoint: {base_url}\033[0m")
    if args.safe_mode:
        print("\033[93m[SAFE MODE]\033[0m Commands run inside Docker container")

    try:
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
                # Trim history before each API call to stay within context limits
                messages = trim_message_history(messages)

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
                                    cmd_result, status, new_cwd = executor.execute(cmd, cwd=shell_state["cwd"])
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
                                cmd_result, status, new_cwd = executor.execute(cmd, cwd=shell_state["cwd"])
                                if new_cwd:
                                    shell_state["cwd"] = new_cwd
                                log_event(logger, "tool_result", {
                                    "command": cmd, "output": cmd_result,
                                    "status": status, "cwd": shell_state["cwd"],
                                    "tool_call_id": tool_call.id,
                                })
                        elif tool_call.function.name == "read_file":
                            tool_args = json.loads(tool_call.function.arguments)
                            file_path = tool_args.get("path", "")
                            full_path = os.path.realpath(
                                os.path.join(shell_state["cwd"], os.path.expanduser(file_path))
                            )

                            log_event(logger, "tool_call", {
                                "tool": "read_file", "path": file_path,
                                "reasoning": reasoning,
                                "tool_call_id": tool_call.id,
                            })

                            safety, reason = _check_read_safety(full_path)
                            if safety == "blocked":
                                cmd_result = f"BLOCKED: Read rejected by safety filter — {reason}."
                                print(f"\033[91m[BLOCKED]\033[0m read_file {file_path}  ({reason})")
                                log_event(logger, "read_blocked", {
                                    "path": file_path, "reason": reason,
                                    "tool_call_id": tool_call.id,
                                })
                            else:
                                print(f"\033[93m[READ]\033[0m {full_path}")
                                cmd_result, status = read_file_content(file_path, shell_state["cwd"])
                                log_event(logger, "tool_result", {
                                    "tool": "read_file", "path": file_path,
                                    "output": cmd_result, "status": status,
                                    "tool_call_id": tool_call.id,
                                })

                        elif tool_call.function.name == "write_file":
                            tool_args = json.loads(tool_call.function.arguments)
                            file_path = tool_args.get("path", "")
                            file_content = tool_args.get("content", "")
                            full_path = os.path.realpath(
                                os.path.join(shell_state["cwd"], os.path.expanduser(file_path))
                            )

                            log_event(logger, "tool_call", {
                                "tool": "write_file", "path": file_path,
                                "content_length": len(file_content),
                                "reasoning": reasoning,
                                "tool_call_id": tool_call.id,
                            })

                            safety, reason = _check_write_safety(full_path)
                            if safety == "blocked":
                                cmd_result = f"BLOCKED: Write rejected by safety filter — {reason}. Do NOT attempt this write again."
                                print(f"\033[91m[BLOCKED]\033[0m write_file {file_path}  ({reason})")
                                log_event(logger, "write_blocked", {
                                    "path": file_path, "reason": reason,
                                    "tool_call_id": tool_call.id,
                                })
                            elif safety == "confirm":
                                print(f"\033[93m[WARNING]\033[0m write_file {file_path}")
                                print(f"  Reason: {reason}")
                                try:
                                    answer = input("  Allow this write? (y/N): ").strip().lower()
                                except (KeyboardInterrupt, EOFError):
                                    answer = "n"
                                if answer == "y":
                                    print(f"\033[93m[WRITE]\033[0m {full_path} ({len(file_content)} chars)")
                                    cmd_result, status = write_file_content(file_path, file_content, shell_state["cwd"])
                                    log_event(logger, "tool_result", {
                                        "tool": "write_file", "path": file_path,
                                        "output": cmd_result, "status": status,
                                        "tool_call_id": tool_call.id,
                                    })
                                else:
                                    cmd_result = f"DENIED: User rejected this write — {reason}."
                                    print(f"\033[91m[DENIED]\033[0m Write rejected by user.")
                                    log_event(logger, "write_denied", {
                                        "path": file_path, "reason": reason,
                                        "tool_call_id": tool_call.id,
                                    })
                            else:
                                print(f"\033[93m[WRITE]\033[0m {full_path} ({len(file_content)} chars)")
                                cmd_result, status = write_file_content(file_path, file_content, shell_state["cwd"])
                                log_event(logger, "tool_result", {
                                    "tool": "write_file", "path": file_path,
                                    "output": cmd_result, "status": status,
                                    "tool_call_id": tool_call.id,
                                })

                        else:
                            cmd_result = f"Error: Unknown tool '{tool_call.function.name}'"

                        messages.append({
                            "role": "tool",
                            "tool_call_id": tool_call.id,
                            "content": cmd_result
                        })

                    # Trim history before each API call to stay within context limits
                    messages = trim_message_history(messages)

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

    finally:
        executor.cleanup()

if __name__ == "__main__":
    chat_loop()
