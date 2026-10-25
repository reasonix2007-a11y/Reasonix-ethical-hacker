import shutil
import subprocess
from pathlib import Path


def find_sqlmap():
    executable = shutil.which("sqlmap")
    if executable:
        return [executable, "--version"]

    script = Path.home() / "sqlmap-dev" / "sqlmap.py"
    python = shutil.which("python3")
    if script.is_file() and python:
        return [python, str(script), "--version"]

    return None


def find_zap():
    for name in ("zaproxy", "zap.sh"):
        executable = shutil.which(name)
        if executable:
            return [executable, "-version"]

    return None


def check_tool(name, command):
    if command is None:
        print(f"Tool {name}: Check Error (not found)")
        return False

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        print(f"Tool {name}: Check Error ({error})")
        return False

    if result.returncode == 0:
        version = (result.stdout or result.stderr).strip().splitlines()
        detail = f" ({version[0]})" if version else ""
        print(f"Tool {name}: OK{detail}")
        return True

    detail = (result.stderr or result.stdout).strip().splitlines()
    message = f" ({detail[0]})" if detail else ""
    print(f"Tool {name}: Check Error (exit {result.returncode}){message}")
    return False


if __name__ == "__main__":
    checks = (
        check_tool("sqlmap", find_sqlmap()),
        check_tool("zaproxy", find_zap()),
    )
    raise SystemExit(0 if all(checks) else 1)
