#!/usr/bin/env python3
"""msf_log_importer.py — turn a manual Metasploit/curl run into report evidence.

You run the exploit MANUALLY (msfconsole, curl, jwt_tool, whatever), then paste
the raw output here. This script attaches it to the existing privesc report as
"What was exploited" — with your own operator note and approval.

No automation. No target traffic from this script.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPORTS_DIR = ROOT / "reports"
LOG_NAME = "msf_execution_log.json"


def _redact(text: str) -> str:
    """Strip obvious secrets before writing evidence to disk."""
    text = re.sub(
        r"(?i)\b(password|passwd|token|secret|api[_-]?key|bearer)\s*[=:]\s*\S+",
        r"\1=[REDACTED]",
        text,
    )
    text = re.sub(
        r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*",
        "[JWT-REDACTED]",
        text,
    )
    return text


def _report_dir_for(hostname: str) -> Path:
    safe = re.sub(r"[^a-z0-9.-]+", "-", hostname.lower()).strip(".-")
    folder = REPORTS_DIR / f"report_{safe}"
    if not folder.is_dir():
        raise SystemExit(f"No report folder for {hostname}; run a scan first.")
    return folder


def log_execution(
    target: str,
    finding_id: str,
    tool_used: str,
    command_run: str,
    raw_output: str,
    operator_note: str = "",
    exploited_successfully: bool | None = None,
) -> Path:
    """Append a manual-run record to the target's msf_execution_log.json."""
    hostname = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
    folder = _report_dir_for(hostname)
    log_path = folder / LOG_NAME

    entries: list[dict] = []
    if log_path.is_file():
        try:
            entries = json.loads(log_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            entries = []

    entry = {
        "loggedAt": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "findingId": finding_id,
        "toolUsed": tool_used,
        "commandRun": _redact(command_run),
        "rawOutput": _redact(raw_output)[:20000],
        "operatorNote": operator_note,
        "exploitedSuccessfully": exploited_successfully,
        "recordedBy": "operator (manual run)",
    }
    entries.append(entry)
    log_path.write_text(json.dumps(entries, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"[SUCCESS] Logged to {log_path} ({len(entries)} total entries)")
    return log_path


def build_final_report(target: str) -> Path:
    """Merge privesc findings + exploitation log into one final report."""
    hostname = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
    folder = _report_dir_for(hostname)

    privesc_path = folder / "privesc_report.json"
    plan_path = folder / "exploitation_plan.json"
    log_path = folder / LOG_NAME

    privesc = json.loads(privesc_path.read_text(encoding="utf-8")) if privesc_path.is_file() else {}
    plan = json.loads(plan_path.read_text(encoding="utf-8")) if plan_path.is_file() else {}
    exec_log = json.loads(log_path.read_text(encoding="utf-8")) if log_path.is_file() else []

    exploited = [
        {
            "findingId": entry.get("findingId"),
            "toolUsed": entry.get("toolUsed"),
            "commandRun": entry.get("commandRun"),
            "outputExcerpt": (entry.get("rawOutput") or "")[:2000],
            "operatorNote": entry.get("operatorNote"),
            "success": entry.get("exploitedSuccessfully"),
            "loggedAt": entry.get("loggedAt"),
        }
        for entry in exec_log
        if entry.get("exploitedSuccessfully")
    ]
    attempted_not_successful = [
        {
            "findingId": entry.get("findingId"),
            "toolUsed": entry.get("toolUsed"),
            "commandRun": entry.get("commandRun"),
            "outputExcerpt": (entry.get("rawOutput") or "")[:1200],
            "loggedAt": entry.get("loggedAt"),
        }
        for entry in exec_log
        if not entry.get("exploitedSuccessfully")
    ]

    final = {
        "target": target,
        "hostname": hostname,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "scanFindings": privesc.get("findings", []),
        "scanScope": privesc.get("scope"),
        "planSteps": plan.get("steps", []),
        "successfullyExploited": exploited,
        "attemptedNotSuccessful": attempted_not_successful,
        "summary": {
            "findingsTotal": len(privesc.get("findings", [])),
            "exploitationAttemptsTotal": len(exec_log),
            "successfullyExploitedTotal": len(exploited),
            "note": "Every exploitation entry above was run manually by the operator; nothing in this pipeline auto-executes.",
        },
    }
    out = folder / "final_report.json"
    out.write_text(json.dumps(final, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"[SUCCESS] Final report written to {out}")
    return out


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Manual exploitation evidence logger")
    parser.add_argument("target", help="e.g. https://target-host/")
    parser.add_argument("--finding", required=True, help="finding id from privesc report")
    parser.add_argument("--tool", required=True, help="e.g. msfconsole / curl / jwt_tool")
    parser.add_argument("--command", required=True, help="what you ran")
    parser.add_argument("--output", required=True, help="path to raw output file, or - for stdin")
    parser.add_argument("--note", default="", help="operator note")
    parser.add_argument("--success", action="store_true", help="mark as successfully exploited")
    parser.add_argument("--final-report", action="store_true", help="also build final_report.json")
    args = parser.parse_args()

    if args.output == "-":
        import sys
        raw = sys.stdin.read()
    else:
        raw = Path(args.output).read_text(encoding="utf-8", errors="replace")

    log_execution(
        args.target, args.finding, args.tool, args.command, raw,
        operator_note=args.note, exploited_successfully=args.success,
    )
    if args.final_report:
        build_final_report(args.target)
