#!/usr/bin/env python3
"""Loopback-only Flask dashboard with Server-Sent Events."""

from __future__ import annotations

import json
import os
import queue
import secrets
import threading
import time
from typing import Any

from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    render_template_string,
    request,
    session,
)

from master_scanner import run_scan
from privesc_scanner import run_privesc_scan
from exploitation_planner import generate_plan_for


app = Flask(__name__)
app.secret_key = os.environ.get("REASONIX_DASHBOARD_SECRET") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=False,
    MAX_CONTENT_LENGTH=4096,
)

JOBS: dict[str, dict[str, Any]] = {}
JOBS_LOCK = threading.Lock()

PAGE = """<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorized Low-Impact Security Check</title>
<style>
body{font:16px system-ui;background:#0b1020;color:#e8edf8;max-width:850px;margin:5vh auto;padding:0 20px}
main{background:#141b2e;padding:24px;border-radius:14px}
input,button{font:inherit;padding:12px;border-radius:8px;border:1px solid #394560}
input{width:min(65%,520px);background:#0b1020;color:white}
button{background:#5eead4;color:#06251f;font-weight:700;cursor:pointer}
pre{white-space:pre-wrap;background:#080c17;padding:16px;min-height:180px;border-radius:8px}
.note{color:#fbbf24}
</style>
<main>
  <h1>Authorized low-impact web check</h1>
  <p class="note">Only configured allowlisted hosts are accepted. No brute-force or exploitation.</p>
  <form id="scan"><input name="target" placeholder="https://allowed.example" required>
  <select name="mode" style="font:inherit;padding:12px;border-radius:8px;border:1px solid #394560;background:#0b1020;color:#e8edf8">
    <option value="basic">Basic headers / CORS</option>
    <option value="privesc">Privilege escalation / JWT / sessions</option>
  </select>
  <button>Run</button></form>
  <form id="plan" style="margin-top:14px"><input name="planTarget" placeholder="https://allowed.example (same as scan target)" required>
  <button style="background:#fbbf24">Exploitation Plan</button></form>
  <pre id="output" aria-live="polite">Ready.</pre>
</main>
<script>
const form=document.querySelector('#scan'), output=document.querySelector('#output');
form.addEventListener('submit',async event=>{
  event.preventDefault(); output.textContent='Starting…';
  try {
    const response=await fetch('/scan',{method:'POST',headers:{
      'Content-Type':'application/json','X-CSRF-Token':{{ csrf_token|tojson }}
    },body:JSON.stringify({target:form.target.value,mode:form.mode.value})});
    const data=await response.json();
    if(!response.ok) throw new Error(data.error||`HTTP ${response.status}`);
    const stream=new EventSource(`/events/${encodeURIComponent(data.jobId)}`);
    stream.onmessage=message=>{
      const item=JSON.parse(message.data);
      output.textContent+=`\\n[${item.state}] ${item.message}`;
      if(item.done){stream.close(); if(item.report) output.textContent+=`\\n\\nReport:\\n${JSON.stringify(item.report,null,2)}`}
    };
    stream.onerror=()=>{stream.close(); output.textContent+='\\nStream disconnected.'};
  } catch(error) { output.textContent+=`\\nERROR: ${error.message}` }
});
const planForm=document.querySelector('#plan');
planForm.addEventListener('submit',async event=>{
  event.preventDefault(); output.textContent='Building plan…';
  try {
    const response=await fetch('/plan',{method:'POST',headers:{
      'Content-Type':'application/json','X-CSRF-Token':{{ csrf_token|tojson }}
    },body:JSON.stringify({target:planForm.planTarget.value})});
    const data=await response.json();
    if(!response.ok) throw new Error(data.error||`HTTP ${response.status}`);
    output.textContent='Plan:\n'+JSON.stringify(data.plan,null,2);
  } catch(error) { output.textContent+=`\nERROR: ${error.message}` }
});
</script>
</html>"""


def emit_event(job: dict[str, Any], state: str, message: str, **extra: Any) -> None:
    job["events"].put({"state": state, "message": message, **extra})


def run_job(job_id: str, target: str, mode: str = "basic") -> None:
    with JOBS_LOCK:
        job = JOBS[job_id]
    try:
        scanner = run_privesc_scan if mode == "privesc" else run_scan
        report = scanner(target, lambda state, message: emit_event(job, state, message))
        emit_event(job, "DONE", "Assessment finished.", done=True, report=report)
    except Exception as error:
        emit_event(job, "FAILED", str(error), done=True)
    finally:
        job["finished"] = True


@app.after_request
def set_security_headers(response: Response) -> Response:
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; connect-src 'self'; "
        "base-uri 'none'; frame-ancestors 'none'"
    )
    return response


@app.get("/")
def index():
    token = session.setdefault("csrf_token", secrets.token_urlsafe(32))
    return render_template_string(PAGE, csrf_token=token)


@app.post("/scan")
def start_scan():
    host = request.host.split(":", 1)[0].strip("[]").lower()
    if host not in {"127.0.0.1", "localhost", "::1"}:
        abort(403)
    if request.headers.get("Origin") not in {None, request.host_url.rstrip("/")}:
        abort(403)
    if request.headers.get("X-CSRF-Token") != session.get("csrf_token"):
        abort(403)

    payload = request.get_json(silent=True)
    target = payload.get("target") if isinstance(payload, dict) else None
    mode = payload.get("mode") if isinstance(payload, dict) else "basic"
    if mode not in {"basic", "privesc"}:
        mode = "basic"
    if not isinstance(target, str) or len(target) > 2048:
        return jsonify(error="Provide one valid target URL."), 400

    with JOBS_LOCK:
        if any(not job["finished"] for job in JOBS.values()):
            return jsonify(error="A scan is already running."), 429
        for old_job in [key for key, job in JOBS.items() if job["finished"]][:10]:
            JOBS.pop(old_job, None)
        job_id = secrets.token_urlsafe(18)
        JOBS[job_id] = {"events": queue.Queue(), "finished": False}

    threading.Thread(target=run_job, args=(job_id, target, mode), daemon=True).start()
    return jsonify(jobId=job_id), 202


@app.get("/events/<job_id>")
def events(job_id: str):
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if job is None:
        abort(404)

    def stream():
        while True:
            try:
                item = job["events"].get(timeout=15)
            except queue.Empty:
                yield ": keep-alive\n\n"
                if job["finished"]:
                    break
                continue
            yield f"data: {json.dumps(item, ensure_ascii=False)}\n\n"
            if item.get("done"):
                break

    return Response(
        stream(),
        mimetype="text/event-stream",
        headers={"X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


@app.post("/plan")
def build_plan():
    host = request.host.split(":", 1)[0].strip("[]").lower()
    if host not in {"127.0.0.1", "localhost", "::1"}:
        abort(403)
    if request.headers.get("Origin") not in {None, request.host_url.rstrip("/")}:
        abort(403)
    if request.headers.get("X-CSRF-Token") != session.get("csrf_token"):
        abort(403)
    payload = request.get_json(silent=True)
    target = payload.get("target") if isinstance(payload, dict) else None
    if not isinstance(target, str) or len(target) > 2048:
        return jsonify(error="Provide one valid target URL."), 400
    try:
        import io, contextlib
        buffer = io.StringIO()
        path = generate_plan_for(target, emit=lambda msg: buffer.write(msg + "\n"))
        plan = json.loads(Path(path).read_text(encoding="utf-8"))
        return jsonify(plan=plan)
    except SystemExit as error:
        return jsonify(error=str(error)), 400
    except Exception as error:
        return jsonify(error=str(error)), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050, threaded=True, debug=False)
