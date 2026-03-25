"""
Interfolio Case & Committee Creator — Web App
=============================================
A local web interface for bulk-creating Interfolio cases and committees
from CSV files.

Usage:
    pip install flask requests
    python interfolio_app.py

Then open http://localhost:5050 in your browser.
"""

import base64
import csv
import hashlib
import hmac
import io
import json
import os
import time
import queue
import threading
from datetime import datetime, timezone

from flask import Flask, Response, jsonify, render_template_string, request

try:
    import requests as req_lib
except ImportError:
    raise SystemExit("Missing dependency: pip install requests flask")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB upload cap

# ---------------------------------------------------------------------------
# Interfolio API helpers (mirrors the standalone script)
# ---------------------------------------------------------------------------

def _hmac_sig(private_key, method, timestamp, path):
    msg = f"{method.upper()}\n\n\n{timestamp}\n{path}"
    raw = hmac.new(private_key.encode(), msg.encode(), hashlib.sha1).digest()
    return base64.b64encode(raw).decode()


def _headers(cfg, method, path, ct="application/json"):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    sig = _hmac_sig(cfg["private_key"], method, ts, path)
    return {
        "Authorization": f"INTF {cfg['public_key']}:{sig}",
        "TimeStamp": ts,
        "Content-Type": ct,
        "Accept": "application/json",
    }


def _call(cfg, method, path, payload=None, form=None, dry_run=False):
    url = cfg["rest_url"] + path
    if dry_run:
        return {"dry_run": True, "url": url,
                "body": payload or form or {}}
    if form:
        h = _headers(cfg, method, path, "application/x-www-form-urlencoded")
        r = req_lib.request(method, url, headers=h, data=form, timeout=30)
    else:
        h = _headers(cfg, method, path)
        r = req_lib.request(method, url, headers=h, json=payload, timeout=30)
    if r.status_code in (200, 201):
        try:
            return r.json()
        except Exception:
            return {"raw": r.text}
    raise RuntimeError(f"API {r.status_code}: {r.text[:400]}")


def create_case(cfg, row, dry_run=False):
    involvement = row.get("candidate_involvement", "").strip().lower() in ("true", "yes", "1")
    payload = {
        "packet": {
            "unitId":               int(row["unit_id"]),
            "packetTypeId":         int(row["packet_type_id"]),
            "candidateFirstName":   row["candidate_first_name"].strip(),
            "candidateLastName":    row["candidate_last_name"].strip(),
            "candidateEmail":       row["candidate_email"].strip(),
            "candidateInvolvement": involvement,
        }
    }
    if row.get("due_date", "").strip():
        payload["packet"]["dueDate"] = row["due_date"].strip()
    if row.get("name", "").strip():
        payload["packet"]["name"] = row["name"].strip()
    path = f"/byc-tenure/{cfg['tenant_id']}/packets"
    result = _call(cfg, "POST", path, payload=payload, dry_run=dry_run)
    pid = result.get("packet", {}).get("id", "N/A") if not dry_run else "preview"
    return pid


def create_committee(cfg, row, dry_run=False):
    form = {
        "committee[name]":    row["committee_name"].strip(),
        "committee[unit_id]": row["unit_id"].strip(),
    }
    result = _call(cfg, "POST", "/standing_committees", form=form, dry_run=dry_run)
    if dry_run:
        return 0
    return result.get("committee", {}).get("id", "?")


def add_member(cfg, committee_id, user_id, manager=False, dry_run=False):
    form = {
        "committee_member[user_id]": str(user_id),
        "committee_member[manager]": "true" if manager else "false",
    }
    _call(cfg, "POST", f"/committees/{committee_id}/committee_members",
          form=form, dry_run=dry_run)


def _split_ids(val):
    return [int(p.strip()) for p in val.split(";") if p.strip().isdigit()]


def parse_csv(file_bytes):
    text = file_bytes.decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(text))
    return [{k.strip(): v for k, v in row.items()} for row in reader]


# ---------------------------------------------------------------------------
# SSE streaming endpoint
# ---------------------------------------------------------------------------

def _run_job(cfg, cases_bytes, committees_bytes, dry_run, q):
    """Background worker; pushes SSE-style dicts into queue q."""

    def emit(kind, **kw):
        q.put({"type": kind, **kw})

    total_ok = total_err = 0

    # ---- Cases --------------------------------------------------------------
    if cases_bytes:
        rows = parse_csv(cases_bytes)
        emit("section", label=f"Cases — {len(rows)} row(s)")
        for i, row in enumerate(rows, 1):
            name = f"{row.get('candidate_first_name','')} {row.get('candidate_last_name','')}".strip()
            emit("row_start", index=i, total=len(rows), label=name)
            try:
                pid = create_case(cfg, row, dry_run=dry_run)
                emit("row_ok", label=name, detail=f"packet ID: {pid}")
                total_ok += 1
            except Exception as exc:
                emit("row_err", label=name, detail=str(exc))
                total_err += 1
            time.sleep(0.3)

    # ---- Committees ---------------------------------------------------------
    if committees_bytes:
        rows = parse_csv(committees_bytes)
        emit("section", label=f"Committees — {len(rows)} row(s)")
        for i, row in enumerate(rows, 1):
            cname = row.get("committee_name", f"Row {i}")
            emit("row_start", index=i, total=len(rows), label=cname)
            try:
                cid = create_committee(cfg, row, dry_run=dry_run)
                members_ok, member_errors = [], []
                for uid in _split_ids(row.get("member_user_ids", "")):
                    try:
                        add_member(cfg, cid, uid, manager=False, dry_run=dry_run)
                        members_ok.append(str(uid))
                    except Exception as e:
                        member_errors.append(f"member {uid}: {e}")
                for uid in _split_ids(row.get("manager_user_ids", "")):
                    try:
                        add_member(cfg, cid, uid, manager=True, dry_run=dry_run)
                        members_ok.append(f"{uid} (mgr)")
                    except Exception as e:
                        member_errors.append(f"manager {uid}: {e}")
                detail = f"committee ID: {cid}"
                if members_ok:
                    detail += f" · members: {', '.join(members_ok)}"
                if member_errors:
                    detail += f" · ⚠ {'; '.join(member_errors)}"
                emit("row_ok", label=cname, detail=detail)
                total_ok += 1
            except Exception as exc:
                emit("row_err", label=cname, detail=str(exc))
                total_err += 1
            time.sleep(0.3)

    emit("done", ok=total_ok, err=total_err)
    q.put(None)  # sentinel


@app.route("/run", methods=["POST"])
def run():
    cfg = {
        "rest_url":    "https://logic.interfolio.com",
        "tenant_id":   request.form.get("tenant_id", "").strip(),
        "public_key":  request.form.get("public_key", "").strip(),
        "private_key": request.form.get("private_key", "").strip(),
    }
    dry_run = request.form.get("dry_run") == "true"

    cases_bytes       = request.files["cases_csv"].read()       if "cases_csv"       in request.files and request.files["cases_csv"].filename       else None
    committees_bytes  = request.files["committees_csv"].read()  if "committees_csv"  in request.files and request.files["committees_csv"].filename  else None

    if not cases_bytes and not committees_bytes:
        return jsonify(error="Please upload at least one CSV file."), 400

    if not dry_run:
        if not cfg["public_key"] or not cfg["private_key"] or not cfg["tenant_id"]:
            return jsonify(error="API credentials are required for live runs."), 400

    q = queue.Queue()
    t = threading.Thread(target=_run_job,
                         args=(cfg, cases_bytes, committees_bytes, dry_run, q),
                         daemon=True)
    t.start()

    def generate():
        while True:
            item = q.get()
            if item is None:
                break
            yield f"data: {json.dumps(item)}\n\n"

    return Response(generate(), mimetype="text/event-stream",
                    headers={"X-Accel-Buffering": "no",
                             "Cache-Control": "no-cache"})


# ---------------------------------------------------------------------------
# Sample CSV download endpoints
# ---------------------------------------------------------------------------

CASES_SAMPLE = (
    "unit_id,packet_type_id,candidate_first_name,candidate_last_name,"
    "candidate_email,candidate_involvement,due_date,name\n"
    "1234,56,Jane,Smith,jsmith@university.edu,true,2026-08-01,"
    "Jane Smith – Promotion to Associate Professor\n"
    "1234,56,John,Doe,jdoe@university.edu,false,,\n"
)

COMMITTEES_SAMPLE = (
    "committee_name,unit_id,member_user_ids,manager_user_ids,packet_id\n"
    "Departmental Review Committee,1234,1001;1002;1003,1001,\n"
    "External Advisory Panel,1234,2001;2002,,9988\n"
)


@app.route("/sample/cases")
def sample_cases():
    return Response(CASES_SAMPLE, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=cases_sample.csv"})


@app.route("/sample/committees")
def sample_committees():
    return Response(COMMITTEES_SAMPLE, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=committees_sample.csv"})


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------

HTML = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Interfolio Case & Committee Creator</title>
<link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.2/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap-icons/1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
<style>
  :root {
    --brand: #1a4a8a;
    --brand-light: #e8f0fb;
    --success: #0d6e3a;
    --danger:  #b91c1c;
  }
  body { background: #f4f6fa; font-family: 'Segoe UI', system-ui, sans-serif; }
  .topbar {
    background: var(--brand);
    color: #fff;
    padding: 1rem 2rem;
    display: flex;
    align-items: center;
    gap: .75rem;
    box-shadow: 0 2px 8px rgba(0,0,0,.18);
  }
  .topbar h1 { font-size: 1.25rem; margin: 0; font-weight: 600; letter-spacing: .01em; }
  .topbar .sub { font-size: .8rem; opacity: .75; }
  .card { border: none; border-radius: 12px; box-shadow: 0 1px 6px rgba(0,0,0,.08); }
  .card-header {
    background: var(--brand-light);
    border-bottom: 1px solid #d0ddf5;
    border-radius: 12px 12px 0 0 !important;
    font-weight: 600;
    color: var(--brand);
    font-size: .95rem;
  }
  .drop-zone {
    border: 2px dashed #b0bfd8;
    border-radius: 10px;
    padding: 1.6rem 1rem;
    text-align: center;
    cursor: pointer;
    transition: background .15s, border-color .15s;
    background: #fafbff;
    position: relative;
  }
  .drop-zone:hover, .drop-zone.drag-over {
    border-color: var(--brand);
    background: var(--brand-light);
  }
  .drop-zone input[type=file] {
    position: absolute; inset: 0; opacity: 0; cursor: pointer; width: 100%; height: 100%;
  }
  .drop-zone .icon { font-size: 2rem; color: #8da4c8; }
  .drop-zone .filename { font-size: .85rem; color: #444; margin-top: .4rem; font-weight: 500; }
  .badge-pill { border-radius: 999px; font-size: .75rem; padding: .25em .7em; }
  #log { max-height: 400px; overflow-y: auto; }
  .log-section {
    background: #1e293b;
    color: #94a3b8;
    padding: .35rem .75rem;
    border-radius: 6px 6px 0 0;
    font-size: .78rem;
    font-weight: 600;
    letter-spacing: .05em;
    text-transform: uppercase;
    margin-top: .75rem;
  }
  .log-row {
    display: flex;
    align-items: flex-start;
    gap: .5rem;
    padding: .45rem .75rem;
    border-bottom: 1px solid #f0f2f5;
    font-size: .85rem;
    background: #fff;
    animation: fadeIn .2s;
  }
  .log-row:last-child { border-bottom: none; }
  .log-row .icon-ok  { color: var(--success); }
  .log-row .icon-err { color: var(--danger); }
  .log-row .icon-spin { animation: spin .8s linear infinite; }
  .log-row .lbl  { font-weight: 500; min-width: 12rem; }
  .log-row .det  { color: #555; word-break: break-all; }
  .summary-bar {
    border-radius: 10px;
    padding: .75rem 1.25rem;
    font-size: .95rem;
    font-weight: 600;
    display: flex;
    align-items: center;
    gap: .75rem;
    margin-top: 1rem;
  }
  .summary-bar.ok  { background: #dcfce7; color: var(--success); }
  .summary-bar.err { background: #fee2e2; color: var(--danger); }
  .progress { height: 6px; border-radius: 999px; }
  @keyframes spin { to { transform: rotate(360deg); } }
  @keyframes fadeIn { from { opacity:0; transform: translateY(4px); } to { opacity:1; transform: none; } }
  .form-control:focus, .form-check-input:focus { box-shadow: 0 0 0 3px rgba(26,74,138,.2); border-color: var(--brand); }
  #btn-run { background: var(--brand); border: none; padding: .6rem 1.8rem; font-size: 1rem; font-weight: 600; border-radius: 8px; }
  #btn-run:hover:not(:disabled) { background: #153d75; }
  #btn-run:disabled { opacity: .6; }
  .cred-toggle { font-size: .82rem; color: var(--brand); cursor: pointer; text-decoration: underline; }
  #creds { display: none; }
</style>
</head>
<body>

<div class="topbar">
  <i class="bi bi-mortarboard-fill" style="font-size:1.6rem"></i>
  <div>
    <h1>Interfolio Case &amp; Committee Creator</h1>
    <div class="sub">Bulk-create cases and review committees from CSV files</div>
  </div>
</div>

<div class="container py-4" style="max-width:860px">

  <form id="main-form" enctype="multipart/form-data">

    <!-- ── CSV Upload Row ── -->
    <div class="row g-3 mb-3">

      <!-- Cases CSV -->
      <div class="col-md-6">
        <div class="card h-100">
          <div class="card-header d-flex align-items-center justify-content-between">
            <span><i class="bi bi-person-lines-fill me-2"></i>Cases CSV</span>
            <a href="/sample/cases" class="badge badge-pill bg-secondary text-decoration-none" style="font-size:.72rem">
              <i class="bi bi-download me-1"></i>Sample
            </a>
          </div>
          <div class="card-body">
            <div class="drop-zone" id="dz-cases">
              <input type="file" name="cases_csv" accept=".csv" id="inp-cases">
              <div class="icon"><i class="bi bi-file-earmark-spreadsheet"></i></div>
              <div class="mt-1 text-muted" style="font-size:.85rem">Click or drag &amp; drop</div>
              <div class="filename" id="fn-cases">No file chosen</div>
            </div>
            <div class="mt-2 text-muted" style="font-size:.76rem">
              Required columns: <code>unit_id · packet_type_id · candidate_first_name · candidate_last_name · candidate_email · candidate_involvement</code>
            </div>
          </div>
        </div>
      </div>

      <!-- Committees CSV -->
      <div class="col-md-6">
        <div class="card h-100">
          <div class="card-header d-flex align-items-center justify-content-between">
            <span><i class="bi bi-people-fill me-2"></i>Committees CSV</span>
            <a href="/sample/committees" class="badge badge-pill bg-secondary text-decoration-none" style="font-size:.72rem">
              <i class="bi bi-download me-1"></i>Sample
            </a>
          </div>
          <div class="card-body">
            <div class="drop-zone" id="dz-committees">
              <input type="file" name="committees_csv" accept=".csv" id="inp-committees">
              <div class="icon"><i class="bi bi-file-earmark-spreadsheet"></i></div>
              <div class="mt-1 text-muted" style="font-size:.85rem">Click or drag &amp; drop</div>
              <div class="filename" id="fn-committees">No file chosen</div>
            </div>
            <div class="mt-2 text-muted" style="font-size:.76rem">
              Required columns: <code>committee_name · unit_id</code> &nbsp;·&nbsp;
              Optional: <code>member_user_ids · manager_user_ids</code> (semicolon-separated IDs)
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- ── Credentials ── -->
    <div class="card mb-3">
      <div class="card-header d-flex align-items-center justify-content-between">
        <span><i class="bi bi-key-fill me-2"></i>API Credentials</span>
        <span class="cred-toggle" id="cred-toggle" onclick="toggleCreds()">Show</span>
      </div>
      <div class="card-body" id="creds">
        <div class="row g-2">
          <div class="col-md-4">
            <label class="form-label small fw-semibold">Tenant ID</label>
            <input type="text" class="form-control form-control-sm" name="tenant_id"
                   placeholder="e.g. 12345">
          </div>
          <div class="col-md-4">
            <label class="form-label small fw-semibold">Public Key</label>
            <input type="text" class="form-control form-control-sm" name="public_key"
                   placeholder="Your public API key">
          </div>
          <div class="col-md-4">
            <label class="form-label small fw-semibold">Private Key</label>
            <input type="password" class="form-control form-control-sm" name="private_key"
                   placeholder="Your private API key">
          </div>
        </div>
        <div class="mt-2 text-muted" style="font-size:.76rem">
          Credentials are only used for this request and are never stored.
        </div>
      </div>
    </div>

    <!-- ── Options & Run ── -->
    <div class="d-flex align-items-center gap-3 flex-wrap">
      <button type="submit" id="btn-run" class="btn btn-primary text-white">
        <i class="bi bi-play-fill me-1"></i>Run
      </button>
      <div class="form-check form-switch mb-0">
        <input class="form-check-input" type="checkbox" id="dry-run" name="dry_run_check">
        <label class="form-check-label small fw-semibold" for="dry-run">
          Dry Run <span class="text-muted fw-normal">(preview without API calls)</span>
        </label>
      </div>
    </div>

  </form>

  <!-- ── Progress ── -->
  <div id="progress-wrap" class="mt-4" style="display:none">
    <div class="d-flex justify-content-between align-items-center mb-1">
      <span class="small fw-semibold text-muted" id="progress-label">Running…</span>
      <span class="small text-muted" id="progress-pct">0%</span>
    </div>
    <div class="progress mb-3">
      <div id="progress-bar" class="progress-bar bg-primary" style="width:0%"></div>
    </div>
    <div id="log"></div>
    <div id="summary"></div>
  </div>

</div>

<script>
let totalRows = 0, doneRows = 0;

function toggleCreds() {
  const el = document.getElementById('creds');
  const tog = document.getElementById('cred-toggle');
  if (el.style.display === 'none') { el.style.display = ''; tog.textContent = 'Hide'; }
  else { el.style.display = 'none'; tog.textContent = 'Show'; }
}

// Drag-and-drop / file name display
['cases','committees'].forEach(key => {
  const inp = document.getElementById('inp-' + key);
  const fn  = document.getElementById('fn-' + key);
  const dz  = document.getElementById('dz-' + key);
  inp.addEventListener('change', () => {
    fn.textContent = inp.files[0] ? inp.files[0].name : 'No file chosen';
    fn.style.color = inp.files[0] ? '#1a4a8a' : '';
  });
  dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('drag-over'); });
  dz.addEventListener('dragleave', () => dz.classList.remove('drag-over'));
  dz.addEventListener('drop', e => {
    e.preventDefault(); dz.classList.remove('drag-over');
    if (e.dataTransfer.files[0]) {
      inp.files = e.dataTransfer.files;
      fn.textContent = e.dataTransfer.files[0].name;
      fn.style.color = '#1a4a8a';
    }
  });
});

document.getElementById('main-form').addEventListener('submit', async e => {
  e.preventDefault();
  const btn  = document.getElementById('btn-run');
  const log  = document.getElementById('log');
  const wrap = document.getElementById('progress-wrap');
  const bar  = document.getElementById('progress-bar');
  const pct  = document.getElementById('progress-pct');
  const lbl  = document.getElementById('progress-label');
  const sum  = document.getElementById('summary');

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Running…';
  log.innerHTML = '';
  sum.innerHTML = '';
  wrap.style.display = '';
  totalRows = 0; doneRows = 0;
  bar.style.width = '0%'; pct.textContent = '0%';
  lbl.textContent = 'Running…';
  bar.classList.remove('bg-danger'); bar.classList.add('bg-primary');

  const fd = new FormData(e.target);
  fd.set('dry_run', document.getElementById('dry-run').checked ? 'true' : 'false');

  // Use fetch with SSE via ReadableStream
  const resp = await fetch('/run', { method: 'POST', body: fd });

  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ error: resp.statusText }));
    sum.innerHTML = `<div class="summary-bar err"><i class="bi bi-x-circle-fill"></i>${err.error}</div>`;
    btn.disabled = false;
    btn.innerHTML = '<i class="bi bi-play-fill me-1"></i>Run';
    return;
  }

  const reader = resp.body.getReader();
  const decoder = new TextDecoder();
  let buf = '';

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    const parts = buf.split('\n\n');
    buf = parts.pop();
    for (const part of parts) {
      const line = part.replace(/^data:\s*/, '').trim();
      if (!line) continue;
      let ev;
      try { ev = JSON.parse(line); } catch { continue; }
      handleEvent(ev, log, bar, pct, lbl, sum);
    }
  }

  btn.disabled = false;
  btn.innerHTML = '<i class="bi bi-play-fill me-1"></i>Run';
});

function handleEvent(ev, log, bar, pct, lbl, sum) {
  if (ev.type === 'section') {
    totalRows += parseInt(ev.label.match(/\d+/)?.[0] || 0);
    const s = document.createElement('div');
    s.className = 'log-section';
    s.textContent = ev.label;
    log.appendChild(s);
  } else if (ev.type === 'row_start') {
    lbl.textContent = `Processing: ${ev.label}`;
    const row = document.createElement('div');
    row.className = 'log-row';
    row.id = 'row-' + ev.index + '-' + Date.now();
    row.innerHTML = `<i class="bi bi-arrow-repeat icon-spin text-secondary"></i>
                     <span class="lbl">${esc(ev.label)}</span>
                     <span class="det text-muted">processing…</span>`;
    log.appendChild(row);
    log.scrollTop = log.scrollHeight;
    row._id = row.id;
    window._lastRow = row;
  } else if (ev.type === 'row_ok') {
    doneRows++;
    updateProgress(bar, pct);
    const row = window._lastRow;
    if (row) {
      row.innerHTML = `<i class="bi bi-check-circle-fill icon-ok"></i>
                       <span class="lbl">${esc(ev.label)}</span>
                       <span class="det">${esc(ev.detail)}</span>`;
    }
    log.scrollTop = log.scrollHeight;
  } else if (ev.type === 'row_err') {
    doneRows++;
    updateProgress(bar, pct);
    const row = window._lastRow;
    if (row) {
      row.innerHTML = `<i class="bi bi-x-circle-fill icon-err"></i>
                       <span class="lbl">${esc(ev.label)}</span>
                       <span class="det text-danger">${esc(ev.detail)}</span>`;
    }
    log.scrollTop = log.scrollHeight;
  } else if (ev.type === 'done') {
    bar.style.width = '100%'; pct.textContent = '100%';
    lbl.textContent = 'Complete';
    const cls = ev.err > 0 ? 'err' : 'ok';
    const icon = ev.err > 0 ? 'exclamation-triangle-fill' : 'check-circle-fill';
    const msg  = ev.err > 0
      ? `${ev.ok} succeeded, ${ev.err} failed`
      : `All ${ev.ok} item(s) completed successfully`;
    sum.innerHTML = `<div class="summary-bar ${cls}">
      <i class="bi bi-${icon}"></i>${msg}
    </div>`;
    if (ev.err > 0) { bar.classList.remove('bg-primary'); bar.classList.add('bg-danger'); }
  }
}

function updateProgress(bar, pct) {
  if (!totalRows) return;
  const p = Math.round((doneRows / totalRows) * 100);
  bar.style.width = p + '%';
  pct.textContent = p + '%';
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    print(f"\n  Interfolio Creator running at  http://localhost:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
