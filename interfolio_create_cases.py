"""
Interfolio Bulk Case & Committee Creator
=========================================
Creates cases (packets) and/or review committees in Interfolio via the REST
API, reading all data from CSV files.

Usage examples:
    # Create cases only
    python interfolio_create_cases.py --cases cases.csv

    # Create committees only (from pre-existing packets)
    python interfolio_create_cases.py --committees committees.csv

    # Create cases AND committees in one pass
    python interfolio_create_cases.py --cases cases.csv --committees committees.csv

    # Preview without hitting the API
    python interfolio_create_cases.py --cases cases.csv --committees committees.csv --dry-run

    # Generate sample CSV templates
    python interfolio_create_cases.py --sample-cases
    python interfolio_create_cases.py --sample-committees

Requirements:
    pip install requests

Configuration — set as environment variables or edit the CONFIG block below:
    INTERFOLIO_PUBLIC_KEY
    INTERFOLIO_PRIVATE_KEY
    INTERFOLIO_TENANT_ID
"""

import argparse
import base64
import csv
import hashlib
import hmac
import json
import os
import sys
import time
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: run  pip install requests  then try again.")

# ---------------------------------------------------------------------------
# CONFIGURATION — edit here or set as environment variables
# ---------------------------------------------------------------------------
CONFIG = {
    "rest_url":    "https://logic.interfolio.com",
    "tenant_id":   int(os.environ.get("INTERFOLIO_TENANT_ID", 0)),
    "public_key":  os.environ.get("INTERFOLIO_PUBLIC_KEY", ""),
    "private_key": os.environ.get("INTERFOLIO_PRIVATE_KEY", ""),
}
# ---------------------------------------------------------------------------


# ===========================================================================
# AUTH HELPERS
# ===========================================================================

def _hmac_signature(private_key: str, method: str, timestamp: str, path: str) -> str:
    """
    HMAC-SHA1 signature for Interfolio.
    Signed string: METHOD\\n\\n\\nTIMESTAMP\\nPATH
    """
    string_to_sign = f"{method.upper()}\n\n\n{timestamp}\n{path}"
    raw = hmac.new(
        private_key.encode("utf-8"),
        string_to_sign.encode("utf-8"),
        hashlib.sha1,
    ).digest()
    return base64.b64encode(raw).decode("utf-8")


def _auth_headers(config: dict, method: str, path: str,
                  content_type: str = "application/json") -> dict:
    """Return signed auth headers for a request."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    sig = _hmac_signature(config["private_key"], method, timestamp, path)
    return {
        "Authorization": f"INTF {config['public_key']}:{sig}",
        "TimeStamp": timestamp,
        "Content-Type": content_type,
        "Accept": "application/json",
    }


def _api_call(config: dict, method: str, path: str,
              payload=None, form_data=None, dry_run: bool = False) -> dict:
    """
    Make an authenticated API call.
    Use `payload` for JSON bodies, `form_data` for form-encoded bodies.
    """
    url = config["rest_url"] + path

    if dry_run:
        body = payload or form_data or {}
        print(f"  [DRY RUN] {method.upper()} {url}")
        print(f"  Body: {json.dumps(body, indent=4)}")
        return {"dry_run": True}

    if form_data is not None:
        headers = _auth_headers(config, method, path,
                                content_type="application/x-www-form-urlencoded")
        response = requests.request(method, url, headers=headers,
                                    data=form_data, timeout=30)
    else:
        headers = _auth_headers(config, method, path)
        response = requests.request(method, url, headers=headers,
                                    json=payload, timeout=30)

    if response.status_code in (200, 201):
        try:
            return response.json()
        except Exception:
            return {"raw": response.text}
    else:
        raise RuntimeError(
            f"API error {response.status_code}: {response.text[:500]}"
        )


# ===========================================================================
# CASE CREATION
# ===========================================================================

def create_case(config: dict, row: dict, dry_run: bool = False) -> dict:
    """
    Create a single case (packet) from a CSV row.

    Required columns:
        unit_id               — numeric unit/department ID
        packet_type_id        — numeric packet type ID
        candidate_first_name
        candidate_last_name
        candidate_email
        candidate_involvement — true/false

    Optional columns:
        due_date              — e.g. 2026-08-01
        name                  — custom case label
    """
    try:
        involvement = row["candidate_involvement"].strip().lower() in ("true", "yes", "1")
        payload = {
            "packet": {
                "unitId":                int(row["unit_id"]),
                "packetTypeId":          int(row["packet_type_id"]),
                "candidateFirstName":    row["candidate_first_name"].strip(),
                "candidateLastName":     row["candidate_last_name"].strip(),
                "candidateEmail":        row["candidate_email"].strip(),
                "candidateInvolvement":  involvement,
            }
        }
    except KeyError as exc:
        raise ValueError(f"Missing required column: {exc}") from exc

    if row.get("due_date", "").strip():
        payload["packet"]["dueDate"] = row["due_date"].strip()
    if row.get("name", "").strip():
        payload["packet"]["name"] = row["name"].strip()

    path = f"/byc-tenure/{config['tenant_id']}/packets"
    return _api_call(config, "POST", path, payload=payload, dry_run=dry_run)


# ===========================================================================
# COMMITTEE CREATION
# ===========================================================================

def create_committee(config: dict, row: dict, dry_run: bool = False) -> dict:
    """
    Create a standing committee from a CSV row.

    Required columns:
        committee_name  — display name of the committee
        unit_id         — numeric unit/department ID

    Returns the created committee dict (includes its new `id`).
    """
    try:
        form_data = {
            "committee[name]":    row["committee_name"].strip(),
            "committee[unit_id]": row["unit_id"].strip(),
        }
    except KeyError as exc:
        raise ValueError(f"Missing required column: {exc}") from exc

    path = "/standing_committees"
    return _api_call(config, "POST", path, form_data=form_data, dry_run=dry_run)


def add_committee_member(config: dict, committee_id: int,
                         user_id: int, manager: bool = False,
                         dry_run: bool = False) -> dict:
    """Add a single user to a committee."""
    form_data = {
        "committee_member[user_id]": str(user_id),
        "committee_member[manager]": "true" if manager else "false",
    }
    path = f"/committees/{committee_id}/committee_members"
    return _api_call(config, "POST", path, form_data=form_data, dry_run=dry_run)


def process_committee_row(config: dict, row: dict, dry_run: bool = False) -> dict:
    """
    Create a committee and populate its members from one CSV row.

    Required columns:
        committee_name       — name of the committee
        unit_id              — numeric unit/department ID

    Optional columns:
        member_user_ids      — semicolon-separated Interfolio user IDs to add
                               as regular members  (e.g. "101;202;303")
        manager_user_ids     — semicolon-separated user IDs to add as managers
        packet_id            — if provided, links the committee to an existing
                               case (informational — stored for your records)
    """
    # Step 1: create the committee
    result = create_committee(config, row, dry_run=dry_run)

    if dry_run:
        committee_id = 0   # placeholder for dry runs
    else:
        try:
            committee_id = result["committee"]["id"]
        except (KeyError, TypeError):
            raise RuntimeError(
                f"Unexpected committee creation response: {result}"
            )

    summary = {
        "committee_name": row.get("committee_name", ""),
        "committee_id":   committee_id,
        "members_added":  [],
        "errors":         [],
    }

    # Step 2: add regular members
    for uid_str in _split_ids(row.get("member_user_ids", "")):
        try:
            add_committee_member(config, committee_id, uid_str,
                                 manager=False, dry_run=dry_run)
            summary["members_added"].append(uid_str)
        except Exception as exc:
            summary["errors"].append(f"member {uid_str}: {exc}")

    # Step 3: add managers
    for uid_str in _split_ids(row.get("manager_user_ids", "")):
        try:
            add_committee_member(config, committee_id, uid_str,
                                 manager=True, dry_run=dry_run)
            summary["members_added"].append(f"{uid_str} (manager)")
        except Exception as exc:
            summary["errors"].append(f"manager {uid_str}: {exc}")

    return summary


def _split_ids(value: str) -> list[int]:
    """Parse a semicolon-separated string of IDs into a list of ints."""
    parts = [p.strip() for p in value.split(";") if p.strip()]
    result = []
    for p in parts:
        try:
            result.append(int(p))
        except ValueError:
            pass  # skip non-numeric entries
    return result


# ===========================================================================
# CSV HELPERS
# ===========================================================================

def load_csv(filepath: str) -> list[dict]:
    """Load rows from a CSV, stripping whitespace from column names."""
    with open(filepath, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        return [{k.strip(): v for k, v in row.items()} for row in reader]


def write_sample_cases_csv(path: str) -> None:
    sample = [
        {
            "unit_id": "1234",
            "packet_type_id": "56",
            "candidate_first_name": "Jane",
            "candidate_last_name": "Smith",
            "candidate_email": "jsmith@university.edu",
            "candidate_involvement": "true",
            "due_date": "2026-08-01",
            "name": "Jane Smith – Promotion to Associate Professor",
        },
        {
            "unit_id": "1234",
            "packet_type_id": "56",
            "candidate_first_name": "John",
            "candidate_last_name": "Doe",
            "candidate_email": "jdoe@university.edu",
            "candidate_involvement": "false",
            "due_date": "",
            "name": "",
        },
    ]
    _write_csv(path, sample)
    print(f"Sample cases CSV written to: {path}")


def write_sample_committees_csv(path: str) -> None:
    sample = [
        {
            "committee_name": "Departmental Review Committee",
            "unit_id": "1234",
            "member_user_ids": "1001;1002;1003",
            "manager_user_ids": "1001",
            "packet_id": "",
        },
        {
            "committee_name": "External Advisory Panel",
            "unit_id": "1234",
            "member_user_ids": "2001;2002",
            "manager_user_ids": "",
            "packet_id": "9988",
        },
    ]
    _write_csv(path, sample)
    print(f"Sample committees CSV written to: {path}")


def _write_csv(path: str, rows: list[dict]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


# ===========================================================================
# VALIDATION
# ===========================================================================

def validate_config(config: dict) -> None:
    missing = [k for k in ("public_key", "private_key") if not config.get(k)]
    if config.get("tenant_id", 0) == 0:
        missing.append("tenant_id")
    if missing:
        sys.exit(
            f"Missing configuration: {', '.join(missing)}\n"
            "Set as environment variables or edit CONFIG in this script."
        )


# ===========================================================================
# RUN PASSES
# ===========================================================================

def run_cases(cases_file: str, delay: float, dry_run: bool) -> list[dict]:
    rows = load_csv(cases_file)
    print(f"{'='*55}")
    print(f"CASES  —  {len(rows)} row(s) from {cases_file}")
    print(f"{'='*55}")
    results = []
    for i, row in enumerate(rows, start=1):
        name = f"{row.get('candidate_first_name','')} {row.get('candidate_last_name','')}".strip()
        print(f"\n[{i}/{len(rows)}] {name}")
        try:
            res = create_case(CONFIG, row, dry_run=dry_run)
            pid = res.get("packet", {}).get("id", "N/A") if not dry_run else "N/A"
            print(f"  ✓ Case created — packet ID: {pid}")
            results.append({"row": i, "name": name, "status": "success", "packet_id": pid})
        except Exception as exc:
            print(f"  ✗ Failed — {exc}")
            results.append({"row": i, "name": name, "status": "error", "error": str(exc)})
        if i < len(rows):
            time.sleep(delay)
    return results


def run_committees(committees_file: str, delay: float, dry_run: bool) -> list[dict]:
    rows = load_csv(committees_file)
    print(f"\n{'='*55}")
    print(f"COMMITTEES  —  {len(rows)} row(s) from {committees_file}")
    print(f"{'='*55}")
    results = []
    for i, row in enumerate(rows, start=1):
        cname = row.get("committee_name", f"Row {i}")
        print(f"\n[{i}/{len(rows)}] {cname}")
        try:
            summary = process_committee_row(CONFIG, row, dry_run=dry_run)
            cid = summary["committee_id"]
            members = summary["members_added"]
            errs = summary["errors"]
            print(f"  ✓ Committee created — ID: {cid}")
            if members:
                print(f"  ✓ Members added: {', '.join(str(m) for m in members)}")
            if errs:
                for e in errs:
                    print(f"  ⚠ Member error — {e}")
            results.append({
                "row": i, "committee": cname, "status": "success",
                "committee_id": cid, "member_errors": errs,
            })
        except Exception as exc:
            print(f"  ✗ Failed — {exc}")
            results.append({"row": i, "committee": cname,
                            "status": "error", "error": str(exc)})
        if i < len(rows):
            time.sleep(delay)
    return results


def print_summary(case_results: list, committee_results: list) -> None:
    print(f"\n{'='*55}")
    print("SUMMARY")
    print(f"{'='*55}")
    if case_results:
        ok  = sum(1 for r in case_results if r["status"] == "success")
        err = sum(1 for r in case_results if r["status"] == "error")
        print(f"Cases:      {ok} created, {err} failed")
        for r in case_results:
            if r["status"] == "error":
                print(f"  ✗ Row {r['row']} ({r['name']}): {r['error']}")
    if committee_results:
        ok  = sum(1 for r in committee_results if r["status"] == "success")
        err = sum(1 for r in committee_results if r["status"] == "error")
        print(f"Committees: {ok} created, {err} failed")
        for r in committee_results:
            if r["status"] == "error":
                print(f"  ✗ Row {r['row']} ({r['committee']}): {r['error']}")
            elif r.get("member_errors"):
                print(f"  ⚠ {r['committee']}: {len(r['member_errors'])} member error(s)")


# ===========================================================================
# CLI
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Bulk-create Interfolio cases and/or review committees from CSV files.\n\n"
            "Examples:\n"
            "  python interfolio_create_cases.py --cases cases.csv\n"
            "  python interfolio_create_cases.py --committees committees.csv\n"
            "  python interfolio_create_cases.py --cases cases.csv --committees committees.csv --dry-run"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--cases",        metavar="FILE", help="CSV file of cases to create.")
    parser.add_argument("--committees",   metavar="FILE", help="CSV file of committees to create.")
    parser.add_argument("--dry-run",      action="store_true",
                        help="Preview API calls without sending them.")
    parser.add_argument("--sample-cases", action="store_true",
                        help="Write a sample cases CSV template and exit.")
    parser.add_argument("--sample-committees", action="store_true",
                        help="Write a sample committees CSV template and exit.")
    parser.add_argument("--delay",        type=float, default=0.5,
                        help="Seconds between API calls (default: 0.5).")
    args = parser.parse_args()

    # Sample generation
    if args.sample_cases:
        write_sample_cases_csv("cases_sample.csv")
        return
    if args.sample_committees:
        write_sample_committees_csv("committees_sample.csv")
        return

    if not args.cases and not args.committees:
        parser.print_help()
        sys.exit("\nError: provide --cases and/or --committees.")

    # Validate files exist
    for f in filter(None, [args.cases, args.committees]):
        if not os.path.isfile(f):
            sys.exit(f"File not found: {f}")

    if not args.dry_run:
        validate_config(CONFIG)

    case_results       = []
    committee_results  = []

    if args.cases:
        case_results = run_cases(args.cases, args.delay, args.dry_run)

    if args.committees:
        committee_results = run_committees(args.committees, args.delay, args.dry_run)

    print_summary(case_results, committee_results)


if __name__ == "__main__":
    main()
