"""Before/after evidence for the per-client rate limit (429 rate_limited), LOCAL server only.

Run it once with the limiter switched off ("before") and once with it on ("after"). Both
runs go into one JSON file and are printed side by side. Only localhost targets are
accepted and every step is capped, so this cannot be pointed at someone else's service.
Standard library only.

    # terminal 1, from backend/: BEFORE, limiter off with the demo switch
    #   PowerShell:  $env:RATE_LIMIT_ENABLED="false"   bash:  export RATE_LIMIT_ENABLED=false
    .venv/Scripts/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers --no-access-log
    # terminal 2, from backend/
    .venv/Scripts/python scripts/security/rate_limit_flood.py --phase before
    # terminal 1: stop the server, unset RATE_LIMIT_ENABLED, start it again (limiter on)
    .venv/Scripts/python scripts/security/rate_limit_flood.py --phase after

Each phase sends, all from this one client:
  1. burst  --burst concurrent requests released together: the 503 cap still works
  2. flood  --flood requests one after another, a new connection each: the 429 appears
  3. spoof  5 requests with a different X-Forwarded-For each: must not reset the limit
  4. wait   (after only) sleep the last Retry-After, then one request: must be 200
"""
import argparse
import http.client
import json
import sys
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
MAX_BURST = 50
MAX_FLOOD = 300
MAX_WAIT = 60
SPOOFS = 5
DEFAULT_OUT = Path(__file__).resolve().parents[2] / "evidence" / "rate_limit_before_after.json"
FLOOD_URL = "paypa1-secure-login.top/verify"
BURST_URL = "example.com/" + "a" * 2036  # the longest valid URL, the most work per analysis
EXPECTED_SERVER = {"before": "limiter off, RATE_LIMIT_ENABLED=false",
                   "after": "limiter on, default settings"}


def post(host: str, port: int, url: str, headers: dict | None = None) -> dict:
    """One POST /analyze on its own connection; returns what the evidence needs."""
    conn = http.client.HTTPConnection(host, port, timeout=30)
    started = time.perf_counter()
    row = {"status": 0, "retry_after": None, "request_id": None}
    try:
        conn.request("POST", "/analyze", body=json.dumps({"url": url}).encode(),
                     headers={"Content-Type": "application/json", **(headers or {})})
        response = conn.getresponse()
        raw = response.read()
        row.update(status=response.status, retry_after=response.getheader("Retry-After"),
                   request_id=response.getheader("X-Request-ID"))
        if response.status >= 400:
            try:
                row["body"] = json.loads(raw)
            except ValueError:
                row["body"] = None
    except OSError as exc:
        row["error"] = type(exc).__name__
    finally:
        conn.close()
    row["ms"] = round((time.perf_counter() - started) * 1000, 1)
    return row


def health(host: str, port: int) -> int:
    conn = http.client.HTTPConnection(host, port, timeout=5)
    try:
        conn.request("GET", "/health")
        response = conn.getresponse()
        response.read()
        return response.status
    except OSError:
        return 0
    finally:
        conn.close()


def burst(host: str, port: int, n: int) -> list[dict]:
    barrier = threading.Barrier(n)
    rows: list[dict] = []
    lock = threading.Lock()

    def one() -> None:
        barrier.wait()
        row = post(host, port, BURST_URL)
        with lock:
            rows.append(row)

    threads = [threading.Thread(target=one) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return rows


def well_formed_429(row: dict) -> bool:
    """The contract's error shape, code rate_limited, whole-second Retry-After of at least 1."""
    body = row.get("body")
    error = body.get("error") if isinstance(body, dict) else None
    ra = row["retry_after"]
    return (isinstance(error, dict)
            and set(error) == {"code", "message", "details", "request_id"}
            and error["code"] == "rate_limited" and error["request_id"] == row["request_id"]
            and ra is not None and ra.isdigit() and int(ra) >= 1)


def counts(rows: list[dict]) -> dict[str, int]:
    return {str(k): v for k, v in sorted(Counter(r["status"] for r in rows).items())}


def retry_afters(rows: list[dict], status: int) -> list[str]:
    values = {r["retry_after"] for r in rows if r["status"] == status and r["retry_after"]}
    return sorted(values, key=lambda v: int(v) if v.isdigit() else -1)


def run_phase(phase: str, host: str, port: int, n_burst: int, n_flood: int,
              max_wait: int) -> dict:
    burst_rows = burst(host, port, n_burst)
    flood_rows = [post(host, port, FLOOD_URL) for _ in range(n_flood)]
    spoof_rows = [post(host, port, FLOOD_URL, {"X-Forwarded-For": f"203.0.113.{i + 1}"})
                  for i in range(SPOOFS)]

    recovery = None
    last = (flood_rows + spoof_rows)[-1]
    if phase == "after" and last["status"] == 429 and (last["retry_after"] or "").isdigit():
        wait = int(last["retry_after"])
        if wait <= max_wait:
            time.sleep(wait)
            row = post(host, port, FLOOD_URL)
            recovery = {"waited_seconds": wait, "status": row["status"]}
        else:
            recovery = {"skipped": f"Retry-After {wait} s is over --max-wait {max_wait}"}

    in_order = burst_rows + flood_rows  # burst rows are in completion order
    first_429 = next((i for i, r in enumerate(in_order) if r["status"] == 429), None)
    first_flood_429 = next((i + 1 for i, r in enumerate(flood_rows) if r["status"] == 429), None)
    every = burst_rows + flood_rows + spoof_rows
    limited = [r for r in every if r["status"] == 429]
    sample = limited[0] if limited else None
    spoof_through = sum(r["status"] == 200 for r in spoof_rows)
    recovered = 1 if recovery and recovery.get("status") == 200 else 0

    problems = []
    unexpected = sorted({r["status"] for r in every} - {200, 429, 503})
    if unexpected:
        problems.append(f"unexpected statuses {unexpected} (0 means no response)")
    if any(r["status"] == 503 and not r["retry_after"] for r in every):
        problems.append("a 503 had no Retry-After")
    if phase == "before":
        if limited:
            problems.append("got 429s, so the limiter is on: restart the server with "
                            "RATE_LIMIT_ENABLED=false for the before phase")
    else:
        if first_flood_429 is None:
            problems.append("no 429 in the flood: is the limiter on, and is --flood larger "
                            "than RATE_LIMIT_REQUESTS?")
        if any(not well_formed_429(r) for r in limited):
            problems.append("a 429 was not in the contract error shape with a whole-second "
                            "Retry-After")
        # With the header trusted, every spoofed request would get a fresh limit and pass.
        # One may pass on a request given back naturally while the check runs.
        if spoof_through > 1:
            problems.append(f"{spoof_through}/{SPOOFS} spoofed requests got through: "
                            "X-Forwarded-For is resetting the limit, run uvicorn with "
                            "--no-proxy-headers")
        if recovery and "status" in recovery and recovery["status"] != 200:
            problems.append(f"after waiting Retry-After the request got {recovery['status']}")

    return {
        "recorded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": f"http://{host}:{port}",
        "expected_server": EXPECTED_SERVER[phase],
        "passed": not problems,
        "problems": problems,
        "burst": {"requests": n_burst, "status_counts": counts(burst_rows),
                  "retry_after_on_503": retry_afters(burst_rows, 503)},
        "flood": {"requests": n_flood, "status_counts": counts(flood_rows),
                  "first_429_at": first_flood_429,
                  "retry_after_on_429": retry_afters(flood_rows, 429),
                  "statuses_in_order": [r["status"] for r in flood_rows]},
        "accepted_before_first_429": first_429,
        "spoofed_forwarded_for": {"requests": SPOOFS, "got_through": spoof_through,
                                  "statuses": [r["status"] for r in spoof_rows]},
        "recovery": recovery,
        "model_runs": sum(r["status"] == 200 for r in every) + recovered,
        "requests_sent": len(every) + (1 if recovery and "status" in recovery else 0),
        "sample_429": None if sample is None else {
            "status": 429, "retry_after": sample["retry_after"],
            "x_request_id": sample["request_id"], "body": sample.get("body")},
    }


def show_phase(phase: str, r: dict) -> None:
    def fmt(c: dict) -> str:
        return ", ".join(f"{k} x{v}" for k, v in c.items()) or "none"

    print(f"{phase.upper()} phase against {r['target']}, server expected with: "
          f"{r['expected_server']}")
    print(f"  burst  {r['burst']['requests']} concurrent: {fmt(r['burst']['status_counts'])}"
          "   (503 = concurrency cap, layer 2)")
    f = r["flood"]
    first = f"first 429 at #{f['first_429_at']}" if f["first_429_at"] else "no 429"
    print(f"  flood  {f['requests']} one by one:  {fmt(f['status_counts'])}   {first}, "
          f"Retry-After {', '.join(f['retry_after_on_429']) or '-'}")
    if r["accepted_before_first_429"] is not None:
        print(f"         {r['accepted_before_first_429']} requests accepted before the first 429")
    s = r["spoofed_forwarded_for"]
    note = "   (no limiter, so every request passes)" if phase == "before" else ""
    print(f"  spoof  {s['requests']} with a new X-Forwarded-For each: {s['got_through']} got "
          f"through {s['statuses']}{note}")
    if r["recovery"]:
        rec = r["recovery"]
        print(f"  wait   {rec['skipped']}" if "skipped" in rec else
              f"  wait   slept {rec['waited_seconds']} s (Retry-After), then got {rec['status']}")
    print(f"  model ran {r['model_runs']} times for {r['requests_sent']} requests")
    print("PASS" if r["passed"] else "FAIL: " + "; ".join(r["problems"]))


def show_comparison(before: dict, after: dict) -> None:
    def pair(r: dict, part: str, a: str, b: str) -> str:
        c = r[part]["status_counts"]
        return f"{c.get(a, 0)} / {c.get(b, 0)}"

    def first(r: dict) -> str:
        return f"#{r['flood']['first_429_at']}" if r["flood"]["first_429_at"] else "-"

    rows = [
        ("burst 200 / 503", pair(before, "burst", "200", "503"), pair(after, "burst", "200", "503")),
        ("flood 200 / 429", pair(before, "flood", "200", "429"), pair(after, "flood", "200", "429")),
        ("first 429 in flood", first(before), first(after)),
        ("Retry-After on 429", ", ".join(before["flood"]["retry_after_on_429"]) or "-",
         ", ".join(after["flood"]["retry_after_on_429"]) or "-"),
        ("spoofed X-Forwarded-For through",
         f"{before['spoofed_forwarded_for']['got_through']} / {SPOOFS} (no limit)",
         f"{after['spoofed_forwarded_for']['got_through']} / {SPOOFS}"),
        ("model runs / requests sent", f"{before['model_runs']} / {before['requests_sent']}",
         f"{after['model_runs']} / {after['requests_sent']}"),
    ]
    print(f"\n{'':34}{'before (off)':>16}{'after (on)':>16}")
    for label, b, a in rows:
        print(f"{label:34}{b:>16}{a:>16}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--phase", required=True, choices=["before", "after"])
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--burst", type=int, default=20,
                        help=f"concurrent requests in step 1 (1 to {MAX_BURST})")
    parser.add_argument("--flood", type=int, default=60,
                        help=f"sequential requests in step 2 (1 to {MAX_FLOOD})")
    parser.add_argument("--max-wait", type=int, default=10,
                        help=f"longest Retry-After to sleep in step 4 (0 to {MAX_WAIT})")
    parser.add_argument("--json-out", type=Path, default=DEFAULT_OUT,
                        help="JSON file both phases are recorded in (default: %(default)s)")
    args = parser.parse_args()

    target = urlsplit(args.base_url)
    if target.scheme != "http" or target.hostname not in LOCAL_HOSTS:
        sys.exit("refusing: --base-url must be http://localhost, 127.0.0.1 or [::1]")
    if not 1 <= args.burst <= MAX_BURST:
        sys.exit(f"refusing: --burst must be between 1 and {MAX_BURST}")
    if not 1 <= args.flood <= MAX_FLOOD:
        sys.exit(f"refusing: --flood must be between 1 and {MAX_FLOOD}")
    if not 0 <= args.max_wait <= MAX_WAIT:
        sys.exit(f"refusing: --max-wait must be between 0 and {MAX_WAIT}")
    host, port = target.hostname, target.port or 80
    if health(host, port) != 200:
        sys.exit(f"no healthy server at {args.base_url}: start it first (see --help)")

    result = run_phase(args.phase, host, port, args.burst, args.flood, args.max_wait)
    show_phase(args.phase, result)

    try:
        record = json.loads(args.json_out.read_text(encoding="utf-8"))
        record.setdefault("phases", {})
    except (OSError, ValueError):
        record = {"phases": {}}
    record["description"] = ("Per-client rate limit, same server code with the limiter "
                             "off (before) and on (after). Written by "
                             "scripts/security/rate_limit_flood.py.")
    record["phases"][args.phase] = result
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(f"recorded the {args.phase} phase in {args.json_out}")

    phases = record["phases"]
    if "before" in phases and "after" in phases:
        show_comparison(phases["before"], phases["after"])
    sys.exit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
