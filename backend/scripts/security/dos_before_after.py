"""Before/after evidence for the denial of service defences (503 cap, 8 KB body limit),
LOCAL server only.

The brief's test: send one expensive request and show other requests are still answered
promptly, then send many at once and show the excess is refused with 503 instead of
freezing the service. DEMO_ANALYZE_DELAY_MS=1000 makes every /analyze take about 1 s, a
stand-in for an expensive model call. The rate limiter is off in both phases, so only the
concurrency cap and the body limit are measured. Only localhost targets are accepted and
every count is capped. Standard library only.

    # terminal 1, from backend/: BEFORE, cap and body limit off
    #   PowerShell:
    #     $env:RATE_LIMIT_ENABLED="false"; $env:CONCURRENCY_CAP_ENABLED="false"
    #     $env:BODY_LIMIT_ENABLED="false"; $env:DEMO_ANALYZE_DELAY_MS="1000"
    #   bash:
    #     export RATE_LIMIT_ENABLED=false CONCURRENCY_CAP_ENABLED=false
    #     export BODY_LIMIT_ENABLED=false DEMO_ANALYZE_DELAY_MS=1000
    .venv/Scripts/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers --no-server-header --no-access-log
    # terminal 2, from backend/
    .venv/Scripts/python scripts/security/dos_before_after.py --phase before
    # terminal 1: stop the server. AFTER: cap (4) and body limit back on, the defaults;
    # RATE_LIMIT_ENABLED=false and DEMO_ANALYZE_DELAY_MS=1000 stay set
    #   PowerShell:  Remove-Item Env:CONCURRENCY_CAP_ENABLED, Env:BODY_LIMIT_ENABLED
    #   bash:        unset CONCURRENCY_CAP_ENABLED BODY_LIMIT_ENABLED
    # start the server again with the same command, then in terminal 2:
    .venv/Scripts/python scripts/security/dos_before_after.py --phase after

Each phase does, per repeat (--repeats, default 5, at most 10):
  1. slow   one /analyze (about 1 s) while 10 /health calls and a second /analyze probe
            are timed: other requests must still be answered
  2. flood  --flood concurrent /analyze (default and at most 100) released together by a
            barrier, with 10 /health calls and one /analyze probe timed during it
and once per phase:
  3. bodies valid JSON padded to 9 KB, 1 MB and 10 MB, sent with Content-Length
"""
import argparse
import http.client
import json
import math
import select
import socket
import statistics
import sys
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
MAX_REPEATS = 10
MAX_FLOOD = 100
HEALTH_CALLS = 10
LEAD_SECONDS = 0.1  # lets the slow request or the flood reach the server before the probes
BODY_SIZES = [9 * 1024, 1024 * 1024, 10 * 1024 * 1024]  # the largest is the 10 MB cap
CHUNK = 64 * 1024
QUICK_MS = 500
DEFAULT_OUT = Path(__file__).resolve().parents[2] / "evidence" / "dos_before_after.json"
URL_BODY = json.dumps({"url": "paypa1-secure-login.top/verify"}).encode()
SETTINGS = {
    "before": {"RATE_LIMIT_ENABLED": False, "CONCURRENCY_CAP_ENABLED": False,
               "BODY_LIMIT_ENABLED": False, "DEMO_ANALYZE_DELAY_MS": 1000},
    "after": {"RATE_LIMIT_ENABLED": False, "CONCURRENCY_CAP_ENABLED": True,
              "BODY_LIMIT_ENABLED": True, "DEMO_ANALYZE_DELAY_MS": 1000,
              "ANALYZE_MAX_CONCURRENCY": 4},
}


def request(host: str, port: int, method: str, path: str, timeout: float = 30) -> dict:
    """One request on its own connection: status (0 means no response), ms, Retry-After."""
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    started = time.perf_counter()
    row = {"status": 0, "retry_after": None}
    try:
        if method == "POST":
            conn.request("POST", path, body=URL_BODY, headers={"Content-Type": "application/json"})
        else:
            conn.request(method, path)
        response = conn.getresponse()
        response.read()
        ra = response.getheader("Retry-After") or ""
        row.update(status=response.status, retry_after=int(ra) if ra.isdigit() else None)
    except OSError:
        pass
    finally:
        conn.close()
    row["ms"] = round((time.perf_counter() - started) * 1000, 1)
    return row


def analyze(host: str, port: int) -> dict:
    return request(host, port, "POST", "/analyze")


def probes(host: str, port: int) -> dict:
    """10 /health calls one after another, with one /analyze probe running beside them."""
    probe: dict = {}
    thread = threading.Thread(target=lambda: probe.update(analyze(host, port)))
    thread.start()
    health = [request(host, port, "GET", "/health", timeout=10) for _ in range(HEALTH_CALLS)]
    thread.join()
    return {"health": health, "probe": probe}


def slow_step(host: str, port: int) -> dict:
    slow: dict = {}
    thread = threading.Thread(target=lambda: slow.update(analyze(host, port)))
    thread.start()
    time.sleep(LEAD_SECONDS)
    timed = probes(host, port)
    thread.join()
    return {"slow": slow, **timed}


def flood_step(host: str, port: int, n: int) -> tuple[dict, list[dict]]:
    barrier = threading.Barrier(n + 1)
    rows: list[dict] = []
    lock = threading.Lock()

    def one() -> None:
        barrier.wait()
        row = analyze(host, port)
        with lock:
            rows.append(row)

    threads = [threading.Thread(target=one) for _ in range(n)]
    for t in threads:
        t.start()
    barrier.wait()
    time.sleep(LEAD_SECONDS)
    timed = probes(host, port)
    for t in threads:
        t.join()
    return {"requests": n, **summarise(rows), **timed}, rows


def oversized(host: str, port: int, size: int) -> dict:
    """POST /analyze with a valid JSON body padded to `size` bytes and a true Content-Length.

    Raw socket, so an early answer (413 on the declared length) is read before the rest of
    the body is pushed into a connection the server is closing.
    """
    body = memoryview(b'{"url": "example.com"}'.ljust(size))
    head = (f"POST /analyze HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n"
            f"Content-Type: application/json\r\nContent-Length: {size}\r\n\r\n").encode()
    started = time.perf_counter()
    status = 0
    try:
        with socket.create_connection((host, port), timeout=30) as s:
            s.sendall(head)
            early = select.select([s], [], [], 0.2)[0]  # a server that refuses on the header
            sent = 0
            while not early and sent < size:
                s.sendall(body[sent:sent + CHUNK])
                sent += CHUNK
                early = select.select([s], [], [], 0)[0]
            data = b""
            while b"\r\n" not in data and (chunk := s.recv(65536)):
                data += chunk
        status = int(data.split(b" ", 2)[1])
    except (OSError, IndexError, ValueError):
        pass
    return {"bytes": size, "status": status,
            "ms": round((time.perf_counter() - started) * 1000, 1)}


def stats(values: list[float]) -> dict | None:
    """min, median, p95 (nearest rank) and max, in ms."""
    if not values:
        return None
    v = sorted(values)
    return {"min": v[0], "median": round(statistics.median(v), 1),
            "p95": v[math.ceil(0.95 * len(v)) - 1], "max": v[-1]}


def counts(rows: list[dict]) -> dict[str, int]:
    return {str(k): v for k, v in sorted(Counter(r["status"] for r in rows).items())}


def summarise(rows: list[dict]) -> dict:
    by_status: dict[int, list[float]] = {}
    for r in rows:
        by_status.setdefault(r["status"], []).append(r["ms"])
    return {"status_counts": counts(rows),
            "ms_by_status": {str(s): stats(v) for s, v in sorted(by_status.items())},
            "retry_after_on_503": sorted({r["retry_after"] for r in rows
                                          if r["status"] == 503 and r["retry_after"] is not None})}


def run_phase(phase: str, host: str, port: int, n_repeats: int, n_flood: int) -> dict:
    repeats, flood_rows = [], []
    for _ in range(n_repeats):
        slow = slow_step(host, port)
        flood, rows = flood_step(host, port, n_flood)
        flood_rows += rows
        repeats.append({"slow": slow, "flood": flood})
    bodies = [oversized(host, port, size) for size in BODY_SIZES]

    slow_rows = [rep["slow"]["slow"] for rep in repeats]
    idle_health = [r for rep in repeats for r in rep["slow"]["health"]]
    idle_probe = [rep["slow"]["probe"] for rep in repeats]
    flood_health = [r for rep in repeats for r in rep["flood"]["health"]]
    flood_probe = [rep["flood"]["probe"] for rep in repeats]
    analyses = slow_rows + idle_probe + flood_rows + flood_probe
    busy = [r for r in analyses if r["status"] == 503]
    busy_median = statistics.median(r["ms"] for r in busy) if busy else None
    no_retry_after = sum(r["retry_after"] is None for r in busy)
    slow_median = statistics.median(r["ms"] for r in slow_rows)

    problems = []
    unexpected = sorted({r["status"] for r in analyses + idle_health + flood_health}
                        - {200, 503})
    if unexpected:
        problems.append(f"unexpected statuses {unexpected} (0 means no response)")
    if sorted({b["status"] for b in bodies} - {200, 413}):
        problems.append(f"body statuses {[b['status'] for b in bodies]} (0 means no response)")
    if slow_median < 900:
        problems.append(f"the slow request took {slow_median} ms: start the server with "
                        "DEMO_ANALYZE_DELAY_MS=1000")
    if phase == "before":
        if busy:
            problems.append(f"got {len(busy)} 503s, so the cap is on: restart the server with "
                            "CONCURRENCY_CAP_ENABLED=false for the before phase")
        if any(b["status"] == 413 for b in bodies):
            problems.append("got 413, so the body limit is on: restart the server with "
                            "BODY_LIMIT_ENABLED=false for the before phase")
    else:
        if not busy:
            problems.append("no 503 in the flood: is the cap on (CONCURRENCY_CAP_ENABLED "
                            "unset) and --flood larger than ANALYZE_MAX_CONCURRENCY?")
        if no_retry_after:
            problems.append(f"{no_retry_after} of {len(busy)} 503s had no whole-second "
                            "Retry-After")
        if busy_median is not None and busy_median >= QUICK_MS:
            problems.append(f"the median 503 took {busy_median} ms, not under {QUICK_MS} ms")
        slowest_health = max(r["ms"] for r in flood_health)
        if slowest_health >= QUICK_MS:
            problems.append(f"a /health during the flood took {slowest_health} ms, not under "
                            f"{QUICK_MS} ms")
        if any(b["status"] != 413 for b in bodies):
            problems.append(f"oversized bodies got {[b['status'] for b in bodies]}, not all 413")

    def ms(rows: list[dict]) -> list[float]:
        return [r["ms"] for r in rows]

    return {
        "recorded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "port": port,
        "server_settings": SETTINGS[phase],
        "repeats": n_repeats,
        "flood_size": n_flood,
        "passed": not problems,
        "problems": problems,
        "summary": {
            "slow_request_ms": stats(ms(slow_rows)),
            "idle": {"health_ms": stats(ms(idle_health)), "health_statuses": counts(idle_health),
                     "analyze_probe_ms": stats(ms(idle_probe)),
                     "analyze_probe_statuses": counts(idle_probe)},
            "flood": {"requests": len(flood_rows), **summarise(flood_rows),
                      "health_ms": stats(ms(flood_health)),
                      "health_statuses": counts(flood_health),
                      "analyze_probe_ms": stats(ms(flood_probe)),
                      "analyze_probe_statuses": counts(flood_probe)},
            "all_503": {"count": len(busy), "median_ms": busy_median,
                        "without_retry_after": no_retry_after},
        },
        "bodies": bodies,
        "per_repeat": repeats,
    }


def fmt_stats(s: dict | None) -> str:
    return "-" if s is None else f"{s['median']:.0f} / {s['p95']:.0f} / {s['max']:.0f}"


def fmt_counts(c: dict) -> str:
    return ", ".join(f"{k} x{v}" for k, v in c.items()) or "none"


def show_phase(phase: str, r: dict) -> None:
    s = r["summary"]
    i, f = s["idle"], s["flood"]
    print(f"{phase.upper()} phase on port {r['port']}, server expected with {r['server_settings']}")
    print(f"  {r['repeats']} repeats; latencies are median / p95 / max in ms")
    print(f"  slow     one /analyze took {fmt_stats(s['slow_request_ms'])}")
    print(f"           beside it: /health {fmt_stats(i['health_ms'])} "
          f"({fmt_counts(i['health_statuses'])}), /analyze probe "
          f"{fmt_stats(i['analyze_probe_ms'])} ({fmt_counts(i['analyze_probe_statuses'])})")
    print(f"  flood    {r['flood_size']} concurrent x {r['repeats']}: "
          f"{fmt_counts(f['status_counts'])}")
    for status, st in f["ms_by_status"].items():
        print(f"           time to {status}: min {st['min']:.0f}, {fmt_stats(st)}")
    print(f"           Retry-After on 503: {f['retry_after_on_503'] or '-'}")
    print(f"           during it: /health {fmt_stats(f['health_ms'])} "
          f"({fmt_counts(f['health_statuses'])}), /analyze probe "
          f"{fmt_stats(f['analyze_probe_ms'])} ({fmt_counts(f['analyze_probe_statuses'])})")
    print("  bodies   " + ", ".join(f"{b['bytes']} B: {b['status']} in {b['ms']:.0f} ms"
                                    for b in r["bodies"]))
    print("PASS" if r["passed"] else "FAIL: " + "; ".join(r["problems"]))


def show_comparison(before: dict, after: dict) -> None:
    def flood(r: dict, key: str) -> dict:
        return r["summary"]["flood"][key]

    def pair(r: dict) -> str:
        c = flood(r, "status_counts")
        return f"{c.get('200', 0)} / {c.get('503', 0)}"

    def by_status(r: dict, status: str) -> str:
        return fmt_stats(flood(r, "ms_by_status").get(status))

    def body(r: dict, n: int) -> str:
        b = r["bodies"][n]
        return f"{b['status']} in {b['ms']:.0f} ms"

    rows = [
        ("slow /analyze ms", fmt_stats(before["summary"]["slow_request_ms"]),
         fmt_stats(after["summary"]["slow_request_ms"])),
        ("beside it: /health ms", fmt_stats(before["summary"]["idle"]["health_ms"]),
         fmt_stats(after["summary"]["idle"]["health_ms"])),
        ("beside it: /analyze probe ms", fmt_stats(before["summary"]["idle"]["analyze_probe_ms"]),
         fmt_stats(after["summary"]["idle"]["analyze_probe_ms"])),
        ("flood 200 / 503", pair(before), pair(after)),
        ("flood time to 200 ms", by_status(before, "200"), by_status(after, "200")),
        ("flood time to 503 ms", by_status(before, "503"), by_status(after, "503")),
        ("Retry-After on 503", str(flood(before, "retry_after_on_503") or "-"),
         str(flood(after, "retry_after_on_503") or "-")),
        ("during flood: /health ms", fmt_stats(flood(before, "health_ms")),
         fmt_stats(flood(after, "health_ms"))),
        ("during flood: /analyze probe ms", fmt_stats(flood(before, "analyze_probe_ms")),
         fmt_stats(flood(after, "analyze_probe_ms"))),
        ("during flood: probe statuses", fmt_counts(flood(before, "analyze_probe_statuses")),
         fmt_counts(flood(after, "analyze_probe_statuses"))),
        ("9 KB body", body(before, 0), body(after, 0)),
        ("1 MB body", body(before, 1), body(after, 1)),
        ("10 MB body", body(before, 2), body(after, 2)),
    ]
    print("\n(ms columns: median / p95 / max)")
    print(f"{'':34}{'before (off)':>22}{'after (on)':>22}")
    for label, b, a in rows:
        print(f"{label:34}{b:>22}{a:>22}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--phase", required=True, choices=["before", "after"])
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--repeats", type=int, default=5,
                        help=f"repeats of steps 1 and 2 (1 to {MAX_REPEATS})")
    parser.add_argument("--flood", type=int, default=MAX_FLOOD,
                        help=f"concurrent requests in step 2 (1 to {MAX_FLOOD})")
    parser.add_argument("--json-out", type=Path, default=DEFAULT_OUT,
                        help="JSON file both phases are recorded in (default: %(default)s)")
    args = parser.parse_args()

    target = urlsplit(args.base_url)
    if target.scheme != "http" or target.hostname not in LOCAL_HOSTS:
        sys.exit("refusing: --base-url must be http://localhost, 127.0.0.1 or [::1]")
    if not 1 <= args.repeats <= MAX_REPEATS:
        sys.exit(f"refusing: --repeats must be between 1 and {MAX_REPEATS}")
    if not 1 <= args.flood <= MAX_FLOOD:
        sys.exit(f"refusing: --flood must be between 1 and {MAX_FLOOD}")
    host, port = target.hostname, target.port or 80
    if request(host, port, "GET", "/health", timeout=5)["status"] != 200:
        sys.exit(f"no healthy server at {args.base_url}: start it first (see --help)")

    result = run_phase(args.phase, host, port, args.repeats, args.flood)
    show_phase(args.phase, result)

    try:
        record = json.loads(args.json_out.read_text(encoding="utf-8"))
        record.setdefault("phases", {})
    except (OSError, ValueError):
        record = {"phases": {}}
    record["description"] = ("Denial of service defences (503 concurrency cap, 8 KB body "
                             "limit), same server code with both off (before) and on (after), "
                             "rate limiter off and a 1 s demo delay per /analyze in both. "
                             "Written by scripts/security/dos_before_after.py.")
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
