"""Before/after evidence for the denial of service defences (503 cap, 8 KB body limit),
LOCAL server only.

The brief's test: send one expensive request and show other requests are still answered
promptly, then send many at once and show the excess is refused with 503 instead of
freezing the service. The rate limiter is off in both phases, so only the concurrency cap
and the body limit are measured. Only localhost targets are accepted and every count is
capped. Standard library only. Run it with the backend's .venv Python: the package
versions recorded with each phase are read from the interpreter running this script.

--expensive picks what makes a request expensive:
  delay (default)  DEMO_ANALYZE_DELAY_MS=1000 makes every /analyze take about 1 s, a
                   stand-in for an expensive model call. Writes evidence/dos_before_after.json.
  real             real inference, NO demo delay: the expensive request is the longest
                   valid URL (2048 characters). Also times 30 short and 30 longest URLs one
                   by one. Writes evidence/dos_before_after_real.json.

DELAY MODE

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
    # terminal 1: stop the server. AFTER: cap (the default of 2) and body limit back on;
    # RATE_LIMIT_ENABLED=false and DEMO_ANALYZE_DELAY_MS=1000 stay set
    #   PowerShell:  Remove-Item Env:CONCURRENCY_CAP_ENABLED, Env:BODY_LIMIT_ENABLED
    #   bash:        unset CONCURRENCY_CAP_ENABLED BODY_LIMIT_ENABLED
    # start the server again with the same command, then in terminal 2:
    .venv/Scripts/python scripts/security/dos_before_after.py --phase after

REAL MODE (DEMO_ANALYZE_DELAY_MS must NOT be set in either phase)

    # terminal 1, from backend/: BEFORE, cap and body limit off
    #   PowerShell:
    #     $env:RATE_LIMIT_ENABLED="false"; $env:CONCURRENCY_CAP_ENABLED="false"
    #     $env:BODY_LIMIT_ENABLED="false"; Remove-Item Env:DEMO_ANALYZE_DELAY_MS -ErrorAction Ignore
    #   bash:
    #     export RATE_LIMIT_ENABLED=false CONCURRENCY_CAP_ENABLED=false
    #     export BODY_LIMIT_ENABLED=false; unset DEMO_ANALYZE_DELAY_MS
    (start the server with the same command as above)
    .venv/Scripts/python scripts/security/dos_before_after.py --phase before --expensive real
    # terminal 1: stop the server. AFTER: only RATE_LIMIT_ENABLED=false stays set
    #   PowerShell:  Remove-Item Env:CONCURRENCY_CAP_ENABLED, Env:BODY_LIMIT_ENABLED
    #   bash:        unset CONCURRENCY_CAP_ENABLED BODY_LIMIT_ENABLED
    # start the server again, then in terminal 2:
    .venv/Scripts/python scripts/security/dos_before_after.py --phase after --expensive real

CAP SWEEP: --max-concurrency N records the server's ANALYZE_MAX_CONCURRENCY (default 2) in
server_settings for an after phase. It does not change the server, so pass the same N the
server was started with. --label names the run and --json-out keeps each run in its own file:

    # server: RATE_LIMIT_ENABLED=false ANALYZE_MAX_CONCURRENCY=1 (no demo delay)
    .venv/Scripts/python scripts/security/dos_before_after.py --phase after --expensive real \
        --max-concurrency 1 --label "cap 1" --json-out evidence/dos_cap_sweep_real_cap1.json

Each phase does, per repeat (--repeats, default 5, at most 10):
  1. slow   one expensive /analyze while 10 /health calls and a second expensive
            /analyze probe are timed: other requests must still be answered
  2. flood  --flood concurrent expensive /analyze (default and at most 100) released
            together by a barrier, with 10 /health calls and one /analyze probe timed
            during it
and once per phase:
  3. crafted (real mode only) 30 short URLs, then 30 longest valid URLs, one by one
  4. bodies valid JSON padded to 9 KB, 1 MB and 10 MB, sent with Content-Length
"""
import argparse
import http.client
import importlib.metadata
import json
import math
import platform
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
CRAFTED_REQUESTS = 30
BACKEND_DIR = Path(__file__).resolve().parents[2]
DEFAULT_OUT = {"delay": BACKEND_DIR / "evidence" / "dos_before_after.json",
               "real": BACKEND_DIR / "evidence" / "dos_before_after_real.json"}
MANIFEST = BACKEND_DIR / "model_manifest.json"
SHORT_BODY = json.dumps({"url": "paypa1-secure-login.top/verify"}).encode()
LONGEST_BODY = json.dumps({"url": "example.com/" + "a" * 2036}).encode()  # 2048 characters
EXPENSIVE_BODY = {"delay": SHORT_BODY, "real": LONGEST_BODY}
SETTINGS = {
    "delay": {
        "before": {"RATE_LIMIT_ENABLED": False, "CONCURRENCY_CAP_ENABLED": False,
                   "BODY_LIMIT_ENABLED": False, "DEMO_ANALYZE_DELAY_MS": 1000},
        "after": {"RATE_LIMIT_ENABLED": False, "CONCURRENCY_CAP_ENABLED": True,
                  "BODY_LIMIT_ENABLED": True, "DEMO_ANALYZE_DELAY_MS": 1000,
                  "ANALYZE_MAX_CONCURRENCY": 2},
    },
    "real": {
        "before": {"RATE_LIMIT_ENABLED": False, "CONCURRENCY_CAP_ENABLED": False,
                   "BODY_LIMIT_ENABLED": False, "DEMO_ANALYZE_DELAY_MS": 0},
        "after": {"RATE_LIMIT_ENABLED": False, "CONCURRENCY_CAP_ENABLED": True,
                  "BODY_LIMIT_ENABLED": True, "DEMO_ANALYZE_DELAY_MS": 0,
                  "ANALYZE_MAX_CONCURRENCY": 2},
    },
}


def environment() -> dict:
    """Versions only, no paths or host names. Packages are read from this interpreter."""
    def version(package: str) -> str:
        try:
            return importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            return "not installed"

    try:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        model = {"name": manifest["name"], "version": manifest["version"]}
    except (OSError, ValueError, KeyError):
        model = None
    return {"python": platform.python_version(), "platform": platform.system(),
            "uvicorn": version("uvicorn"), "fastapi": version("fastapi"),
            "scikit_learn": version("scikit-learn"), "model": model}


def request(host: str, port: int, method: str, path: str, body: bytes | None = None,
            timeout: float = 30) -> dict:
    """One request on its own connection: status (0 means no response), ms, Retry-After."""
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    started = time.perf_counter()
    row = {"status": 0, "retry_after": None}
    try:
        if body is not None:
            conn.request(method, path, body=body, headers={"Content-Type": "application/json"})
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


def analyze(host: str, port: int, body: bytes) -> dict:
    return request(host, port, "POST", "/analyze", body)


def probes(host: str, port: int, body: bytes) -> dict:
    """10 /health calls one after another, with one /analyze probe running beside them."""
    probe: dict = {}
    thread = threading.Thread(target=lambda: probe.update(analyze(host, port, body)))
    thread.start()
    health = [request(host, port, "GET", "/health", timeout=10) for _ in range(HEALTH_CALLS)]
    thread.join()
    return {"health": health, "probe": probe}


def slow_step(host: str, port: int, body: bytes) -> dict:
    slow: dict = {}
    thread = threading.Thread(target=lambda: slow.update(analyze(host, port, body)))
    thread.start()
    time.sleep(LEAD_SECONDS)
    timed = probes(host, port, body)
    thread.join()
    return {"slow": slow, **timed}


def flood_step(host: str, port: int, n: int, body: bytes) -> tuple[dict, list[dict]]:
    barrier = threading.Barrier(n + 1)
    rows: list[dict] = []
    lock = threading.Lock()

    def one() -> None:
        barrier.wait()
        row = analyze(host, port, body)
        with lock:
            rows.append(row)

    threads = [threading.Thread(target=one) for _ in range(n)]
    for t in threads:
        t.start()
    barrier.wait()
    time.sleep(LEAD_SECONDS)
    timed = probes(host, port, body)
    for t in threads:
        t.join()
    return {"requests": n, **summarise(rows), **timed}, rows


def crafted_step(host: str, port: int) -> tuple[dict, list[dict]]:
    """Cost of crafted input: short URLs, then longest valid URLs, one at a time."""
    short = [analyze(host, port, SHORT_BODY) for _ in range(CRAFTED_REQUESTS)]
    longest = [analyze(host, port, LONGEST_BODY) for _ in range(CRAFTED_REQUESTS)]
    s, l = stats([r["ms"] for r in short]), stats([r["ms"] for r in longest])
    return {"requests_each": CRAFTED_REQUESTS,
            "short_url": {"chars": len(json.loads(SHORT_BODY)["url"]), "ms": s,
                          "statuses": counts(short)},
            "longest_url": {"chars": len(json.loads(LONGEST_BODY)["url"]), "ms": l,
                            "statuses": counts(longest)},
            "ratio_longest_to_short": {
                "median": round(l["median"] / s["median"], 1) if s["median"] else None,
                "p95": round(l["p95"] / s["p95"], 1) if s["p95"] else None},
            }, short + longest


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


def run_phase(phase: str, mode: str, host: str, port: int, n_repeats: int,
              n_flood: int, max_concurrency: int = 2) -> dict:
    body = EXPENSIVE_BODY[mode]
    server_settings = dict(SETTINGS[mode][phase])
    if "ANALYZE_MAX_CONCURRENCY" in server_settings:  # after phases only
        server_settings["ANALYZE_MAX_CONCURRENCY"] = max_concurrency
    repeats, flood_rows = [], []
    for _ in range(n_repeats):
        slow = slow_step(host, port, body)
        flood, rows = flood_step(host, port, n_flood, body)
        flood_rows += rows
        repeats.append({"slow": slow, "flood": flood})
    crafted, crafted_rows = crafted_step(host, port) if mode == "real" else (None, [])
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
    if any(r["status"] != 200 for r in crafted_rows):
        problems.append(f"crafted-input requests got {counts(crafted_rows)}, not all 200")
    if sorted({b["status"] for b in bodies} - {200, 413}):
        problems.append(f"body statuses {[b['status'] for b in bodies]} (0 means no response)")
    if mode == "delay" and slow_median < 900:
        problems.append(f"the slow request took {slow_median} ms: start the server with "
                        "DEMO_ANALYZE_DELAY_MS=1000")
    if mode == "real" and slow_median >= 900:
        problems.append(f"the slow request took {slow_median} ms: real mode needs the server "
                        "started WITHOUT DEMO_ANALYZE_DELAY_MS")
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
        health_p95 = stats([r["ms"] for r in flood_health])["p95"]
        if health_p95 >= QUICK_MS:
            problems.append(f"/health during the flood had p95 {health_p95} ms, not under "
                            f"{QUICK_MS} ms")
        if any(b["status"] != 413 for b in bodies):
            problems.append(f"oversized bodies got {[b['status'] for b in bodies]}, not all 413")

    def ms(rows: list[dict]) -> list[float]:
        return [r["ms"] for r in rows]

    return {
        "recorded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "port": port,
        "expensive": mode,
        "environment": environment(),
        "server_settings": server_settings,
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
        "crafted_input": crafted,
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
    print(f"{phase.upper()} phase ({r['expensive']} mode) on port {r['port']}, server expected "
          f"with {r['server_settings']}")
    print(f"  environment {r['environment']}")
    print(f"  {r['repeats']} repeats; latencies are median / p95 / max in ms")
    print(f"  slow     one expensive /analyze took {fmt_stats(s['slow_request_ms'])}")
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
    c = r["crafted_input"]
    if c:
        print(f"  crafted  {c['requests_each']} one by one: short URL "
              f"{fmt_stats(c['short_url']['ms'])}, longest URL {fmt_stats(c['longest_url']['ms'])}, "
              f"ratio median {c['ratio_longest_to_short']['median']}x, "
              f"p95 {c['ratio_longest_to_short']['p95']}x")
    print("  bodies   " +", ".join(f"{b['bytes']} B: {b['status']} in {b['ms']:.0f} ms"
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
    if before["crafted_input"] and after["crafted_input"]:
        def crafted(r: dict, key: str) -> str:
            return fmt_stats(r["crafted_input"][key]["ms"])

        def ratio(r: dict) -> str:
            q = r["crafted_input"]["ratio_longest_to_short"]
            return f"{q['median']}x / {q['p95']}x"

        rows += [("crafted: short URL ms", crafted(before, "short_url"),
                  crafted(after, "short_url")),
                 ("crafted: longest URL ms", crafted(before, "longest_url"),
                  crafted(after, "longest_url")),
                 ("crafted: ratio median / p95", ratio(before), ratio(after))]
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
    parser.add_argument("--expensive", choices=["delay", "real"], default="delay",
                        help="delay: 1 s demo delay per /analyze (stand-in); real: real "
                             "inference on the longest valid URL (default: %(default)s)")
    parser.add_argument("--json-out", type=Path, default=None,
                        help="JSON file both phases are recorded in (default: "
                             "evidence/dos_before_after.json, or dos_before_after_real.json "
                             "with --expensive real)")
    parser.add_argument("--label", default=None,
                        help="short name for this run, stored in the JSON (e.g. \"cap 1\")")
    parser.add_argument("--max-concurrency", type=int, default=2,
                        help="the server's ANALYZE_MAX_CONCURRENCY, recorded for after phases "
                             "only; it does not change the server (1 to 64, default "
                             "%(default)s)")
    args = parser.parse_args()

    target = urlsplit(args.base_url)
    if target.scheme != "http" or target.hostname not in LOCAL_HOSTS:
        sys.exit("refusing: --base-url must be http://localhost, 127.0.0.1 or [::1]")
    if not 1 <= args.repeats <= MAX_REPEATS:
        sys.exit(f"refusing: --repeats must be between 1 and {MAX_REPEATS}")
    if not 1 <= args.flood <= MAX_FLOOD:
        sys.exit(f"refusing: --flood must be between 1 and {MAX_FLOOD}")
    if not 1 <= args.max_concurrency <= 64:
        sys.exit("refusing: --max-concurrency must be between 1 and 64")
    host, port = target.hostname, target.port or 80
    if request(host, port, "GET", "/health", timeout=5)["status"] != 200:
        sys.exit(f"no healthy server at {args.base_url}: start it first (see --help)")

    args.json_out = args.json_out or DEFAULT_OUT[args.expensive]

    result = {"label": args.label,
              **run_phase(args.phase, args.expensive, host, port, args.repeats, args.flood,
                          args.max_concurrency)}
    if args.label:
        print(f"label: {args.label}")
    show_phase(args.phase, result)

    try:
        record = json.loads(args.json_out.read_text(encoding="utf-8"))
        record.setdefault("phases", {})
    except (OSError, ValueError):
        record = {"phases": {}}
    cost = ("a 1 s demo delay per /analyze, a stand-in for an expensive model call"
            if args.expensive == "delay" else
            "real inference on the longest valid URL (2048 characters), no demo delay")
    record["description"] = ("Denial of service defences (503 concurrency cap, 8 KB body "
                             "limit), same server code with both off (before) and on (after), "
                             f"rate limiter off and {cost} in both. "
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
