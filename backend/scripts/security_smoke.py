"""Bounded smoke test of the body-size limit and overload guard against a LOCAL server.

Only localhost targets are accepted, and the burst is a single, capped round of
concurrent requests, so this cannot be pointed at someone else's service or turned into a
flood. Standard library only. It does not replace the team's DoS write-up and scripts;
it gives reproducible numbers for the two backend defences.

    # terminal 1 (from backend/)
    .venv/Scripts/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
    # terminal 2
    .venv/Scripts/python scripts/security_smoke.py --burst 40 --json-out smoke.json
"""
import argparse
import http.client
import json
import socket
import sys
import threading
import time
from collections import Counter
from urllib.parse import urlsplit

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
MAX_BURST = 100
LIMIT = 8192


def body_of_size(size: int) -> bytes:
    body = b'{"url": "example.com"}'
    return body + b" " * (size - len(body))


def raw_status(host: str, port: int, head: str, parts: list[bytes]) -> tuple[int, float]:
    """Send a hand-built HTTP/1.1 request; return (status, seconds)."""
    started = time.perf_counter()
    with socket.create_connection((host, port), timeout=10) as s:
        s.sendall(head.encode("ascii"))
        for part in parts:
            s.sendall(part)
        data = b""
        try:
            while b"\r\n" not in data and (chunk := s.recv(4096)):
                data += chunk
        except ConnectionResetError:
            pass
    status = int(data.split(b" ", 2)[1]) if data.startswith(b"HTTP/") else 0
    return status, time.perf_counter() - started


def chunked(body: bytes, size: int = 1000) -> list[bytes]:
    return [b"%x\r\n%s\r\n" % (len(body[i:i + size]), body[i:i + size])
            for i in range(0, len(body), size)] + [b"0\r\n\r\n"]


def body_limit_checks(host: str, port: int) -> list[dict]:
    head = (f"POST /analyze HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n"
            "Content-Type: application/json\r\n")
    cases = [
        ("8192 bytes, Content-Length", 200,
         head + f"Content-Length: {LIMIT}\r\n\r\n", [body_of_size(LIMIT)]),
        ("8193 bytes, Content-Length", 413,
         head + f"Content-Length: {LIMIT + 1}\r\n\r\n", [body_of_size(LIMIT + 1)]),
        ("8192 bytes, chunked (no Content-Length)", 200,
         head + "Transfer-Encoding: chunked\r\n\r\n", chunked(body_of_size(LIMIT))),
        ("8193 bytes, chunked (no Content-Length)", 413,
         head + "Transfer-Encoding: chunked\r\n\r\n", chunked(body_of_size(LIMIT + 1))),
        ("declared 100 MB, no body sent", 413,
         head + "Content-Length: 100000000\r\n\r\n", []),
    ]
    results = []
    for name, expected, request_head, parts in cases:
        status, seconds = raw_status(host, port, request_head, parts)
        results.append({"case": name, "expected": expected, "status": status,
                        "ok": status == expected, "seconds": round(seconds, 4)})
    return results


def burst(host: str, port: int, n: int) -> dict:
    """n concurrent POST /analyze, released together; the longest valid URL is used so each
    analysis does the most work allowed."""
    payload = json.dumps({"url": "example.com/" + "a" * 2036}).encode()
    barrier = threading.Barrier(n)
    results: list[tuple[int, str | None, float]] = []
    lock = threading.Lock()

    def one() -> None:
        conn = http.client.HTTPConnection(host, port, timeout=30)
        try:
            barrier.wait()
            started = time.perf_counter()
            conn.request("POST", "/analyze", body=payload,
                         headers={"Content-Type": "application/json"})
            response = conn.getresponse()
            response.read()
            row = (response.status, response.getheader("Retry-After"),
                   time.perf_counter() - started)
        except OSError:
            row = (0, None, 0.0)
        finally:
            conn.close()
        with lock:
            results.append(row)

    threads = [threading.Thread(target=one) for _ in range(n)]
    started = time.perf_counter()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.perf_counter() - started
    statuses = Counter(status for status, _, _ in results)
    busy_retry_after = sorted({ra for status, ra, _ in results if status == 503})
    ok_latencies = sorted(s for status, _, s in results if status == 200)
    return {
        "requests": n,
        "status_counts": {str(k): v for k, v in sorted(statuses.items())},
        "retry_after_values_on_503": busy_retry_after,
        "all_503_have_retry_after": all(ra is not None for status, ra, _ in results
                                        if status == 503),
        "unexpected_statuses": sorted(str(s) for s in statuses if s not in (200, 503)),
        "wall_seconds": round(elapsed, 4),
        "p50_ok_seconds": round(ok_latencies[len(ok_latencies) // 2], 4) if ok_latencies else None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--burst", type=int, default=20,
                        help=f"concurrent requests in the single burst (max {MAX_BURST})")
    parser.add_argument("--json-out", help="also write the results to this JSON file")
    args = parser.parse_args()

    target = urlsplit(args.base_url)
    if target.scheme != "http" or target.hostname not in LOCAL_HOSTS:
        sys.exit("refusing: --base-url must be http://localhost, 127.0.0.1 or [::1]")
    if not 1 <= args.burst <= MAX_BURST:
        sys.exit(f"refusing: --burst must be between 1 and {MAX_BURST}")
    host, port = target.hostname, target.port or 80

    report = {"target": args.base_url, "body_limit": body_limit_checks(host, port),
              "burst": burst(host, port, args.burst)}
    for row in report["body_limit"]:
        print(f"{'PASS' if row['ok'] else 'FAIL'}  {row['case']:<42} expected {row['expected']}, "
              f"got {row['status']} in {row['seconds']:.3f}s")
    b = report["burst"]
    print(f"burst of {b['requests']}: {b['status_counts']}, Retry-After on 503: "
          f"{b['retry_after_values_on_503']}, wall {b['wall_seconds']:.3f}s")
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
    ok = (all(r["ok"] for r in report["body_limit"]) and not b["unexpected_statuses"]
          and b["all_503_have_retry_after"])
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
