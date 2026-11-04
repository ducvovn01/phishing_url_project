"""Security header and CORS check against a LOCAL running server (section 2.7 evidence).

Sends nine requests (the frontend's Origin on the ordinary ones) and records, for each, the
status and the security-relevant response headers. Anything that looks like a
misconfiguration is marked FINDING: a Server header that leaks a version, a CORS grant to
http://evil.example (or "*"), a JSON response without nosniff, and /docs or /openapi.json
being reachable. Only localhost targets are accepted. Standard library only.

    # terminal 1, from backend/ (the README command)
    .venv/Scripts/python -m uvicorn app.main:app --host 127.0.0.1 --port 8001 --no-proxy-headers --no-server-header --no-access-log
    # terminal 2, from backend/
    .venv/Scripts/python scripts/security/check_headers.py --base-url http://127.0.0.1:8001 --label "docs on (default)"
    # again with the server started with API_DOCS_ENABLED=false:
    .venv/Scripts/python scripts/security/check_headers.py --base-url http://127.0.0.1:8001 --label "docs off"

Each run is stored under its --label in evidence/security_headers.json.
"""
import argparse
import http.client
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
FRONTEND = "http://localhost:5173"
EVIL = "http://evil.example"
HEADERS = ["X-Content-Type-Options", "Referrer-Policy", "Cache-Control",
           "Content-Security-Policy", "X-Frame-Options", "Cross-Origin-Resource-Policy", "Server",
           "Access-Control-Allow-Origin", "Access-Control-Expose-Headers"]
JSON_TYPE = {"Content-Type": "application/json"}
PREFLIGHT = {"Access-Control-Request-Method": "POST",
             "Access-Control-Request-Headers": "content-type"}
DEFAULT_OUT = Path(__file__).resolve().parents[2] / "evidence" / "security_headers.json"
# (name, method, path, body, extra headers); ordinary requests carry the frontend's Origin.
REQUESTS = [
    ("GET /health", "GET", "/health", None, {"Origin": FRONTEND}),
    ("POST /analyze (valid)", "POST", "/analyze", b'{"url": "example.com"}',
     {"Origin": FRONTEND, **JSON_TYPE}),
    ("POST /analyze (422)", "POST", "/analyze", b'{"url": ""}', {"Origin": FRONTEND, **JSON_TYPE}),
    ("GET /nope (404)", "GET", "/nope", None, {"Origin": FRONTEND}),
    ("DELETE /health (405)", "DELETE", "/health", None, {"Origin": FRONTEND}),
    ("OPTIONS /analyze from frontend", "OPTIONS", "/analyze", None, {"Origin": FRONTEND, **PREFLIGHT}),
    ("OPTIONS /analyze from evil.example", "OPTIONS", "/analyze", None, {"Origin": EVIL, **PREFLIGHT}),
    ("GET /docs", "GET", "/docs", None, {}),
    ("GET /openapi.json", "GET", "/openapi.json", None, {}),
]


def send(host: str, port: int, method: str, path: str, body: bytes | None,
         headers: dict) -> tuple[int, dict]:
    conn = http.client.HTTPConnection(host, port, timeout=10)
    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        response.read()
        return response.status, {k.lower(): v for k, v in response.getheaders()}
    except OSError:
        return 0, {}
    finally:
        conn.close()


def findings_for(name: str, path: str, origin: str | None, status: int,
                 got: dict) -> list[str]:
    found = []
    server = got.get("server")
    if server and re.search(r"\d", server):
        found.append(f"Server header leaks a version: {server!r}")
    acao = got.get("access-control-allow-origin")
    if acao == "*" or (origin == EVIL and acao is not None):
        found.append(f"CORS grants {acao!r} to {origin}")
    if (got.get("content-type", "").startswith("application/json")
            and got.get("x-content-type-options", "").lower() != "nosniff"):
        found.append("JSON response without X-Content-Type-Options: nosniff")
    if path in ("/docs", "/openapi.json") and status == 200:
        found.append(f"{path} is reachable (set API_DOCS_ENABLED=false in deployment)")
    return found


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--label", default="default", help="name of this run in the JSON")
    parser.add_argument("--json-out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    target = urlsplit(args.base_url)
    if target.scheme != "http" or target.hostname not in LOCAL_HOSTS:
        sys.exit("refusing: --base-url must be http://localhost, 127.0.0.1 or [::1]")
    host, port = target.hostname, target.port or 80

    rows, all_findings, no_answer = [], [], 0
    print(f"header check against port {port}, run {args.label!r}")
    for name, method, path, body, headers in REQUESTS:
        status, got = send(host, port, method, path, body, headers)
        no_answer += status == 0
        values = {h: got.get(h.lower()) for h in HEADERS}
        found = findings_for(name, path, headers.get("Origin"), status, got)
        rows.append({"request": name, "status": status,
                     "content_type": got.get("content-type"), "headers": values,
                     "findings": found})
        all_findings += [f"{name}: {f}" for f in found]
        print(f"\n{name}: {status} ({got.get('content-type') or 'no content type'})")
        for h in HEADERS:
            print(f"  {h:30} {values[h] if values[h] is not None else '-'}")
        for f in found:
            print(f"  FINDING: {f}")

    print(f"\n{len(all_findings)} finding(s)" + (":" if all_findings else ""))
    for f in all_findings:
        print(f"  FINDING {f}")

    try:
        record = json.loads(args.json_out.read_text(encoding="utf-8"))
        record.setdefault("runs", {})
    except (OSError, ValueError):
        record = {"runs": {}}
    record["description"] = ("Security header and CORS check of the running API. Written by "
                             "scripts/security/check_headers.py.")
    record["runs"][args.label] = {
        "recorded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "port": port, "requests": rows, "findings": all_findings}
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(f"recorded run {args.label!r} in {args.json_out}")
    sys.exit(1 if no_answer else 0)


if __name__ == "__main__":
    main()
