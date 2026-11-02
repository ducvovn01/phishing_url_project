"""Before/after evidence for the detection evasion defence (section 2.8), LOCAL server only.

Attacks the RUNNING API with the look-alike variants the P2 experiment generated
(experiments/results/cases.csv, categories A and C, five strategies) and measures how
often a phishing URL gets through, once with the homoglyph defence off ("before") and
once with it on ("after"). Both phases go into one JSON file and are printed side by side.
Only localhost targets are accepted and every count is capped. Requests are sent one at a
time. Standard library only. URLs are only sent as text to /analyze; none is opened.

    # terminal 1, from backend/: BEFORE, defence off, rate limiter off
    #   PowerShell:  $env:RATE_LIMIT_ENABLED="false"; $env:HOMOGLYPH_DEFENCE="false"
    #   bash:        export RATE_LIMIT_ENABLED=false HOMOGLYPH_DEFENCE=false
    .venv/Scripts/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers --no-server-header --no-access-log
    # terminal 2, from backend/
    .venv/Scripts/python scripts/security/evasion_before_after.py --phase before
    # terminal 1: stop the server. AFTER: the defence back on (its default), limiter still off
    #   PowerShell:  Remove-Item Env:HOMOGLYPH_DEFENCE
    #   bash:        unset HOMOGLYPH_DEFENCE
    # start the server again with the same command, then in terminal 2:
    .venv/Scripts/python scripts/security/evasion_before_after.py --phase after

Each phase, per repeat r = 1..--repeats (default 10, at most 20):
  attack  a sample of 100 distinct C bases drawn with seed r (the same in both phases),
          plus every A variant; every variant of those bases is POSTed. Evasion rate =
          share of variants labelled legitimate, per strategy and overall. Adaptive
          attacker rate = share of bases with at least one strategy that got through.
          Only bases the undefended model flags as phishing count (base_detected).
and once per phase:
  benign  300 legitimate URLs from experiments/results/benign.csv (every non-ASCII one,
          the rest drawn with a fixed seed): false positive rate over the URLs scored.
          A few non-ASCII rows contain control characters, which the API's URL policy
          refuses with 422; they are counted as refused, not scored.
The run passes when it is sound (attack requests all 200, benign requests 200 or 422, the
server in the expected mode, the same samples as the other phase). It does not require the
defence to help.
"""
import argparse
import csv
import hashlib
import http.client
import json
import math
import random
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
MAX_REPEATS = 20
C_BASES_PER_REPEAT = 100
BENIGN_URLS = 300
BENIGN_SEED = 0
NEAR_ZERO = 0.01  # a mean evasion rate below this, without the defence, is "already near zero"
STRATEGIES = ["cyrillic_one", "cyrillic_all", "greek_mixed", "fullwidth",
              "dot_diacritics_uncovered"]
BACKEND_DIR = Path(__file__).resolve().parents[2]
RESULTS = BACKEND_DIR / "experiments" / "results"
DEFAULT_OUT = BACKEND_DIR / "evidence" / "evasion_before_after.json"
MODE_CASE = "A01-cyrillic_one"  # its base folds back from this variant exactly
EXPECTED_MODE = {"before": "off", "after": "on"}
EXPECTED_SERVER = {"before": {"HOMOGLYPH_DEFENCE": False, "RATE_LIMIT_ENABLED": False},
                   "after": {"HOMOGLYPH_DEFENCE": True, "RATE_LIMIT_ENABLED": False}}


def analyze(host: str, port: int, url: str) -> dict:
    """One POST /analyze on its own connection: status (0 means no response), ms, body."""
    conn = http.client.HTTPConnection(host, port, timeout=30)
    started = time.perf_counter()
    row = {"status": 0, "body": None}
    try:
        conn.request("POST", "/analyze", body=json.dumps({"url": url}).encode(),
                     headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        raw = response.read()
        row["status"] = response.status
        if response.status == 200:
            row["body"] = json.loads(raw)
    except (OSError, ValueError):
        pass
    finally:
        conn.close()
    row["ms"] = (time.perf_counter() - started) * 1000
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


def load_attack() -> tuple[dict[str, list[dict]], list[str], list[str], dict]:
    """Variants of A and C bases the undefended model detects, grouped by base."""
    with (RESULTS / "cases.csv").open(encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    by_base: dict[str, list[dict]] = {}
    for r in rows:
        if r["category"] in ("A", "C") and r["base_detected"] == "True":
            by_base.setdefault(r["base_id"], []).append(r)
    a_bases = sorted(b for b in by_base if by_base[b][0]["category"] == "A")
    c_bases = sorted(b for b in by_base if by_base[b][0]["category"] == "C")
    mode_row = next(r for r in rows if r["case_id"] == MODE_CASE)
    return by_base, a_bases, c_bases, mode_row


def load_benign() -> list[str]:
    with (RESULTS / "benign.csv").open(encoding="utf-8", newline="") as f:
        urls = list(dict.fromkeys(r["url"] for r in csv.DictReader(f)))
    non_ascii = [u for u in urls if not u.isascii()]
    rest = random.Random(BENIGN_SEED).sample([u for u in urls if u.isascii()],
                                             BENIGN_URLS - len(non_ascii))
    return non_ascii + rest


def detect_mode(host: str, port: int, mode_row: dict) -> dict:
    """'on' when the variant scores exactly like its base and its n-gram offsets are null."""
    base = analyze(host, port, mode_row["base_url"])["body"]
    variant = analyze(host, port, mode_row["variant_url"])["body"]
    if base is None or variant is None:
        return {"mode": "unknown"}
    ngrams = [s for s in variant["signals"] if s["kind"] == "ngram"]
    folded = (variant["phishing_probability"] == base["phishing_probability"]
              and all(s["start"] is None for s in ngrams))
    return {"mode": "on" if folded else "off", "base_probability": base["phishing_probability"],
            "variant_probability": variant["phishing_probability"]}


def dist(values: list[float]) -> dict:
    return {"mean": round(statistics.fmean(values), 4), "min": round(min(values), 4),
            "max": round(max(values), 4), "median": round(statistics.median(values), 4)}


def latency(ms: list[float]) -> dict:
    v = sorted(ms)
    return {"median": round(statistics.median(v), 2), "p95": round(v[math.ceil(0.95 * len(v)) - 1], 2),
            "requests": len(v)}


def run_phase(phase: str, host: str, port: int, n_repeats: int) -> dict:
    by_base, a_bases, c_bases, mode_row = load_attack()
    mode = detect_mode(host, port, mode_row)
    statuses: dict[str, int] = {}
    attack_ms: list[float] = []
    fingerprint = hashlib.sha256()
    repeats = []
    for r in range(1, n_repeats + 1):
        bases = a_bases + random.Random(r).sample(c_bases, C_BASES_PER_REPEAT)
        got_through = {s: [0, 0] for s in STRATEGIES}  # strategy -> [legitimate, sent]
        bases_through = 0
        for base_id in bases:
            through = False
            for case in by_base[base_id]:
                fingerprint.update(case["variant_url"].encode() + b"\n")
                row = analyze(host, port, case["variant_url"])
                statuses[str(row["status"])] = statuses.get(str(row["status"]), 0) + 1
                attack_ms.append(row["ms"])
                legitimate = row["body"] is not None and row["body"]["label"] == "legitimate"
                got_through[case["strategy"]][0] += legitimate
                got_through[case["strategy"]][1] += 1
                through |= legitimate
            bases_through += through
        variants = sum(n for _, n in got_through.values())
        repeats.append({
            "seed": r, "bases": len(bases), "variants": variants,
            "evaded": sum(k for k, _ in got_through.values()),
            "evasion_rate": sum(k for k, _ in got_through.values()) / variants,
            "adaptive_rate": bases_through / len(bases),
            "by_strategy": {s: {"evaded": k, "of": n, "rate": k / n}
                            for s, (k, n) in got_through.items()},
        })

    benign_urls = load_benign()
    benign_statuses: dict[str, int] = {}
    benign_ms, flagged, flagged_non_ascii = [], 0, 0
    for url in benign_urls:
        fingerprint.update(url.encode() + b"\n")
        row = analyze(host, port, url)
        benign_statuses[str(row["status"])] = benign_statuses.get(str(row["status"]), 0) + 1
        benign_ms.append(row["ms"])
        phishing = row["body"] is not None and row["body"]["label"] == "phishing"
        flagged += phishing
        flagged_non_ascii += phishing and not url.isascii()

    problems = []
    if set(statuses) != {"200"} or not set(benign_statuses) <= {"200", "422"}:
        problems.append(f"unexpected statuses: attack {statuses}, benign {benign_statuses} "
                        "(0 means no response; 429 means start the server with "
                        "RATE_LIMIT_ENABLED=false)")
    scored = benign_statuses.get("200", 0)
    if mode["mode"] != EXPECTED_MODE[phase]:
        problems.append(f"the server's homoglyph defence looks {mode['mode']!r}, expected "
                        f"{EXPECTED_MODE[phase]!r}: restart it with the settings in --help")
    overall = [r["evasion_rate"] for r in repeats]
    return {
        "recorded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "port": port,
        "expected_server": EXPECTED_SERVER[phase],
        "detected_defence": mode,
        "repeats": n_repeats,
        "sample": {"a_bases": len(a_bases), "c_bases_per_repeat": C_BASES_PER_REPEAT,
                   "variants_per_repeat": [r["variants"] for r in repeats],
                   "benign_urls": len(benign_urls),
                   "benign_non_ascii": sum(not u.isascii() for u in benign_urls),
                   "fingerprint": fingerprint.hexdigest()},
        "passed": not problems,
        "problems": problems,
        "statuses": {"attack": statuses, "benign": benign_statuses},
        "summary": {
            "evasion_rate": dist(overall),
            "adaptive_rate": dist([r["adaptive_rate"] for r in repeats]),
            "by_strategy": {s: dist([r["by_strategy"][s]["rate"] for r in repeats])
                            for s in STRATEGIES},
            "benign": {"sent": len(benign_urls),
                       "refused_by_validation": benign_statuses.get("422", 0),
                       "flagged": flagged, "of": scored,
                       "false_positive_rate": round(flagged / scored, 4) if scored else None,
                       "flagged_non_ascii": flagged_non_ascii},
            "latency_ms": {"attack": latency(attack_ms), "benign": latency(benign_ms)},
        },
        "per_repeat": [{**r, "evasion_rate": round(r["evasion_rate"], 4),
                        "adaptive_rate": round(r["adaptive_rate"], 4),
                        "by_strategy": {s: {**v, "rate": round(v["rate"], 4)}
                                        for s, v in r["by_strategy"].items()}}
                       for r in repeats],
    }


def pct(d: dict) -> str:
    return (f"{100 * d['mean']:.2f}% ({100 * d['min']:.2f} to {100 * d['max']:.2f}, "
            f"med {100 * d['median']:.2f})")


def show_phase(phase: str, r: dict) -> None:
    s = r["summary"]
    print(f"{phase.upper()} phase on port {r['port']}, server expected with {r['expected_server']}")
    print(f"  defence detected: {r['detected_defence']}")
    print(f"  {r['repeats']} repeats of {r['sample']['variants_per_repeat'][0]} variants "
          f"({r['sample']['a_bases']} A bases + {r['sample']['c_bases_per_repeat']} C bases); "
          "rates as mean (min to max, median) over repeats")
    print(f"  evasion overall   {pct(s['evasion_rate'])}")
    for strategy, d in s["by_strategy"].items():
        print(f"    {strategy:26}{pct(d)}")
    print(f"  adaptive attacker {pct(s['adaptive_rate'])} of bases had a strategy that got through")
    b = s["benign"]
    print(f"  benign            {b['flagged']} of {b['of']} scored flagged "
          f"({100 * b['false_positive_rate']:.2f}%), {b['flagged_non_ascii']} of them non-ASCII; "
          f"{b['refused_by_validation']} of {b['sent']} refused by URL validation (422)")
    la, lb = s["latency_ms"]["attack"], s["latency_ms"]["benign"]
    print(f"  latency ms        attack median {la['median']} / p95 {la['p95']} ({la['requests']} "
          f"requests), benign median {lb['median']} / p95 {lb['p95']}")
    print(f"  statuses          {r['statuses']}")
    if phase == "before" and s["evasion_rate"]["mean"] < NEAR_ZERO:
        print(f"  NOTE: evasion is already near zero without the defence (mean "
              f"{100 * s['evasion_rate']['mean']:.2f}%), so there is little room to improve.")
    print("PASS" if r["passed"] else "FAIL: " + "; ".join(r["problems"]))


def paired(before: dict, after: dict, key: str) -> dict:
    diffs = [b[key] - a[key] for b, a in zip(before["per_repeat"], after["per_repeat"])]
    return {"before_minus_after": dist(diffs), "helped": sum(d > 0 for d in diffs),
            "equal": sum(d == 0 for d in diffs), "hurt": sum(d < 0 for d in diffs)}


def show_comparison(before: dict, after: dict) -> dict:
    sb, sa = before["summary"], after["summary"]

    def fp(s: dict) -> str:
        b = s["benign"]
        return f"{b['flagged']}/{b['of']} ({100 * b['false_positive_rate']:.2f}%)"

    def lat(s: dict, kind: str) -> str:
        d = s["latency_ms"][kind]
        return f"{d['median']} / {d['p95']} ms"

    rows = [("evasion overall", pct(sb["evasion_rate"]), pct(sa["evasion_rate"]))]
    rows += [(f"  {s}", pct(sb["by_strategy"][s]), pct(sa["by_strategy"][s])) for s in STRATEGIES]
    rows += [("adaptive attacker", pct(sb["adaptive_rate"]), pct(sa["adaptive_rate"])),
             ("benign false positives", fp(sb), fp(sa)),
             ("benign non-ASCII flagged", str(sb["benign"]["flagged_non_ascii"]),
              str(sa["benign"]["flagged_non_ascii"])),
             ("benign refused (422)", str(sb["benign"]["refused_by_validation"]),
              str(sa["benign"]["refused_by_validation"])),
             ("latency attack median / p95", lat(sb, "attack"), lat(sa, "attack")),
             ("latency benign median / p95", lat(sb, "benign"), lat(sa, "benign"))]
    print(f"\n{'':30}{'before (defence off)':>36}{'after (defence on)':>36}")
    for label, b, a in rows:
        print(f"{label:30}{b:>36}{a:>36}")
    comparison = {"evasion_rate": paired(before, after, "evasion_rate"),
                  "adaptive_rate": paired(before, after, "adaptive_rate")}
    for key, c in comparison.items():
        d = c["before_minus_after"]
        print(f"paired {key} (before minus after, percentage points): mean {100 * d['mean']:.2f}, "
              f"min {100 * d['min']:.2f}, max {100 * d['max']:.2f}; defence helped in "
              f"{c['helped']}, equal in {c['equal']}, hurt in {c['hurt']} of "
              f"{len(before['per_repeat'])} repeats")
    if sb["evasion_rate"]["mean"] < NEAR_ZERO:
        print(f"NOTE: without the defence the evasion rate is already near zero "
              f"({100 * sb['evasion_rate']['mean']:.2f}% mean): the baseline model is hard to evade "
              "with look-alikes, so the defence has little room to improve it.")
    return comparison


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--phase", required=True, choices=["before", "after"])
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--repeats", type=int, default=10,
                        help=f"seeded attack samples (1 to {MAX_REPEATS})")
    parser.add_argument("--json-out", type=Path, default=DEFAULT_OUT,
                        help="JSON file both phases are recorded in (default: %(default)s)")
    args = parser.parse_args()

    target = urlsplit(args.base_url)
    if target.scheme != "http" or target.hostname not in LOCAL_HOSTS:
        sys.exit("refusing: --base-url must be http://localhost, 127.0.0.1 or [::1]")
    if not 1 <= args.repeats <= MAX_REPEATS:
        sys.exit(f"refusing: --repeats must be between 1 and {MAX_REPEATS}")
    host, port = target.hostname, target.port or 80
    if health(host, port) != 200:
        sys.exit(f"no healthy server at {args.base_url}: start it first (see --help)")

    result = run_phase(args.phase, host, port, args.repeats)
    try:
        record = json.loads(args.json_out.read_text(encoding="utf-8"))
        record.setdefault("phases", {})
    except (OSError, ValueError):
        record = {"phases": {}}
    other = record["phases"].get("after" if args.phase == "before" else "before")
    if other and (other.get("sample") or {}).get("fingerprint") != result["sample"]["fingerprint"]:
        result["problems"].append("the samples differ from the other phase's: run both phases "
                                  "with the same --repeats and the same results files")
        result["passed"] = False
    show_phase(args.phase, result)

    record["description"] = ("Detection evasion (section 2.8): look-alike variants from "
                             "experiments/results/cases.csv sent to the running API with the "
                             "homoglyph defence off (before) and on (after), rate limiter off. "
                             "Written by scripts/security/evasion_before_after.py.")
    record["phases"][args.phase] = result
    record.pop("comparison", None)
    if "before" in record["phases"] and "after" in record["phases"]:
        record["comparison"] = show_comparison(record["phases"]["before"],
                                               record["phases"]["after"])
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(f"recorded the {args.phase} phase in {args.json_out}")
    sys.exit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
