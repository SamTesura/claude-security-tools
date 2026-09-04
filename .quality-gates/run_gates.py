#!/usr/bin/env python3
"""
Deterministic quality gates — Python edition.

Runs the checks a script can prove — tests pass, lint is clean, coverage did
not fall, complexity and CRAP did not get worse — and either reports them (warn
mode) or rejects the push (block mode).

Nothing here asks an LLM whether the code is good. Every number comes from a
tool, and the thresholds ratchet: a repo can only get better than the day the
gates were installed.

    python .quality-gates/run_gates.py            # run the gates
    python .quality-gates/run_gates.py --record   # re-record the baseline
    python .quality-gates/run_gates.py --report   # print numbers, never fail
"""

import json
import os
import pathlib
import subprocess
import sys
from datetime import date, datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CONFIG_PATH = os.path.join(HERE, "gates.config.json")

sys.path.insert(0, HERE)
from crap import analyze_coverage, format_report  # noqa: E402

ARGV = set(sys.argv[1:])
FORCE_RECORD = "--record" in ARGV
REPORT_ONLY = "--report" in ARGV

_TTY = sys.stdout.isatty()
C = {
    "red": "\x1b[31m", "green": "\x1b[32m", "yellow": "\x1b[33m",
    "dim": "\x1b[2m", "bold": "\x1b[1m", "off": "\x1b[0m",
} if _TTY else {k: "" for k in ("red", "green", "yellow", "dim", "bold", "off")}


def load_config():
    with open(CONFIG_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def save_config(config):
    with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(config, indent=2) + "\n")


def which(binary):
    for path in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(path, binary)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def run(label, command):
    sys.stdout.write(f"{C['dim']}· {label}{C['off']}\n")
    sys.stdout.flush()
    res = subprocess.run(
        command, cwd=ROOT, shell=isinstance(command, str),
        capture_output=True, text=True,
    )
    output = (res.stdout or "") + (res.stderr or "")
    return res.returncode == 0, res.returncode, output


def main():
    config = load_config()
    thresholds = config.get("thresholds", {})
    gates = config.get("gates", {})
    crap_max = thresholds.get("crapMax", 30)
    complexity_max = thresholds.get("complexityMax", 6)

    block_after = config.get("blockAfter")
    blocking = False
    if not REPORT_ONLY and block_after:
        try:
            ramp = datetime.strptime(block_after, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            blocking = datetime.now(timezone.utc) >= ramp
        except ValueError:
            blocking = False

    failures = []
    notes = []

    def fail(gate, detail):
        failures.append((gate, detail))

    py = sys.executable or "python3"

    # -------------------------------------------------------------- lint
    if gates.get("lint") is not False:
        if which("ruff"):
            ok, _code, output = run("lint (ruff)", ["ruff", "check", "."])
            if not ok:
                fail("lint", "\n".join(output.strip().splitlines()[-25:]))
        else:
            notes.append("lint: ruff not installed — skipped")

    # --------------------------------------------------- tests + coverage
    analysis = None
    want_coverage = gates.get("coverage") is not False
    have_pytest = subprocess.run(
        [py, "-m", "pytest", "--version"],
        cwd=ROOT, capture_output=True,
    ).returncode == 0
    if gates.get("test") is not False and not have_pytest:
        # Not installed is an environment gap, not a code defect. CI installs
        # requirements-dev.txt and enforces this gate for real.
        notes.append("tests: pytest not installed — run `pip install -r requirements-dev.txt`. "
                     "CI still enforces this gate.")
    elif gates.get("test") is not False:
        cov_source = config.get("coverageSource", ".")
        cmd = [py, "-m", "pytest"]
        if want_coverage:
            cmd += [
                f"--cov={cov_source}",
                "--cov-report=xml:coverage.xml",
                "--cov-report=term-missing",
            ]
        # Passing with no tests collected is an environment gap, not a defect.
        cmd.append("-q")
        ok, code, output = run("tests + coverage" if want_coverage else "tests", cmd)
        # pytest exit code 5 == "no tests collected"; treat as a note, not a fail.
        if code == 5:
            notes.append("tests: no tests collected — test gate skipped")
        elif not ok:
            fail("tests", "\n".join(output.strip().splitlines()[-30:]))
        if want_coverage and code != 5:
            cov_xml = os.path.join(ROOT, "coverage.xml")
            analysis = analyze_coverage(cov_xml, root=ROOT)
            if not analysis:
                from crap import cc_visit as _cc
                if _cc is None:
                    notes.append("coverage: radon not installed — run `pip install -r requirements-dev.txt`. CI still enforces this gate.")
                else:
                    notes.append("coverage: no coverage.xml produced — CRAP gate skipped")

    # -------------------------------------------------- ratchet comparisons
    measured = None
    if analysis:
        measured = {
            "coverage": round(analysis["totalCoverage"], 4),
            "worstCrap": round(analysis["worstCrap"], 2),
            "maxComplexity": analysis["maxComplexity"],
            "functions": len(analysis["functions"]),
        }

    baseline = config.get("baseline")
    # CI throws its working tree away, so a baseline recorded there never
    # persists. Quietly re-recording each run would make the ratchets a no-op.
    in_ci = bool(os.environ.get("CI"))

    if measured:
        if not baseline and in_ci and not FORCE_RECORD:
            msg = ("no committed baseline — the coverage, CRAP and complexity ratchets are "
                   "INACTIVE. Run `python .quality-gates/run_gates.py --record` locally and "
                   "commit gates.config.json.")
            if blocking:
                fail("baseline", msg)
            else:
                notes.append("\u26a0 " + msg)
        elif not baseline or FORCE_RECORD:
            config["baseline"] = {**measured, "recordedAt": date.today().isoformat()}
            save_config(config)
            baseline = config["baseline"]
            notes.append(
                f"baseline recorded: coverage {measured['coverage'] * 100:.1f}%, "
                f"worst CRAP {measured['worstCrap']}, max complexity {measured['maxComplexity']}"
            )
        else:
            if thresholds.get("coverageRatchet") is not False and \
                    measured["coverage"] < baseline["coverage"] - 0.005:
                fail("coverage", (
                    f"dropped to {measured['coverage'] * 100:.2f}% from a floor of "
                    f"{baseline['coverage'] * 100:.2f}%"
                ))
            crap_ceiling = max(baseline["worstCrap"], crap_max)
            if measured["worstCrap"] > crap_ceiling:
                fail("crap", f"worst CRAP {measured['worstCrap']} exceeds ceiling {crap_ceiling}")
            cc_ceiling = max(baseline["maxComplexity"], complexity_max)
            if measured["maxComplexity"] > cc_ceiling:
                fail("complexity", (
                    f"max cyclomatic complexity {measured['maxComplexity']} "
                    f"exceeds ceiling {cc_ceiling}"
                ))

    # ------------------------------------------------------------- report
    repo = os.path.basename(ROOT)
    print(f"\n{C['bold']}quality gates{C['off']} {C['dim']}{repo}{C['off']}")

    if measured:
        b = config.get("baseline")
        cov_floor = f"{C['dim']}  floor {b['coverage'] * 100:.2f}%{C['off']}" if b else ""
        print(f"  coverage       {measured['coverage'] * 100:.2f}%{cov_floor}")
        crap_ceil = f"{C['dim']}  ceiling {max(b['worstCrap'], crap_max)}{C['off']}" if b else ""
        print(f"  worst CRAP     {measured['worstCrap']}{crap_ceil}")
        cc_ceil = f"{C['dim']}  ceiling {max(b['maxComplexity'], complexity_max)}{C['off']}" if b else ""
        print(f"  max complexity {measured['maxComplexity']}{cc_ceil}")
        print(f"  functions      {measured['functions']}")
        offenders = format_report(analysis, crap_max=crap_max, complexity_max=complexity_max)
        if "within CRAP" not in offenders:
            print(f"\n{C['yellow']}  worst offenders{C['off']}")
            print(offenders)

    for note in notes:
        print(f"  {C['dim']}{note}{C['off']}")

    if not failures:
        print(f"\n{C['green']}✓ all gates passed{C['off']}\n")
        return 0

    print(f"\n{C['red']}✗ {len(failures)} gate(s) failed{C['off']}")
    for gate, detail in failures:
        print(f"\n{C['red']}  [{gate}]{C['off']}")
        print("\n".join(f"    {line}" for line in detail.splitlines()))

    if REPORT_ONLY:
        print(f"\n{C['dim']}report mode — not failing{C['off']}\n")
        return 0

    if not blocking:
        when = block_after or "never"
        print(f"\n{C['yellow']}⚠ warn mode — these become blocking on {when}. "
              f"Push allowed.{C['off']}\n")
        return 0

    print(f"\n{C['red']}Push rejected. Fix the above, or run with --report to inspect.{C['off']}\n")
    return 1


def _blocking_now():
    """Read just enough config to decide whether a crash should reject the push."""
    try:
        import json
        cfg = json.loads((pathlib.Path(__file__).parent / "gates.config.json").read_text())
        ba = cfg.get("blockAfter")
        return bool(ba) and date.today().isoformat() >= ba
    except Exception:
        return False


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        import traceback
        print("\nquality gates: the gate script itself failed —", file=sys.stderr)
        traceback.print_exc()
        # A broken gate must not silently block work during the warn ramp.
        if _blocking_now():
            print("\nPush rejected: gates are in blocking mode and could not run.", file=sys.stderr)
            sys.exit(1)
        print("\n\u26a0 warn mode — push allowed despite the gate failing to run.\n", file=sys.stderr)
        sys.exit(0)
