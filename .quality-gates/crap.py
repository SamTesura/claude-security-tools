#!/usr/bin/env python3
"""
CRAP (Change Risk Anti-Patterns) analyzer — Python edition.

    CRAP(f) = CC(f)**2 * (1 - cov(f))**3 + CC(f)

Reads a Cobertura-shaped ``coverage.xml`` (what coverage.py emits with
``--cov-report=xml``) and derives, per function/method:

  - cyclomatic complexity, from ``radon.complexity.cc_visit`` run against the
    source file the function lives in
  - statement coverage, as covered executable lines inside the function's line
    range / all executable lines inside that range (line hits come straight out
    of coverage.xml)

The only dependency beyond the stdlib is ``radon`` — the same complexity engine
``radon cc`` uses on the command line.
"""

import os
import sys
import xml.etree.ElementTree as ET

try:
    from radon.complexity import cc_visit
except ImportError:  # pragma: no cover - reported by run_gates instead
    cc_visit = None


def _parse_coverage_xml(coverage_path):
    """Return {abs_or_rel_filename: {line_no: hits}} plus the <source> roots."""
    tree = ET.parse(coverage_path)
    root = tree.getroot()

    sources = [s.text for s in root.findall("./sources/source") if s.text]

    files = {}
    for cls in root.iter("class"):
        filename = cls.get("filename")
        if not filename:
            continue
        line_map = files.setdefault(filename, {})
        for line in cls.findall("./lines/line"):
            try:
                num = int(line.get("number"))
                hits = int(line.get("hits"))
            except (TypeError, ValueError):
                continue
            # A class may appear more than once (methods split); keep max hits.
            line_map[num] = max(line_map.get(num, 0), hits)
    return files, sources


def _resolve_source(filename, sources, root):
    """Find the on-disk path for a coverage.xml filename entry."""
    candidates = []
    if os.path.isabs(filename):
        candidates.append(filename)
    for src in sources:
        candidates.append(os.path.join(src, filename))
    candidates.append(os.path.join(root, filename))
    candidates.append(filename)
    for cand in candidates:
        if os.path.isfile(cand):
            return cand
    return None


def _coverage_in_range(line_map, start, end, def_line):
    """(covered, total) executable lines within [start, end] from coverage.xml."""
    total = 0
    covered = 0
    for num, hits in line_map.items():
        if start <= num <= end:
            total += 1
            if hits > 0:
                covered += 1
    if total == 0:
        # No executable lines of its own (e.g. a one-line lambda-ish body):
        # fall back to whether the def line itself was executed.
        if def_line in line_map:
            return (1, 1) if line_map[def_line] > 0 else (0, 1)
        return (0, 0)
    return covered, total


def analyze_coverage(coverage_path, root=None):
    """Complexity + coverage for every function in a coverage.xml report."""
    if cc_visit is None:
        raise RuntimeError("radon is not installed — cannot compute complexity")
    if root is None:
        root = os.path.dirname(os.path.abspath(coverage_path)) or "."

    try:
        files, sources = _parse_coverage_xml(coverage_path)
    except (ET.ParseError, FileNotFoundError):
        return None

    functions = []
    total_lines = 0
    covered_lines = 0

    for filename, line_map in sorted(files.items()):
        for hits in line_map.values():
            total_lines += 1
            if hits > 0:
                covered_lines += 1

        src_path = _resolve_source(filename, sources, root)
        if not src_path:
            continue
        try:
            with open(src_path, encoding="utf-8") as fh:
                source = fh.read()
        except (OSError, UnicodeDecodeError):
            continue
        try:
            blocks = cc_visit(source)
        except SyntaxError:
            continue

        for block in blocks:
            start = block.lineno
            end = getattr(block, "endline", None) or start
            covered, total = _coverage_in_range(line_map, start, end, start)
            coverage = covered / total if total > 0 else 0.0

            classname = getattr(block, "classname", None)
            name = block.name
            if classname:
                name = f"{classname}.{name}"

            complexity = block.complexity
            crap = complexity ** 2 * (1 - coverage) ** 3 + complexity
            functions.append({
                "file": filename.replace("\\", "/"),
                "name": name,
                "line": start,
                "complexity": complexity,
                "coverage": coverage,
                "crap": round(crap * 100) / 100,
            })

    return {
        "functions": functions,
        "totalCoverage": covered_lines / total_lines if total_lines else 0.0,
        "totalStatements": total_lines,
        "worstCrap": max((f["crap"] for f in functions), default=0),
        "maxComplexity": max((f["complexity"] for f in functions), default=0),
    }


def format_report(analysis, crap_max=30, complexity_max=6, limit=10):
    if not analysis or not analysis["functions"]:
        return "  (no coverage data — no functions analyzed)"
    offenders = sorted(analysis["functions"], key=lambda f: f["crap"], reverse=True)
    offenders = [
        f for f in offenders
        if f["crap"] > crap_max or f["complexity"] > complexity_max
    ][:limit]
    if not offenders:
        return "  all functions within CRAP and complexity limits"

    rows = []
    for f in offenders:
        loc = f"{f['file']}:{f['line']}"
        rows.append(
            f"  CRAP {str(f['crap']).rjust(7)}  CC {str(f['complexity']).rjust(3)}  "
            f"cov {str(round(f['coverage'] * 100)).rjust(3)}%  {f['name']}\n      {loc}"
        )
    return "\n".join(rows)


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "coverage.xml"
    result = analyze_coverage(path)
    if not result:
        sys.stderr.write(f"No coverage report at {path}\n")
        sys.exit(2)
    print(f"Functions analyzed: {len(result['functions'])}")
    print(f"Overall line coverage: {result['totalCoverage'] * 100:.2f}%")
    print(f"Worst CRAP: {result['worstCrap']}   Max complexity: {result['maxComplexity']}")
    print(format_report(result, crap_max=30, complexity_max=6))
