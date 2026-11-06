#!/usr/bin/env python3
"""RAG Corpus Poison Scanner.

Scans documents *before* they are indexed into a RAG (retrieval-augmented
generation) corpus and flags content an attacker could use to steer the
LLM that later retrieves them: embedded instructions, hidden text,
fake citations, and exfiltration triggers.

Why ingestion time matters: once a poisoned document is chunked and
embedded, every future retrieval can surface the payload to the model.
Catching it at the door is cheaper than catching it at query time.

Usage:
    python rag_corpus_scanner.py docs/
    python rag_corpus_scanner.py docs/ --json report.json
    python rag_corpus_scanner.py docs/ --fail-on high   # CI gate
    python rag_corpus_scanner.py single-doc.md
    cat doc.md | python rag_corpus_scanner.py -

Exit codes: 0 = corpus clean, 1 = findings, 2 = usage/input error.

Standard library only. No network calls, no API keys, no data leaves
the machine.
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# ---------------------------------------------------------------------------
# Detection rules: (finding, severity, pattern)
# ---------------------------------------------------------------------------

RULES = [
    # Embedded instructions aimed at the model that will read the chunk.
    ("instruction_override", "critical",
     re.compile(r"\b(ignore|disregard|override|forget)\b[^.\n]{0,60}\b"
                r"(previous|prior|above|earlier|original|system|your)\b[^.\n]{0,40}"
                r"\b(instructions?|prompt|rules?|guidelines?)\b", re.I)),
    ("role_reassignment", "critical",
     re.compile(r"\b(you are now|from now on you are|act as|pretend (to be|you are)|"
                r"your new (role|identity|persona))\b", re.I)),
    ("fake_system_marker", "critical",
     re.compile(r"(^\s*(SYSTEM|ASSISTANT|USER)\s*:)|(\[INST\]|<<SYS>>|<\|system\|>|"
                r"<\|im_start\|>)", re.I | re.M)),
    ("exfiltration_instruction", "critical",
     re.compile(r"\b(send|share|forward|upload|email|exfiltrate|leak|reveal|disclose)\b"
                r"[^.\n]{0,80}\b(private|confidential|secret|password|api[- ]?key|"
                r"credentials?|personal data|ssn|credit card)\b", re.I)),
    ("fake_citation", "high",
     re.compile(r"\b(according to|as (?:stated|reported|shown) (?:in|by)|"
                r"see (?:the )?(?:study|report|paper|source))\b[^.\n]{0,80}"
                r"\b(doi:\s*10\.\S+|https?://\S+|arxiv:\S+)\b", re.I)),
    ("credential_harvest", "high",
     re.compile(r"\b(enter|provide|type|submit|paste)\b[^.\n]{0,50}\b"
                r"(your )?(password|api[- ]?key|token|otp|one[- ]time code|"
                r"private key|secret)\b", re.I)),
    ("tool_abuse", "high",
     re.compile(r"\b(run|execute|call|invoke|trigger)\b[^.\n]{0,40}\b"
                r"(shell|command|script|tool|function|api|sql|query|delete|"
                r"drop table|rm -rf|wget|curl)\b", re.I)),
    ("urgency_override", "medium",
     re.compile(r"\b(urgent|immediately|right now|as soon as possible|"
                r"do not (ask|verify|check|confirm)|without (asking|verification|"
                r"confirmation))\b", re.I)),
    ("authority_claim", "medium",
     re.compile(r"\b(as (?:an? )?(?:admin|administrator|developer|system|"
                r"security team|the user)|i am (?:the )?(?:admin|developer|"
                r"system|your creator))\b", re.I)),
    ("jailbreak_attempt", "high",
     re.compile(r"\b(dan mode|developer mode|jailbreak|do anything now|"
                r"no (?:restrictions|limits|filter)|bypass (?:the )?(?:filter|"
                r"safety|guardrail))\b", re.I)),
]

# Hidden-text detectors: content a human reader will not see, but a
# chunker / embedder will still ingest.
HIDDEN_PATTERNS = [
    ("zero_width_chars", "high",
     re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]")),
    ("html_comment", "high",
     re.compile(r"<!--.*?-->", re.S)),
    ("hidden_html", "high",
     re.compile(r"<[^>]+(?:display\s*:\s*none|visibility\s*:\s*hidden|"
                r"font-size\s*:\s*0|color\s*:\s*(?:#fff(?:fff)?|white|"
                r"transparent))[^>]*>", re.I)),
    ("white_on_white", "medium",
     re.compile(r"color\s*:\s*(?:#fff(?:fff)?|white)\s*;\s*background(?:-color)?"
                r"\s*:\s*(?:#fff(?:fff)?|white)", re.I)),
    ("homoglyph_mix", "medium",
     re.compile(r"[\u0430-\u044f\u0456\u0458\u0501\u0406\u0405\u0408\u0405]"
                r"[a-zA-Z]|[a-zA-Z][\u0430-\u044f]")),
]


@dataclass
class Finding:
    file: str
    line: int
    rule: str
    severity: str
    snippet: str


@dataclass
class FileReport:
    path: str
    findings: list = field(default_factory=list)
    lines: int = 0

    @property
    def worst(self) -> str:
        if not self.findings:
            return "clean"
        return max((f.severity for f in self.findings),
                   key=lambda s: SEVERITY_RANK[s])


def scan_text(text: str, filename: str) -> FileReport:
    """Scan one document's text and return its findings."""
    report = FileReport(path=filename, lines=text.count("\n") + 1)
    lines = text.splitlines()

    def add(rule, severity, line_no, snippet):
        snippet = snippet.strip()
        if len(snippet) > 120:
            snippet = snippet[:117] + "..."
        report.findings.append(
            Finding(filename, line_no, rule, severity, snippet))

    for i, line in enumerate(lines, 1):
        for rule, severity, pattern in RULES:
            match = pattern.search(line)
            if match:
                add(rule, severity, i, match.group(0))

    # Hidden-text rules run over the whole document (comments and tags
    # can span lines), then get mapped back to a line number.
    for rule, severity, pattern in HIDDEN_PATTERNS:
        for match in pattern.finditer(text):
            line_no = text.count("\n", 0, match.start()) + 1
            add(rule, severity, line_no, match.group(0))

    return report


def scan_path(path: Path) -> list:
    """Scan a file, or every supported file under a directory."""
    exts = {".txt", ".md", ".markdown", ".html", ".htm", ".rst"}
    if path.is_file():
        targets = [path]
    elif path.is_dir():
        targets = sorted(p for p in path.rglob("*")
                         if p.is_file() and p.suffix.lower() in exts)
    else:
        raise FileNotFoundError(f"no such file or directory: {path}")

    reports = []
    for target in targets:
        try:
            text = target.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"warning: cannot read {target}: {exc}", file=sys.stderr)
            continue
        reports.append(scan_text(text, str(target)))
    return reports


def summarize(reports: list) -> dict:
    total_findings = sum(len(r.findings) for r in reports)
    worst = "clean"
    for r in reports:
        if SEVERITY_RANK.get(r.worst, 0) > SEVERITY_RANK.get(worst, 0):
            worst = r.worst
    poisoned = [r.path for r in reports if r.findings]
    counts = {}
    for r in reports:
        for f in r.findings:
            counts[f.rule] = counts.get(f.rule, 0) + 1
    return {
        "files_scanned": len(reports),
        "files_flagged": len(poisoned),
        "total_findings": total_findings,
        "worst_severity": worst,
        "rule_counts": counts,
        "flagged_files": poisoned,
    }


def print_report(reports: list) -> None:
    summary = summarize(reports)
    print(f"{summary['files_scanned']} file(s) scanned, "
          f"{summary['files_flagged']} flagged, "
          f"{summary['total_findings']} finding(s), "
          f"worst severity: {summary['worst_severity']}")
    for r in reports:
        for f in r.findings:
            print(f"  {f.file}:{f.line}: [{f.severity}] {f.rule}: "
                  f"{f.snippet}")
    if summary["rule_counts"]:
        counts = ", ".join(f"{k}={v}"
                           for k, v in sorted(summary["rule_counts"].items()))
        print(f"Counts: {counts}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Scan documents before RAG indexing for poisoned content.")
    parser.add_argument("path", help="file, directory, or '-' for stdin")
    parser.add_argument("--json", metavar="FILE",
                        help="write a JSON report to FILE")
    parser.add_argument("--fail-on", choices=list(SEVERITY_RANK),
                        default="critical",
                        help="exit 1 when a finding of at least this "
                             "severity appears (default: critical)")
    args = parser.parse_args(argv)

    if args.path == "-":
        text = sys.stdin.read()
        reports = [scan_text(text, "<stdin>")]
    else:
        try:
            reports = scan_path(Path(args.path))
        except FileNotFoundError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if not reports:
        print("no supported documents found", file=sys.stderr)
        return 2

    summary = summarize(reports)
    if args.json:
        payload = {
            "summary": summary,
            "files": [
                {"path": r.path, "lines": r.lines, "worst": r.worst,
                 "findings": [vars(f) for f in r.findings]}
                for r in reports
            ],
        }
        Path(args.json).write_text(json.dumps(payload, indent=2),
                                   encoding="utf-8")
        print(f"JSON report written to {args.json}")

    print_report(reports)
    threshold = SEVERITY_RANK[args.fail_on]
    worst = SEVERITY_RANK.get(summary["worst_severity"], 0)
    return 1 if worst >= threshold else 0


if __name__ == "__main__":
    sys.exit(main())
