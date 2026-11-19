#!/usr/bin/env python3
"""
AI Code Security Scanner (aisec_scan.py)
Zero-Dependency SAST Auditor for AI-Generated / Vibe-Coded Python, JS/TS, SQL & Go Code.
Detects SQL Injection, OS Command Injection, eval/exec, insecure deserialization,
XSS (dangerouslySetInnerHTML), weak crypto, TLS verification bypass & hardcoded secrets.
Author: Wallison Araujo (@WallisonWS) | License: MIT
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple


SAST_RULES: List[Tuple[str, str, str, str, str]] = [
    ("CWE-89", "SQL Injection (String Interpolation)", "CRITICAL", r"(?i)(?:execute|query)\(\s*(?:f['\"]|`[^`]*\$\{|['\"][^'\"]*\s*\+\s*)", "Use parameterized queries / prepared statements instead of string concatenation."),
    ("CWE-78", "OS Command Injection (shell=True / exec)", "CRITICAL", r"(?i)(?:subprocess\.(?:run|Popen|call)\([^)]*shell\s*=\s*True|child_process\.exec\(|os\.system\()", "Pass argument lists with shell=False or use execFile()."),
    ("CWE-94", "Dynamic Code Execution (eval / exec)", "CRITICAL", r"\b(?:eval|exec)\s*\(", "Eliminate eval/exec; use JSON.parse or safe AST parsers."),
    ("CWE-502", "Insecure Deserialization (pickle / yaml.load)", "CRITICAL", r"(?:pickle\.loads?\(|yaml\.load\([^)]*(?!Loader\s*=\s*yaml\.SafeLoader))", "Use json.loads() or yaml.safe_load()."),
    ("CWE-79", "DOM XSS (dangerouslySetInnerHTML / innerHTML)", "HIGH", r"(?:dangerouslySetInnerHTML|\.innerHTML\s*=)", "Use textContent or sanitize HTML via DOMPurify."),
    ("CWE-295", "TLS Certificate Verification Disabled", "CRITICAL", r"(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true)", "Never disable TLS certificate validation in production."),
    ("CWE-942", "Permissive Wildcard CORS (*)", "MEDIUM", r"(?i)(?:Access-Control-Allow-Origin['\"]?\s*[:=]\s*['\"]\*['\"]|allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\])", "Explicitly allowlist trusted production origins."),
    ("CWE-327", "Weak Cryptography (MD5 / SHA1)", "MEDIUM", r"(?i)(?:hashlib\.(?:md5|sha1)\(|createHash\(['\"](?:md5|sha1)['\"]\))", "Upgrade to SHA-256 / Argon2id / bcrypt."),
    ("CWE-798", "Hardcoded API Key / Credential", "CRITICAL", r"\b(?:AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{36}|AIza[0-9A-Za-z\-_]{35})\b", "Move secrets into environment variables or a Secrets Manager."),
]


def scan_code(code: str, filename: str = "<stdin>") -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    for line_no, line in enumerate(code.splitlines(), start=1):
        for cwe, title, sev, pattern, fix in SAST_RULES:
            if re.search(pattern, line):
                findings.append({"file": filename, "line": line_no, "cwe": cwe, "rule": title, "severity": sev, "fix": fix, "snippet": line.strip()[:90]})
    penalty = sum(25 if f["severity"] == "CRITICAL" else 15 if f["severity"] == "HIGH" else 8 for f in findings)
    score = max(0, 100 - penalty)
    grade = "A+" if score >= 95 else "A" if score >= 85 else "B" if score >= 75 else "C" if score >= 60 else "F"
    return {"file": filename, "score": score, "grade": grade, "findings_count": len(findings), "findings": findings}


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aisec-scan", description="Zero-Dependency SAST Scanner for AI-Generated Code")
    parser.add_argument("target", help="File or directory to audit")
    args = parser.parse_args(argv)
    target = Path(args.target)
    reports = []
    if target.is_file():
        reports.append(scan_code(target.read_text(encoding="utf-8", errors="ignore"), str(target)))
    else:
        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "venv", ".venv", "__pycache__")]
            for f in files:
                if f.endswith((".py", ".js", ".ts", ".tsx", ".go")):
                    fp = Path(root) / f
                    rep = scan_code(fp.read_text(encoding="utf-8", errors="ignore"), str(fp))
                    if rep["findings"]:
                        reports.append(rep)
    print(json.dumps(reports, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
