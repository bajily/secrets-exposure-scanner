"""Shared validation, findings, suppressions and reporting for defensive tools."""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import math
import sys
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

VERSION = "0.1.0"
SEVERITIES = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("timestamp must be an ISO 8601 string with a timezone")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("timestamps require a timezone")
    return result.astimezone(timezone.utc)


def object_value(value, label="input"):
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value


def records(data, key, required=()):
    object_value(data)
    rows = data.get(key)
    if not isinstance(rows, list):
        raise ValueError(f"{key} must be an array")
    for index, row in enumerate(rows):
        object_value(row, f"{key}[{index}]")
        if any(field not in row for field in required):
            raise ValueError(f"{key}[{index}] is missing required fields: {', '.join(required)}")
    return rows


def text(value, label):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value


def boolean(value, label):
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be boolean")
    return value


def number(value, label, minimum=0, maximum=None):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"{label} must be a finite number")
    if value < minimum or (maximum is not None and value > maximum):
        raise ValueError(f"{label} is outside the permitted range")
    return value


def string_list(value, label):
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{label} must be an array of non-empty strings")
    return value


def setting(policy, key, default, minimum=0, maximum=None):
    return number(policy.get(key, default), f"policy.{key}", minimum, maximum)


def finding(rule, severity, resource, title, evidence, remediation, **extra):
    if severity not in SEVERITIES:
        raise ValueError("unknown finding severity")
    resource = str(resource)
    stable = json.dumps([TOOL, rule, resource, extra.get("subject", "")], ensure_ascii=False)
    result = {"rule": rule, "severity": severity, "resource": resource,
              "title": title, "evidence": evidence, "remediation": remediation,
              "fingerprint": hashlib.sha256(stable.encode()).hexdigest()[:24]}
    result.update(extra)
    return result


def unique_rows(rows, key):
    result = {}
    for row in rows:
        identifier = text(row[key], key)
        if identifier in result:
            raise ValueError(f"duplicate {key} in inventory")
        result[identifier] = row
    return result


def decode_json(content):
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("JSON contains a duplicate key")
            result[key] = value
        return result
    return json.loads(content, object_pairs_hook=reject_duplicates,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("non-finite JSON number")))


def load_json(path):
    if path.stat().st_size > 10 * 1024 * 1024:
        raise ValueError("JSON input exceeds the 10 MiB limit")
    return decode_json(path.read_text(encoding="utf-8-sig"))


def build_report(findings, suppressions=(), now=None):
    now = now or datetime.now(timezone.utc)
    active, suppressed = [], []
    fingerprints = set()
    for suppression in suppressions:
        object_value(suppression, "suppression")
        text(suppression.get("fingerprint"), "suppression fingerprint")
        text(suppression.get("reason"), "suppression reason")
        timestamp(suppression.get("expires"))
        if suppression["fingerprint"] in fingerprints:
            raise ValueError("duplicate suppression fingerprint")
        fingerprints.add(suppression["fingerprint"])
    known = {item["fingerprint"]: item for item in suppressions
             if timestamp(item["expires"]) > now}
    for item in findings:
        if item["fingerprint"] in known:
            suppressed.append({**item, "suppression_reason": known[item["fingerprint"]]["reason"]})
        else:
            active.append(item)
    active.sort(key=lambda item: (-SEVERITIES[item["severity"]], item["resource"], item["rule"], item["fingerprint"]))
    return {"tool": TOOL, "version": VERSION, "generated_at": now.isoformat(),
            "summary": dict(Counter(item["severity"] for item in active)),
            "findings": active, "suppressed": suppressed}


def sarif(report):
    rules = {item["rule"]: item["title"] for item in report["findings"]}
    results = []
    for item in report["findings"]:
        results.append({"ruleId": item["rule"],
                        "level": "error" if SEVERITIES[item["severity"]] >= 3 else "warning" if SEVERITIES[item["severity"]] >= 1 else "note",
                        "message": {"text": item["title"] + ". " + item["remediation"]},
                        "locations": [{"logicalLocations": [{"name": item["resource"]}]}],
                        "partialFingerprints": {"securityToolFingerprint/v1": item["fingerprint"]},
                        "properties": {"severity": item["severity"], "evidence": item["evidence"]}})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": TOOL, "version": VERSION,
                       "rules": [{"id": key, "shortDescription": {"text": title}} for key, title in sorted(rules.items())]}},
                       "results": results}]}


def markdown(report):
    def escape(value):
        return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")
    lines = [f"# {TOOL} report", "", f"Version: {VERSION}. Findings: {len(report['findings'])}.", "",
             "| Severity | Resource | Finding | Recommended action |", "|---|---|---|---|"]
    for item in report["findings"]:
        lines.append("| " + " | ".join(escape(item[key]) for key in ("severity", "resource", "title", "remediation")) + " |")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument("input", nargs="?", type=Path, help="JSON inventory, event export or tool configuration")
    parser.add_argument("--demo", action="store_true", help="run the embedded synthetic example")
    parser.add_argument("--policy", type=Path, help="JSON object overriding documented defaults")
    parser.add_argument("--suppressions", type=Path, help="JSON array: fingerprint, reason, expires")
    parser.add_argument("--format", choices=["json", "sarif", "markdown"], default="json")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--fail-on", choices=list(SEVERITIES), default="high")
    parser.add_argument("--now", help="timezone-aware ISO timestamp for reproducible reviews")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args()
    if args.demo == bool(args.input):
        parser.error("provide exactly one of input or --demo")
    try:
        now = timestamp(args.now) if args.now else datetime.now(timezone.utc)
        data = object_value(json.loads(json.dumps(DEMO)) if args.demo else load_json(args.input))
        policy = object_value(load_json(args.policy), "policy") if args.policy else {}
        suppressions = load_json(args.suppressions) if args.suppressions else []
        if not isinstance(suppressions, list):
            raise ValueError("suppressions must be an array")
        report = build_report(audit(data, policy, now), suppressions, now)
        content = markdown(report) if args.format == "markdown" else json.dumps(sarif(report) if args.format == "sarif" else report, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            # Exclusive creation keeps earlier evidence from being overwritten.
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(content)
        else:
            print(content, end="")
        return int(any(SEVERITIES[item["severity"]] >= SEVERITIES[args.fail_on] for item in report["findings"]))
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        parser.exit(2, f"error: {type(exc).__name__}: {exc}\n")
import re

TOOL = "secrets-exposure-scanner"
DESCRIPTION = "Scan local source text for credential indicators without exposing matched secret values."
DEMO = {"documents": [{"path": "src/settings.py", "text": 'API_KEY = "aB7x9Q2n4T6m8R0p3Z5v1H7k"\nkey = "AKIAABCDEFGHIJKLMNOP"\n'}]}
PATTERNS = {"SECRET-AWS-ACCESS-ID": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
            "SECRET-GITHUB-TOKEN": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
            "SECRET-PRIVATE-KEY": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
            "SECRET-ASSIGNMENT": re.compile(r'''(?i)\b(?:api[_-]?key|access[_-]?token|secret|password)\s*[:=]\s*["']([^"'\s]{16,255})["']''')}


def entropy(value):
    if not value:
        return 0
    counts = Counter(value)
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def source_documents(data, policy):
    maximum_bytes = int(setting(policy, "maximum_file_bytes", 1024 * 1024, 1, 10 * 1024 * 1024))
    maximum_files = int(setting(policy, "maximum_files", 10000, 1, 100000))
    exclusions = string_list(policy.get("exclude", [".git/**", ".venv/**", "node_modules/**"]), "exclude")
    documents, skipped = [], []
    if "root" in data:
        root = Path(text(data["root"], "root")).resolve(strict=True)
        if not root.is_dir():
            raise ValueError("root must be a directory")
        for path in root.rglob("*"):
            relative = path.relative_to(root).as_posix()
            if path.is_symlink() or not path.is_file() or any(fnmatch.fnmatchcase(relative, pattern) for pattern in exclusions):
                continue
            if len(documents) + len(skipped) >= maximum_files:
                skipped.append({"path": ".", "reason": "file-count-limit"})
                break
            try:
                if path.stat().st_size > maximum_bytes:
                    skipped.append({"path": relative, "reason": "size-limit"})
                    continue
                with path.open("rb") as stream:
                    content = stream.read(maximum_bytes + 1)
                if len(content) > maximum_bytes:
                    skipped.append({"path": relative, "reason": "size-limit"})
                    continue
                if b"\0" in content[:4096]:
                    skipped.append({"path": relative, "reason": "binary"})
                    continue
                documents.append({"path": relative, "text": content.decode("utf-8")})
            except (OSError, UnicodeError):
                skipped.append({"path": relative, "reason": "unreadable-or-non-utf8"})
    else:
        for row in records(data, "documents", ("path", "text")):
            text(row["path"], "path")
            if not isinstance(row["text"], str):
                raise ValueError("document text must be a string")
            if any(fnmatch.fnmatchcase(row["path"], pattern) for pattern in exclusions):
                continue
            if len(row["text"].encode()) > maximum_bytes:
                skipped.append({"path": row["path"], "reason": "size-limit"})
            else:
                documents.append(row)
        if len(documents) > maximum_files:
            raise ValueError("document count exceeds the configured limit")
    return documents, skipped


def audit(data, policy, now):
    object_value(data)
    minimum_entropy = setting(policy, "minimum_entropy", 3.5, 0, 8)
    documents, skipped = source_documents(data, policy)
    result, reported = [], set()
    placeholders = string_list(policy.get("placeholder_values", ["CHANGEME", "EXAMPLE", "PLACEHOLDER"]), "placeholder_values")
    for document in documents:
        for line_number, line in enumerate(document["text"].splitlines(), 1):
            for rule, pattern in PATTERNS.items():
                for match in pattern.finditer(line):
                    value = match.group(1) if rule == "SECRET-ASSIGNMENT" else match.group(0)
                    if rule == "SECRET-ASSIGNMENT" and (entropy(value) < minimum_entropy or any(marker.lower() in value.lower() for marker in placeholders)):
                        continue
                    key = rule, document["path"], line_number
                    if key in reported:
                        continue
                    reported.add(key)
                    result.append(finding(rule, "high", document["path"], "Potential credential material in source text",
                                          {"line": line_number, "matched_value": "[REDACTED]", "match_length": len(value)},
                                          "Verify privately, rotate genuine credentials and remove them from source and relevant history.", subject=str(line_number)))
    for row in skipped:
        result.append(finding("SECRET-INSPECTION-GAP", "info", row["path"], "File was not inspected",
                              {"reason": row["reason"]}, "Review the inspection gap or use a suitable binary/file-format scanner."))
    return result


if __name__ == "__main__":
    raise SystemExit(main())
