# Secrets Exposure Scanner

Local source-code secret scanning with redacted findings, entropy checks, bounded file reads, exclusion rules and CI-friendly SARIF output.

Detect likely credential material in a repository without printing matched secret values.

**Python 3.11+ · Standard library · JSON, SARIF 2.1.0 and Markdown reports · MIT license**

## Quick start

```bash
git clone https://github.com/bajily/secrets-exposure-scanner.git
cd secrets-exposure-scanner
python security_tool.py --demo --now 2026-10-13T12:00:00Z
python -m unittest discover -v
```

The synthetic example intentionally contains risky conditions. Exit status `1` means a finding met the configured threshold; it is not a crash.

```bash
python security_tool.py example.json --format sarif --output findings.sarif
python security_tool.py example.json --format markdown --output review.md --fail-on critical
python security_tool.py example.json --policy policy.json --suppressions exceptions.json
```

## How the review works

Detect likely credential material in a repository without printing matched secret values.

Implemented rule families: `SECRET-ASSIGNMENT`, `SECRET-AWS-ACCESS-ID`, `SECRET-GITHUB-TOKEN`, `SECRET-INSPECTION-GAP`, `SECRET-PRIVATE-KEY`.

Each finding includes a rule ID, severity, resource, evidence, a recommended review action and a stable fingerprint. Reports sort findings by severity and resource. No automatic enforcement is performed.

## Input contract

The example below is the minimal supported export structure. Required fields are validated; malformed or ambiguous inputs cause exit status 2.

For local source inspection use `{"root":"/absolute/path/to/a-controlled-repository"}` instead of inline documents. File reads are bounded and matches are redacted. Use a directory under your control; simultaneous adversarial filesystem changes are outside the inspection model.

```json
{
  "documents": [
    {
      "path": "src/settings.py",
      "text": "API_KEY = \"aB7x9Q2n4T6m8R0p3Z5v1H7k\"\nkey = \"AKIAABCDEFGHIJKLMNOP\"\n"
    }
  ]
}
```

Identifiers in examples are synthetic. Adapt exports to this exact shape instead of assuming provider APIs use identical field names.

## Policy and integration

Policy defaults and the input fields are documented below and in the audit function. Review thresholds before operational use.

```json
{
  "minimum_entropy": 3.5,
  "maximum_files": 10000,
  "exclude": [
    ".git/**",
    ".venv/**",
    "node_modules/**"
  ],
  "placeholder_values": [
    "CHANGEME",
    "EXAMPLE",
    "PLACEHOLDER"
  ]
}
```

The empty object selects defaults. Every input file is limited to 10 MiB. Duplicate JSON keys and non-finite numbers are rejected. Timestamps require explicit timezones. `--now` makes time-dependent reviews reproducible.

Exit statuses: `0` means no active finding meets `--fail-on`; `1` means the threshold is met; `2` means invalid input or an operational error. Output files are created exclusively and existing evidence is not overwritten. A clean report does not establish that a system is secure.

## Reviewed exceptions

Use a finding's exact fingerprint, an explanation and an expiration date:

```json
[
  {"fingerprint": "COPY-A-FINDING-FINGERPRINT", "reason": "Approved temporary exception; ticket SEC-123", "expires": "2027-01-01T00:00:00Z"}
]
```

Expired exceptions stop suppressing findings. Suppressed findings remain in JSON evidence. Keep exception review separate from code changes.

## Validation and deployment limits

Unit tests exercise the detector, clean inputs, boundary conditions, report generation, input failures and exception expiry. GitHub Actions runs the suite on Python 3.11 and 3.14.

Heuristic rules can miss secrets and produce false positives. The scanner reads an explicitly configured local root, skips symbolic links and binary files, and reports files that could not be inspected. It never validates credentials against a service.

Version 0.1.0 is an initial implementation for controlled evaluation. Establish a company-specific baseline, test representative sanitized exports, review false positives and perform an independent security review before relying on it operationally. These projects have no measured production performance or effectiveness claims.

## Security and contributions

Keep secrets, private inventories, real email, signing keys and sensitive logs out of public issues and repositories. Publish only synthetic or sanitized fixtures. Findings and generated reports can contain private asset identifiers; protect them as internal security records.

For a suspected vulnerability, use GitHub private reporting if available. Otherwise describe the issue without secrets or sensitive exploit details. Include a reproducible synthetic test with focused changes, and run the test suite before proposing a contribution.

## بالعربية

أداة دفاعية لتحليل الأدلة الأمنية وإنتاج نتائج قابلة للمراجعة مع قواعد واضحة واختبارات. تعمل على مدخلات موثقة وتدعم ضبط السياسات والاستثناءات المؤقتة. يلزم تقييمها على بيئة الشركة قبل الاعتماد التشغيلي؛ لا تقدّم ضمانًا شاملًا لحماية الأنظمة.

## Reference model

[OWASP secrets management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html). The focused checks above cover the documented subset and do not imply full conformance.
