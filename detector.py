from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any


PATTERNS_FILE = Path(__file__).with_name("patterns.json")

MAX_FILE_SIZE_BYTES = 1 * 1024 * 1024

ALLOWED_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".java",
    ".go",
    ".rb",
    ".php",
    ".sh",
    ".html",
    ".css",
    ".json",
    ".yaml",
    ".yml",
    ".env",
    ".txt",
    ".config",
}

PLACEHOLDER_WORDS = {
    "example",
    "sample",
    "dummy",
    "fake",
    "test",
    "testing",
    "placeholder",
    "changeme",
    "change_me",
    "replace_me",
    "your_key_here",
    "your_token_here",
    "not_a_real_key",
    "xxx",
    "todo",
}

TEST_FILENAME_WORDS = {
    "test",
    "tests",
    "sample",
    "samples",
    "example",
    "examples",
    "demo",
}

ENV_REFERENCE_MARKERS = (
    "os.getenv(",
    "os.environ[",
    "process.env.",
    "getenv(",
    "${",
    "[REDACTED]",
)

SECRET_VARIABLE_PATTERN = re.compile(
    r"(?i)\b("
    r"password|passwd|pwd|secret|token|api[_-]?key|apikey|"
    r"access[_-]?key|client[_-]?secret|auth|database[_-]?url"
    r")\b"
)

ASSIGNMENT_VALUE_PATTERN = re.compile(
    r"""(?x)
    (?P<variable>[A-Za-z_][A-Za-z0-9_-]*)
    \s*(?:=|:)\s*
    ["']
    (?P<value>[^"']{8,})
    ["']
    """
)


def load_patterns() -> list[dict[str, Any]]:
    """Load secret-detection patterns from patterns.json."""
    try:
        with PATTERNS_FILE.open("r", encoding="utf-8") as file:
            patterns = json.load(file)
    except FileNotFoundError as error:
        raise RuntimeError(f"Missing pattern file: {PATTERNS_FILE}") from error
    except json.JSONDecodeError as error:
        raise RuntimeError("patterns.json contains invalid JSON.") from error

    required_fields = {"name", "service", "severity", "regex"}

    for pattern in patterns:
        missing = required_fields - pattern.keys()
        if missing:
            raise RuntimeError(
                f"Pattern {pattern!r} is missing fields: {sorted(missing)}"
            )

        try:
            pattern["_compiled"] = re.compile(pattern["regex"])
        except re.error as error:
            raise RuntimeError(
                f"Invalid regex for {pattern['name']}: {error}"
            ) from error

    return patterns


PATTERNS = load_patterns()


def shannon_entropy(value: str) -> float:
    """Calculate Shannon entropy in bits per character."""
    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def redact_secret(secret: str) -> str:
    """Return a safe preview that does not reveal the full secret."""
    if not secret or len(secret) < 10:
        return "[REDACTED]"

    if secret.startswith("-----BEGIN"):
        return "-----BEGIN [REDACTED] PRIVATE KEY-----"

    if "://" in secret:
        scheme = secret.split("://", 1)[0]
        return f"{scheme}://[REDACTED]"

    visible_start = 4 if len(secret) >= 16 else 2
    visible_end = 4 if len(secret) >= 20 else 2
    hidden_count = min(16, max(8, len(secret) - visible_start - visible_end))

    return (
        secret[:visible_start]
        + ("•" * hidden_count)
        + secret[-visible_end:]
    )


def redact_context(line: str, secret: str) -> str:
    """Replace the detected secret in its line with [REDACTED]."""
    if not secret:
        return line.strip()

    return line.replace(secret, "[REDACTED]").strip()


def is_comment_line(line: str) -> bool:
    """Perform simple comment detection for common programming languages."""
    stripped = line.lstrip()

    return stripped.startswith((
        "#",
        "//",
        "/*",
        "*",
        "<!--",
    ))


def looks_like_placeholder(value: str, line: str = "") -> bool:
    """Return True when a value or its context appears to be fake/demo data."""
    combined = f"{value} {line}".lower()

    return any(word in combined for word in PLACEHOLDER_WORDS)


def is_test_or_example_file(filename: str) -> bool:
    """Return True for filenames likely used in tests, samples, or demos."""
    lowered = Path(filename).name.lower()

    return any(word in lowered for word in TEST_FILENAME_WORDS)


def contains_environment_reference(line: str) -> bool:
    """Return True when the line already gets its value securely."""
    lowered = line.lower()

    return any(marker.lower() in lowered for marker in ENV_REFERENCE_MARKERS)


def extract_variable_name(line: str, match_start: int) -> str:
    """Try to identify the variable associated with a detected secret."""
    prefix = line[:match_start]

    assignment_match = re.search(
        r"([A-Za-z_][A-Za-z0-9_-]*)\s*(?:=|:)\s*[\"']?[^\"']*$",
        prefix,
    )

    if assignment_match:
        return assignment_match.group(1)

    variable_match = SECRET_VARIABLE_PATTERN.search(line)

    if variable_match:
        return variable_match.group(1)

    return "SECRET"


def normalize_environment_variable(name: str, service: str) -> str:
    """Convert a variable name into uppercase SCREAMING_SNAKE_CASE."""
    candidate = name or service or "SECRET"

    candidate = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", candidate)
    candidate = re.sub(r"[^A-Za-z0-9]+", "_", candidate)
    candidate = candidate.strip("_").upper()

    return candidate or f"{service.upper()}_SECRET"


def adjust_severity(
    default_severity: str,
    *,
    is_placeholder: bool,
    in_comment: bool,
    test_file: bool,
) -> str:
    """Lower severity when context suggests the finding is not production data."""
    order = ["Low", "Medium", "High", "Critical"]

    try:
        index = order.index(default_severity)
    except ValueError:
        index = 1

    reduction = 0

    if is_placeholder:
        reduction += 2

    if in_comment:
        reduction += 1

    if test_file:
        reduction += 1

    return order[max(0, index - reduction)]


def calculate_confidence(
    *,
    known_format: bool,
    entropy: float,
    secret_length: int,
    variable_name: str,
    is_placeholder: bool,
    in_comment: bool,
    test_file: bool,
) -> int:
    """Calculate a deterministic confidence score from 0 to 100."""
    confidence = 45

    if known_format:
        confidence += 30

    if SECRET_VARIABLE_PATTERN.search(variable_name):
        confidence += 10

    if secret_length >= 20:
        confidence += 5

    if secret_length >= 32:
        confidence += 5

    if entropy >= 3.5:
        confidence += 5

    if entropy >= 4.2:
        confidence += 5

    if is_placeholder:
        confidence -= 45

    if in_comment:
        confidence -= 20

    if test_file:
        confidence -= 15

    return max(0, min(100, confidence))


def finding_id(
    *,
    secret: str,
    secret_type: str,
    filename: str,
    line_number: int,
) -> str:
    """Create a non-reversible identifier without exposing the secret."""
    raw = f"{secret_type}|{filename}|{line_number}|{secret}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def build_finding(
    *,
    pattern: dict[str, Any],
    secret: str,
    line: str,
    filename: str,
    line_number: int,
    column_number: int,
    variable_name: str,
) -> dict[str, Any]:
    """Build one normalized finding dictionary."""
    entropy = round(shannon_entropy(secret), 2)
    placeholder = looks_like_placeholder(secret, line)
    comment = is_comment_line(line)
    test_file = is_test_or_example_file(filename)
    known_format = pattern["service"] not in {
        "generic_api",
        "generic_token",
        "password",
    }

    confidence = calculate_confidence(
        known_format=known_format,
        entropy=entropy,
        secret_length=len(secret),
        variable_name=variable_name,
        is_placeholder=placeholder,
        in_comment=comment,
        test_file=test_file,
    )

    severity = adjust_severity(
        pattern["severity"],
        is_placeholder=placeholder,
        in_comment=comment,
        test_file=test_file,
    )

    environment_variable = normalize_environment_variable(
        variable_name,
        pattern["service"],
    )

    return {
        "id": finding_id(
            secret=secret,
            secret_type=pattern["name"],
            filename=filename,
            line_number=line_number,
        ),
        "type": pattern["name"],
        "service": pattern["service"],
        "file": filename,
        "line": line_number,
        "column": column_number,
        "severity": severity,
        "confidence": confidence,
        "redacted": redact_secret(secret),
        "context_redacted": redact_context(line, secret),
        "variable_name": variable_name,
        "entropy": entropy,
        "is_placeholder": placeholder,
        "in_comment": comment,
        "known_format": known_format,
        "explanation": "",
        "blast_radius": "",
        "remediation": "",
        "fixed_line": "",
        "environment_variable": environment_variable,
        "_secret": secret,
    }


def scan_known_patterns(
    text: str,
    filename: str,
) -> list[dict[str, Any]]:
    """Scan text using provider-specific and generic regex patterns."""
    findings: list[dict[str, Any]] = []

    for line_number, line in enumerate(text.splitlines(), start=1):
        if contains_environment_reference(line):
            continue

        for pattern in PATTERNS:
            compiled: re.Pattern[str] = pattern["_compiled"]

            for match in compiled.finditer(line):
                # Assignment-style patterns capture only the credential value
                # in group 1. Provider-specific patterns normally use group 0.
                secret_group = 1 if match.lastindex else 0
                secret = match.group(secret_group)
                secret_start = match.start(secret_group)

                if not secret or not secret.strip():
                    continue

                variable_name = extract_variable_name(line, match.start())

                findings.append(
                    build_finding(
                        pattern=pattern,
                        secret=secret,
                        line=line,
                        filename=filename,
                        line_number=line_number,
                        column_number=secret_start + 1,
                        variable_name=variable_name,
                    )
                )

    return findings


def scan_entropy_candidates(
    text: str,
    filename: str,
) -> list[dict[str, Any]]:
    """Find suspicious high-entropy assignments missed by known patterns."""
    findings: list[dict[str, Any]] = []

    entropy_pattern = {
        "name": "Suspicious High-Entropy Secret",
        "service": "high_entropy",
        "severity": "Medium",
    }

    for line_number, line in enumerate(text.splitlines(), start=1):
        if contains_environment_reference(line) or is_comment_line(line):
            continue

        for match in ASSIGNMENT_VALUE_PATTERN.finditer(line):
            variable_name = match.group("variable")
            value = match.group("value")

            if not SECRET_VARIABLE_PATTERN.search(variable_name):
                continue

            if looks_like_placeholder(value, line):
                continue

            if len(value) < 16:
                continue

            entropy = shannon_entropy(value)

            if entropy < 3.5:
                continue

            findings.append(
                build_finding(
                    pattern=entropy_pattern,
                    secret=value,
                    line=line,
                    filename=filename,
                    line_number=line_number,
                    column_number=match.start("value") + 1,
                    variable_name=variable_name,
                )
            )

    return findings


def deduplicate_findings(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Remove duplicate findings while preserving the strongest match."""
    severity_rank = {
        "Low": 1,
        "Medium": 2,
        "High": 3,
        "Critical": 4,
    }

    selected: dict[tuple[str, int, int], dict[str, Any]] = {}

    for finding in findings:
        key = (
            finding["file"],
            finding["line"],
            finding["column"],
        )

        existing = selected.get(key)

        if existing is None:
            selected[key] = finding
            continue

        existing_rank = severity_rank.get(existing["severity"], 0)
        new_rank = severity_rank.get(finding["severity"], 0)

        if new_rank > existing_rank:
            selected[key] = finding
        elif (
            new_rank == existing_rank
            and finding["confidence"] > existing["confidence"]
        ):
            selected[key] = finding

    return sorted(
        selected.values(),
        key=lambda finding: (
            finding["line"],
            finding["column"],
            finding["type"],
        ),
    )


def scan_text(
    text: str,
    filename: str = "input.txt",
    *,
    include_internal_secret: bool = False,
) -> list[dict[str, Any]]:
    """
    Scan source code and return normalized findings.

    By default, plaintext matched values are removed before results are returned.
    Set include_internal_secret=True only for trusted remediation code.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    if not text.strip():
        return []

    findings = scan_known_patterns(text, filename)
    findings.extend(scan_entropy_candidates(text, filename))
    findings = deduplicate_findings(findings)

    if not include_internal_secret:
        for finding in findings:
            finding.pop("_secret", None)

    return findings


def calculate_overall_risk(findings: list[dict[str, Any]]) -> int:
    """Calculate an overall risk score from 0 to 100."""
    if not findings:
        return 0

    severity_weight = {
        "Critical": 1.0,
        "High": 0.75,
        "Medium": 0.45,
        "Low": 0.2,
    }

    weighted_scores = [
        severity_weight.get(finding["severity"], 0.2)
        * (finding["confidence"] / 100)
        for finding in findings
    ]

    strongest = max(weighted_scores)
    additional = sum(sorted(weighted_scores, reverse=True)[1:4]) * 0.25

    score = (strongest + additional) * 100

    return max(0, min(100, round(score)))



def validate_filename(filename: str) -> None:
    """Raise ValueError when a file extension is unsupported."""
    if not filename or not filename.strip():
        raise ValueError("A filename is required.")

    suffix = Path(filename).suffix.lower()

    if suffix not in ALLOWED_EXTENSIONS:
        allowed = ", ".join(sorted(ALLOWED_EXTENSIONS))
        raise ValueError(
            f"Unsupported file type '{suffix or '[none]'}'. "
            f"Allowed extensions: {allowed}"
        )


def decode_text_bytes(data: bytes) -> str:
    """Decode an uploaded file while rejecting binary or invalid text."""
    if not isinstance(data, bytes):
        raise TypeError("Uploaded file content must be bytes.")

    if len(data) > MAX_FILE_SIZE_BYTES:
        raise ValueError("File is larger than the 1 MB upload limit.")

    if not data:
        raise ValueError("The uploaded file is empty.")

    # A null byte is a strong indication that the file is binary.
    if b"\x00" in data:
        raise ValueError("Binary files are not supported.")

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("The file must be valid UTF-8 text.") from error

    if not text.strip():
        raise ValueError("The uploaded file contains no readable code.")

    return text


def scan_uploaded_file(
    data: bytes,
    filename: str,
    *,
    include_internal_secret: bool = False,
) -> list[dict[str, Any]]:
    """
    Scan bytes received from a web uploader.

    Streamlit can call this with:
        scan_uploaded_file(uploaded_file.getvalue(), uploaded_file.name)
    """
    validate_filename(filename)
    text = decode_text_bytes(data)

    return scan_text(
        text,
        filename=Path(filename).name,
        include_internal_secret=include_internal_secret,
    )


def scan_file(
    file_path: str | Path,
    *,
    include_internal_secret: bool = False,
) -> list[dict[str, Any]]:
    """Read and scan a local source-code file."""
    path = Path(file_path)
    validate_filename(path.name)

    try:
        data = path.read_bytes()
    except FileNotFoundError as error:
        raise ValueError(f"File not found: {path}") from error
    except OSError as error:
        raise ValueError(f"Could not read file: {path}") from error

    return scan_uploaded_file(
        data,
        filename=path.name,
        include_internal_secret=include_internal_secret,
    )



def scan_for_ai(
    text: str,
    filename: str = "input.txt",
) -> list[dict[str, Any]]:
    """
    Return findings in the exact format expected by the AI branch.

    The actual credential is never included. Both the matched value and
    surrounding context are redacted before being returned.
    """
    findings = scan_text(
        text,
        filename=filename,
        include_internal_secret=False,
    )

    return [
        {
            "type": finding["type"],
            "service": finding["service"].lower(),
            "severity": finding["severity"].lower(),
            "line": finding["line"],
            "match": finding["redacted"],
            "context": finding["context_redacted"],
            "file": finding["file"],
        }
        for finding in findings
    ]

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Scan a local source-code file for possible secrets."
    )
    parser.add_argument(
        "file",
        nargs="?",
        help="Path to the source-code file to scan.",
    )
    args = parser.parse_args()

    if not args.file:
        parser.print_help()
        raise SystemExit(0)

    try:
        findings = scan_file(args.file)
    except (TypeError, ValueError) as error:
        print(f"Error: {error}")
        raise SystemExit(1) from error

    print(
        json.dumps(
            {
                "file": Path(args.file).name,
                "risk_score": calculate_overall_risk(findings),
                "findings": findings,
            },
            indent=2,
            ensure_ascii=False,
        )
    )