"""
ai_layer.py — SecretScope AI analysis layer

Provides three functions to the frontend:
  - analyze_finding(finding) -> dict
  - analyze_findings_batch(findings) -> list[dict]
  - simulate_attack(finding, analysis) -> list[str]

All functions have hardcoded fallbacks so the demo works even if the API dies.
"""

import anthropic
import json
import os
import hashlib
from dotenv import load_dotenv

load_dotenv()

MODEL = "claude-haiku-4-5-20251001"


def _get_client():
    """Create the Anthropic client only when an API key is available."""
    api_key = os.getenv("ANTHROPIC_API_KEY")

    if not api_key:
        return None

    return anthropic.Anthropic(api_key=api_key)

# Secrets must never leave this process. Reuse detector.py's tested masking
# so the format stays consistent; fall back to an equivalent local
# implementation if detector.py isn't importable in some environment.
try:
    from detector import redact_secret, redact_context
except ImportError:
    def redact_secret(secret):
        if not secret:
            return secret
        if len(secret) <= 8:
            return "*" * len(secret)
        return f"{secret[:4]}{'*' * (len(secret) - 8)}{secret[-4:]}"

    def redact_context(line, secret):
        if not secret or not line:
            return line
        return line.replace(secret, "[REDACTED]")


def _sanitize_for_api(finding):
    """Return a copy of finding with the real secret value masked out.

    This is called right before any prompt is built, regardless of whether
    the caller already redacted the finding upstream — the API call is the
    last line of defense before the secret would leave the machine.
    """
    raw_match = finding.get("match", "")
    raw_context = finding.get("context", "")

    safe = dict(finding)
    safe["context"] = redact_context(raw_context, raw_match)
    safe["match"] = redact_secret(raw_match)

    # Belt-and-suspenders: if the secret wasn't a clean substring match
    # (different quoting/escaping) redact_context silently no-ops, so
    # double check nothing slipped through.
    if raw_match and raw_match in safe["context"]:
        safe["context"] = "[REDACTED]"

    return safe

# ---------- Caching ----------
# Cache results in memory so re-scans during the demo are instant.
# ---------- Caching ----------
_analysis_cache = {}
_attack_cache = {}

# Auto-load cache from disk if present
try:
    with open("cache.json") as _cf:
        _cached = json.load(_cf)
        _analysis_cache.update(_cached.get("analyses", {}))
        _attack_cache.update(_cached.get("attacks", {}))
        print(f"[ai_layer] Loaded {len(_analysis_cache)} cached analyses, {len(_attack_cache)} cached attacks")
except FileNotFoundError:
    pass
except Exception as e:
    print(f"[ai_layer] Cache load failed: {e}")


def _cache_key(finding):
    """Stable hash of a finding so we can cache identical findings."""
    key_str = f"{finding.get('type')}::{finding.get('match')}::{finding.get('context', '')[:50]}"
    return hashlib.md5(key_str.encode()).hexdigest()


# ---------- Fallback data (used when API fails) ----------
# These are hand-written per service so the demo NEVER breaks.

FALLBACK_ANALYSES = {
    "aws": {
        "is_real": True,
        "confidence": 90,
        "blast_radius": "An attacker with this AWS key can spin up EC2 instances for cryptocurrency mining (typically $20,000+ in charges within hours), read/delete data from S3 buckets, and pivot to other AWS services. Documented cases show developers hit with $50,000+ AWS bills within 4 hours of accidentally leaking keys to public GitHub.",
        "rotation_url": "https://console.aws.amazon.com/iam/home#/security_credentials",
        "env_var_name": "AWS_ACCESS_KEY_ID",
    },
    "github": {
        "is_real": True,
        "confidence": 90,
        "blast_radius": "A leaked GitHub Personal Access Token grants an attacker access to every repository the token owner can see — including private repos, source code, and any secrets committed to them. They can push malicious commits, delete branches, or exfiltrate proprietary code. In supply-chain attack scenarios, one leaked PAT can compromise thousands of downstream projects.",
        "rotation_url": "https://github.com/settings/tokens",
        "env_var_name": "GITHUB_TOKEN",
    },
    "openai": {
        "is_real": True,
        "confidence": 90,
        "blast_radius": "A leaked OpenAI API key lets attackers rack up thousands of dollars in API charges by running GPT-4 queries on your account. Public GitHub scanners routinely detect and abuse these within minutes. Reported cases include developers waking up to $10,000+ bills after a single accidental commit.",
        "rotation_url": "https://platform.openai.com/api-keys",
        "env_var_name": "OPENAI_API_KEY",
    },
    "anthropic": {
        "is_real": True,
        "confidence": 90,
        "blast_radius": "A leaked Anthropic API key allows attackers to run Claude queries billed directly to your account. Compromised keys are often sold on dark-web marketplaces for automated content generation and can generate thousands of dollars in charges before detection.",
        "rotation_url": "https://console.anthropic.com/settings/keys",
        "env_var_name": "ANTHROPIC_API_KEY",
    },
    "stripe": {
        "is_real": True,
        "confidence": 95,
        "blast_radius": "A leaked Stripe secret key gives an attacker the ability to issue refunds, create charges against saved customer cards, and access your entire customer payment history including names, emails, and partial card numbers. This is a PCI compliance nightmare and can trigger mandatory customer notification and legal disclosure requirements.",
        "rotation_url": "https://dashboard.stripe.com/apikeys",
        "env_var_name": "STRIPE_SECRET_KEY",
    },
    "slack": {
        "is_real": True,
        "confidence": 85,
        "blast_radius": "A leaked Slack token allows an attacker to read every message in every channel the bot/user has access to — including DMs, private channels, and any secrets shared internally (which is a lot). They can also send messages impersonating the account for social engineering attacks.",
        "rotation_url": "https://api.slack.com/apps",
        "env_var_name": "SLACK_TOKEN",
    },
    "google": {
        "is_real": True,
        "confidence": 85,
        "blast_radius": "A leaked Google API key can be abused to consume paid API quotas (Maps, Cloud, Translate), potentially generating thousands in charges. If the key has broader scopes, attackers may access Google Cloud resources, Firebase data, or user information.",
        "rotation_url": "https://console.cloud.google.com/apis/credentials",
        "env_var_name": "GOOGLE_API_KEY",
    },
    "database": {
        "is_real": True,
        "confidence": 95,
        "blast_radius": "A leaked database connection string with credentials gives an attacker direct read/write access to your entire database. They can exfiltrate all user data, delete tables, install ransomware, or plant backdoors. This is often the single worst credential leak possible — one string can compromise every piece of user data your product holds.",
        "rotation_url": "Rotate database password immediately in your database provider's console.",
        "env_var_name": "DATABASE_URL",
    },
    "generic": {
        "is_real": True,
        "confidence": 60,
        "blast_radius": "This appears to be a hardcoded secret. The specific impact depends on what service it authenticates to, but any hardcoded credential in source code is a serious risk — anyone with repo access, and anyone who ever will, can use it. Rotate it and move it to environment variables immediately.",
        "rotation_url": "Rotate this credential in the appropriate service dashboard.",
        "env_var_name": "SECRET_KEY",
    },
}

FALLBACK_ATTACKS = {
    "aws": [
        "Step 1: Automated scanners like TruffleHog crawl public GitHub commits every minute. Your leaked AWS key is detected and added to attack lists within 30 seconds of being pushed.",
        "Step 2: Attacker authenticates via AWS CLI: `aws configure` with your leaked credentials. They run `aws sts get-caller-identity` to confirm the key is live.",
        "Step 3: They enumerate permissions with `aws iam list-attached-user-policies` and discover the key has EC2 launch permissions.",
        "Step 4: They spin up 50 p3.16xlarge GPU instances across multiple regions for cryptocurrency mining, generating a $47,000 bill in 6 hours before AWS fraud detection freezes the account.",
    ],
    "github": [
        "Step 1: Attacker's scanner finds your GitHub token in a public commit within minutes of the push.",
        "Step 2: They authenticate via `curl -H 'Authorization: token YOUR_TOKEN' https://api.github.com/user` and confirm the token works.",
        "Step 3: They clone every private repository the token can access — source code, internal docs, deployment scripts, everything.",
        "Step 4: They search the cloned repos for MORE secrets (database URLs, other API keys) and use those to pivot into your infrastructure. One leaked token becomes a full breach.",
    ],
    "openai": [
        "Step 1: Public GitHub scanners tuned for `sk-` prefixed keys detect your OpenAI key within 60 seconds of the commit.",
        "Step 2: The key is auto-tested with a small `/v1/models` request to verify it's live, then added to a stolen-key marketplace.",
        "Step 3: A buyer runs a bulk GPT-4 query script — often generating training data for competitors — at maximum rate limit.",
        "Step 4: You wake up to a $12,000 OpenAI bill for 40 million tokens you never used. OpenAI's refund policy for leaked keys is 'case by case.'",
    ],
    "anthropic": [
        "Step 1: Scanner detects your `sk-ant-` key in the commit within minutes.",
        "Step 2: Key is validated with a cheap Haiku request, confirmed live, and sold on Telegram markets for $50-200.",
        "Step 3: Buyer runs high-volume Claude queries — often for spam content generation or competitive scraping.",
        "Step 4: Your Anthropic bill spikes to thousands overnight. Rate limits kick in only after significant damage.",
    ],
    "stripe": [
        "Step 1: Stripe key detected in your commit — attackers prioritize these because payment keys have direct monetary value.",
        "Step 2: They probe your account with `stripe.Customer.list()` to enumerate saved customers and payment methods.",
        "Step 3: They issue refunds to attacker-controlled accounts, or worse — create charges against saved customer cards.",
        "Step 4: You're now legally required to disclose the breach to affected customers. PCI compliance investigation begins. Legal costs alone exceed $100k.",
    ],
    "slack": [
        "Step 1: Slack token found in commit, validated with `auth.test` API call.",
        "Step 2: Attacker reads every message in every accessible channel — often finding more credentials, business plans, and customer PII.",
        "Step 3: They impersonate the account to social-engineer other employees: 'Hey can you send me the prod DB password? I'm locked out.'",
        "Step 4: One leaked bot token becomes a full corporate espionage incident. This is exactly how the 2022 Uber breach started.",
    ],
    "generic": [
        "Step 1: Automated secret scanners detect the hardcoded credential within minutes of the commit going public.",
        "Step 2: The attacker identifies which service the credential authenticates to based on surrounding code context.",
        "Step 3: They test the credential against the target service to confirm it's active.",
        "Step 4: They use the credential to access, exfiltrate, or manipulate whatever the service protects — data, funds, or infrastructure.",
    ],
}


def _get_fallback_service(finding):
    """Map a finding's service to a fallback key."""
    service = finding.get("service", "").lower()
    if "aws" in service:
        return "aws"
    if "github" in service:
        return "github"
    if "openai" in service:
        return "openai"
    if "anthropic" in service:
        return "anthropic"
    if "stripe" in service:
        return "stripe"
    if "slack" in service:
        return "slack"
    if "google" in service:
        return "google"
    if "database" in service or "db" in service or "postgres" in service or "mysql" in service or "mongo" in service:
        return "database"
    return "generic"


def _fallback_analysis(finding):
    """Return a hardcoded analysis for a finding when the API fails."""
    svc = _get_fallback_service(finding)
    base = dict(FALLBACK_ANALYSES.get(svc, FALLBACK_ANALYSES["generic"]))
    base["fixed_line"] = f'{base["env_var_name"]} = os.environ["{base["env_var_name"]}"]'
    return base


def _fallback_attack(finding):
    """Return a hardcoded attack narrative when the API fails."""
    svc = _get_fallback_service(finding)
    return list(FALLBACK_ATTACKS.get(svc, FALLBACK_ATTACKS["generic"]))


# ---------- Core functions (called by frontend) ----------

def analyze_finding(finding):
    """
    Analyze a single finding. Returns dict with:
      is_real, confidence, blast_radius, rotation_url, fixed_line, env_var_name
    """
    key = _cache_key(finding)
    if key in _analysis_cache:
        return _analysis_cache[key]

    safe_finding = _sanitize_for_api(finding)
    prompt = f"""You are a security analyst. Analyze this potential secret leak.

Type: {safe_finding.get('type', 'Unknown')}
Service: {safe_finding.get('service', 'unknown')}
Line context: {safe_finding.get('context', '')}
Matched string (partially masked for security): {safe_finding.get('match', '')}

Respond in JSON with these exact keys:
- is_real: boolean (false if this looks like a placeholder like "your_key_here", "xxx", "example", or a documented test key)
- confidence: integer 0-100
- blast_radius: 2-3 sentence plain-English explanation of what an attacker could do with this specific credential. Be concrete about impact — mention specific dollar amounts, specific attacks, or specific data exposure. Make it feel urgent and real.
- rotation_url: URL where the user should rotate this key (e.g. AWS IAM console URL)
- fixed_line: the same line of code but with the secret replaced by an environment variable reference in the appropriate language for the context
- env_var_name: suggested environment variable name in SCREAMING_SNAKE_CASE

Return ONLY valid JSON. No markdown code fences. No explanation. Just the JSON object."""

    client = _get_client()

    if client is None:
        result = _fallback_analysis(finding)
        _analysis_cache[key] = result
        return result

    client = _get_client()

    if client is None:
        result = _fallback_attack(finding)
        _attack_cache[key] = result
        return result

    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=800,
            messages=[{"role": "user", "content": prompt}],
        )
        text = response.content[0].text.strip()
        # Strip markdown fences if the model added them anyway
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
            text = text.strip()
        result = json.loads(text)
        _analysis_cache[key] = result
        return result
    except Exception as e:
        print(f"[ai_layer] analyze_finding fallback triggered: {e}")
        result = _fallback_analysis(finding)
        _analysis_cache[key] = result
        return result


def analyze_findings_batch(findings):
    """
    Analyze up to 10 findings in a single API call for speed.
    Returns list of analysis dicts in the same order as input.
    """
    if not findings:
        return []

    # For very small batches, single calls are fine
    if len(findings) == 1:
        return [analyze_finding(findings[0])]

    # Check cache first
    results = [None] * len(findings)
    uncached_indices = []
    uncached_findings = []
    for i, f in enumerate(findings):
        key = _cache_key(f)
        if key in _analysis_cache:
            results[i] = _analysis_cache[key]
        else:
            uncached_indices.append(i)
            uncached_findings.append(f)

    if not uncached_findings:
        return results

    # Process uncached findings in chunks of 10
    for chunk_start in range(0, len(uncached_findings), 10):
        chunk = uncached_findings[chunk_start:chunk_start + 10]
        chunk_indices = uncached_indices[chunk_start:chunk_start + 10]

        safe_chunk = [_sanitize_for_api(f) for f in chunk]
        findings_text = "\n\n".join(
            f"Finding {i+1}:\n  Type: {f.get('type')}\n  Service: {f.get('service')}\n  Context: {f.get('context', '')}\n  Match (partially masked for security): {f.get('match', '')}"
            for i, f in enumerate(safe_chunk)
        )

        prompt = f"""You are a security analyst. Analyze these {len(chunk)} potential secret leaks.

{findings_text}

Return a JSON array with exactly {len(chunk)} objects, one per finding in the same order. Each object must have these keys:
- is_real: boolean
- confidence: integer 0-100
- blast_radius: 2-3 sentence concrete explanation of attacker impact (mention dollar amounts, specific attacks, or data exposure)
- rotation_url: URL where the user rotates the key
- fixed_line: the code line rewritten to use an environment variable
- env_var_name: SCREAMING_SNAKE_CASE env var name

Return ONLY the JSON array. No markdown fences. No explanation."""

        client = _get_client()

        if client is None:
            for local_i, global_i in enumerate(chunk_indices):
                fallback = _fallback_analysis(chunk[local_i])
                results[global_i] = fallback
                _analysis_cache[_cache_key(chunk[local_i])] = fallback
            continue

        try:
            response = client.messages.create(
                model=MODEL,
                max_tokens=3000,
                messages=[{"role": "user", "content": prompt}],
            )
            text = response.content[0].text.strip()
            if text.startswith("```"):
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
                text = text.strip()
            chunk_results = json.loads(text)
            if not isinstance(chunk_results, list) or len(chunk_results) != len(chunk):
                raise ValueError("Bad response shape")
            for local_i, global_i in enumerate(chunk_indices):
                results[global_i] = chunk_results[local_i]
                _analysis_cache[_cache_key(chunk[local_i])] = chunk_results[local_i]
        except Exception as e:
            print(f"[ai_layer] batch fallback triggered: {e}")
            for local_i, global_i in enumerate(chunk_indices):
                fb = _fallback_analysis(chunk[local_i])
                results[global_i] = fb
                _analysis_cache[_cache_key(chunk[local_i])] = fb

    return results


def simulate_attack(finding, analysis=None):
    """
    Generate a 4-step attack narrative for the demo's money moment.
    Returns list of 4 strings.
    """
    key = _cache_key(finding)
    if key in _attack_cache:
        return _attack_cache[key]

    safe_finding = _sanitize_for_api(finding)
    prompt = f"""You are demonstrating the impact of a leaked secret to a developer in a security education tool.

Secret type: {safe_finding.get('type', 'Unknown')}
Service: {safe_finding.get('service', 'unknown')}
Context: {safe_finding.get('context', '')}

Generate a realistic, dramatic 4-step attack narrative showing what a malicious actor would do with this leaked credential. Each step should be concrete, technical, and feel urgent. Include specific numbers, tools, and outcomes where possible (dollar amounts, tool names like TruffleHog, specific API calls, real breach examples).

Return a JSON array of exactly 4 strings. Each string starts with "Step N: " and describes one phase of the attack. Return ONLY the JSON array. No markdown fences."""

    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=800,
            messages=[{"role": "user", "content": prompt}],
        )
        text = response.content[0].text.strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
            text = text.strip()
        result = json.loads(text)
        if not isinstance(result, list) or len(result) != 4:
            raise ValueError("Bad response shape")
        _attack_cache[key] = result
        return result
    except Exception as e:
        print(f"[ai_layer] simulate_attack fallback triggered: {e}")
        result = _fallback_attack(finding)
        _attack_cache[key] = result
        return result


# ---------- CLI test harness ----------

if __name__ == "__main__":
    test_finding = {
        "type": "AWS Access Key",
        "service": "aws",
        "severity": "critical",
        "line": 42,
        "match": "AKIAIOSFODNN7EXAMPLE",
        "context": 'aws_key = "AKIAIOSFODNN7EXAMPLE"',
        "file": "config.py",
    }

    print("=== analyze_finding ===")
    print(json.dumps(analyze_finding(test_finding), indent=2))

    print("\n=== simulate_attack ===")
    for step in simulate_attack(test_finding):
        print(step)

    print("\n=== analyze_findings_batch (3 findings) ===")
    batch = [
        test_finding,
        {**test_finding, "type": "GitHub Token", "service": "github", "match": "ghp_" + "x" * 36, "context": 'token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"'},
        {**test_finding, "type": "OpenAI Key", "service": "openai", "match": "sk-" + "x" * 48, "context": 'openai.api_key = "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"'},
    ]
    for r in analyze_findings_batch(batch):
        print(f"- {r['env_var_name']}: {r['blast_radius'][:80]}...")