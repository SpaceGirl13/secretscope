"""
Run this BEFORE the demo to prewarm the AI cache with the exact findings
that will show up in the demo. Zero-latency demo.
"""

from ai_layer import analyze_findings_batch, simulate_attack, _analysis_cache, _attack_cache
import json

# These MUST match exactly what shows up in Person 3's demo input.
# Coordinate with Person 3 to pick the exact strings.
DEMO_FINDINGS = [
    {
        "type": "AWS Access Key",
        "service": "aws",
        "severity": "critical",
        "line": 12,
        "match": "AKIAFAKEKEY1234567890",
        "context": 'AWS_ACCESS_KEY = "AKIAFAKEKEY1234567890"',
        "file": "config.py",
    },
    {
        "type": "OpenAI API Key",
        "service": "openai",
        "severity": "critical",
        "line": 18,
        "match": "sk-FAKE-not-a-real-key-abcdefghij1234567890ABCDEFGHIJKL",
        "context": 'openai.api_key = "sk-FAKE-not-a-real-key-abcdefghij1234567890ABCDEFGHIJKL"',
        "file": "config.py",
    },
    {
        "type": "Stripe Secret Key",
        "service": "stripe",
        "severity": "critical",
        "line": 25,
        "match": "STRIPE_KEY_PLACEHOLDER_NOT_REAL_9876543210",
        "context": 'stripe.api_key = "STRIPE_KEY_PLACEHOLDER_NOT_REAL_9876543210"',
        "file": "config.py",
    },
    {
        "type": "GitHub Token",
        "service": "github",
        "severity": "high",
        "line": 31,
        "match": "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        "context": 'GH_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"',
        "file": "config.py",
    },
]

print("Prewarming analyses...")
analyses = analyze_findings_batch(DEMO_FINDINGS)
print(f"✓ {len(analyses)} analyses cached")

print("Prewarming attack simulations...")
for f in DEMO_FINDINGS:
    simulate_attack(f)
print(f"✓ {len(DEMO_FINDINGS)} attack narratives cached")

# Save cache to disk so it survives a restart
with open("cache.json", "w") as f:
    json.dump({"analyses": _analysis_cache, "attacks": _attack_cache}, f, indent=2)
print("✓ Cache written to cache.json")