"""
Message-behavior signal extraction — deterministic, not LLM-decided (the model
explains a finished investigation; it never produces one — see krisis/ai/explain.py).

Each category is a structured observation with the matched snippet carried as
provenance, exactly like any collector's evidence: a message saying "your
account will be blocked today" is evidence of urgency language, not proof of
anything on its own — correlation and risk decide what it means combined with
everything else.
"""

from __future__ import annotations

import re

# occam: hand-picked phrase lists, not an NLP classifier — extend when a real
# message shows a phrasing KRISIS missed. The failure mode is a missed signal,
# never a fabricated one.
_URGENCY_PATTERNS = [
    r"\bimmediately\b", r"\burgent(?:ly)?\b", r"\bright away\b",
    r"\bwithin\s+\d+\s*(?:hours?|minutes?|days?)\b",
    r"\bwill be (?:blocked|suspended|locked|closed|terminated|deactivated)\b",
    r"\bact now\b", r"\bexpires? (?:soon|today|in \d)", r"\blast (?:chance|warning)\b",
    r"\bfinal notice\b",
]
_CREDENTIAL_PATTERNS = [
    r"\bverify your (?:account|identity|password|details)\b",
    r"\bconfirm your (?:account|identity|password|details)\b",
    r"\blog\s?in to\b", r"\bsign\s?in to\b", r"\bre-?enter your password\b",
    r"\bupdate your (?:password|payment|billing) (?:details|information)\b",
    r"\bprovide your (?:password|pin|otp|one[- ]time code)\b",
]
_FINANCIAL_PATTERNS = [
    r"\brefund\b", r"\binvoice\b", r"\bpayment (?:failed|declined|due)\b",
    r"\bwire transfer\b", r"\$\s?\d", r"\bunauthorized (?:charge|transaction)\b",
    r"\btax refund\b", r"\bwinnings?\b", r"\byou(?:'ve| have) won\b",
]
_CALL_TO_ACTION_PATTERNS = [
    r"\bclick (?:here|the link|below)\b", r"\bfollow this link\b",
    r"\btap (?:here|below)\b", r"\bdownload (?:the attachment|now)\b",
    r"\bopen the attached\b",
]

_CATEGORIES: dict[str, list[str]] = {
    "urgency_language": _URGENCY_PATTERNS,
    "credential_request": _CREDENTIAL_PATTERNS,
    "financial_lure": _FINANCIAL_PATTERNS,
    "call_to_action": _CALL_TO_ACTION_PATTERNS,
}


def extract(text: str) -> dict[str, list[str]]:
    """category -> matched snippets (deduplicated, original casing preserved).

    Empty dict means no recognizable phrasing was present.
    """
    found: dict[str, list[str]] = {}
    for category, patterns in _CATEGORIES.items():
        matches: list[str] = []
        for pattern in patterns:
            for m in re.finditer(pattern, text, re.IGNORECASE):
                snippet = m.group(0)
                if snippet not in matches:
                    matches.append(snippet)
        if matches:
            found[category] = matches
    return found
