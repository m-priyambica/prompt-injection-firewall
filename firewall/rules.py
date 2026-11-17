
import re
import unicodedata
from typing import Any


# Structural indicators that may appear in prompt injection attempts.
# These are format-level indicators, not memorized attack sentences.

STRUCTURAL_PATTERNS = {
    "control_token": re.compile(
        r"<\|(?:im_start|im_end|system|assistant|developer|"
        r"endoftext|fim_prefix|fim_middle|fim_suffix)\|>",
        re.IGNORECASE
    ),
    "xml_instruction_tag": re.compile(
        r"</?(?:system|developer|instruction|prompt|assistant)\b[^>]*>",
        re.IGNORECASE
    ),
    "hidden_html_content": re.compile(
        r"<(?:script|iframe|style)\b[^>]*>.*?</(?:script|iframe|style)>",
        re.IGNORECASE | re.DOTALL
    ),
}


def inspect_structure(text: str) -> dict[str, Any]:
    """
    Inspect a prompt for suspicious structural features.

    This function does not decide whether a prompt is malicious.
    It produces evidence for the firewall's risk assessment.
    """

    if not isinstance(text, str):
        raise TypeError("Input must be a string.")

    findings = []

    # 1. Check for special model/control tokens.
    for category, pattern in STRUCTURAL_PATTERNS.items():
        if pattern.search(text):
            findings.append({
                "category": category,
                "evidence": "Suspicious structural pattern detected."
            })

    # 2. Check for Unicode formatting/control characters.
    hidden_chars = [
        char for char in text
        if unicodedata.category(char) in {"Cf", "Cc"}
        and char not in "\n\r\t"
    ]

    if hidden_chars:
        findings.append({
            "category": "hidden_unicode",
            "evidence": f"{len(hidden_chars)} hidden/control character(s) found."
        })

    # 3. Check for unusually large encoded-looking blocks.
    encoded_blocks = re.findall(
        r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/])",
        text
    )

    if encoded_blocks:
        findings.append({
            "category": "encoded_content",
            "evidence": f"{len(encoded_blocks)} long encoded-looking block(s) found."
        })

    # 4. Check for attempts to access application-specific protected data.
    # These are resource identifiers, not a list of attack sentences.
    protected_resources = re.findall(
        r"\b(?:"
        r"system_prompt|system_message|"
        r"api_key|secret_key|access_token|"
        r"database_password|private_key|"
        r"internal_credentials"
        r")\b",
        text,
        re.IGNORECASE
    )

    if protected_resources:
        findings.append({
            "category": "protected_resource_reference",
            "evidence": "Prompt references protected application resources.",
            "resources": sorted(set(protected_resources))
        })

    # 5. Calculate a supplementary structural risk score.
    weights = {
        "control_token": 0.35,
        "xml_instruction_tag": 0.25,
        "hidden_html_content": 0.25,
        "hidden_unicode": 0.20,
        "encoded_content": 0.15,
        "protected_resource_reference": 0.30,
    }

    score = min(
        1.0,
        sum(weights.get(item["category"], 0) for item in findings)
    )

    return {
        "rule_score": round(score, 4),
        "rule_triggered": bool(findings),
        "findings": findings
    }


def rule_detect(text: str) -> dict[str, Any]:
    """
    Public function used by the firewall pipeline.
    """

    return inspect_structure(text)
