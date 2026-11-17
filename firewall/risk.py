
from typing import Any


# Decision thresholds
BLOCK_THRESHOLD = 0.70
REVIEW_THRESHOLD = 0.35

# Weights assigned to each detection layer
RULE_WEIGHT = 0.30
ML_WEIGHT = 0.70


def calculate_risk(
    rule_result: dict[str, Any],
    ml_result: dict[str, Any]
) -> dict[str, Any]:
    """
    Combine rule-based and ML detection results
    to calculate the overall prompt risk.
    """

    rule_score = float(rule_result["rule_score"])
    injection_probability = float(
        ml_result["injection_probability"]
    )

    # Validate probability ranges
    if not 0.0 <= rule_score <= 1.0:
        raise ValueError("Rule score must be between 0 and 1.")

    if not 0.0 <= injection_probability <= 1.0:
        raise ValueError(
            "Injection probability must be between 0 and 1."
        )

    # Weighted risk calculation
    risk_score = (
        RULE_WEIGHT * rule_score
        + ML_WEIGHT * injection_probability
    )

    risk_score = round(risk_score, 4)

    # Determine firewall decision
    if risk_score >= BLOCK_THRESHOLD:
        decision = "BLOCK"

    elif risk_score >= REVIEW_THRESHOLD:
        decision = "REVIEW"

    else:
        decision = "ALLOW"

    return {
        "rule_score": round(rule_score, 4),
        "ml_injection_probability": round(
            injection_probability, 4
        ),
        "risk_score": risk_score,
        "decision": decision
    }
