
from firewall.normalizer import normalize_prompt
from firewall.rules import rule_detect
from firewall.ml_detector import ml_detect
from firewall.risk import calculate_risk


def analyze_prompt(prompt: str) -> dict:
    """
    Analyze the original prompt and all its normalized variants.

    Each variant is checked by:
    1. Rule-based structural detection.
    2. Pretrained ML detection.
    3. Combined risk calculation.

    The highest risk across all variants determines
    the final firewall decision.
    """

    if not isinstance(prompt, str):
        raise TypeError("Prompt must be a string.")

    if not prompt.strip():
        raise ValueError("Prompt cannot be empty.")

    # Step 1: Normalize and generate variants.
    normalized = normalize_prompt(prompt)
    variants = normalized["variants"]

    variant_results = []

    # Step 2: Analyze every variant.
    for variant in variants:

        variant_text = variant["text"]

        # Rule-based detection.
        rule_result = rule_detect(variant_text)

        # Pretrained ML detection.
        ml_result = ml_detect(variant_text)

        # Combined risk calculation.
        risk_result = calculate_risk(
            rule_result,
            ml_result
        )

        variant_results.append({
            "source": variant["source"],
            "text": variant_text,
            "rule_analysis": rule_result,
            "ml_analysis": ml_result,
            "risk_analysis": risk_result,
            "decision": risk_result["decision"]
        })

    # Step 3: Select the variant with the highest risk.
    highest_risk_result = max(
        variant_results,
        key=lambda result: result["risk_analysis"]["risk_score"]
    )

    # Step 4: Return complete analysis.
    return {
        "original_prompt": prompt,
        "normalized_prompt": normalized["normalized"],
        "normalization_variants": variants,
        "variant_analyses": variant_results,
        "highest_risk_analysis": highest_risk_result,
        "final_risk_score": highest_risk_result[
            "risk_analysis"
        ]["risk_score"],
        "decision": highest_risk_result["decision"]
    }
