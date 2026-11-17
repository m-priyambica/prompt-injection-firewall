
import re

from firewall.pipeline import analyze_prompt
from firewall.llm import generate_response

from firewall.confidential_data import (
    load_employee_records,
    get_confidential_secrets,
)

from firewall.review_queue import add_to_review_queue


# ============================================================
# 1. DIRECT CONFIDENTIAL-DATA REQUEST DETECTION
# ============================================================

def detect_sensitive_request(prompt):
    """Detect direct requests for protected company information."""

    if not isinstance(prompt, str):
        return {
            "is_sensitive": False,
            "categories": [],
            "reason": None,
        }

    text = prompt.casefold()

    action_pattern = re.compile(
        r"\b("
        r"list|show|reveal|disclose|provide|give|send|print|dump|"
        r"export|retrieve|fetch|extract|share|display|"
        r"tell me|what is|what are|who is|who are"
        r")\b"
    )

    has_action = bool(action_pattern.search(text))
    categories = []

    employee_patterns = {
        "employee_salary": (
            r"\b(salar(?:y|ies)|annual compensation|payroll|"
            r"earnings|lpa|bank account|bank details|account number)\b"
        ),
        "employee_identity_records": (
            r"\b(all employees|employee names|employee records|"
            r"employee details|personal details|staff records)\b"
        ),
        "employee_contact_information": (
            r"\b(employee emails|email addresses|phone numbers)\b"
        ),
    }

    for category, pattern in employee_patterns.items():
        if re.search(pattern, text):
            categories.append(category)

    secret_patterns = {
        "database_credentials": (
            r"\b(database password|db password|database credentials|"
            r"database login)\b"
        ),
        "api_credentials": (
            r"\b(api key|api token|access token|secret key)\b"
        ),
        "system_credentials": (
            r"\b(password|credentials|private key|authentication secret)\b"
        ),
        "internal_infrastructure": (
            r"\b(internal server|internal database|private endpoint)\b"
        ),
        "confidential_projects": (
            r"\b(unreleased project|confidential project|"
            r"internal project details)\b"
        ),
    }

    for category, pattern in secret_patterns.items():
        if re.search(pattern, text):
            categories.append(category)

    general_pattern = (
        r"\b(confidential data|sensitive company data|"
        r"private company information|protected records)\b"
    )

    if re.search(general_pattern, text):
        categories.append("confidential_company_information")

    has_employee_reference = bool(
        re.search(r"\b(employee|employees|staff|personnel)\b", text)
    )

    has_sensitive_employee_field = bool(
        re.search(
            r"\b(salary|salaries|compensation|bank|account|"
            r"email|personal details|records)\b",
            text,
        )
    )

    if has_employee_reference and has_sensitive_employee_field:
        categories.append("employee_sensitive_information")

    if has_action and categories:
        return {
            "is_sensitive": True,
            "categories": list(dict.fromkeys(categories)),
            "reason": (
                "The prompt requests access to protected "
                "company information."
            ),
        }

    return {
        "is_sensitive": False,
        "categories": [],
        "reason": None,
    }


# ============================================================
# 2. EXTRACT REAL DETECTOR SCORES
# ============================================================

def add_score_details(analysis):
    """
    Extract actual scores from the highest-risk variant.

    Source:
    highest_risk_analysis
        -> rule_analysis
        -> rule_score

    highest_risk_analysis
        -> ml_analysis
        -> injection_probability
    """

    highest = analysis.get("highest_risk_analysis") or {}

    rule_analysis = highest.get("rule_analysis") or {}
    ml_analysis = highest.get("ml_analysis") or {}

    risk_analysis = highest.get("risk_analysis") or {}

    analysis["rule_score"] = rule_analysis.get("rule_score")
    analysis["ml_score"] = ml_analysis.get("injection_probability")

    analysis["final_risk_score"] = analysis.get(
        "final_risk_score",
        risk_analysis.get("risk_score"),
    )

    return analysis


# ============================================================
# 3. OUTPUT CONFIDENTIAL-DATA INSPECTION
# ============================================================

def inspect_output(response):
    """Inspect generated responses for confidential information."""

    findings = []

    if not response:
        return {
            "is_safe": True,
            "findings": [],
        }

    response_lower = response.casefold()
    records = load_employee_records()

    def add_finding(finding_type, employee=None):
        finding = {"type": finding_type}

        if employee:
            finding["employee"] = employee

        if finding not in findings:
            findings.append(finding)

    # Exact employee identifiers and financial IDs
    for record in records:
        sensitive_fields = {
            "employee_id": record["employee_id"],
            "bank_account": record["bank_account"],
            "email": record["email"],
        }

        for field, value in sensitive_fields.items():
            if value and value.casefold() in response_lower:
                add_finding(field, record["name"])

    # Employee names with sensitive information
    sensitive_keywords = [
        "salary",
        "salaries",
        "lpa",
        "annual compensation",
        "earns",
        "earning",
        "bank",
        "account",
        "employee id",
        "email",
        "confidential record",
    ]

    for record in records:
        name = record["name"].casefold()

        name_matches = list(
            re.finditer(re.escape(name), response_lower)
        )

        for match in name_matches:
            start = max(0, match.start() - 100)
            end = min(len(response_lower), match.end() + 150)

            surrounding_text = response_lower[start:end]

            matching_keywords = [
                keyword
                for keyword in sensitive_keywords
                if keyword in surrounding_text
            ]

            if matching_keywords:
                add_finding(
                    "employee_sensitive_information",
                    record["name"],
                )

            salary = record["annual_salary_lpa"]

            salary_pattern = (
                rf"\b{re.escape(str(int(salary)))}(?:\.0)?\s*lpa\b"
            )

            if re.search(salary_pattern, surrounding_text):
                add_finding(
                    "employee_salary",
                    record["name"],
                )

            role = record["role"].casefold()

            if role in surrounding_text and matching_keywords:
                add_finding(
                    "employee_role_with_sensitive_context",
                    record["name"],
                )

    # Centralized company secrets
    secrets = get_confidential_secrets()

    for secret_type, secret_value in secrets.items():
        if secret_value and secret_value.casefold() in response_lower:
            add_finding(f"company_secret:{secret_type}")

    return {
        "is_safe": len(findings) == 0,
        "findings": findings,
    }


# ============================================================
# 4. PROTECTED LLM EXECUTION
# ============================================================

def generate_protected_response(prompt):
    """
    Analyse, route, execute and inspect a user prompt.
    """

    # STEP 1: Run structural and ML analysis.
    analysis = analyze_prompt(prompt)

    # STEP 2: Extract actual scores for the frontend.
    analysis = add_score_details(analysis)

    # STEP 3: Detect direct confidential-data requests.
    sensitive_check = detect_sensitive_request(prompt)

    if sensitive_check["is_sensitive"]:

        analysis["decision"] = "BLOCK"
        analysis["final_risk_score"] = 1.0

        analysis["sensitive_request_detection"] = sensitive_check

        highest = analysis.get("highest_risk_analysis")

        if isinstance(highest, dict):
            highest["decision"] = "BLOCK"
            highest["sensitive_categories"] = (
                sensitive_check["categories"]
            )
            highest["reason"] = sensitive_check["reason"]

        return {
            "status": "blocked",
            "message": (
                "Request blocked: the prompt attempts to access "
                "protected company information."
            ),
            "analysis": analysis,
            "response": None,
            "output_inspection": None,
            "review_record": None,
        }

    # STEP 4: Apply normal risk-engine decision.
    decision = analysis["decision"]

    if decision == "BLOCK":
        return {
            "status": "blocked",
            "message": "Prompt blocked by the security firewall.",
            "analysis": analysis,
            "response": None,
            "output_inspection": None,
            "review_record": None,
        }

    # STEP 5: Send medium-risk prompts for review.
    if decision == "REVIEW":

        review_record = add_to_review_queue(
            prompt=prompt,
            analysis=analysis,
        )

        return {
            "status": "review",
            "message": "Prompt saved for security review.",
            "analysis": analysis,
            "response": None,
            "output_inspection": None,
            "review_record": review_record,
        }

    # STEP 6: Execute allowed prompts.
    response = generate_response(prompt)

    if not isinstance(response, str) or response.startswith("ERROR:"):

        error_message = (
            response
            if isinstance(response, str)
            else "The model returned an invalid response."
        )

        return {
            "status": "error",
            "message": error_message,
            "analysis": analysis,
            "response": None,
            "output_inspection": None,
            "review_record": None,
        }

    # STEP 7: Inspect generated output.
    output_check = inspect_output(response)

    if not output_check["is_safe"]:
        return {
            "status": "output_blocked",
            "message": (
                "Response blocked because confidential "
                "information was detected."
            ),
            "analysis": analysis,
            "response": None,
            "output_inspection": output_check,
            "review_record": None,
        }

    # STEP 8: Return safe response.
    return {
        "status": "success",
        "message": "Prompt passed security checks.",
        "analysis": analysis,
        "response": response,
        "output_inspection": output_check,
        "review_record": None,
    }
