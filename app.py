
import json
import time
from pathlib import Path
from threading import Lock
from datetime import datetime, timezone

from flask import Flask, jsonify, render_template, request

from firewall.llm import (
    generate_baseline_response,
    MODEL_NAME,
    BASELINE_MODEL_NAME
)

from firewall.guarded_llm import generate_protected_response

from firewall.review_queue import (
    get_pending_reviews,
    update_review_status
)


# --------------------------------------------------
# 1. APPLICATION CONFIGURATION
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"
ACTIVITY_FILE = DATA_DIR / "activity_log.json"

DATA_DIR.mkdir(exist_ok=True)

app = Flask(
    __name__,
    template_folder="frontend",
    static_folder="frontend",
    static_url_path="/frontend"
)

activity_lock = Lock()


# --------------------------------------------------
# 2. ACTIVITY LOG
# --------------------------------------------------

def load_activity_log():
    """Load previously recorded application events."""

    if not ACTIVITY_FILE.exists():
        return []

    try:
        with open(ACTIVITY_FILE, "r", encoding="utf-8") as file:
            return json.load(file)

    except (json.JSONDecodeError, OSError):
        app.logger.exception("Could not read activity log.")
        return []


def record_activity(event):
    """
    Store request metadata.

    Raw prompts and generated responses are not stored.
    """

    with activity_lock:

        events = load_activity_log()
        events.append(event)

        # Keep the most recent 5000 events.
        events = events[-5000:]

        temporary_file = ACTIVITY_FILE.with_suffix(".tmp")

        with open(temporary_file, "w", encoding="utf-8") as file:
            json.dump(events, file, indent=4)

        temporary_file.replace(ACTIVITY_FILE)


# --------------------------------------------------
# 3. HOME PAGE
# --------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html")


# --------------------------------------------------
# 4. CHAT API
# --------------------------------------------------

@app.route("/api/chat", methods=["POST"])
def chat():

    data = request.get_json(silent=True) or {}

    prompt = data.get("prompt", "").strip()
    mode = data.get("mode", "protected").lower()

    if not isinstance(prompt, str):
        return jsonify({
            "status": "error",
            "message": "Prompt must be a string."
        }), 400

    if not prompt:
        return jsonify({
            "status": "error",
            "message": "Please enter a prompt."
        }), 400

    if len(prompt) > 10000:
        return jsonify({
            "status": "error",
            "message": "Prompt is too long. Maximum length is 10000 characters."
        }), 400

    if mode not in ["baseline", "protected"]:
        return jsonify({
            "status": "error",
            "message": "Invalid execution mode."
        }), 400

    start_time = time.perf_counter()

    response_text = None
    analysis = None
    output_inspection = None
    review_record = None

    try:

        # ------------------------------------------
        # BASELINE: NO FIREWALL
        # ------------------------------------------

        if mode == "baseline":

            # Directly call PlainBot.
            # No input firewall or output inspection.

            response_text = generate_baseline_response(prompt)

            if response_text.startswith("ERROR:"):

                status = "error"
                message = response_text
                response_text = None

            else:

                status = "success"

                message = (
                    "Baseline response generated using PlainBot "
                    "without firewall protection."
                )

        # ------------------------------------------
        # PROTECTED: FIREWALL ENABLED
        # ------------------------------------------

        else:

            result = generate_protected_response(prompt)

            status = result.get("status", "error")
            message = result.get("message", "")

            analysis = result.get("analysis")
            output_inspection = result.get("output_inspection")
            review_record = result.get("review_record")

            # Return generated content only when the
            # protected pipeline reports successful inspection.

            if status == "success":

                response_text = result.get("response")

            else:

                response_text = None

        # ------------------------------------------
        # MEASURE LATENCY
        # ------------------------------------------

        latency_ms = round(
            (time.perf_counter() - start_time) * 1000,
            2
        )

        # ------------------------------------------
        # RECORD EVENT
        # ------------------------------------------

        risk_score = None
        decision = None

        if analysis:

            risk_score = analysis.get("final_risk_score")
            decision = analysis.get("decision")

        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "mode": mode,
            "status": status,
            "decision": decision,
            "risk_score": risk_score,
            "latency_ms": latency_ms,
            "prompt_length": len(prompt)
        }

        record_activity(event)

        # ------------------------------------------
        # API RESPONSE
        # ------------------------------------------

        return jsonify({
            "mode": mode,
            "status": status,
            "message": message,
            "response": response_text,
            "analysis": analysis,
            "output_inspection": output_inspection,
            "review_record": review_record,
            "latency_ms": latency_ms
        })

    except Exception:

        app.logger.exception("Chat request failed.")

        latency_ms = round(
            (time.perf_counter() - start_time) * 1000,
            2
        )

        record_activity({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "mode": mode,
            "status": "error",
            "decision": None,
            "risk_score": None,
            "latency_ms": latency_ms,
            "prompt_length": len(prompt)
        })

        return jsonify({
            "mode": mode,
            "status": "error",
            "message": (
                "An internal error occurred. "
                "Check the Flask terminal for details."
            ),
            "response": None
        }), 500


# --------------------------------------------------
# 5. DASHBOARD METRICS API
# --------------------------------------------------

@app.route("/api/metrics", methods=["GET"])
def metrics():

    with activity_lock:
        events = load_activity_log()

    total = len(events)

    baseline_events = [
        event for event in events
        if event.get("mode") == "baseline"
    ]

    protected_events = [
        event for event in events
        if event.get("mode") == "protected"
    ]

    allowed = sum(
        1 for event in protected_events
        if event.get("status") == "success"
    )

    blocked = sum(
        1 for event in protected_events
        if event.get("status") == "blocked"
    )

    review = sum(
        1 for event in protected_events
        if event.get("status") == "review"
    )

    output_blocked = sum(
        1 for event in protected_events
        if event.get("status") == "output_blocked"
    )

    errors = sum(
        1 for event in events
        if event.get("status") == "error"
    )

    latencies = [
        event.get("latency_ms", 0)
        for event in events
        if isinstance(event.get("latency_ms"), (int, float))
    ]

    average_latency = (
        round(sum(latencies) / len(latencies), 2)
        if latencies else 0
    )

    recent_events = sorted(
        events,
        key=lambda event: event.get("timestamp", ""),
        reverse=True
    )[:10]

    return jsonify({
        "total_requests": total,
        "baseline_requests": len(baseline_events),
        "protected_requests": len(protected_events),

        "baseline_successes": sum(
            1 for event in baseline_events
            if event.get("status") == "success"
        ),

        "allowed": allowed,
        "blocked": blocked,
        "review": review,
        "output_blocked": output_blocked,
        "errors": errors,
        "average_latency_ms": average_latency,
        "recent_events": recent_events
    })


# --------------------------------------------------
# 6. REVIEW QUEUE API
# --------------------------------------------------

@app.route("/api/reviews", methods=["GET"])
def reviews():

    pending = get_pending_reviews()

    return jsonify({
        "count": len(pending),
        "reviews": pending
    })


@app.route("/api/reviews/<review_id>", methods=["POST"])
def update_review(review_id):

    data = request.get_json(silent=True) or {}

    new_status = data.get("status", "").upper()

    if new_status not in ["APPROVED", "REJECTED"]:

        return jsonify({
            "status": "error",
            "message": "Status must be APPROVED or REJECTED."
        }), 400

    result = update_review_status(
        review_id,
        new_status
    )

    return jsonify({
        "status": "success" if result else "error",
        "message": (
            "Review status updated."
            if result else
            "Review record not found."
        )
    }), 200 if result else 404


# --------------------------------------------------
# 7. HEALTH CHECK
# --------------------------------------------------

@app.route("/api/health", methods=["GET"])
def health():

    return jsonify({
        "status": "online",
        "model": MODEL_NAME,
        "baseline_model": BASELINE_MODEL_NAME,
        "firewall": "Prompt Injection Firewall"
    })


# --------------------------------------------------
# 8. START APPLICATION
# --------------------------------------------------

if __name__ == "__main__":

    print("\n" + "=" * 50)
    print("       PROMPT GUARD - SECURITY DASHBOARD")
    print("=" * 50)

    print("Protected Model:", MODEL_NAME)
    print("Baseline Model:", BASELINE_MODEL_NAME)

    print("URL: http://127.0.0.1:5000")

    print("=" * 50 + "\n")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
