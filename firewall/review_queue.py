
import json
from pathlib import Path
from datetime import datetime, timezone
from threading import Lock


PROJECT_ROOT = Path(__file__).resolve().parent.parent
QUEUE_FILE = PROJECT_ROOT / "data" / "review_queue.json"

_queue_lock = Lock()


def load_review_queue():
    """Load pending review records from the JSON file."""

    if not QUEUE_FILE.exists():
        return []

    try:
        with QUEUE_FILE.open("r", encoding="utf-8") as file:
            records = json.load(file)

        if not isinstance(records, list):
            raise ValueError("Review queue must contain a JSON list.")

        return records

    except json.JSONDecodeError as error:
        raise ValueError(
            f"Review queue JSON is corrupted: {error}"
        )


def save_review_queue(records):
    """Save review records to the JSON file."""

    QUEUE_FILE.parent.mkdir(parents=True, exist_ok=True)

    temporary_file = QUEUE_FILE.with_suffix(".tmp")

    with temporary_file.open("w", encoding="utf-8") as file:
        json.dump(records, file, indent=4)

    temporary_file.replace(QUEUE_FILE)


def add_to_review_queue(prompt, analysis):
    """Add a prompt requiring review."""

    record = {
        "review_id": datetime.now(timezone.utc).strftime(
            "%Y%m%d%H%M%S%f"
        ),
        "prompt": prompt,
        "risk_score": analysis.get("final_risk_score"),
        "decision": analysis.get("decision"),
        "findings": analysis.get("highest_risk_analysis", {}),
        "status": "PENDING",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    with _queue_lock:
        records = load_review_queue()
        records.append(record)
        save_review_queue(records)

    return record


def get_pending_reviews():
    """Return all prompts awaiting review."""

    with _queue_lock:
        records = load_review_queue()

    return [
        record for record in records
        if record.get("status") == "PENDING"
    ]


def update_review_status(review_id, new_status):
    """Update the status of a review record."""

    allowed_statuses = {
        "APPROVED",
        "REJECTED",
    }

    if new_status not in allowed_statuses:
        raise ValueError(
            f"Invalid status. Choose from {allowed_statuses}."
        )

    with _queue_lock:
        records = load_review_queue()

        for record in records:
            if record["review_id"] == review_id:

                if record["status"] != "PENDING":
                    raise ValueError(
                        "Only pending reviews can be updated."
                    )

                record["status"] = new_status
                record["reviewed_at"] = (
                    datetime.now(timezone.utc).isoformat()
                )

                save_review_queue(records)
                return record

    return None
