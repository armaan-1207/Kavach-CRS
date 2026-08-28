"""
Hash-chained ledger — Kavach-CRS Phase 8

Each stage appends a JSON entry containing sha256(prev_hash + json(this_entry)).
This makes the ledger tamper-evident: any modification to a past entry breaks
all subsequent hashes — a reviewer can verify the chain in one pass.

Ledger is written to run_output/ledger.json.
"""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


LEDGER_PATH = Path("run_output") / "ledger.json"


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def load() -> list[dict]:
    """Load existing ledger or return empty list."""
    LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)
    if LEDGER_PATH.exists():
        return json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
    return []


def _prev_hash(entries: list[dict]) -> str:
    if not entries:
        return "0" * 64
    return entries[-1]["hash"]


def append(stage: str, data: dict) -> dict:
    """
    Append a new entry to the ledger and persist it.

    Entry format:
    {
        "seq":       int    — sequential index (1-based)
        "timestamp": str    — ISO 8601 UTC
        "stage":     str    — e.g. "DETECT", "TRIAGE", "REASON", ...
        "data":      dict   — stage-specific payload
        "prev_hash": str    — hash of the previous entry
        "hash":      str    — sha256(prev_hash + json(this payload))
    }
    """
    entries = load()
    prev = _prev_hash(entries)

    # Canonical JSON for hashing (sorted keys, no extra whitespace)
    payload_str = json.dumps(data, sort_keys=True, ensure_ascii=False)
    entry_hash = _sha256(prev + payload_str)

    entry = {
        "seq": len(entries) + 1,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stage": stage,
        "data": data,
        "prev_hash": prev,
        "hash": entry_hash,
    }
    entries.append(entry)
    LEDGER_PATH.write_text(
        json.dumps(entries, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return entry


def verify_chain() -> tuple[bool, str]:
    """
    Verify the integrity of the entire ledger chain.
    Returns (True, "Chain OK") or (False, error_description).
    """
    entries = load()
    prev = "0" * 64
    for i, entry in enumerate(entries):
        payload_str = json.dumps(entry["data"], sort_keys=True, ensure_ascii=False)
        expected_hash = _sha256(prev + payload_str)
        if entry["hash"] != expected_hash:
            return False, f"Chain broken at entry {i+1} (stage={entry['stage']})"
        if entry["prev_hash"] != prev:
            return False, f"prev_hash mismatch at entry {i+1}"
        prev = entry["hash"]
    return True, f"Chain OK — {len(entries)} entries verified."
