"""
Hash-chained ledger — Kavach-CRS Phase 8

Each stage appends a JSON entry containing sha256(prev_hash + json(this_entry)).
This makes the ledger tamper-evident: any modification to a past entry breaks
all subsequent hashes — a reviewer can verify the chain in one pass.

Ledger is written to run_output/ledger.json.
"""
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path


LEDGER_PATH = Path("run_output") / "ledger.json"


import hmac
import secrets

def get_ledger_key() -> bytes:
    key = os.environ.get("KAVACH_LEDGER_KEY")
    if key: return key.encode("utf-8")
    
    key_file = Path(".ledger_key")
    if key_file.exists():
        return key_file.read_bytes()
        
    new_key = secrets.token_hex(32).encode("utf-8")
    key_file.write_bytes(new_key)
    return new_key

def _sha256(data: str) -> str:
    key = get_ledger_key()
    return hmac.new(key, data.encode("utf-8"), hashlib.sha256).hexdigest()

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
    Append a new entry to the ledger and persist it atomically.
    """
    entries = load()
    prev = _prev_hash(entries)

    # Sanitize data to remove absolute paths (prevent leaking local folder paths)
    import os
    cwd = str(Path.cwd())
    
    def _sanitize(obj):
        if isinstance(obj, dict):
            return {k: _sanitize(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [_sanitize(item) for item in obj]
        elif isinstance(obj, str) and cwd in obj:
            try:
                # Attempt to relativize
                return str(Path(obj).relative_to(cwd))
            except ValueError:
                return obj.replace(cwd, ".")
        return obj

    sanitized_data = _sanitize(data)

    # Canonical JSON for hashing (sorted keys, no extra whitespace)
    payload_str = json.dumps(sanitized_data, sort_keys=True, ensure_ascii=False)
    entry_hash = _sha256(prev + payload_str)

    entry = {
        "seq": len(entries) + 1,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stage": stage,
        "data": sanitized_data,
        "prev_hash": prev,
        "hash": entry_hash,
    }
    entries.append(entry)
    
    # Atomic write to prevent corruption mid-write
    import os
    tmp_path = LEDGER_PATH.with_suffix(".json.tmp")
    tmp_path.write_text(
        json.dumps(entries, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    os.replace(tmp_path, LEDGER_PATH)
    
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
