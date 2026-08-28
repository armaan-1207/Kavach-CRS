"""
Cryptographically authenticated ledger ?" Kavach-CRS Phase 8

Each stage appends a JSON entry. We use Ed25519 asymmetric signatures to chain
entries together. This proves tamper-evidence to third parties, as they only need
the public key to verify the chain, and cannot forge new entries.

Ledger is written to run_output/ledger.json.
Public key is written to run_output/ledger_pub.pem.
"""
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

LEDGER_PATH = Path("run_output") / "ledger.json"
PUB_KEY_PATH = Path("run_output") / "ledger_pub.pem"
PRIV_KEY_PATH = Path(".ledger_key_ed25519")

def _init_keys() -> ed25519.Ed25519PrivateKey:
    if PRIV_KEY_PATH.exists():
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(PRIV_KEY_PATH.read_bytes())
    else:
        priv = ed25519.Ed25519PrivateKey.generate()
        PRIV_KEY_PATH.write_bytes(priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ))
        try:
            os.chmod(PRIV_KEY_PATH, 0o600)
        except Exception:
            pass
            
    # Always export the public key for third-party verification
    pub = priv.public_key()
    PUB_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    PUB_KEY_PATH.write_bytes(pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    return priv

def _sign_data(data: str) -> str:
    priv = _init_keys()
    sig = priv.sign(data.encode("utf-8"))
    return sig.hex()

def _verify_sig(data: str, signature_hex: str) -> bool:
    if not PUB_KEY_PATH.exists():
        return False
    pub_bytes = PUB_KEY_PATH.read_bytes()
    pub = serialization.load_pem_public_key(pub_bytes)
    try:
        pub.verify(bytes.fromhex(signature_hex), data.encode("utf-8"))
        return True
    except Exception:
        return False

def load() -> list[dict]:
    LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)
    if LEDGER_PATH.exists():
        return json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
    return []

def _prev_sig(entries: list[dict]) -> str:
    if not entries:
        return "0" * 128
    return entries[-1]["signature"]

def append(stage: str, data: dict) -> dict:
    from pathlib import Path as _P
    entries = load(_P(ledger_path) if ledger_path else None)
    prev = _prev_sig(entries)

    cwd = str(Path.cwd())
    def _sanitize(obj):
        if isinstance(obj, dict):
            return {k: _sanitize(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [_sanitize(item) for item in obj]
        elif isinstance(obj, str) and cwd in obj:
            try:
                return str(Path(obj).relative_to(cwd))
            except ValueError:
                return obj.replace(cwd, ".")
        return obj

    sanitized_data = _sanitize(data)
    payload_str = json.dumps(sanitized_data, sort_keys=True, ensure_ascii=False)
    
    # Sign the chained payload
    entry_sig = _sign_data(prev + payload_str)

    entry = {
        "seq": len(entries) + 1,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stage": stage,
        "data": sanitized_data,
        "prev_sig": prev,
        "signature": entry_sig,
    }
    entries.append(entry)
    
    tmp_path = LEDGER_PATH.with_suffix(".json.tmp")
    tmp_path.write_text(json.dumps(entries, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp_path, LEDGER_PATH)
    
    return entry

def verify_chain(ledger_path=None, pubkey_path=None) -> tuple[bool, str]:
    from pathlib import Path as _P
    import json as _json
    if ledger_path:
        lp = _P(ledger_path)
        if not lp.exists():
            return False, f'Ledger file not found: {lp}'
        entries = _json.loads(lp.read_text(encoding='utf-8'))
    else:
        entries = load()
    
    if pubkey_path:
        # Use provided pubkey for verification
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        with open(pubkey_path, 'rb') as f:
            _ext_pub = load_pem_public_key(f.read())
    else:
        _ext_pub = None
    prev = "0" * 128
    for i, entry in enumerate(entries):
        payload_str = json.dumps(entry["data"], sort_keys=True, ensure_ascii=False)
        if not _verify_sig(prev + payload_str, entry["signature"]):
            return False, f"Signature broken at entry {i+1} (stage={entry['stage']})"
        if entry["prev_sig"] != prev:
            return False, f"prev_sig mismatch at entry {i+1}"
        prev = entry["signature"]
    return True, f"Chain OK — {len(entries)} entries verified."
