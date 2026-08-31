"""
Cryptographically authenticated ledger ?" Kavach-CRS Phase 8

Each stage appends a JSON entry. We use Ed25519 asymmetric signatures to chain
entries together. This proves tamper-evidence to third parties, as they only need
the public key to verify the chain and cannot forge new entries.

Ledger is written to run_output/ledger.json.
Public key is written to run_output/ledger_pub.pem.
"""
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

LEDGER_PATH = Path("run_output") / "ledger.json"
PUB_KEY_PATH = Path("run_output") / "ledger_pub.pem"
PRIV_KEY_PATH = Path(".ledger_key_ed25519")
_ledger_lock = threading.Lock()
_priv_key_cache = None

def _init_keys() -> ed25519.Ed25519PrivateKey:
    global _priv_key_cache
    if _priv_key_cache is not None:
        return _priv_key_cache

    passphrase = os.environ.get("LEDGER_PASSPHRASE", "").encode()
    if PRIV_KEY_PATH.exists():
        _priv_key_cache = serialization.load_pem_private_key(
            PRIV_KEY_PATH.read_bytes(), 
            password=passphrase if passphrase else None
        )
    else:
        _priv_key_cache = ed25519.Ed25519PrivateKey.generate()
        enc_algo = serialization.BestAvailableEncryption(passphrase) if passphrase else serialization.NoEncryption()
        PRIV_KEY_PATH.write_bytes(_priv_key_cache.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc_algo
        ))
        PUB_KEY_PATH.parent.mkdir(exist_ok=True)
        PUB_KEY_PATH.write_bytes(_priv_key_cache.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    return _priv_key_cache

def _sign_data(data: str) -> str:
    priv = _init_keys()
    sig = priv.sign(data.encode("utf-8"))
    return sig.hex()

def _verify_sig(data: str, signature_hex: str, external_pub_key=None) -> bool:
    if external_pub_key:
        pub = external_pub_key
    else:
        if not PUB_KEY_PATH.exists():
            return False
        pub_bytes = PUB_KEY_PATH.read_bytes()
        pub = serialization.load_pem_public_key(pub_bytes)
    try:
        pub.verify(bytes.fromhex(signature_hex), data.encode("utf-8"))
        return True
    except Exception:
        return False

def load(path=None) -> list[dict]:
    p = path or LEDGER_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))
    return []

def _prev_sig(entries: list[dict]) -> str:
    if not entries:
        return "0" * 128
    return entries[-1].get("signature", "0" * 128)

def append(stage: str, data: dict) -> dict:
    with _ledger_lock:
        from pathlib import Path as _P
    entries = load()
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
        if not _verify_sig(prev + payload_str, entry["signature"], _ext_pub):
            return False, f"Signature broken at entry {i+1} (stage={entry['stage']})"
        if entry["prev_sig"] != prev:
            return False, f"prev_sig mismatch at entry {i+1}"
        prev = entry["signature"]
    return True, f"Chain OK - {len(entries)} entries verified."
