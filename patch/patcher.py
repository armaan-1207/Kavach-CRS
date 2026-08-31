"""
PATCH stage - Kavach-CRS Phase 5

Applies a PatchSpec to the target file:
  1. Creates a timestamped backup of the original.
  2. Writes the patched content to a shadow file (.kavach_shadow).
  3. Generates and stores a unified diff for the ledger/report.
  4. Provides swap_shadow() to atomically overwrite the live file.

Nothing is silently overwritten - every change is attributable and reversible.
"""
import difflib
import os
import shutil
from datetime import datetime
from pathlib import Path


BACKUP_DIR = Path("run_output") / "backups"


def _backup_path(filepath: str, finding_id: str) -> Path:
    ts = datetime.now().strftime("%Y%m%dT%H%M%S")
    stem = Path(filepath).stem
    suffix = Path(filepath).suffix
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    return BACKUP_DIR / f"{stem}_{finding_id}_{ts}{suffix}"


def apply_patch(patch_spec: dict) -> dict:
    """
    Apply a PatchSpec to its target file.

    Returns a result dict:
    {
        "status":       "PATCHED" | "SKIPPED" | "ERROR"
        "finding_id":   str
        "file":         str
        "backup_path":  str,
        "shadow_path":  str        # path to unverified patched file
        "unified_diff": str        # full unified diff string
        "reason":       str        # human-readable outcome
    }
    """
    if patch_spec.get("status") == "TEMPLATE_MISS":
        return {
            "status": "SKIPPED",
            "finding_id": patch_spec.get("finding_id", "?"),
            "file": patch_spec.get("file", ""),
            "backup_path": "",
            "unified_diff": "",
            "reason": f"[STUB] No patch generated: {patch_spec.get('rationale', '')}",
        }

    filepath = patch_spec["file"]
    target_root = Path(os.environ.get("KAVACH_TARGET_ROOT", ".")).resolve()
    if not Path(filepath).resolve().is_relative_to(target_root):
        return {
            "status": "ERROR",
            "finding_id": patch_spec.get("finding_id", "?"),
            "file": filepath,
            "backup_path": "",
            "unified_diff": "",
            "reason": "Refused: resolved path escapes target root.",
        }

    old_lines_to_replace = patch_spec.get("old_lines", [])
    new_lines_replacement = patch_spec.get("new_lines", [])
    finding_id = patch_spec.get("finding_id", "F???")

    if not old_lines_to_replace:
        return {
            "status": "SKIPPED",
            "finding_id": finding_id,
            "file": filepath,
            "backup_path": "",
            "unified_diff": "",
            "reason": "PatchSpec contained no old_lines - nothing to replace.",
        }

    # Read current LIVE file (the original, untouched source of truth).
    # We always patch from a fresh copy of the original so each finding's
    # shadow is an isolated single-fix diff — not an accumulation of all
    # previous findings' patches on the same file.
    try:
        original_content = Path(filepath).read_text(encoding="utf-8")
    except OSError as e:
        return _error(finding_id, filepath, str(e))

    original_lines = original_content.splitlines(keepends=True)

    # Find the first occurrence of old_lines (as a contiguous block)
    target_line = patch_spec.get("line_number", 0)
    match_start = _find_block(original_lines, old_lines_to_replace, target_line)
    if match_start is None:
        return {
            "status": "SKIPPED",
            "finding_id": finding_id,
            "file": filepath,
            "backup_path": "",
            "unified_diff": "",
            "reason": (
                f"Target lines not found verbatim in {Path(filepath).name}. "
                "File may have already been patched, or template matched incorrectly."
            ),
        }

    # Build patched content
    patched_lines = (
        original_lines[:match_start]
        + new_lines_replacement
        + original_lines[match_start + len(old_lines_to_replace):]
    )
    patched_content = "".join(patched_lines)

    # Timestamped backup of the original (for rollback and differential oracle)
    backup = _backup_path(filepath, finding_id)
    shutil.copy2(filepath, backup)

    import hashlib
    backup_sha256 = hashlib.sha256(Path(backup).read_bytes()).hexdigest()
    patched_sha256 = hashlib.sha256(patched_content.encode("utf-8")).hexdigest()

    # Per-finding isolated shadow file: app_F001_shadow.py
    # Using a unique name per finding prevents sequential patches in the same
    # file from accumulating into one shared shadow and corrupting the differential.
    # CRITICAL: Must end in .py so importlib can load it in the worker!
    stem = Path(filepath).stem
    shadow_path = str(Path(filepath).parent / f"{stem}_{finding_id}_shadow.py")
    try:
        Path(shadow_path).write_text(patched_content, encoding="utf-8")
    except OSError as e:
        return _error(finding_id, filepath, f"Shadow write failed: {e}")

    # Generate unified diff
    diff = "".join(difflib.unified_diff(
        original_lines,
        patched_lines,
        fromfile=f"a/{Path(filepath).name}",
        tofile=f"b/{Path(filepath).name}",
        lineterm="",
    ))

    return {
        "status": "PATCHED",
        "finding_id": finding_id,
        "file": filepath,
        "backup_path": str(backup),
        "shadow_path": shadow_path,
        "backup_sha256": backup_sha256,
        "patched_sha256": patched_sha256,
        "unified_diff": diff,
        "reason": patch_spec.get("rationale", ""),
        "llm_generated": patch_spec.get("llm_generated", False),
    }



def swap_shadow(patch_result: dict) -> bool:
    """
    Atomically replace the live file with the verified shadow file.
    shadow_path is the per-finding isolated shadow (e.g. app_F001.kavach_shadow).
    """
    shadow = patch_result.get("shadow_path", "")
    target = patch_result.get("file", "")
    if not shadow or not Path(shadow).exists() or not target:
        return False
    os.replace(shadow, target)
    return True


def cleanup_shadow(patch_result: dict) -> None:
    """Remove the per-finding shadow file if not merging."""
    shadow = patch_result.get("shadow_path", "")
    if shadow and Path(shadow).exists():
        os.remove(shadow)

def rollback(patch_result: dict) -> bool:
    """
    Restore the original file from its backup.
    Returns True on success, False if no backup exists.
    """
    backup = patch_result.get("backup_path", "")
    if not backup or not Path(backup).exists():
        return False
    shutil.copy2(backup, patch_result["file"])
    return True


def _find_block(lines: list[str], block: list[str], target_line: int) -> int | None:
    """
    Find the 0-indexed start of lock as a contiguous subsequence in lines.
    Compares stripped content to be whitespace-tolerant.
    Finds the closest match to 	arget_line to disambiguate duplicated code blocks.
    Only accepts matches within +/- 5 lines of the target_line.
    """
    stripped_block = [b.rstrip("\n").rstrip() for b in block]
    
    best_match = None
    best_distance = float('inf')
    
    for i in range(len(lines) - len(block) + 1):
        window = [lines[i + j].rstrip("\n").rstrip() for j in range(len(block))]
        if window == stripped_block:
            # 1-indexed start line of the match
            match_lineno = i + 1
            dist = abs(match_lineno - target_line)
            if dist <= 5 and dist < best_distance:
                best_distance = dist
                best_match = i
                
    return best_match


def _error(finding_id: str, filepath: str, msg: str) -> dict:
    return {
        "status": "ERROR",
        "finding_id": finding_id,
        "file": filepath,
        "backup_path": "",
        "unified_diff": "",
        "reason": msg,
    }
