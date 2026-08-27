"""
PATCH stage — Kavach-CRS Phase 5

Applies a PatchSpec to the target file:
  1. Creates a timestamped backup before touching anything.
  2. Applies the patch (replace old_lines with new_lines at the right location).
  3. Generates and stores a unified diff for the ledger/report.
  4. Provides rollback() to restore from the backup.

Nothing is silently overwritten — every change is attributable and reversible.
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
        "backup_path":  str        # path to pre-patch backup
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
            "reason": "PatchSpec contained no old_lines — nothing to replace.",
        }

    # Read current file
    try:
        original_content = Path(filepath).read_text(encoding="utf-8")
    except OSError as e:
        return _error(finding_id, filepath, str(e))

    original_lines = original_content.splitlines(keepends=True)

    # Find the first occurrence of old_lines (as a contiguous block)
    match_start = _find_block(original_lines, old_lines_to_replace)
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

    # Timestamped backup
    backup = _backup_path(filepath, finding_id)
    shutil.copy2(filepath, backup)

    # Write patched file
    try:
        Path(filepath).write_text(patched_content, encoding="utf-8")
    except OSError as e:
        # Restore backup on write failure
        shutil.copy2(backup, filepath)
        return _error(finding_id, filepath, f"Write failed, backup restored: {e}")

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
        "unified_diff": diff,
        "reason": patch_spec.get("rationale", ""),
    }


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


def _find_block(lines: list[str], block: list[str]) -> int | None:
    """
    Find the 0-indexed start of `block` as a contiguous subsequence in `lines`.
    Compares stripped content to be whitespace-tolerant.
    """
    stripped_block = [b.rstrip("\n").rstrip() for b in block]
    for i in range(len(lines) - len(block) + 1):
        window = [lines[i + j].rstrip("\n").rstrip() for j in range(len(block))]
        if window == stripped_block:
            return i
    return None


def _error(finding_id: str, filepath: str, msg: str) -> dict:
    return {
        "status": "ERROR",
        "finding_id": finding_id,
        "file": filepath,
        "backup_path": "",
        "unified_diff": "",
        "reason": msg,
    }
