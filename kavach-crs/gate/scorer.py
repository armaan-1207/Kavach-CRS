"""
Confidence Gate — Kavach-CRS Phase 7

Transparent weighted scoring formula — not a black box.
Formula is shown in the HTML report so a reviewer can audit it.

Score components (0.0–1.0 each, with weights):
  W1 = 0.40  PoV replay result         (PASS=1.0, FAIL=0.0, SKIPPED=0.5)
  W2 = 0.35  Differential replay        (PASS=1.0, PARTIAL=0.6, FAIL=0.0, SKIPPED=0.5)
  W3 = 0.15  Regression check           (PASS=1.0, NO_SUITE=0.5, FAIL=0.0, SKIPPED=0.5)
  W4 = 0.10  Diff size penalty          (1.0 if diff ≤ 10 lines; degrades linearly to 0.0 at 100 lines)

Final score = W1*s1 + W2*s2 + W3*s3 + W4*s4   (range 0.0–1.0)

Decision:
  score ≥ 0.75  → AUTO_MERGE      (high confidence, autonomous action)
  score ≥ 0.45  → HUMAN_REVIEW    (route to human with evidence bundle)
  score < 0.45  → REJECT          (confidence too low; do not apply)

Thresholds and weights are shown in the report — adjust per deployment.

── SECURITY HARDENING (Phase B) ─────────────────────────────────────────────
The weighted formula alone has a gap: PoV=PASS(1.0), DiffReplay=SKIPPED(0.5),
Regression=NO_SUITE_PRESENT(0.5), DiffSize=1.0 scores to exactly 0.75 —
AUTO_MERGE — with *zero* differential-replay evidence gathered. That happens
whenever a CWE class has a patch template but no corpus cases yet (see
prove/differential.py's `_load_corpus` returning [] → SKIPPED). The weighted
average can't distinguish "checked and it's fine" from "wasn't checked at
all" once both land at 0.5.

Fix: a hard safety cap layered on top of the score, not folded into it. A
high score can never promote a patch to AUTO_MERGE if PoV replay or
differential replay produced no evidence — it can only get *downgraded* by
this rule, never upgraded, so the transparent formula above still means
exactly what it says.
"""

WEIGHTS = {
    "pov":        0.40,
    "diff_replay": 0.35,
    "regression": 0.15,
    "diff_size":  0.10,
}

THRESHOLD_AUTO   = 0.75
THRESHOLD_REVIEW = 0.45


def _pov_score(pov_result: dict) -> float:
    s = pov_result.get("status", "SKIPPED")
    return {"PASS": 1.0, "FAIL": 0.0, "SKIPPED": 0.5}.get(s, 0.5)


def _diff_score(diff_result: dict) -> float:
    s = diff_result.get("status", "SKIPPED")
    return {"PASS": 1.0, "PARTIAL": 0.6, "FAIL": 0.0, "SKIPPED": 0.5}.get(s, 0.5)


def _regression_score(reg_result: dict) -> float:
    s = reg_result.get("status", "SKIPPED")
    return {
        "PASS": 1.0,
        "NO_SUITE_PRESENT": 0.5,
        "FAIL": 0.0,
        "SKIPPED": 0.5,
    }.get(s, 0.5)


def _diff_size_score(patch_result: dict) -> float:
    diff = patch_result.get("unified_diff", "")
    changed_lines = sum(
        1 for line in diff.splitlines()
        if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
    )
    if changed_lines <= 10:
        return 1.0
    if changed_lines >= 100:
        return 0.0
    return 1.0 - ((changed_lines - 10) / 90.0)


def score(
    pov_result: dict,
    diff_result: dict,
    reg_result: dict,
    patch_result: dict,
) -> dict:
    """
    Compute the confidence score and routing decision.

    Returns:
    {
        "score":          float   (0.0–1.0)
        "decision":       "AUTO_MERGE" | "HUMAN_REVIEW" | "REJECT"
        "components": {
            "pov":         float
            "diff_replay": float
            "regression":  float
            "diff_size":   float
        }
        "weights":         dict   (the formula, for the report)
        "thresholds":      dict   (for the report)
        "rationale":       str
        "safety_cap_applied": bool  — True if a high score was downgraded
                                       because PoV/differential evidence was
                                       missing (see module docstring)
    }
    """
    s_pov  = _pov_score(pov_result)
    s_diff = _diff_score(diff_result)
    s_reg  = _regression_score(reg_result)
    s_size = _diff_size_score(patch_result)

    final = (
        WEIGHTS["pov"]         * s_pov  +
        WEIGHTS["diff_replay"] * s_diff +
        WEIGHTS["regression"]  * s_reg  +
        WEIGHTS["diff_size"]   * s_size
    )
    final = round(final, 4)

    if final >= THRESHOLD_AUTO:
        decision = "AUTO_MERGE"
        rationale = (
            f"Score {final:.2f} ≥ {THRESHOLD_AUTO} — confidence is high enough for "
            "autonomous application. Patch is applied and recorded in the ledger."
        )
    elif final >= THRESHOLD_REVIEW:
        decision = "HUMAN_REVIEW"
        rationale = (
            f"Score {final:.2f} is between {THRESHOLD_REVIEW} and {THRESHOLD_AUTO} — "
            "routing to human reviewer with full evidence bundle. "
            "Human sign-off required before this patch enters production."
        )
    else:
        decision = "REJECT"
        rationale = (
            f"Score {final:.2f} < {THRESHOLD_REVIEW} — confidence too low. "
            "Patch is NOT applied. Recommend re-running with a revised template "
            "or escalating to manual remediation."
        )

    # ── Hard safety cap — evidence gaps can only downgrade, never be
    # papered over by the weighted average. See module docstring.
    evidence_gap = (
        pov_result.get("status") == "SKIPPED"
        or diff_result.get("status") == "SKIPPED"
    )
    safety_cap_applied = False
    if evidence_gap and decision == "AUTO_MERGE":
        decision = "HUMAN_REVIEW"
        safety_cap_applied = True
        rationale = (
            f"Score {final:.2f} ≥ {THRESHOLD_AUTO} would normally AUTO_MERGE, but "
            "PoV replay and/or differential replay produced NO evidence "
            "(status=SKIPPED) — capped at HUMAN_REVIEW. A high weighted score "
            "cannot substitute for missing behavioral evidence."
        )

    return {
        "score": final,
        "decision": decision,
        "components": {
            "pov":         round(s_pov,  4),
            "diff_replay": round(s_diff, 4),
            "regression":  round(s_reg,  4),
            "diff_size":   round(s_size, 4),
        },
        "weights": WEIGHTS,
        "thresholds": {
            "auto_merge":    THRESHOLD_AUTO,
            "human_review":  THRESHOLD_REVIEW,
        },
        "rationale": rationale,
        "safety_cap_applied": safety_cap_applied,
    }
