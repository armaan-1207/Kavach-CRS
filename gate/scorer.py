"""
Confidence Gate - Kavach-CRS Phase 7

Transparent weighted scoring formula - not a black box.
Formula is shown in the HTML report so a reviewer can audit it.

Score components (0.0–1.0 each, with weights):
  W1 = 0.30  PoV replay result         (PASS=1.0, FAIL=0.0, SKIPPED=0.5)
  W2 = 0.30  Differential replay        (PASS=1.0, PARTIAL=0.6, FAIL=0.0, SKIPPED=0.5)
  W3 = 0.15  Regression check           (PASS=1.0, NO_SUITE=0.5, FAIL=0.0, SKIPPED=0.5)
  W4 = 0.15  Post-patch fuzz pass       (PASS=1.0, FAIL=0.0, SKIPPED=0.5)
  W5 = 0.10  Diff size penalty          (1.0 if diff ≤ 10 lines; degrades to 0.0 at 100 lines)

Final score = W1*s1 + W2*s2 + W3*s3 + W4*s4 + W5*s5   (range 0.0–1.0)

Decision:
  score ≥ 0.75  → AUTO_MERGE      (high confidence, autonomous action)
  score ≥ 0.45  → HUMAN_REVIEW    (partial confidence, requires manual triage)
  score < 0.45  → REJECT          (patch is unsafe or breaks functionality)

Thresholds and weights are shown in the report - adjust per deployment.

⚖️ OVERFITTING RISK & BOUNDED EVIDENCE (Phase B) ⚖️
--------------------------------------------------
Per automated program repair (APR) theory (e.g. "Undecidability of Overfitting in APR"), 
no finite corpus of tests or replay traces can guarantee general semantic correctness. 
Therefore, Kavach-CRS does not "prove" a fix is 100% correct. Instead, the Confidence Gate 
bounds the risk of regression and incomplete fixes by weighting behavioral deltas 
(via Differential Replay, mimicking PATCH-SIM/Shibboleth principles) against strict safety caps.

A high score can never promote a patch to AUTO_MERGE if PoV replay or differential 
replay produced no evidence - it can only get downgraded by this rule.
"""

WEIGHTS = {
    "pov":        0.30,
    "diff_replay": 0.30,
    "regression":  0.15,
    "post_fuzz":   0.15,
    "diff_size":   0.10,
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


def _post_fuzz_score(fuzz_result: dict) -> float:
    s = fuzz_result.get("status", "SKIPPED")
    return {"PASS": 1.0, "FAIL": 0.0, "SKIPPED": 0.5}.get(s, 0.5)


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
    fuzz_result: dict = None,
) -> dict:
    """
    Compute the confidence score and routing decision.

    Returns:
    {
        "decision":       "AUTO_MERGE" | "HUMAN_REVIEW" | "REJECT"
        "components": {
            "pov":         float
            "diff_replay": float
            "regression":  float
            "post_fuzz":   float
            "diff_size":   float
        }
        "weights":         dict   (the formula, for the report)
        "thresholds":      dict   (for the report)
        "rationale":       str
        "safety_cap_applied": bool
    }
    """
    if fuzz_result is None:
        fuzz_result = {"status": "SKIPPED"}

    s_pov  = _pov_score(pov_result)
    s_diff = _diff_score(diff_result)
    s_reg  = _regression_score(reg_result)
    s_fuzz = _post_fuzz_score(fuzz_result)
    s_size = _diff_size_score(patch_result)

    final = (
        WEIGHTS["pov"]         * s_pov  +
        WEIGHTS["diff_replay"] * s_diff +
        WEIGHTS["regression"]  * s_reg  +
        WEIGHTS["post_fuzz"]   * s_fuzz +
        WEIGHTS["diff_size"]   * s_size
    )
    final = round(final, 4)

    if final >= THRESHOLD_AUTO:
        decision = "AUTO_MERGE"
    elif final >= THRESHOLD_REVIEW:
        decision = "HUMAN_REVIEW"
    else:
        decision = "REJECT"

    rationale = f"Score {final:.2f} bounds risk within {decision} threshold."

    # Safety Cap: block AUTO_MERGE if missing core behavioral evidence
    evidence_gap = (
        pov_result.get("status") == "SKIPPED"
        or diff_result.get("status") == "SKIPPED"
    )
    is_llm = "[LLM GENERATED" in patch_result.get("reason", "") or patch_result.get("llm_generated") is True
    
    safety_cap_applied = False
    if decision == "AUTO_MERGE":
        if evidence_gap or is_llm:
            decision = "HUMAN_REVIEW"
            safety_cap_applied = True
            rationale = (
                f"Score {final:.2f} >= {THRESHOLD_AUTO} would normally AUTO_MERGE, but "
                "behavioral evidence was missing or LLM was used "
                "-> capped at HUMAN_REVIEW. We bound risk based on evidence, not trust."
            )

    return {
        "score": final,
        "decision": decision,
        "components": {
            "pov":         round(s_pov,  4),
            "diff_replay": round(s_diff, 4),
            "regression":  round(s_reg,  4),
            "post_fuzz":   round(s_fuzz, 4),
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
