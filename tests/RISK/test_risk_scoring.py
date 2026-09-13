from detector.rules import (
    calculate_risk_score,
    get_risk_level,
)


def make_finding(rule_id, severity):
    """
    Create a simple test finding.
    """

    return {
        "id": rule_id,
        "rule": f"Test Rule {rule_id}",
        "severity": severity,
        "description": "Synthetic finding for risk scoring test."
    }


def run_test(name, findings, expected_score, expected_level):
    """
    Run one risk-scoring test case.
    """

    score = calculate_risk_score(findings)
    level = get_risk_level(score)

    print(f"\n{name}")
    print("-" * 60)
    print(f"Expected Score : {expected_score}")
    print(f"Actual Score   : {score}")
    print(f"Expected Level : {expected_level}")
    print(f"Actual Level   : {level}")

    if score != expected_score:
        print("FAIL: Incorrect risk score.")
        return False

    if level != expected_level:
        print("FAIL: Incorrect risk level.")
        return False

    print("PASS")
    return True


print("=" * 60)
print("RISK SCORING TEST")
print("=" * 60)


# ============================================================
# TEST 1 — No findings
# ============================================================

test_1 = run_test(
    "TEST 1 - No Findings",
    [],
    0,
    "Low"
)


# ============================================================
# TEST 2 — One Medium finding
# ============================================================

test_2 = run_test(
    "TEST 2 - One Medium Finding",
    [
        make_finding("KD-001", "Medium")
    ],
    20,
    "Medium"
)


# ============================================================
# TEST 3 — One High finding
# ============================================================

test_3 = run_test(
    "TEST 3 - One High Finding",
    [
        make_finding("KD-005", "High")
    ],
    30,
    "High"
)


# ============================================================
# TEST 4 — Multiple findings
# ============================================================

test_4 = run_test(
    "TEST 4 - Multiple Findings",
    [
        make_finding("KD-001", "Medium"),
        make_finding("KD-008", "Medium"),
        make_finding("KD-009", "High")
    ],
    70,
    "High"
)


# ============================================================
# TEST 5 — Critical score
# ============================================================

test_5 = run_test(
    "TEST 5 - Critical Risk",
    [
        make_finding("KD-001", "Critical"),
        make_finding("KD-002", "Critical")
    ],
    80,
    "Critical"
)


# ============================================================
# TEST 6 — Score capped at 100
# ============================================================

test_6 = run_test(
    "TEST 6 - Score Maximum",
    [
        make_finding("KD-001", "Critical"),
        make_finding("KD-002", "Critical"),
        make_finding("KD-003", "Critical")
    ],
    100,
    "Critical"
)


# ============================================================
# TEST 7 — Duplicate rule IDs
# ============================================================

test_7 = run_test(
    "TEST 7 - Duplicate Rule Protection",
    [
        make_finding("KD-005", "High"),
        make_finding("KD-005", "High"),
        make_finding("KD-005", "High")
    ],
    30,
    "High"
)


# ============================================================
# FINAL RESULT
# ============================================================

all_tests = [
    test_1,
    test_2,
    test_3,
    test_4,
    test_5,
    test_6,
    test_7,
]

print("\n" + "=" * 60)
print("RISK SCORING TEST SUMMARY")
print("=" * 60)

passed = sum(all_tests)
failed = len(all_tests) - passed

print(f"Tests Passed : {passed}")
print(f"Tests Failed : {failed}")

if failed == 0:
    print("\nPASS: Risk scoring engine is working correctly.")
else:
    print("\nFAIL: One or more risk scoring tests failed.")