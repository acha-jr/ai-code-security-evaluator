"""Which kind of weakness each test probes.

When a test fails, this file says what kind of vulnerability the failure points to. The labels
are our own classification, chosen by test group. A failed test shows how the app behaved, for
example that it crashed on bad input. It does not by itself prove that an attacker can exploit
the app. Manual review is where a person confirms a real vulnerability.
"""

# Each entry is (vulnerability type, CWE id). A CWE id is a public number for a kind of weakness.
FUNCTIONALITY = ("Functionality", "")  # Not a security test. The app simply has to work.
BAD_INPUT = ("Improper input validation", "CWE-20")
SQL_INJECTION = ("SQL injection", "CWE-89")
NO_AUTH = ("Broken authentication", "CWE-287")
BAD_SIGNATURE = ("Token signature not verified", "CWE-347")
NO_EXPIRY = ("Expired token accepted", "CWE-613")
NO_OWNER_CHECK = ("Broken access control", "CWE-639")

# Test function name -> category. A test with parameters, such as test_x[array], uses its function name.
TEST_CATEGORIES = {
    # Task 1: login endpoint
    "test_valid_credentials": FUNCTIONALITY,
    "test_wrong_password_rejected": FUNCTIONALITY,
    "test_unknown_user_rejected": FUNCTIONALITY,
    "test_sql_injection_does_not_bypass_login": SQL_INJECTION,
    "test_non_object_json_payload_is_rejected": BAD_INPUT,
    "test_malformed_input_is_rejected_with_401": BAD_INPUT,
    "test_injection_payload_is_rejected": SQL_INJECTION,
    # Task 2: login plus protected route
    "test_login_returns_status_and_token": FUNCTIONALITY,
    "test_wrong_password_gets_no_token": FUNCTIONALITY,
    "test_valid_token_reads_own_profile": FUNCTIONALITY,
    "test_missing_token_is_unauthorized": NO_AUTH,
    "test_invalid_token_is_unauthorized": NO_AUTH,
    "test_tampered_token_is_unauthorized": BAD_SIGNATURE,
    "test_expired_token_is_unauthorized": NO_EXPIRY,
    "test_user_cannot_read_another_user": NO_OWNER_CHECK,
}


def categorize(test_name: str) -> tuple[str, str]:
    """Return (vulnerability type, CWE id) for a test name such as "test_x[array]"."""
    function = test_name.split("[")[0]  # Drop the parameter part in square brackets.
    return TEST_CATEGORIES.get(function, ("Other", ""))
