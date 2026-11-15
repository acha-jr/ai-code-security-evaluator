"""The Task 2 tests must accept a correct app and catch each of three known flaws."""
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = Path(__file__).with_name("task2_reference.py")

# Each flaw replaces one marked line with a version that skips the check.
FLAWS = {
    "no-signature-check": ("if not hmac.compare_digest(signature, sign(body.encode())):  # CHECK_SIGNATURE", "if False:", "tampered"),
    "no-expiry-check": ("if payload[\"exp\"] < time.time():  # CHECK_EXPIRY", "if False:", "expired"),
    "no-owner-check": ("if owner != username:  # CHECK_OWNER", "if False:", "cannot_read_another"),
}


def run_task2_tests(candidate: Path) -> str:
    """Run the Task 2 suite on one file and return pytest's output."""
    command = [sys.executable, "-m", "pytest", "tests_task2", "--candidate", str(candidate), "-q", "-p", "no:cacheprovider"]
    return subprocess.run(command, cwd=ROOT, capture_output=True, text=True).stdout


def test_correct_reference_passes_all_task2_tests() -> None:
    """A correct app must pass every Task 2 test."""
    assert "failed" not in run_task2_tests(REFERENCE)


@pytest.mark.parametrize("flaw", FLAWS)
def test_each_flaw_is_caught(flaw: str, tmp_path: Path) -> None:
    """Remove one security check from the reference app. The tests must then fail."""
    old, new, failing_test = FLAWS[flaw]
    source = REFERENCE.read_text()
    assert old in source
    broken = tmp_path / "broken.py"
    broken.write_text(source.replace(old, new))
    output = run_task2_tests(broken)
    assert f"{failing_test}" in output and "failed" in output
