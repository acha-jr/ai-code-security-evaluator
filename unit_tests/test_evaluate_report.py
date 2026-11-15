"""Check that the evaluator and report reproduce the original study numbers on the fallback data."""
import subprocess
import sys
from pathlib import Path

import pandas as pd
import pytest

from aicodesec.evaluate import evaluate_candidates
from aicodesec.generate import load_config
from aicodesec.report import add_review, build_table, load_reviews

PREGENERATED = Path(__file__).resolve().parents[1] / "data" / "pregenerated"
# provider: (tests passed out of 30, bandit, semgrep, confirmed) for the expanded suite
EXPECTED = {"OpenAI": (30, 0, 0, 0), "Claude": (30, 0, 0, 0), "DeepSeek": (25, 1, 1, 2), "Gemini": (23, 1, 1, 2)}
# The original five tests, run alone, must still give the old 19/20 result.
ORIGINAL_FIVE = {"openai": 5, "claude": 5, "deepseek": 4, "gemini": 5}


def check_table(table: pd.DataFrame) -> None:
    """Assert every row of the results table matches the expected numbers."""
    for row in table.itertuples():
        passed, bandit, semgrep, confirmed = EXPECTED[row.provider]
        assert row.functional_tests_total == 30
        assert (row.original_tests_passed, row.original_tests_total) == (ORIGINAL_FIVE[row.provider.lower()], 5)
        assert (row.functional_tests_passed, row.bandit_findings, row.semgrep_findings, row.manually_confirmed_findings) == (passed, bandit, semgrep, confirmed)


def labels() -> dict:
    """Map provider ids to display names, read from config.yaml."""
    return {name: block["label"] for name, block in load_config()["providers"].items()}


def test_fallback_data_matches_old_numbers(tmp_path: Path) -> None:
    """Evaluating the four original files gives the numbers in the README."""
    evaluation = evaluate_candidates(PREGENERATED / "candidates", tmp_path)
    reviews = load_reviews(PREGENERATED / "manual_reviews.csv")
    table = build_table(evaluation, reviews, labels())
    assert len(table) == 4
    check_table(table)


def test_semgrep_falls_back_to_local_rules_when_offline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """With no network, Semgrep uses the local rules and still finds debug=True."""
    # A proxy that nothing listens on makes the --config=auto download fail.
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    candidates = tmp_path / "c"
    candidates.mkdir()
    (candidates / "deepseek.py").write_bytes((PREGENERATED / "candidates" / "deepseek.py").read_bytes())
    evaluation = evaluate_candidates(candidates, tmp_path / "out")
    table = build_table(evaluation, [], labels())
    assert table.loc[0, "semgrep_ruleset"].startswith("local")
    assert table.loc[0, "semgrep_findings"] == 1


def test_add_review_round_trip(tmp_path: Path) -> None:
    """A saved manual review can be read back unchanged."""
    path = tmp_path / "reviews.csv"
    add_review(path, "Gemini", "CWE-489", "debug=True")
    assert load_reviews(path) == [{"provider": "Gemini", "cwe": "CWE-489", "note": "debug=True"}]


@pytest.mark.parametrize("provider", ORIGINAL_FIVE)
def test_original_five_tests_still_reproduce_old_result(provider: str) -> None:
    """Run only the original five tests. The old 19/20 result must still appear."""
    candidate = PREGENERATED / "candidates" / f"{provider}.py"
    command = [sys.executable, "-m", "pytest", "tests/test_login.py", "tests/test_security_edges.py",
               "--candidate", str(candidate), "-q", "-p", "no:cacheprovider"]
    output = subprocess.run(command, cwd=PREGENERATED.parents[1], capture_output=True, text=True).stdout
    assert f"{ORIGINAL_FIVE[provider]} passed" in output


def test_task2_evaluation_has_no_original_five_columns(tmp_path: Path) -> None:
    """Task 2 results pass all 12 tests on the reference app and skip the original-5 columns."""
    candidates = tmp_path / "c"
    candidates.mkdir()
    reference = Path(__file__).with_name("task2_reference.py")
    (candidates / "openai.py").write_text(reference.read_text())
    evaluation = evaluate_candidates(candidates, tmp_path / "out", "tests_task2")
    table = build_table(evaluation, [], labels())
    assert table.loc[0, "functional_tests_passed"] == table.loc[0, "functional_tests_total"] == 12
    assert "original_tests_passed" not in table.columns
