"""Check that the evaluator and report give the known results on the four stored original candidates."""
import os
import subprocess
import sys
from pathlib import Path

import pandas as pd
import pytest

from aicodesec import evaluate, report
from aicodesec.evaluate import evaluate_candidates
from aicodesec.generate import load_config
from aicodesec.report import add_review, build_table, load_reviews

PREGENERATED = Path(__file__).resolve().parents[1] / "data" / "pregenerated"
# provider: (tests passed out of 30, bandit, semgrep) for the full suite. These are test fixtures
# for checking the tool, not published results. Manual reviews are not part of them.
EXPECTED = {"OpenAI": (30, 0, 0), "Claude": (30, 0, 0), "DeepSeek": (25, 1, 1), "Gemini": (23, 1, 1)}
# The original five tests, run alone, must still give the old 19/20 result.
ORIGINAL_FIVE = {"openai": 5, "claude": 5, "deepseek": 4, "gemini": 5}


def check_table(table: pd.DataFrame) -> None:
    """Assert every row of the results table matches the expected numbers."""
    for row in table.itertuples():
        passed, bandit, semgrep = EXPECTED[row.provider]
        assert row.functional_tests_total == 30
        assert (row.original_tests_passed, row.original_tests_total) == (ORIGINAL_FIVE[row.provider.lower()], 5)
        assert (row.functional_tests_passed, row.bandit_findings, row.semgrep_findings) == (passed, bandit, semgrep)
        assert row.manually_confirmed_findings == 0  # A fallback run starts with no manual reviews.


def labels() -> dict:
    """Map provider ids to display names, read from config.yaml."""
    return {name: block["label"] for name, block in load_config()["providers"].items()}


def test_fallback_data_matches_old_numbers(tmp_path: Path) -> None:
    """Evaluating the four stored original files gives the known test and scanner numbers."""
    evaluation = evaluate_candidates(PREGENERATED / "candidates", tmp_path)
    table = build_table(evaluation, [], labels())
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


def one_candidate(tmp_path: Path) -> Path:
    """Make a folder holding only the old DeepSeek file, and return the folder."""
    folder = tmp_path / "c"
    folder.mkdir()
    (folder / "deepseek.py").write_bytes((PREGENERATED / "candidates" / "deepseek.py").read_bytes())
    return folder


def test_semgrep_auto_timeout_falls_back_to_local_rules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """If Semgrep "auto" times out, the local rules run and the evaluation does not crash."""
    real_run = evaluate.run_quietly

    def auto_times_out(command: list[str], timeout: int) -> bool:
        """Pretend that only the "auto" run hit its time limit."""
        return False if "auto" in command else real_run(command, timeout)

    monkeypatch.setattr(evaluate, "run_quietly", auto_times_out)
    table = build_table(evaluate_candidates(one_candidate(tmp_path), tmp_path / "out"), [], labels())
    assert table.loc[0, "semgrep_ruleset"].startswith("local") and table.loc[0, "semgrep_findings"] == 1


@pytest.mark.skipif(os.name == "nt", reason="The fake Semgrep below is a shell-style script.")
def test_really_hanging_semgrep_is_stopped_and_local_rules_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A Semgrep that hangs on "auto" is stopped after the limit, then the real local rules run."""
    helper = tmp_path / "fake_semgrep.py"
    # Hangs when asked for "auto". Otherwise hands the job to the real Semgrep.
    helper.write_text(f"import subprocess, sys, time\n"
                      f"if 'auto' in sys.argv:\n    time.sleep(120)\n"
                      f"sys.exit(subprocess.run([{evaluate.SEMGREP!r}] + sys.argv[1:]).returncode)\n")
    # A shell wrapper is used because a "#!" line cannot hold a Python path that contains a space.
    fake = tmp_path / "fake_semgrep"
    fake.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{helper}" "$@"\n')
    fake.chmod(0o755)
    monkeypatch.setattr(evaluate, "SEMGREP", str(fake))
    monkeypatch.setattr(evaluate, "AUTO_TIMEOUT", 3)
    table = build_table(evaluate_candidates(one_candidate(tmp_path), tmp_path / "out"), [], labels())
    assert table.loc[0, "semgrep_ruleset"].startswith("local") and table.loc[0, "semgrep_findings"] == 1


def test_bandit_timeout_gives_no_count_instead_of_crashing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """If Bandit times out, its count is "not run" (not 0) and the rest of the evaluation continues."""
    real_run = evaluate.run_quietly

    def bandit_times_out(command: list[str], timeout: int) -> bool:
        """Pretend that only the Bandit run hit its time limit."""
        return False if "bandit" in command else real_run(command, timeout)

    monkeypatch.setattr(evaluate, "run_quietly", bandit_times_out)
    table = build_table(evaluate_candidates(one_candidate(tmp_path), tmp_path / "out"), [], labels())
    assert table.loc[0, "bandit_findings"] is pd.NA
    assert table.loc[0, "semgrep_findings"] == 1 and table.loc[0, "functional_tests_total"] == 30


def test_no_candidates_gives_an_empty_table_not_an_error(tmp_path: Path) -> None:
    """With no code files (every provider failed), the report is empty instead of raising."""
    (tmp_path / "empty").mkdir()
    table = build_table(evaluate_candidates(tmp_path / "empty", tmp_path / "out"), [], labels())
    assert table.empty


def test_chart_axis_starts_at_zero_with_a_top_of_at_least_one(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When every confirmed count is 0, the right-hand axis is 0 to 1, not a strange -0.04 to 0.04."""
    drawn = []
    monkeypatch.setattr(report.plt, "close", drawn.append)  # Keep the figure so the test can inspect it.
    table = pd.DataFrame({
        "provider": ["OpenAI", "Claude"], "candidate_file": ["openai.py", "claude.py"],
        "functional_tests_passed": [30, 25], "functional_tests_total": [30, 30], "manually_confirmed_findings": [0, 0],
    })
    report.save_chart(table, tmp_path / "chart.png")
    assert drawn[0].axes[1].get_ylim() == (0, 1)
