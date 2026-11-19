"""Check that the evaluator and report give the known results on the four pre-generated candidates."""
import os
import re
import sys
from pathlib import Path

import pandas as pd
import pytest

from aicodesec import evaluate, report
from aicodesec.categories import TEST_CATEGORIES, categorize
from aicodesec.evaluate import evaluate_candidates
from aicodesec.generate import load_config
from aicodesec.report import add_review, build_findings, build_table, load_reviews

PREGENERATED = Path(__file__).resolve().parents[1] / "data" / "pregenerated"
# provider: (tests passed out of 30, bandit, semgrep) for the full suite. These are test fixtures
# for checking the tool, not published results. Manual reviews are not part of them.
EXPECTED = {"OpenAI": (30, 0, 0), "Claude": (30, 0, 0), "DeepSeek": (25, 1, 1), "Gemini": (23, 1, 1)}


def check_table(table: pd.DataFrame) -> None:
    """Assert every row of the results table matches the expected numbers."""
    for row in table.itertuples():
        passed, bandit, semgrep = EXPECTED[row.provider]
        assert row.tests_total == 30
        assert (row.tests_passed, row.bandit_findings, row.semgrep_findings) == (passed, bandit, semgrep)
        assert row.manually_confirmed_findings == 0  # A fallback run starts with no manual reviews.


def labels() -> dict:
    """Map provider ids to display names, read from config.yaml."""
    return {name: block["label"] for name, block in load_config()["providers"].items()}


def test_pregenerated_candidates_give_known_numbers(tmp_path: Path) -> None:
    """Evaluating the four pre-generated files gives the known test and scanner numbers."""
    evaluation = evaluate_candidates(PREGENERATED / "candidates", tmp_path)
    table = build_table(evaluation, [], labels())
    assert len(table) == 4
    check_table(table)

    # The findings table says what kind of weakness each failure points to.
    findings = build_findings(evaluation, labels())
    assert findings[findings["provider"].isin(["OpenAI", "Claude"])].empty  # Clean candidates: nothing listed.
    deepseek = findings[findings["provider"] == "DeepSeek"]
    crashes = deepseek[deepseek["source"] == "Tests"]
    assert len(crashes) == 5 and set(crashes["vulnerability_type"]) == {"Improper input validation"}
    assert crashes["detail"].str.contains("AttributeError").all()  # The real error is shown.
    assert set(crashes["cwe"]) == {"CWE-20"}
    bandit = deepseek[deepseek["source"] == "Bandit"].iloc[0]
    assert bandit["vulnerability_type"].startswith("B201") and bandit["cwe"] == "CWE-94" and bandit["line"] > 0
    assert (deepseek["source"] == "Semgrep").sum() == 1
    assert "Improper input validation (CWE-20): 5 failed" in table.set_index("provider").loc["DeepSeek", "failed_vulnerability_types"]
    assert table.set_index("provider").loc["Claude", "failed_vulnerability_types"] == "None"


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


def test_task2_reference_app_passes_every_test(tmp_path: Path) -> None:
    """The hand-written Task 2 reference app passes all 12 Task 2 tests."""
    candidates = tmp_path / "c"
    candidates.mkdir()
    reference = Path(__file__).with_name("task2_reference.py")
    (candidates / "openai.py").write_text(reference.read_text())
    evaluation = evaluate_candidates(candidates, tmp_path / "out", "tests_task2")
    table = build_table(evaluation, [], labels())
    assert table.loc[0, "tests_passed"] == table.loc[0, "tests_total"] == 12


def one_candidate(tmp_path: Path) -> Path:
    """Make a folder holding only the pre-generated DeepSeek file, and return the folder."""
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
    assert table.loc[0, "semgrep_findings"] == 1 and table.loc[0, "tests_total"] == 30


def test_no_candidates_gives_an_empty_table_not_an_error(tmp_path: Path) -> None:
    """With no code files (every provider failed), the report is empty instead of raising."""
    (tmp_path / "empty").mkdir()
    evaluation = evaluate_candidates(tmp_path / "empty", tmp_path / "out")
    assert build_table(evaluation, [], labels()).empty
    assert build_findings(evaluation, labels()).empty


def test_chart_axis_starts_at_zero_with_a_top_of_at_least_one(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When every confirmed count is 0, the right-hand axis is 0 to 1, not a strange -0.04 to 0.04."""
    drawn = []
    monkeypatch.setattr(report.plt, "close", drawn.append)  # Keep the figure so the test can inspect it.
    table = pd.DataFrame({
        "provider": ["OpenAI", "Claude"], "candidate_file": ["openai.py", "claude.py"],
        "tests_passed": [30, 25], "tests_total": [30, 30], "manually_confirmed_findings": [0, 0],
    })
    report.save_chart(table, tmp_path / "chart.png")
    assert drawn[0].axes[1].get_ylim() == (0, 1)


def test_every_test_function_has_a_weakness_category() -> None:
    """A new test must be added to categories.py, or its failures would be labeled "Other"."""
    root = Path(__file__).resolve().parents[1]
    names = set()
    for folder in ("tests", "tests_task2"):
        for file in (root / folder).glob("test_*.py"):
            names |= set(re.findall(r"^def (test_\w+)\(", file.read_text(), flags=re.MULTILINE))
    assert names and names <= set(TEST_CATEGORIES), sorted(names - set(TEST_CATEGORIES))


def test_categorize_ignores_the_parameter_part_of_a_test_name() -> None:
    """A test id with parameters in brackets is looked up by its function name."""
    assert categorize("test_injection_payload_is_rejected[drop-table-username]") == ("SQL injection", "CWE-89")
    assert categorize("test_not_in_the_list") == ("Other", "")
