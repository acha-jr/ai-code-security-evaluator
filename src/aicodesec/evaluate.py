"""Run the shared tests, Bandit and Semgrep on each candidate file.

Every check runs in its own subprocess (a separate program started from this one).
That keeps a crashing or hanging candidate from taking down the whole tool.
We never run the candidate's own __main__ block: the tests import it as a module.
"""
import json
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from collections.abc import Callable
from importlib.metadata import version
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOCAL_RULES = ROOT / "rules" / "semgrep_local.yml"
TEST_TIMEOUT = 120  # Seconds before a stuck test run is stopped.
SCAN_TIMEOUT = 300  # Seconds before a stuck scanner is stopped.
# Semgrep "auto" must download its rules. With no network it can hang instead of failing fast,
# so it gets a much shorter limit. After that we fall back to the local rules.
AUTO_TIMEOUT = 60
# Semgrep is installed next to this Python, so the venv does not need to be activated.
SEMGREP = str(Path(sys.executable).parent / "semgrep")


def run_quietly(command: list[str], timeout: int) -> bool:
    """Run a command and wait up to `timeout` seconds. Return False if it had to be stopped.

    This is the one place that catches subprocess.TimeoutExpired, so a hung tool can never
    crash the evaluation. Output goes to DEVNULL (nowhere) on purpose: every tool here writes
    its results to a file, and not reading from a pipe means a stuck child cannot keep us waiting.
    """
    try:
        subprocess.run(command, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout)
        return True
    except subprocess.TimeoutExpired:
        return False


def read_results(out_file: Path) -> list | None:
    """Read the "results" list from a scanner's JSON file, or None if the file is missing or broken."""
    try:
        return json.loads(out_file.read_text())["results"]
    except (OSError, ValueError, KeyError):
        return None


def run_tests(candidate: Path, tests_dir: str = "tests") -> dict:
    """Run a pytest suite on one candidate in a subprocess and count the results."""
    # If the tests cannot run or are stopped, report zero tests. A failing candidate is a result too.
    no_result = {"tests_passed": 0, "tests_total": 0}
    # A temporary folder holds pytest's result file. It is deleted when the block ends.
    with tempfile.TemporaryDirectory() as temp:
        report = Path(temp) / "junit.xml"
        # This is the same command you would type yourself:
        #   pytest tests --candidate <file>
        # --junit-xml makes pytest write the results to a file we can read back.
        command = [
            sys.executable, "-m", "pytest", tests_dir, "--candidate", str(candidate),
            "-q", "-p", "no:cacheprovider", f"--junit-xml={report}",
        ]
        if not run_quietly(command, TEST_TIMEOUT) or not report.exists():
            return no_result
        # The XML file lists one <testcase> per test. A failed test has a <failure> or <error> inside it.
        cases = list(ET.parse(report).getroot().iter("testcase"))

    def passed(case: ET.Element) -> bool:
        """A test counts as passed only if it has no failure, error or skip marker."""
        return not any(case.find(tag) is not None for tag in ("failure", "error", "skipped"))

    return {
        "tests_passed": sum(passed(case) for case in cases),
        "tests_total": len(cases),
    }


def run_bandit(candidate: Path, out_file: Path) -> dict:
    """Run Bandit, save its JSON, and return the finding count and CWE ids.

    If Bandit times out or writes no usable file, the count is None ("not run").
    A 0 would wrongly say the code was scanned and found clean.
    """
    out_file.unlink(missing_ok=True)  # Never reuse an old file from an earlier run.
    command = [sys.executable, "-m", "bandit", "-q", "-f", "json", "-o", str(out_file), str(candidate)]
    finished = run_quietly(command, SCAN_TIMEOUT)  # Exit code 1 only means "findings", so it is not checked.
    results = read_results(out_file) if finished else None
    if results is None:
        out_file.unlink(missing_ok=True)  # Drop a half-written file.
        return {"bandit_findings": None, "bandit_cwes": []}
    return {
        "bandit_findings": len(results),
        "bandit_cwes": sorted({f"CWE-{item['issue_cwe']['id']}" for item in results}),
    }


def run_semgrep(candidate: Path, out_file: Path) -> dict:
    """Run Semgrep with --config=auto, or with the local rules if auto fails or hangs."""
    # Try the online ruleset first, with a short limit. If it fails or hangs (no internet),
    # try the small local ruleset instead.
    for config, timeout, ruleset in (
        ("auto", AUTO_TIMEOUT, "auto"),
        (str(LOCAL_RULES), SCAN_TIMEOUT, f"local ({LOCAL_RULES.name})"),
    ):
        out_file.unlink(missing_ok=True)  # Remove old output so a failed run is not mistaken for a good one.
        command = [SEMGREP, "--config", config, "--json", "-q", "-o", str(out_file), str(candidate)]
        finished = run_quietly(command, timeout)
        results = read_results(out_file) if finished else None
        if results is not None:
            # Record which ruleset really ran, so offline results are never presented as online ones.
            return {"semgrep_findings": len(results), "semgrep_ruleset": ruleset}
    # Neither ruleset produced a result. Say "not run" (None), never a false 0.
    out_file.unlink(missing_ok=True)
    return {"semgrep_findings": None, "semgrep_ruleset": "failed to run"}


def evaluate_candidates(
    candidates_dir: Path, out_dir: Path, tests_dir: str = "tests", log: Callable[[str], None] = print
) -> Path:
    """Evaluate every .py file in a folder and write evaluation.json plus raw scanner JSON."""
    out_dir.mkdir(parents=True, exist_ok=True)
    results = []
    # One loop checks every candidate the same way.
    for candidate in sorted(candidates_dir.glob("*.py")):
        name = candidate.stem  # File name without ".py", such as "openai".
        log(f"Evaluating {candidate.name}: tests, Bandit, Semgrep...")
        entry = {"name": name, "candidate_file": candidate.name}
        entry.update(run_tests(candidate, tests_dir))
        entry.update(run_bandit(candidate, out_dir / f"{name}_bandit.json"))
        entry.update(run_semgrep(candidate, out_dir / f"{name}_semgrep.json"))
        results.append(entry)

    # Record the tool versions so the results can be reproduced and explained later.
    versions = {
        "bandit": version("bandit"),
        "semgrep": subprocess.run([SEMGREP, "--version"], capture_output=True, text=True).stdout.strip(),
        "pytest": version("pytest"),
        "python": sys.version.split()[0],
    }
    evaluation = out_dir / "evaluation.json"
    evaluation.write_text(json.dumps({"tool_versions": versions, "results": results}, indent=2) + "\n")
    return evaluation


if __name__ == "__main__":
    # Command line use: python -m aicodesec.evaluate <candidates_dir> <out_dir> [tests_dir]
    print(evaluate_candidates(Path(sys.argv[1]), Path(sys.argv[2]), *sys.argv[3:4]))
