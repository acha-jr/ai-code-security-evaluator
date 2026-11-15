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
# The first five tests of the study. They are reported on their own so the old 19/20 stays visible.
ORIGINAL_FILES = ("tests.test_login", "tests.test_security_edges")
# Semgrep is installed next to this Python, so the venv does not need to be activated.
SEMGREP = str(Path(sys.executable).parent / "semgrep")


def run_tests(candidate: Path, tests_dir: str = "tests") -> dict:
    """Run a pytest suite on one candidate in a subprocess and count the results."""
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
        try:
            subprocess.run(command, cwd=ROOT, capture_output=True, timeout=TEST_TIMEOUT)
        except subprocess.TimeoutExpired:
            return {"tests_passed": 0, "tests_total": 0, "original_passed": 0, "original_total": 0}
        if not report.exists():
            return {"tests_passed": 0, "tests_total": 0, "original_passed": 0, "original_total": 0}
        # The XML file lists one <testcase> per test. A failed test has a <failure> or <error> inside it.
        cases = list(ET.parse(report).getroot().iter("testcase"))

    def passed(case: ET.Element) -> bool:
        """A test counts as passed only if it has no failure, error or skip marker."""
        return not any(case.find(tag) is not None for tag in ("failure", "error", "skipped"))

    # Count the original five tests separately so the old result (such as 4/5) stays visible.
    original = [case for case in cases if case.get("classname") in ORIGINAL_FILES]
    return {
        "tests_passed": sum(passed(case) for case in cases),
        "tests_total": len(cases),
        "original_passed": sum(passed(case) for case in original),
        "original_total": len(original),
    }


def run_bandit(candidate: Path, out_file: Path) -> dict:
    """Run Bandit, save its JSON, and return the finding count and CWE ids."""
    command = [sys.executable, "-m", "bandit", "-q", "-f", "json", "-o", str(out_file), str(candidate)]
    subprocess.run(command, capture_output=True, timeout=SCAN_TIMEOUT)  # Exit code 1 only means "findings".
    results = json.loads(out_file.read_text())["results"]
    return {
        "bandit_findings": len(results),
        "bandit_cwes": sorted({f"CWE-{item['issue_cwe']['id']}" for item in results}),
    }


def run_semgrep(candidate: Path, out_file: Path) -> dict:
    """Run Semgrep with --config=auto, or with the local rules if auto cannot download."""
    ruleset = "auto"
    # Try the online ruleset first. If it fails (no internet), try the small local one.
    for config in ("auto", str(LOCAL_RULES)):
        out_file.unlink(missing_ok=True)  # Remove old output so a failed run is not mistaken for a good one.
        command = [SEMGREP, "--config", config, "--json", "-q", "-o", str(out_file), str(candidate)]
        subprocess.run(command, capture_output=True, timeout=SCAN_TIMEOUT)
        if out_file.exists():
            # Record which ruleset really ran, so offline results are never presented as online ones.
            ruleset = "auto" if config == "auto" else f"local ({LOCAL_RULES.name})"
            break
    else:
        # The loop finished without a break: neither ruleset produced a result.
        return {"semgrep_findings": 0, "semgrep_ruleset": "failed to run"}
    results = json.loads(out_file.read_text())["results"]
    return {"semgrep_findings": len(results), "semgrep_ruleset": ruleset}


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
