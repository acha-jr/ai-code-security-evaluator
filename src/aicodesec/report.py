"""Build the results table, the CSV and the chart from evaluation output and manual reviews.

Two kinds of numbers meet here:
  computed numbers   test results and scanner counts, produced by evaluate.py
  human numbers      manual review findings, typed in by a person and saved to a CSV file
The two are kept apart on purpose. A scanner count is only a warning. A manual review
finding means a person read the code and confirmed a real problem.
"""
import csv
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # Draw to a file. No window is needed.
import matplotlib.pyplot as plt
import pandas as pd

REVIEW_FIELDS = ["provider", "cwe", "note"]  # The three columns of manual_reviews.csv.


def load_reviews(path: Path) -> list[dict]:
    """Read the manual review rows (provider, cwe, note). A missing file means no reviews yet."""
    if not path.exists():
        return []
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle))  # Each row becomes a dict like {"provider": "Gemini", ...}.


def add_review(path: Path, provider: str, cwe: str, note: str) -> None:
    """Append one manual review row. The GUI calls this when a reviewer saves a finding."""
    is_new = not path.exists()
    with path.open("a", newline="") as handle:  # "a" adds to the end and never erases earlier rows.
        writer = csv.DictWriter(handle, fieldnames=REVIEW_FIELDS)
        if is_new:
            writer.writeheader()  # Column names go in the first row of a new file only.
        writer.writerow({"provider": provider, "cwe": cwe, "note": note})


def build_table(evaluation_file: Path, reviews: list[dict], labels: dict[str, str], metadata_file: Path | None = None) -> pd.DataFrame:
    """Combine tests, scanner counts and manual reviews into one row per candidate."""
    evaluation = json.loads(evaluation_file.read_text())

    # Look up the model name each candidate really came from. Pre-generated files have
    # none, so they stay "Not recorded". We never guess a model version.
    models = {}
    if metadata_file and metadata_file.exists():
        for item in json.loads(metadata_file.read_text())["candidates"]:
            models[item["name"]] = item.get("model_returned", "Not recorded")

    rows = []
    for item in evaluation["results"]:
        # "openai_2" belongs to provider "openai", so split off the repeat number.
        label = labels[item["name"].split("_")[0]]
        mine = [review for review in reviews if review["provider"] == label]
        rows.append({
            "provider": label,
            "model_version": models.get(item["name"], "Not recorded"),
            "candidate_file": item["candidate_file"],
            "functional_tests_passed": item["tests_passed"],
            "functional_tests_total": item["tests_total"],
            "bandit_findings": item["bandit_findings"],
            "semgrep_findings": item["semgrep_findings"],
            # Confirmed findings are just the number of manual review rows for this provider.
            "manually_confirmed_findings": len(mine),
            "cwe_classification": "; ".join(sorted({review["cwe"] for review in mine})) or "None assigned",
            "manual_review_notes": " ".join(review["note"] for review in mine) or "No specific vulnerability confirmed.",
            "semgrep_ruleset": item["semgrep_ruleset"],
        })
    if not rows:
        return pd.DataFrame()  # Nothing was evaluated (for example every provider failed). Callers check .empty.
    # Keep the provider order from config.yaml so every table and chart reads the same way.
    order = list(labels.values())
    table = pd.DataFrame(sorted(rows, key=lambda row: (order.index(row["provider"]), row["candidate_file"])))
    # A scanner that did not run has no count (None). Int64 keeps real counts as whole numbers
    # and shows the missing ones as <NA>, instead of turning every count into a decimal.
    for column in ("bandit_findings", "semgrep_findings"):
        table[column] = table[column].astype("Int64")
    return table


def save_chart(table: pd.DataFrame, path: Path) -> None:
    """Draw pass rate and confirmed findings per candidate, one chart above the other."""
    figure, (top, bottom) = plt.subplots(2, 1, figsize=(7, 8))  # Two charts, one above the other.
    stems = table["candidate_file"].str.removesuffix(".py")
    # Repeated generations are named openai_1, openai_2 and so on. Show the number after the label.
    names = [f"{label} {stem.split('_')[1]}" if "_" in stem else label for label, stem in zip(table["provider"], stems)]
    rate = 100 * table["functional_tests_passed"] / table["functional_tests_total"]
    top.bar(names, rate, color="#6553BD")
    top.set(title="Functional test pass rate", ylabel="Passed (%)", ylim=(0, 110))
    bottom.bar(names, table["manually_confirmed_findings"], color="#273B63")
    bottom.set(title="Manually confirmed issue instances", ylabel="Issue instances")
    bottom.yaxis.get_major_locator().set_params(integer=True)  # Whole numbers only, since we count issues.
    # Start at 0 and never let the top drop below 1. With all counts at zero, matplotlib would
    # otherwise draw a strange axis from about -0.04 to 0.04. The extra 15 percent leaves room
    # for the number written above the tallest bar.
    bottom.set_ylim(0, max(1, 1.15 * table["manually_confirmed_findings"].max()))
    # Write the value above each bar.
    for axis, values, suffix in ((top, rate, "%"), (bottom, table["manually_confirmed_findings"], "")):
        for position, value in enumerate(values):
            axis.text(position, value, f"{value:.0f}{suffix}", ha="center", va="bottom")
        axis.tick_params(axis="x", rotation=15)
    figure.tight_layout()
    figure.savefig(path, dpi=150)
    plt.close(figure)  # Free the memory, since the GUI may draw this many times.
