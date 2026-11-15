"""Streamlit GUI: generate code from four providers, evaluate it, and compare the results.

How Streamlit works, in two lines:
  1. Every time you click something, Streamlit runs this whole file again from the top.
  2. st.session_state is a dictionary that survives those re-runs, so it is where we
     remember things such as "which run folder are we working on".

The page has a sidebar for settings and three tabs for the three steps:
  1. Get the code    send the prompt (or load the saved candidates)
  2. Test and scan   run pytest, Bandit and Semgrep
  3. Compare         table, chart, CSV and the manual review form
"""
import inspect
import json
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

# Streamlit starts this file directly, so Python does not know about src/ yet.
# This line adds src/ to the search path so that "from aicodesec ..." works.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aicodesec import generate  # noqa: E402  (needs the path line above)
from aicodesec.evaluate import evaluate_candidates  # noqa: E402
from aicodesec.providers import build_providers  # noqa: E402
from aicodesec.report import add_review, build_table, load_reviews, save_chart  # noqa: E402

PREGENERATED = ROOT / "data" / "pregenerated"

# Settings come from config.yaml. labels maps "openai" to the display name "OpenAI".
config = generate.load_config()
labels = {name: block["label"] for name, block in config["providers"].items()}

st.set_page_config(page_title="AI-Generated Code Security", page_icon=":material/shield:", layout="wide")


def candidate_card(item: dict, run_dir: Path) -> None:
    """Show one generated candidate: who made it, what came back, and the saved code."""
    with st.container(border=True):
        st.markdown(f"**{item['provider']}**")
        if "error" in item:
            # The API call failed (no credits, wrong key, and so on). Show why, then stop.
            st.error(item["error"][:160], icon=":material/error:")
            return
        st.caption(f"{item['model_returned']}  \n{item['input_tokens']} tokens in, {item['output_tokens']} out")
        st.caption(item["extraction_note"])
        # Side by side proof for the demo: what the API sent back, and what we saved.
        with st.expander("Raw reply and saved code"):
            st.caption("Raw reply from the API")
            st.code((run_dir / item["raw_file"]).read_text(), language="markdown")
            st.caption("Code saved without changes")
            st.code((run_dir / item["candidate_file"]).read_text(), language="python")


def results_table(table: pd.DataFrame) -> None:
    """Show the comparison table with a bar for the test pass rate."""
    shown = table.copy()  # Work on a copy so the CSV keeps the original column names.
    shown["pass rate"] = 100 * shown["functional_tests_passed"] / shown["functional_tests_total"]
    shown["tests"] = shown["functional_tests_passed"].astype(str) + "/" + shown["functional_tests_total"].astype(str)
    columns = ["provider", "model_version", "tests", "pass rate"]
    # Task 2 has no "original 5" columns, so only add them when they exist.
    if "original_tests_passed" in shown:
        shown["original 5"] = shown["original_tests_passed"].astype(str) + "/" + shown["original_tests_total"].astype(str)
        columns.append("original 5")
    columns += ["bandit_findings", "semgrep_findings", "manually_confirmed_findings", "cwe_classification", "semgrep_ruleset"]
    st.dataframe(
        shown[columns],
        hide_index=True,
        width="stretch",
        # column_config only changes how columns are displayed (names, the progress bar).
        column_config={
            "pass rate": st.column_config.ProgressColumn("Pass rate", min_value=0, max_value=100, format="%.0f%%"),
            "provider": "Provider",
            "model_version": "Model",
            "tests": "Tests passed",
            "original 5": "Original 5",
            "bandit_findings": "Bandit",
            "semgrep_findings": "Semgrep",
            "manually_confirmed_findings": "Confirmed",
            "cwe_classification": "CWE",
            "semgrep_ruleset": "Semgrep rules",
        },
    )


# ---- Sidebar: settings ----
with st.sidebar:
    st.header("Setup")
    task_name = st.radio(
        "Task", list(config["tasks"]), format_func=lambda name: config["tasks"][name]["label"], key="task"
    )
    task = config["tasks"][task_name]
    # The old candidates only exist for Task 1, so the toggle is switched off for Task 2.
    use_fallback = (
        st.toggle(
            "Use pre-generated code",
            help="Loads the four original candidates. No keys or internet needed.",
            disabled=task_name != "task1",
            key="fallback",
        )
        and task_name == "task1"
    )
    if not use_fallback:
        chosen = st.multiselect("Providers", list(labels), default=list(labels), format_func=labels.get, key="providers")
        repeats = st.number_input("Generations per provider", 1, 10, config["runs_per_model"], key="repeats")
        # A green dot means the API key for that provider was found in .env or the environment.
        for name in chosen:
            block = config["providers"][name]
            found = bool(os.environ.get(block["api_key_env"]))
            st.caption(f"{':green[●]' if found else ':red[●]'} {labels[name]} · `{block['model']}` · key {'found' if found else 'missing'}")

# ---- Header and progress ----
st.title("Evaluating Security Vulnerabilities in AI-Generated Code for Common Web-Application Tasks")
st.caption("COMP 5112 · One fixed prompt goes to four providers. The code that comes back is tested and scanned.")

# Read what earlier clicks saved. run_dir is the folder of the run we are working on.
run_dir: Path | None = st.session_state.get("run_dir")
evaluated = st.session_state.get("evaluation") is not None
steps = [("1", "Get the code", run_dir is not None), ("2", "Test and scan", evaluated), ("3", "Compare", evaluated)]
for column, (number, title, done) in zip(st.columns(3), steps):
    column.markdown(f"{':green[✔]' if done else ':gray[○]'} **{number}. {title}**")

tab_generate, tab_evaluate, tab_compare = st.tabs(["1 · Get the code", "2 · Test and scan", "3 · Compare"])

# ---- Step 1: get the candidates ----
with tab_generate:
    prompt_file = ROOT / task["prompt"]
    original_prompt = prompt_file.read_text().strip()
    prompt_key = f"prompt_{task_name}"  # Each task remembers its own edited text.
    prompt = original_prompt
    with st.container(border=True):
        st.markdown("**The prompt**")
        if use_fallback:
            # Pre-generated code was made earlier, so no prompt is sent. Show it read-only.
            st.code(original_prompt, language="text", wrap_lines=True)
        else:
            # Fill the box with the original text once. After that the box owns its own text.
            st.session_state.setdefault(prompt_key, original_prompt)
            prompt = st.text_area("Prompt", key=prompt_key, height=230, label_visibility="collapsed")
            if prompt.strip() == original_prompt:
                st.caption("Original study prompt, unchanged. Results are comparable with the earlier runs.")
            else:
                st.warning("This prompt was edited. Results are not comparable with the original study.", icon=":material/edit:")
            st.button(
                "Reset to original",
                on_click=lambda: st.session_state.update({prompt_key: original_prompt}),
                disabled=prompt.strip() == original_prompt,
            )

    if use_fallback:
        st.info("The four original candidates from `data/pregenerated/` will be used. Their model versions were not recorded.")
        if st.button("Load pre-generated code", type="primary"):
            # Work on a copy in a new run folder, so the original files in data/ are never touched.
            run_dir = ROOT / "runs" / (datetime.now().strftime("%Y%m%d-%H%M%S") + "-pregenerated")
            (run_dir / "candidates").mkdir(parents=True)
            for file in (PREGENERATED / "candidates").glob("*.py"):
                shutil.copy2(file, run_dir / "candidates" / file.name)
            # Copy the reviews so new entries never change the original data.
            shutil.copy2(PREGENERATED / "manual_reviews.csv", run_dir / "manual_reviews.csv")
            # Remember the run, so the other tabs (and the next re-run of this script) can use it.
            st.session_state.update(run_dir=run_dir, candidates_dir=run_dir / "candidates", evaluation=None, tests=task["tests"])
    else:
        # For the demo: this shows the real function that sends the prompt, read from the source file.
        with st.expander("Show the code that sends the prompt"):
            st.code(inspect.getsource(generate.generate_one), language="python")
        if st.button("Generate code", type="primary", disabled=not chosen or not prompt.strip()):
            prompt_name = prompt_file.name if prompt.strip() == original_prompt else f"custom (edited from {prompt_file.name})"
            with st.status("Generating...", expanded=True) as status:
                # This is the real work: send the prompt to each chosen provider and save the replies.
                # log=st.write prints each progress line on the page as it happens.
                run_dir = generate.run_generation(
                    prompt, build_providers(config, chosen), repeats=int(repeats), log=st.write, prompt_name=prompt_name
                )
                status.update(label="Generation finished", state="complete")
            st.session_state.update(run_dir=run_dir, candidates_dir=run_dir, evaluation=None, tests=task["tests"])

    # Show one card per candidate from the most recent run.
    run_dir = st.session_state.get("run_dir")
    if run_dir is not None:
        st.success(f"Run folder: {run_dir.relative_to(ROOT)}", icon=":material/folder:")
        metadata_file = run_dir / "metadata.json"
        if metadata_file.exists():  # Pre-generated runs have no metadata file.
            items = json.loads(metadata_file.read_text())["candidates"]
            for start in range(0, len(items), 4):  # Four cards per row.
                for column, item in zip(st.columns(4), items[start:start + 4]):
                    with column:
                        candidate_card(item, run_dir)

# ---- Step 2: evaluate ----
with tab_evaluate:
    if run_dir is None:
        st.info("Get the code first (step 1).")
    else:
        st.write("Runs the shared pytest suite, Bandit and Semgrep on every candidate. This takes a few minutes.")
        if st.button("Run tests, Bandit and Semgrep", type="primary"):
            with st.status("Evaluating...", expanded=True) as status:
                # evaluate_candidates returns the path of evaluation.json, which step 3 reads.
                st.session_state["evaluation"] = evaluate_candidates(
                    st.session_state["candidates_dir"], run_dir, st.session_state["tests"], log=st.write
                )
                status.update(label="Evaluation finished", state="complete")
            st.rerun()  # Run the script again so the progress row and step 3 update.
        evaluation = st.session_state.get("evaluation")
        if evaluation is not None:
            versions = json.loads(evaluation.read_text())["tool_versions"]
            st.success("Evaluation finished. See step 3.", icon=":material/check_circle:")
            st.caption("Tool versions: " + " · ".join(f"{tool} {number}" for tool, number in versions.items()))

# ---- Step 3: compare ----
with tab_compare:
    evaluation = st.session_state.get("evaluation")
    if evaluation is None:
        st.info("Run the tests and scanners first (step 2).")
    else:
        reviews_file = run_dir / "manual_reviews.csv"
        # One row per candidate: tests, scanner counts, and the manual review findings.
        table = build_table(evaluation, load_reviews(reviews_file), labels, run_dir / "metadata.json")

        # A summary card for each provider.
        for column, row in zip(st.columns(len(table)), table.itertuples()):
            with column.container(border=True):
                st.metric(
                    row.provider,
                    f"{row.functional_tests_passed}/{row.functional_tests_total} tests",
                    f"Bandit {row.bandit_findings} · Semgrep {row.semgrep_findings} · Confirmed {row.manually_confirmed_findings}",
                    delta_color="off",
                    delta_arrow="off",
                )

        results_table(table)
        # Save the same numbers to disk, so the GUI, the CSV and the chart can never disagree.
        table.to_csv(run_dir / "results.csv", index=False)
        save_chart(table, run_dir / "model_comparison.png")
        st.image(str(run_dir / "model_comparison.png"))
        st.download_button("Download results.csv", (run_dir / "results.csv").read_bytes(), "results.csv", icon=":material/download:")
        st.caption("Bandit and Semgrep findings can overlap when both flag the same issue.")

        # Manual review: a person records what they confirmed by reading the code.
        # These rows are saved to manual_reviews.csv and counted as "confirmed findings".
        with st.container(border=True):
            st.markdown("**Manual review**")
            st.caption("Scanner counts are not confirmed vulnerabilities. Enter what you confirmed by reading the code.")
            with st.form("review", clear_on_submit=True):
                left, right = st.columns([1, 1])
                provider = left.selectbox("Provider", list(dict.fromkeys(table["provider"])))
                cwe = right.text_input("CWE", placeholder="CWE-489")
                note = st.text_area("Note")
                if st.form_submit_button("Save finding", type="primary") and cwe.strip():
                    add_review(reviews_file, provider, cwe.strip(), note.strip())
                    st.rerun()  # Re-run so the table above counts the new finding.
            saved = load_reviews(reviews_file)
            if saved:
                st.dataframe(pd.DataFrame(saved), hide_index=True, width="stretch")
