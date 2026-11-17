# Evaluating Security Vulnerabilities in AI-Generated Code for Common Web-Application Tasks

Course project for COMP 5112 (Dr. Fiaidhi). Authors: Obinna Achazie, Ahmed Omar Ali.

This tool runs our study from start to finish. It sends one fixed prompt to four
providers (OpenAI, Claude, DeepSeek, Gemini), saves the generated code unchanged, runs the
same pytest tests plus Bandit and Semgrep on each result, and shows the comparison.

## What happens, step by step

1. **Generate.** `src/aicodesec/generate.py` reads the prompt, sends it to each provider
   (`provider.complete(prompt)`), and saves the raw reply, the extracted code and a
   `metadata.json`. The code is saved exactly as the model wrote it.
2. **Evaluate.** `src/aicodesec/evaluate.py` runs the shared tests in a subprocess against
   each candidate file, then runs Bandit and Semgrep and saves their JSON.
3. **Compare.** `src/aicodesec/report.py` builds the results table, `results.csv` and the chart.
   Manual review findings are typed into the GUI and saved. They are not computed.

## Install

You need Python 3.11 or newer.

```
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Put your own keys in `.env`. Never commit that file. It is already in `.gitignore`.
You can skip the keys and use the pre-generated code instead (see Fallback below).

## Run the GUI

```
streamlit run app/streamlit_app.py
```

The page has three steps: get the code, test and scan, compare. Step 1 shows the prompt.
After generating, each candidate has an expander with the raw API reply next to the code
that was saved. For the code that sends the prompt, see:
`generate_one()` in `src/aicodesec/generate.py` and the `complete()` method of each class in
`src/aicodesec/providers.py`.

## Run without the GUI

```
export PYTHONPATH=src
python -m aicodesec.generate openai claude          # pick providers, or give none for all four
python -m aicodesec.evaluate runs/<timestamp> runs/<timestamp>
```

Run the shared tests on any single file:

```
pytest --candidate data/pregenerated/candidates/deepseek.py
```

## Fallback (no keys, no internet)

Turn on "Use pre-generated code" in the GUI. It loads four pre-generated candidates from
`data/pregenerated/candidates/`. Their model versions were never recorded, so the tables show
"Not recorded".

Only the code is stored. A fallback run is tested and scanned by the tool like any other run,
and it starts with no manual reviews, the same as a live run. Its results come from running
the tool, not from files in this repository.

Semgrep normally runs with `--config=auto`, which downloads rules and sends usage metrics to
Semgrep. If that fails or does not answer within 60 seconds (for example with the network
blocked), the tool falls back to the small ruleset in `rules/semgrep_local.yml`. The ruleset
used is saved in the results (`semgrep_ruleset`). The local ruleset has only two rules, so
offline runs can find fewer issues. If a scanner cannot run at all, its count shows as "n/a"
and is never reported as 0, because 0 would wrongly mean "scanned and clean".

## Settings

`config.yaml` holds the model IDs, temperature, token limit, timeout and number of
generations per model. Check the model IDs against each provider's model list before a real
run. For every run, `metadata.json` records the model name the API returned, the temperature,
token usage and a hash of the prompt.

Temperature is not the same for every provider. Claude and OpenAI are set to `null`, which
means no temperature is sent, because the installed Claude SDK has no temperature option and
some OpenAI models only allow their default. DeepSeek and Gemini use 0.0. Mention this as a limitation.

## The tests

| Folder | What it checks |
|---|---|
| `tests/test_login.py`, `tests/test_security_edges.py` | 5 basic login tests: valid login, wrong password, unknown user, one SQL injection attempt, and a JSON array body. |
| `tests/test_malformed.py` | 15 malformed inputs. Each must give 401, never an exception or 5xx. |
| `tests/test_sql_injection.py` | 5 SQL injection payloads in each field. No login, table still works. |
| `tests_task2/` | Task 2 only: token required, tampered and expired tokens rejected, user A cannot read user B. |
| `unit_tests/` | Tests for this tool itself (extraction, generation with a fake provider, evaluation, report). |

Run the tool's own tests with `pytest unit_tests`. They take a few minutes because Semgrep
downloads rules for each file.

## Tasks

- **Task 1** (`prompts/login_v1.txt`): the login prompt, saved word for word.
- **Task 2** (`prompts/login_v2.txt`): the same login plus one protected route. It covers the
  authorization-bypass claim in our proposal. There are no pre-generated Task 2 candidates, so
  it needs API keys. Its tests were checked against a correct hand-written app and three
  broken ones (`unit_tests/task2_reference.py`), and it has also been run on live model output.

## Results

This repository stores no results. Run the tool to produce them. Every run writes
`results.csv`, `model_comparison.png` and `evaluation.json` into its own `runs/<timestamp>/`
folder, and the GUI shows the same table. When you quote a number, say which run produced it.

## Limits to state in the paper

- One generation per model by default. The GUI can run several.
- Scanner counts are not confirmed vulnerabilities. Confirmed findings come from manual review.
- The pre-generated candidates have no recorded model versions.
- Temperature is not the same for all providers (see Settings).
- Scanner versions can change over time. Each run records the versions it used.

## Layout

```
config.yaml  prompts/  rules/  conftest.py  pytest.ini  requirements.txt  .env.example
src/aicodesec/   generate, providers, extract, evaluate, report
app/streamlit_app.py
tests/  tests_task2/  unit_tests/
data/pregenerated/   four pre-generated candidates (code only)
runs/<timestamp>/    output of each run (ignored by git)
docs/                paper and report sources (to be added)
```
