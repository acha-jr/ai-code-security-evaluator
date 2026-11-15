# Evaluating Security Vulnerabilities in AI-Generated Code for Common Web-Application Tasks

Course project for COMP 5112 (Dr. Fiaidhi). Authors: Obinna Achazie, Ahmed Omar Ali.

This tool repeats our study without the Colab notebook. It sends one fixed prompt to four
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

The page has three steps: get the code, test and scan, compare. Step 1 shows the prompt and
the source of the function that sends it. After generating, each candidate has an expander
with the raw API reply next to the code that was saved.

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

Turn on "Use the pre-generated code" in the GUI. It loads the four candidates from the
original study in `data/pregenerated/`. These files are untouched. Their model versions were
never recorded, so the tables show "Not recorded".

Semgrep normally runs with `--config=auto`, which downloads rules and sends usage metrics to
Semgrep. If it cannot reach the network, it falls back to the small ruleset in
`rules/semgrep_local.yml`. The ruleset used is saved in the results (`semgrep_ruleset`).
The local ruleset has only two rules, so offline runs can find fewer issues.

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
| `tests/test_login.py`, `tests/test_security_edges.py` | The original five tests, unchanged. |
| `tests/test_malformed.py` | 15 malformed inputs. Each must give 401, never an exception or 5xx. |
| `tests/test_sql_injection.py` | 5 SQL injection payloads in each field. No login, table still works. |
| `tests_task2/` | Task 2 only: token required, tampered and expired tokens rejected, user A cannot read user B. |
| `unit_tests/` | Tests for this tool itself (extraction, generation with a fake provider, evaluation, report). |

Run the tool's own tests with `pytest unit_tests`. They take a few minutes because Semgrep
downloads rules for each file.

## Tasks

- **Task 1** (`prompts/login_v1.txt`): the original login prompt, word for word.
- **Task 2** (`prompts/login_v2.txt`): the same login plus one protected route. It covers the
  authorization-bypass claim in our proposal. There are no pre-generated Task 2 candidates, so
  it needs API keys. Its tests were checked against a correct hand-written app and three
  broken ones (`unit_tests/task2_reference.py`), not against real model output yet.

## Results on the original four candidates

| Provider | Original 5 tests | All 30 tests | Bandit | Semgrep | Confirmed |
|---|---|---|---|---|---|
| OpenAI | 5/5 | 30/30 | 0 | 0 | 0 |
| Claude | 5/5 | 30/30 | 0 | 0 | 0 |
| DeepSeek | 4/5 | 25/30 | 1 | 1 | 2 (CWE-1287, CWE-489) |
| Gemini | 5/5 | 23/30 | 1 | 1 | 2 (CWE-1287, CWE-489) |

The original suite gives 19/20. The expanded suite gives 108/120. Always say which suite a
number comes from.

DeepSeek crashes on a JSON array, number, string or boolean as the whole body. Gemini crashes
on a number or boolean body, on a number, null or boolean password, and on a list or object
username. OpenAI and Claude return 401 on all of them. Both scanners flag `debug=True` in the
DeepSeek and Gemini files.

## Limits to state in the paper

- One generation per model by default. The GUI can run several, but the old results are single runs.
- Scanner counts are not confirmed vulnerabilities. Confirmed findings come from manual review.
- The four old candidates have no recorded model versions.
- Temperature is not the same for all providers (see Settings).
- Bandit and Semgrep versions are newer than in the original run. The counts did not change.

## Layout

```
config.yaml  prompts/  rules/  conftest.py  pytest.ini  requirements.txt  .env.example
src/aicodesec/   generate, providers, extract, evaluate, report
app/streamlit_app.py
tests/  tests_task2/  unit_tests/
data/pregenerated/   the four original candidates, scanner reports, results CSV, chart
runs/<timestamp>/    output of each run (ignored by git, except runs/sample)
docs/                paper and report sources (to be added)
```
