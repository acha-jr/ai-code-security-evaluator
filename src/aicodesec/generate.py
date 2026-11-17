"""Send the fixed prompt to each provider and save what comes back.

This is the step shown in the demo: the prompt goes out in provider.complete(),
the reply comes back as a Reply, and the code is saved without changes.

Each run creates a folder like runs/20261115-183133/ that holds:
  prompt.txt        the exact prompt that was sent
  raw/<name>.txt    the full reply from the model
  <name>.py         the code taken out of that reply, unchanged
  metadata.json     model names, settings, token counts and notes for every candidate
"""
import hashlib
import json
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

import yaml
from dotenv import load_dotenv

from aicodesec.extract import extract_code
from aicodesec.providers import Provider, build_providers

# The repository root folder, found from this file's own location so no path is hardcoded.
ROOT = Path(__file__).resolve().parents[2]

# When a provider says "temporarily unavailable" we wait and try again. These are the waits, in
# seconds, before the second and third attempt. After that the failure is recorded.
RETRY_WAITS = (5, 20)
# HTTP codes that usually go away on their own. 503 is "high demand", 500, 502 and 504 are server problems.
# 429 is left out on purpose: it can also mean "no credits left", which waiting does not fix.
TEMPORARY_CODES = (500, 502, 503, 504)


def is_temporary(error: Exception) -> bool:
    """True for errors that usually clear up by themselves, such as 503 "high demand"."""
    # OpenAI and Anthropic errors carry the HTTP code as status_code. Google's carry it as code.
    code = getattr(error, "status_code", None) or getattr(error, "code", None)
    return code in TEMPORARY_CODES


def load_config(path: Path = ROOT / "config.yaml") -> dict:
    """Read config.yaml and load any keys from a local .env file."""
    # load_dotenv copies the keys in .env into environment variables for this program.
    load_dotenv(ROOT / ".env")
    return yaml.safe_load(path.read_text())


def run_generation(
    prompt: str,
    providers: list[Provider],
    runs_dir: Path = ROOT / "runs",
    repeats: int = 1,
    log: Callable[[str], None] = print,
    prompt_name: str = "custom",
) -> Path:
    """Generate code from every provider, `repeats` times each, and return the run folder.

    prompt_name says where the text came from, for example "login_v1.txt" or "custom".
    log is any function that takes a message. It is print on the command line
    and st.write in the GUI, so both show the same progress lines.
    """
    prompt = prompt.strip()
    # A hash is a short fingerprint of the text. Two runs with the same hash used the same prompt.
    prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()
    started = datetime.now(timezone.utc)
    run_dir = runs_dir / started.strftime("%Y%m%d-%H%M%S")
    (run_dir / "raw").mkdir(parents=True)
    # Keep the exact text that was sent, so any run can be repeated later.
    (run_dir / "prompt.txt").write_text(prompt)

    # One loop covers every provider, so there is no separate copy of the code per provider.
    candidates = []
    for provider in providers:
        for number in range(1, repeats + 1):
            # One generation keeps the plain name. Repeats get a number.
            name = provider.name if repeats == 1 else f"{provider.name}_{number}"
            candidates.append(generate_one(provider, name, prompt, run_dir, log))

    metadata = {
        "prompt_file": prompt_name,
        "prompt_sha256": prompt_hash,
        "timestamp_utc": started.isoformat(timespec="seconds"),
        "candidates": candidates,
    }
    (run_dir / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    return run_dir


def generate_one(provider: Provider, name: str, prompt: str, run_dir: Path, log: Callable[[str], None]) -> dict:
    """Run one generation. A failure is recorded and does not stop the other providers."""
    # Start the metadata entry with what we asked for. The answer is added below.
    entry = {
        "name": name,
        "provider": provider.label,
        "model_requested": provider.model,
        "temperature": provider.temperature,
        "max_output_tokens": provider.max_output_tokens,
    }
    log(f"Sending prompt to {provider.label} ({provider.model})...")
    waits = iter(RETRY_WAITS)
    entry["attempts"] = 0
    while True:
        entry["attempts"] += 1
        try:
            # The prompt goes out to the provider here, and the reply comes back.
            reply = provider.complete(prompt)
            break
        except Exception as error:  # Any API or network failure is saved as the result for this provider.
            wait = next(waits, None)  # None means there are no attempts left.
            if wait is None or not is_temporary(error):
                log(f"  {provider.label} failed: {error}")
                entry["error"] = f"{type(error).__name__}: {error}"
                return entry
            log(f"  {provider.label} is busy right now. Trying again in {wait} seconds...")
            time.sleep(wait)

    # Save the raw reply first, then the code taken out of it. Nothing is edited.
    (run_dir / "raw" / f"{name}.txt").write_text(reply.text)
    extraction = extract_code(reply.text)
    (run_dir / f"{name}.py").write_text(extraction.code)
    log(f"  Got {len(reply.text)} characters back. Saved {name}.py. {extraction.note}")

    # Add what actually came back, which can differ from what we asked for.
    entry.update(
        model_returned=reply.model_returned,
        input_tokens=reply.input_tokens,
        output_tokens=reply.output_tokens,
        candidate_file=f"{name}.py",
        raw_file=f"raw/{name}.txt",
        extraction_note=extraction.note,
        prose_dropped=extraction.prose_dropped,
    )
    return entry


if __name__ == "__main__":
    # Command line use: python -m aicodesec.generate [provider ...]
    # With no provider names it runs all four.
    import sys

    config = load_config()
    chosen = build_providers(config, sys.argv[1:] or None)
    prompt_file = ROOT / "prompts" / "login_v1.txt"
    print(run_generation(prompt_file.read_text(), chosen, repeats=config["runs_per_model"], prompt_name=prompt_file.name))
