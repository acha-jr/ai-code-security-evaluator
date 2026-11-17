"""Tests for extraction and generation, using a fake provider so no network is needed."""
import json
from pathlib import Path

import pytest

from aicodesec import generate
from aicodesec.extract import extract_code
from aicodesec.generate import run_generation
from aicodesec.providers import Provider, Reply

CODE = "def create_app(database_path):\n    return None\n"
REPLY = f"Here is the app:\n\n```python\n{CODE}```\n\nRun it with flask.\n"


class FakeProvider(Provider):
    """Returns a canned reply, or raises, instead of calling an API."""

    def __init__(self, name: str, fail: bool = False) -> None:
        """Build a provider with fixed settings."""
        settings = {"label": name.title(), "model": "fake-1", "api_key_env": "NONE"}
        super().__init__(name, settings, {"temperature": 0.0, "max_output_tokens": 10, "timeout_seconds": 1})
        self.fail = fail

    def complete(self, prompt: str) -> Reply:
        """Return the canned reply."""
        if self.fail:
            raise RuntimeError("no network")
        return Reply(REPLY, "fake-1-2026", 12, 34)


def test_extract_keeps_code_unchanged_and_notes_dropped_prose() -> None:
    """The code comes out exactly as written, and the dropped chat text is noted."""
    result = extract_code(REPLY)
    assert result.code == CODE
    assert result.prose_dropped
    assert "dropped" in result.note


def test_extract_code_only_reply_drops_nothing() -> None:
    """A reply that is only code reports that nothing was dropped."""
    result = extract_code(f"```python\n{CODE}```")
    assert result.code == CODE
    assert not result.prose_dropped


def test_extract_prefers_block_with_create_app() -> None:
    """With several code blocks, the one that defines create_app is chosen."""
    reply = f"```bash\npip install flask\n```\n```python\n{CODE}```\n"
    assert extract_code(reply).code == CODE


def test_extract_without_fence_saves_whole_reply() -> None:
    """With no code fence, the whole reply is kept and the note says so."""
    result = extract_code("x = 1\n")
    assert result.code == "x = 1\n"
    assert "No code fence" in result.note


def test_run_generation_saves_files_and_metadata(tmp_path: Path) -> None:
    """A good provider leaves files and metadata. A failing one is recorded as an error."""
    run_dir = run_generation(
        "Say hello\n", [FakeProvider("openai"), FakeProvider("claude", fail=True)], tmp_path / "runs",
        log=lambda _: None, prompt_name="login_v1.txt",
    )
    assert (run_dir / "prompt.txt").read_text() == "Say hello"

    assert (run_dir / "openai.py").read_text() == CODE
    assert (run_dir / "raw" / "openai.txt").read_text() == REPLY
    meta = json.loads((run_dir / "metadata.json").read_text())
    ok, failed = meta["candidates"]
    assert ok["model_returned"] == "fake-1-2026" and ok["output_tokens"] == 34
    assert ok["temperature"] == 0.0 and ok["prose_dropped"] is True
    assert "error" in failed and not (run_dir / "claude.py").exists()
    assert len(meta["prompt_sha256"]) == 64 and meta["prompt_file"] == "login_v1.txt"


def test_repeats_get_numbered_names(tmp_path: Path) -> None:
    """Two generations from one provider are saved as openai_1.py and openai_2.py."""
    run_dir = run_generation("Say hello", [FakeProvider("openai")], tmp_path / "runs", repeats=2, log=lambda _: None)
    assert (run_dir / "openai_1.py").exists() and (run_dir / "openai_2.py").exists()


class FlakyProvider(FakeProvider):
    """Fails with the given HTTP code a set number of times, then returns the canned reply."""

    def __init__(self, failures: int, code: int) -> None:
        """Remember how many times to fail, and which HTTP code the failure carries."""
        super().__init__("gemini")
        self.failures_left = failures
        self.code = code

    def complete(self, prompt: str) -> Reply:
        """Raise an error that carries an HTTP code until the failures run out."""
        if self.failures_left > 0:
            self.failures_left -= 1
            error = RuntimeError("provider error")
            error.code = self.code  # Google-style errors carry the HTTP code as .code.
            raise error
        return super().complete(prompt)


def run_flaky(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, provider: FlakyProvider) -> dict:
    """Run one generation with no real waiting and return its metadata entry."""
    monkeypatch.setattr(generate, "RETRY_WAITS", (0, 0))
    run_dir = run_generation("Say hello", [provider], tmp_path / "runs", log=lambda _: None)
    return json.loads((run_dir / "metadata.json").read_text())["candidates"][0]


def test_temporary_503_is_retried_and_then_succeeds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Two 503 errors followed by a good reply give a normal result, and the attempts are recorded."""
    entry = run_flaky(tmp_path, monkeypatch, FlakyProvider(failures=2, code=503))
    assert "error" not in entry and entry["attempts"] == 3


def test_temporary_error_is_recorded_after_the_last_attempt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """If every attempt gets a 503, the failure is recorded after three tries."""
    entry = run_flaky(tmp_path, monkeypatch, FlakyProvider(failures=10, code=503))
    assert "error" in entry and entry["attempts"] == 3


@pytest.mark.parametrize("code", [401, 402, 404, 429])
def test_other_errors_are_not_retried(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: int) -> None:
    """Bad key, no credits, unknown model and rate or quota errors fail at once, with one attempt."""
    entry = run_flaky(tmp_path, monkeypatch, FlakyProvider(failures=10, code=code))
    assert "error" in entry and entry["attempts"] == 1
