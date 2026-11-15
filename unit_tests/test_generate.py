"""Tests for extraction and generation, using a fake provider so no network is needed."""
import json
from pathlib import Path

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
