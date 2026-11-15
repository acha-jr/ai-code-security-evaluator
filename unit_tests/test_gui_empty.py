"""The GUI must show a friendly message, not a traceback, when every provider fails."""
import shutil

import pytest
from streamlit.testing.v1 import AppTest

from pathlib import Path

APP = Path(__file__).resolve().parents[1] / "app" / "streamlit_app.py"


def test_gui_explains_what_to_do_when_all_providers_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    """With no usable keys, Generate shows a clear error. Steps 2 and 3 show messages, not crashes."""
    # Empty keys stop real API calls. load_dotenv does not overwrite variables that already exist.
    for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "DEEPSEEK_API_KEY", "GEMINI_API_KEY"):
        monkeypatch.setenv(name, "")
    at = AppTest.from_file(str(APP), default_timeout=60).run()
    next(button for button in at.button if button.label == "Generate code").click().run()
    run_dir = at.session_state["run_dir"]
    try:
        assert not at.exception
        assert any("No provider returned any code" in error.value for error in at.error)
        assert any("no code to test" in warning.value for warning in at.warning)
    finally:
        shutil.rmtree(run_dir)  # The test made a real run folder. Remove it.
