"""Shared test setup (pytest fixtures). The candidate file under test comes from --candidate.

pytest reads this file automatically. A "fixture" is a helper that builds what a test
needs, such as a Flask test client, so each test starts from a clean state.
"""
import importlib.util
import sqlite3
from pathlib import Path
from types import ModuleType

import pytest
from werkzeug.security import generate_password_hash


def pytest_addoption(parser: pytest.Parser) -> None:
    """Add the --candidate option so one suite can test any generated file."""
    parser.addoption(
        "--candidate",
        default=None,
        help="Path to the candidate .py file that defines create_app(database_path).",
    )


def load_candidate(path: Path) -> ModuleType:
    """Load a candidate file by path, without running its __main__ block."""
    # We load the file from its path instead of using "import", because the file name changes
    # for every candidate. The module name is not "__main__", so the candidate's startup code
    # (such as app.run) stays off and nothing starts listening on a port.
    spec = importlib.util.spec_from_file_location("candidate", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def candidate_create_app(request: pytest.FixtureRequest):
    """Return create_app from the file given with --candidate."""
    option = request.config.getoption("--candidate")
    if option is None:
        raise pytest.UsageError("Pass --candidate path/to/file.py to run the candidate tests.")
    return load_candidate(Path(option).resolve()).create_app


def create_database(path: Path, users: dict[str, str]) -> None:
    """Create the users table and add the given username: password pairs."""
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE users ("
            "id INTEGER PRIMARY KEY, "
            "username TEXT UNIQUE, "
            "password_hash TEXT NOT NULL)"
        )
        for username, password in users.items():
            # Only the hash is stored, never the plain password. The ? marks are placeholders
            # filled in safely by SQLite, which is also how a correct login query should work.
            connection.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, generate_password_hash(password)),
            )


@pytest.fixture
def client(request: pytest.FixtureRequest, tmp_path: Path):
    """Give each test a Flask test client backed by a fresh temp database (user alice)."""
    create_app = candidate_create_app(request)
    # tmp_path is a new empty folder for each test, so tests cannot affect each other.
    database_path = tmp_path / "users.sqlite"
    create_database(database_path, {"alice": "correct-horse"})

    app = create_app(str(database_path))
    # TESTING makes Flask raise real exceptions, so a crash shows up as a failed test.
    app.config["TESTING"] = True

    with app.test_client() as test_client:
        yield test_client


@pytest.fixture
def make_client(request: pytest.FixtureRequest, tmp_path: Path):
    """Task 2: return a function that builds a client with users alice and bob.

    The optional token_lifetime_seconds lets a test ask for tokens that expire at once.
    """
    create_app = candidate_create_app(request)
    database_path = tmp_path / "users.sqlite"
    create_database(database_path, {"alice": "correct-horse", "bob": "battery-staple"})

    def build(**options):
        """Create the app, passing along any options such as token_lifetime_seconds."""
        app = create_app(str(database_path), **options)
        app.config["TESTING"] = True
        return app.test_client()

    return build
