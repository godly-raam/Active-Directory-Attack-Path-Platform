import pathlib
import re

import ap_engine
from ap_engine.config import Config


def test_env_file_is_loaded(monkeypatch, tmp_path):
    monkeypatch.delenv("USER_LLM_API_KEY", raising=False)
    env = tmp_path / ".env"
    env.write_text("USER_LLM_API_KEY=from-file\nUSER_LLM_MODEL=custom-model\n")
    config = Config.from_env(env)
    assert config.api_key == "from-file"
    assert config.model == "custom-model"
    assert config.llm_enabled is True
    monkeypatch.delenv("USER_LLM_API_KEY", raising=False)
    monkeypatch.delenv("USER_LLM_MODEL", raising=False)


def test_real_environment_wins_over_env_file(monkeypatch, tmp_path):
    env = tmp_path / ".env"
    env.write_text("USER_LLM_API_KEY=from-file\n")
    monkeypatch.setenv("USER_LLM_API_KEY", "from-shell")
    config = Config.from_env(env)
    assert config.api_key == "from-shell"


def test_offline_toggle(monkeypatch, tmp_path):
    monkeypatch.setenv("AP_ENGINE_OFFLINE", "true")
    config = Config.from_env(tmp_path / "missing.env")
    assert config.offline is True
    assert config.llm_enabled is False
    monkeypatch.delenv("AP_ENGINE_OFFLINE", raising=False)


def test_platform_keys_are_ignored(monkeypatch, tmp_path):
    monkeypatch.delenv("USER_LLM_API_KEY", raising=False)
    monkeypatch.setenv("MCAI_LLM_API_KEY", "must-not-be-used")
    config = Config.from_env(tmp_path / "missing.env")
    assert config.api_key is None
    assert config.llm_enabled is False


def test_source_never_reads_platform_vars():
    package_dir = pathlib.Path(ap_engine.__file__).resolve().parent
    pattern = re.compile(r"""(getenv|environ)\s*[\[\(]\s*["']MCAI_""")
    for source in package_dir.rglob("*.py"):
        text = source.read_text(encoding="utf-8")
        matches = [line for line in text.splitlines() if pattern.search(line)]
        assert not matches, f"platform credential read in {source}: {matches}"
