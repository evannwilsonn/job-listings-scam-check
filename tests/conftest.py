"""Every test gets its own file-backed store in a temp folder, never the real data folder or a database."""

import pytest

from scam_detector import store as store_mod


@pytest.fixture(autouse=True)
def _isolated_store(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("REPORT_QUEUE_PATH", raising=False)
    s = store_mod.JsonlStore(data_dir=tmp_path / "store")
    store_mod.reset_store(s)
    yield s
    store_mod.reset_store(None)
