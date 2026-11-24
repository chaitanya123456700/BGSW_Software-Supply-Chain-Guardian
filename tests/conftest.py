import os

import httpx
import pytest


@pytest.fixture(autouse=True)
def offline_optional_metadata(monkeypatch):
    """Optional intelligence stays deterministic; explicit test transports take precedence."""
    if os.getenv("GUARDIAN_METADATA_INTEGRATION") != "1":
        monkeypatch.setattr("guardian.metadata.DEFAULT_TRANSPORT", httpx.MockTransport(
            lambda request: httpx.Response(404, json={"error": "Optional metadata unavailable in offline tests"})))
    monkeypatch.setenv("AI_ENABLED", "false")
