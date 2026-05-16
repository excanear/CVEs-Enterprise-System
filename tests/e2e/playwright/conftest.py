"""Playwright conftest — configures browser and base URL for E2E tests."""
from __future__ import annotations

import os
import pytest


@pytest.fixture(scope="session")
def base_url() -> str:
    return os.getenv("DASHBOARD_URL", "http://localhost:3000")


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args):
    return {
        **browser_context_args,
        "viewport": {"width": 1440, "height": 900},
        "locale": "en-US",
        "ignore_https_errors": True,
    }
