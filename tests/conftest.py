"""Shared test fixtures."""

import pytest
from fastapi.testclient import TestClient

from vlamguard.main import app


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)
