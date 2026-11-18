"""Shared test fixtures and sample data."""

import os

# SERVER_VERSION is required at server.py import time. Set a sentinel
# value before any test imports the server module.
os.environ.setdefault("SERVER_VERSION", "test")

import pytest


@pytest.fixture(autouse=True)
def _runs_held_only(monkeypatch: pytest.MonkeyPatch):
    """A write carries only a run a test holds: no test meets the platform
    lookup of the caller's open run (``MipitiClient._run_for_write``) unless
    it asks for it (``real_run_lookup``), so a mocked API need not answer it."""
    from mipiti_mcp import client as client_mod

    async def held(self, model_id: str) -> str:
        return self.held_run(model_id)

    client_mod.forget_runs()
    monkeypatch.setattr(client_mod.MipitiClient, "_run_for_write", held)
    yield
    client_mod.forget_runs()


@pytest.fixture()
def real_run_lookup(monkeypatch: pytest.MonkeyPatch):
    """The real lookup of the caller's open run on a write."""
    from mipiti_mcp import client as client_mod

    monkeypatch.setattr(client_mod.MipitiClient, "_run_for_write", _REAL_RUN_FOR_WRITE)


def _real_run_for_write():
    from mipiti_mcp.client import MipitiClient
    return MipitiClient._run_for_write


_REAL_RUN_FOR_WRITE = _real_run_for_write()


@pytest.fixture()
def mock_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set required env vars for MipitiClient."""
    monkeypatch.setenv("MIPITI_API_KEY", "test-key-123")
    monkeypatch.setenv("MIPITI_API_URL", "https://test.api.mipiti.io")


SAMPLE_THREAT_MODEL = {
    "id": "tm-001",
    "feature_description": "User login with OAuth",
    "title": "User Login OAuth",
    "version": 1,
    "created_at": "2026-02-11T00:00:00",
    "trust_boundaries": [
        {"id": "TB1", "description": "Internet to DMZ", "crosses": ["A1", "T1"]},
    ],
    "assets": [
        {
            "id": "A1",
            "name": "OAuth Tokens",
            "description": "Bearer tokens for user sessions",
            "security_properties": ["C", "I"],
            "notes": "",
        },
        {
            "id": "A2",
            "name": "User Credentials DB",
            "description": "Stored hashed passwords",
            "security_properties": ["C", "I", "A"],
            "notes": "",
        },
    ],
    "attackers": [
        {
            "id": "T1",
            "capability": "Credential stuffing",
            "position": "External",
            "archetype": "Automated attacker",
        },
    ],
    "control_objectives": [
        {
            "id": "CO1",
            "asset_id": "A1",
            "security_properties": ["C"],
            "attacker_id": "T1",
            "statement": "Ensure the confidentiality of OAuth Tokens against Credential stuffing (External)",
        },
    ],
    "assumptions": [
        {"id": "AS1", "description": "OAuth provider is trusted", "status": "active"},
    ],
}

SAMPLE_MODELS_LIST = [
    {
        "id": "tm-001",
        "title": "User Login OAuth",
        "feature_description": "User login with OAuth",
        "created_at": "2026-02-11T00:00:00",
        "version": 1,
    },
    {
        "id": "tm-002",
        "title": "Payment Processing",
        "feature_description": "Stripe payment integration",
        "created_at": "2026-02-10T00:00:00",
        "version": 2,
    },
]

SAMPLE_CONTROLS = {
    "controls": [
        {
            "id": "CO1-1",
            "control_objective_ids": ["CO1"],
            "description": "Implement token rotation with short-lived access tokens",
            "status": "not_implemented",
            "implementation_notes": "",
        },
        {
            "id": "CO1-2",
            "control_objective_ids": ["CO1"],
            "description": "Rate-limit authentication attempts per IP",
            "status": "implemented",
            "implementation_notes": "Using express-rate-limit middleware",
        },
    ]
}
