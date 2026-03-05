"""Shared test fixtures and sample data."""

import pytest


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
