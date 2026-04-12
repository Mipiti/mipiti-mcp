"""Tests for the _api_error helper that converts httpx errors to ToolError.

Special focus on the DUPLICATE_NATURAL_KEY 409 case (Tier 3 uniqueness
constraint surfacing through to MCP tools).
"""

import httpx
import pytest

from fastmcp.exceptions import ToolError

from mipiti_mcp.server import _api_error


def _make_status_error(status: int, body: dict | str) -> httpx.HTTPStatusError:
    """Construct an httpx.HTTPStatusError with a synthesized response."""
    request = httpx.Request("POST", "https://example.com/api/things")
    if isinstance(body, dict):
        import json as _json
        content = _json.dumps(body).encode("utf-8")
        headers = {"content-type": "application/json"}
    else:
        content = body.encode("utf-8")
        headers = {"content-type": "text/plain"}
    response = httpx.Response(status_code=status, content=content, headers=headers, request=request)
    return httpx.HTTPStatusError(f"HTTP {status}", request=request, response=response)


class TestApiErrorBasic:
    def test_non_http_error_passes_message(self):
        result = _api_error(RuntimeError("connection refused"))
        assert isinstance(result, ToolError)
        assert "connection refused" in str(result)

    def test_400_returns_generic_api_error(self):
        exc = _make_status_error(400, {"detail": "bad input"})
        result = _api_error(exc)
        assert isinstance(result, ToolError)
        msg = str(result)
        assert "400" in msg
        assert "bad input" in msg


class TestDuplicateNaturalKey:
    def test_409_with_duplicate_natural_key_returns_clean_message(self):
        exc = _make_status_error(409, {
            "detail": {
                "error": "DUPLICATE_NATURAL_KEY",
                "entity_type": "asset",
                "message": "An asset with this name already exists.",
                "existing_id": "A1",
                "existing_entity": {"id": "A1", "name": "User Token"},
            },
        })
        result = _api_error(exc)
        assert isinstance(result, ToolError)
        msg = str(result)
        assert "asset" in msg.lower()
        assert "name" in msg.lower()
        assert "A1" in msg
        # The friendly tail telling the agent what to do next
        assert "rename" in msg.lower() or "differentiate" in msg.lower()

    def test_409_attacker_includes_compound_key_label(self):
        exc = _make_status_error(409, {
            "detail": {
                "error": "DUPLICATE_NATURAL_KEY",
                "entity_type": "attacker",
                "message": "An attacker with this (capability, position) already exists.",
                "existing_id": "T-03",
                "existing_entity": {"id": "T-03", "capability": "x", "position": "Remote"},
            },
        })
        result = _api_error(exc)
        msg = str(result)
        assert "attacker" in msg.lower()
        assert "T-03" in msg

    def test_409_without_duplicate_natural_key_falls_through(self):
        exc = _make_status_error(409, {"detail": "some other 409"})
        result = _api_error(exc)
        msg = str(result)
        # Generic API error path
        assert "409" in msg
        assert "some other 409" in msg

    def test_409_with_no_existing_id_still_works(self):
        exc = _make_status_error(409, {
            "detail": {
                "error": "DUPLICATE_NATURAL_KEY",
                "entity_type": "trust_boundary",
                "message": "Already exists.",
            },
        })
        result = _api_error(exc)
        msg = str(result)
        assert "trust_boundary" in msg or "Already exists" in msg
        assert "(unknown id)" in msg or "id=" in msg
