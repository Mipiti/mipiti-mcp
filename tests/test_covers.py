"""``covers``: the type-independent binding of evidence to what it proves.

One definition of the accepted form, applied before a submission leaves the
client and by the platform on arrival, so both refuse the same value with
the same message.
"""

import json
import re
from unittest.mock import AsyncMock, patch

import pytest
from fastmcp.exceptions import ToolError

from mipiti_mcp import server
from mipiti_mcp.assertion_types import (
    COVERS_MAX,
    COVERS_PATTERN,
    covers_key,
    validate_covers,
)

GOOD = ["CO-1", "CO12", "CO-0012", "CO-9999", "cls_0123456789ab", "cls_ffffffffffff"]
BAD = [
    "CO", "CO-", "CO-12345", "co-1", "C0-1", "CO_1",
    "cls_", "cls_0123456789", "cls_0123456789abc", "cls_0123456789AB", "cls-0123456789ab",
    "CTRL-01", " CO-1", "CO-1 ", "", "A1",
]


@pytest.mark.parametrize("value", GOOD)
def test_accepted_forms(value):
    assert re.match(COVERS_PATTERN, value)
    assert validate_covers([value]) == []


@pytest.mark.parametrize("value", BAD)
def test_refused_forms(value):
    assert not re.match(COVERS_PATTERN, value)
    errors = validate_covers([value])
    assert len(errors) == 1 and "covers[0]" in errors[0] and "CO-NN" in errors[0]


def test_absent_declaration_passes():
    assert validate_covers(None) == []
    assert validate_covers([]) == []


def test_a_non_array_is_refused():
    errors = validate_covers("CO-1")
    assert len(errors) == 1 and "JSON array" in errors[0]


def test_the_count_is_bounded():
    assert COVERS_MAX == 16
    assert validate_covers([f"CO-{i}" for i in range(1, 17)]) == []
    errors = validate_covers([f"CO-{i}" for i in range(1, 18)])
    assert len(errors) == 1 and "17" in errors[0] and "16" in errors[0]


def test_the_two_objective_spellings_name_one_objective():
    assert covers_key("CO12") == covers_key("CO-12") == covers_key("CO-012") == "CO-12"
    assert covers_key("cls_0123456789ab") == "cls_0123456789ab"
    errors = validate_covers(["CO12", "CO-12"])
    assert len(errors) == 1 and "repeats" in errors[0] and "same objective" in errors[0]


def test_exact_repeats_are_refused():
    errors = validate_covers(["cls_0123456789ab", "cls_0123456789ab"])
    assert len(errors) == 1 and "repeats" in errors[0]


def test_non_string_entries_are_refused_individually():
    errors = validate_covers([5, None, "CO-1"])
    assert len(errors) == 2


# ---------------------------------------------------------------------------
# The server applies the rule before sending.
# ---------------------------------------------------------------------------

def _client(**overrides):
    client = AsyncMock()
    for name, value in overrides.items():
        setattr(client, name, AsyncMock(return_value=value))
    return client


async def test_submit_assertions_refuses_malformed_covers_before_sending(monkeypatch):
    called = []
    monkeypatch.setattr(server, "_get_client", lambda: called.append(1))
    body = json.dumps([{"type": "file_exists", "params": {"file": "a.py"}, "repo": "o/r",
                        "covers": ["CTRL-01"]}])
    with pytest.raises(ToolError, match="covers\\[0\\]"):
        await server.submit_assertions(server_version="x", model_id="m", assertions_json=body, control_id="c")
    with pytest.raises(ToolError, match="covers\\[0\\]"):
        await server.submit_functional_test_assertions(
            server_version="x", model_id="m", functional_test_id="f", assertions_json=body,
        )
    assert called == []


async def test_covers_is_a_top_level_field_forwarded_verbatim():
    client = _client(submit_assertions={"assertions": []})
    payload = [{"type": "file_exists", "params": {"file": "a.py"}, "repo": "o/r",
                "covers": ["CO-3", "cls_0123456789ab"]}]
    with patch("mipiti_mcp.server._get_client", return_value=client):
        await server.submit_assertions(
            server_version="x", model_id="m", assertions_json=json.dumps(payload), control_id="c",
        )
    sent = client.submit_assertions.await_args.args[1]
    assert sent == payload
    assert "covers" not in sent[0]["params"]


async def test_functional_test_assertions_forward_covers():
    client = _client(submit_functional_tests={"functional_test_id": "FT-1", "assertions": []})
    payload = [{"type": "test_attested", "params": {"test": "t"}, "repo": "o/r", "covers": ["CO1"]}]
    with patch("mipiti_mcp.server._get_client", return_value=client):
        await server.submit_functional_test_assertions(
            server_version="x", model_id="m", functional_test_id="FT-1",
            assertions_json=json.dumps(payload),
        )
    client.submit_functional_tests.assert_awaited_once_with("m", "FT-1", payload)


async def test_submit_attestation_forwards_covers_as_a_list():
    client = _client(submit_attestation={"id": "att-1"})
    with patch("mipiti_mcp.server._get_client", return_value=client):
        await server.submit_attestation(
            server_version="x", model_id="m", assumption_id="AS1",
            attested_by="a", statement="s", expires_at="2027-01-01T00:00:00Z",
            covers="CO-2, cls_0123456789ab",
        )
    assert client.submit_attestation.await_args.kwargs["covers"] == ["CO-2", "cls_0123456789ab"]


async def test_submit_attestation_without_covers_sends_none():
    client = _client(submit_attestation={"id": "att-1"})
    with patch("mipiti_mcp.server._get_client", return_value=client):
        await server.submit_attestation(
            server_version="x", model_id="m", assumption_id="AS1", attested_by="a",
        )
    assert client.submit_attestation.await_args.kwargs["covers"] is None


async def test_submit_attestation_refuses_malformed_covers_before_sending(monkeypatch):
    called = []
    monkeypatch.setattr(server, "_get_client", lambda: called.append(1))
    with pytest.raises(ToolError, match="covers\\[1\\]"):
        await server.submit_attestation(
            server_version="x", model_id="m", assumption_id="AS1", covers="CO-1,CTRL-1",
        )
    assert called == []


async def test_bind_assertion_forwards_the_declaration():
    client = _client(bind_assertion={"assertion": {"id": "a1", "covers": ["CO-3"]}})
    with patch("mipiti_mcp.server._get_client", return_value=client):
        out = await server.bind_assertion(
            server_version="x", model_id="m", control_id="CTRL-01", assertion_id="a1",
            covers="CO-3",
        )
    client.bind_assertion.assert_awaited_once_with("m", "CTRL-01", "a1", ["CO-3"])
    assert out["assertion"]["covers"] == ["CO-3"]


async def test_bind_assertion_requires_a_declaration(monkeypatch):
    called = []
    monkeypatch.setattr(server, "_get_client", lambda: called.append(1))
    with pytest.raises(ToolError, match="covers is required"):
        await server.bind_assertion(
            server_version="x", model_id="m", control_id="c", assertion_id="a", covers="",
        )
    with pytest.raises(ToolError, match="repeats"):
        await server.bind_assertion(
            server_version="x", model_id="m", control_id="c", assertion_id="a", covers="CO12,CO-12",
        )
    assert called == []


def test_bind_assertion_documents_the_expansion_rule():
    fn = server.bind_assertion
    doc = (getattr(fn, "__doc__", "") or "") + (getattr(getattr(fn, "fn", None), "__doc__", "") or "")
    assert "multi-clause" in doc and "clause refs" in doc


async def test_a_binding_hidden_inside_params_is_refused(monkeypatch):
    """``covers`` is the assertion's own field. Inside ``params`` it would
    ride the dedup key, so the same declaration would name a different row on
    every edit; the submission is refused with the fix named."""
    called = []
    monkeypatch.setattr(server, "_get_client", lambda: called.append(1))
    body = json.dumps([{"type": "file_exists",
                        "params": {"file": "a.py", "covers": ["CO-1"]},
                        "repo": "o/r"}])
    with pytest.raises(ToolError, match="never a param"):
        await server.submit_assertions(
            server_version="x", model_id="m", assertions_json=body, control_id="c",
        )
    with pytest.raises(ToolError, match="never a param"):
        await server.submit_functional_test_assertions(
            server_version="x", model_id="m", functional_test_id="f", assertions_json=body,
        )
    assert called == []


def test_the_submit_description_says_where_a_binding_goes_and_which_type_when():
    """The description is what a client shows an agent, so it has to say both
    that a binding is the assertion's own field and which of the two sound
    types the for-all case takes -- the rest is a get_assertion_types call."""
    doc = server._SUBMIT_ASSERTIONS_DOC
    assert "never in params" in doc
    assert "for-all" in doc
    tail = doc[doc.index("A for-all clause"):]
    assert tail.index("typed_boundary") < tail.index("sink_default_deny")
    assert "sinks accept one boundary type" in tail
