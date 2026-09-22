"""The client returns a resume refusal as data, so an agent can relay it."""

import httpx
import pytest
import respx

from mipiti_mcp.client import MipitiClient

URL = "https://test.api.mipiti.io/api/models/tm-1/controls/resume"


@pytest.mark.asyncio
@respx.mock
async def test_resumed(mock_env: None) -> None:
    respx.post(URL).mock(return_value=httpx.Response(
        200, json={"resumed": True, "status": "queued"}))
    assert await MipitiClient().resume_control_generation("tm-1") == {
        "resumed": True, "status": "queued"}


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("status,code", [(503, "dependency_unavailable"),
                                         (409, "retry_too_soon"),
                                         (409, "not_blocked")])
async def test_refusals_come_back_as_data(mock_env: None, status: int, code: str) -> None:
    respx.post(URL).mock(return_value=httpx.Response(
        status, json={"detail": {"code": code, "message": "m",
                                 "retry_after_seconds": 60}}))
    out = await MipitiClient().resume_control_generation("tm-1")
    assert out["resumed"] is False and out["http_status"] == status
    assert out["code"] == code and out["retry_after_seconds"] == 60


@pytest.mark.asyncio
@respx.mock
async def test_other_failures_raise(mock_env: None) -> None:
    respx.post(URL).mock(return_value=httpx.Response(500, json={"detail": "x"}))
    with pytest.raises(httpx.HTTPStatusError):
        await MipitiClient().resume_control_generation("tm-1")
