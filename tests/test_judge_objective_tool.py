"""The per-objective judgement: one objective, one judgement, and a refusal
that can be relayed.

Two properties carry this tool, and each has a way of going wrong that a
"does it call the route" test would not see.

The first is SCOPE. An agent that reaches for ``recompute_verdicts`` to move
one objective pays for every control and every live objective on the model.
The whole reason this tool exists is that the cheap act was unreachable, so
the published text has to steer at it by name from the reason that calls for
it (``awaiting_judgement``) — an unreachable remedy and an unmentioned one
cost the same.

The second is that a judgement IS NOT A REPAIR. It can come back
insufficient, and then the objective reads worse than before the call. An
agent that has been told this queues a judgement and reports an answer; one
that has not reports a fix, and the user believes an objective was closed by
a call that may have just opened it. So the text is asserted to say so.
"""

from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from mipiti_mcp.client import MipitiClient
from mipiti_mcp.server import build_instructions, judge_objective

_QUEUED = {
    "model_id": "tm-001",
    "model_version": 12,
    "co_id": "CO5",
    "queued": True,
    "state": "queued",
    "hint": "Judging runs in the background; re-read get_mitigation_groups shortly.",
    "governor": {"exhausted": False, "resets_at": "2026-09-28T00:00:00+00:00"},
    "billing": {"pool": "personal", "balance": 900.0, "sufficient": True,
                "estimated_credits": 3.0},
}

_FRESH = {**_QUEUED, "queued": False, "state": "already_fresh",
          "hint": "A current judgement already exists for this objective."}

_PATH = "https://test.api.mipiti.io/api/models/tm-001/control-objectives/CO5/judge"


def _status_error(status: int, detail) -> httpx.HTTPStatusError:
    request = httpx.Request("POST", "http://x/api/models/tm-001/control-objectives/CO5/judge")
    return httpx.HTTPStatusError(
        "refused", request=request,
        response=httpx.Response(status, json={"detail": detail}, request=request),
    )


# ------------------------------------------------------------------
# Tool level
# ------------------------------------------------------------------


class TestJudgeObjectiveTool:
    @pytest.mark.asyncio
    async def test_forwards_both_ids_and_returns_envelope(self) -> None:
        client = AsyncMock()
        client.judge_objective = AsyncMock(return_value=_QUEUED)
        with patch("mipiti_mcp.server._get_client", return_value=client):
            result = await judge_objective(
                server_version="0", model_id="tm-001", co_id="CO5",
            )
        client.judge_objective.assert_awaited_once_with("tm-001", "CO5")
        assert result == _QUEUED

    @pytest.mark.asyncio
    async def test_an_already_judged_objective_queues_nothing(self) -> None:
        """``already_fresh`` is a distinct outcome, not a failure. A caller that
        could not tell it from ``queued`` would wait for a background run that
        was never started."""
        client = AsyncMock()
        client.judge_objective = AsyncMock(return_value=_FRESH)
        with patch("mipiti_mcp.server._get_client", return_value=client):
            result = await judge_objective(
                server_version="0", model_id="tm-001", co_id="CO5",
            )
        assert result["state"] == "already_fresh"
        assert result["queued"] is False

    @pytest.mark.asyncio
    @pytest.mark.parametrize("blank", ["", "   "])
    async def test_a_blank_id_is_refused_before_the_call(self, blank: str) -> None:
        """A blank id would address the model's collection rather than one
        objective. Refused here, where the caller can still see which argument
        it was."""
        client = AsyncMock()
        with patch("mipiti_mcp.server._get_client", return_value=client):
            with pytest.raises(ToolError, match="co_id"):
                await judge_objective(
                    server_version="0", model_id="tm-001", co_id=blank,
                )
            with pytest.raises(ToolError, match="model_id"):
                await judge_objective(
                    server_version="0", model_id=blank, co_id="CO5",
                )
        client.judge_objective.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_an_absent_route_raises_rather_than_reading_as_queued(self) -> None:
        """A deployment whose backend does not serve this route answers 404.
        That must raise: returned as data it would be indistinguishable from a
        queued judgement, and the agent would report work nothing is doing."""
        client = AsyncMock()
        client.judge_objective = AsyncMock(side_effect=_status_error(404, "Not Found"))
        with patch("mipiti_mcp.server._get_client", return_value=client):
            with pytest.raises(ToolError, match="404"):
                await judge_objective(
                    server_version="0", model_id="tm-001", co_id="CO5",
                )


# ------------------------------------------------------------------
# Client level — path, and the refusals that are answers
# ------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_client_posts_the_per_objective_path(mock_env: None) -> None:
    """The path is addressed by the objective. A model-scoped path here would
    be the whole-model sweep this tool exists to avoid."""
    route = respx.post(_PATH).mock(return_value=httpx.Response(200, json=_QUEUED))
    client = MipitiClient()
    data = await client.judge_objective("tm-001", "CO5")
    assert route.called
    assert data["state"] == "queued"
    await client.close()


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("status,detail", [
    (409, {"message": "Controls are still being generated for this model."}),
    (503, "Group-sufficiency judging is not enabled on this deployment."),
    (402, {"code": "insufficient_credits", "message": "Balance is 0.0 credits."}),
])
async def test_a_refusal_comes_back_as_data(
    mock_env: None, status: int, detail,
) -> None:
    """Each of these is an answer the caller relays, not a fault it retries.
    A string detail is carried under ``message`` so the shape is one shape."""
    respx.post(_PATH).mock(return_value=httpx.Response(status, json={"detail": detail}))
    client = MipitiClient()
    data = await client.judge_objective("tm-001", "CO5")
    assert data["queued"] is False
    assert data["http_status"] == status
    assert data["message"]
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_a_refusal_with_an_unreadable_body_still_reports_its_status(
    mock_env: None,
) -> None:
    """A gateway can answer 503 with HTML. The status is the part that tells a
    caller what to do, so it survives a body that does not parse."""
    respx.post(_PATH).mock(return_value=httpx.Response(503, text="<html>upstream</html>"))
    client = MipitiClient()
    data = await client.judge_objective("tm-001", "CO5")
    assert data == {"queued": False, "http_status": 503}
    await client.close()


@pytest.mark.asyncio
@respx.mock
async def test_an_unexpected_failure_raises(mock_env: None) -> None:
    """Only the three refusals are answers. Everything else is a fault, and a
    fault reported as ``queued: false`` would be retried for ever instead of
    surfacing."""
    respx.post(_PATH).mock(return_value=httpx.Response(500, json={"detail": "boom"}))
    client = MipitiClient()
    with pytest.raises(httpx.HTTPStatusError):
        await client.judge_objective("tm-001", "CO5")
    await client.close()


# ------------------------------------------------------------------
# What the published text has to say
# ------------------------------------------------------------------


@pytest.mark.parametrize("tier", ["pro", "organization", "enterprise", "developer"])
def test_the_reason_routes_to_this_tool_on_every_tier(tier: str) -> None:
    """``awaiting_judgement`` is the reason this tool answers. An agent that
    meets the reason and is not sent here generates controls instead, which
    cannot move the objective — the remedy is unreachable in practice even
    though the tool exists."""
    text = build_instructions(tier, "user")
    assert "awaiting_judgement" in text
    assert "judge_objective" in text
    routing = text.split("`awaiting_judgement` →", 1)
    assert len(routing) == 2, "awaiting_judgement has no action routing"
    assert "judge_objective" in routing[1][:400]


def test_the_text_does_not_promise_a_repair() -> None:
    """The judgement can return insufficient. Said plainly in both the tool's
    own description and the routing paragraph, because an agent reads whichever
    one its client renders."""
    import inspect

    from mipiti_mcp import server

    doc = inspect.getdoc(judge_objective) or ""
    assert "insufficient" in doc
    assert "not a repair" in doc.lower()
    assert "insufficient" in server.build_instructions("pro", "user").split(
        "`awaiting_judgement` →", 1)[1][:600]


def test_the_cheaper_scope_is_stated_against_the_sweep() -> None:
    """The tool's value is that it is not ``recompute_verdicts``. If the text
    does not say so, an agent picks the tool it already knows."""
    import inspect

    doc = inspect.getdoc(judge_objective) or ""
    assert "recompute_verdicts" in doc
