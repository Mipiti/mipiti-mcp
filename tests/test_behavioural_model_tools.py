"""The behavioural model tools: each reaches its route with the body the API
takes, refusals that are answers come back as data, a program's refused
judgment surfaces its escalation, and the published text says what an agent
must do with an estimate or a possible threat."""

import asyncio
import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from mipiti_mcp import server
from mipiti_mcp.client import MipitiClient
from mipiti_mcp.server import build_instructions

BASE = "https://test.api.mipiti.io/api/models/tm-1/behavioural-model"


def _body(route) -> dict:
    return json.loads(route.calls.last.request.content)


# ------------------------------------------------------------------
# Client: routes and bodies
# ------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_reads_use_get_on_their_routes(mock_env: None) -> None:
    client = MipitiClient()
    for tail, call in (
        ("", client.get_behavioural_model),
        ("/links", client.get_behavioural_links),
        ("/threats", client.get_behavioural_threats),
    ):
        route = respx.get(BASE + tail).mock(
            return_value=httpx.Response(200, json={"status": "ok"}))
        assert await call("tm-1") == {"status": "ok"}
        assert route.called
    delta = respx.get(BASE + "/controls/CTRL-1/delta").mock(
        return_value=httpx.Response(200, json={"status": "absent"}))
    assert (await client.get_control_delta("tm-1", "CTRL-1"))["status"] == "absent"
    assert delta.called


@pytest.mark.asyncio
@respx.mock
async def test_extract_estimate_sends_only_the_flag(mock_env: None) -> None:
    route = respx.post(BASE + "/extract").mock(return_value=httpx.Response(
        200, json={"confirmed": False, "model_version": 4, "set_revision": 2,
                   "estimate": {"credits": 12.0}}))
    out = await MipitiClient().extract_behavioural_model("tm-1")
    assert out["estimate"]["credits"] == 12.0
    assert _body(route) == {"confirm_estimate": False}


@pytest.mark.asyncio
@respx.mock
async def test_extract_confirmation_names_the_reviewed_values(mock_env: None) -> None:
    route = respx.post(BASE + "/extract").mock(return_value=httpx.Response(
        200, json={"confirmed": True, "status": "extracted"}))
    await MipitiClient().extract_behavioural_model(
        "tm-1", confirm_estimate=True, model_version=4, set_revision=2)
    assert _body(route) == {"confirm_estimate": True, "model_version": 4,
                            "set_revision": 2}


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("status,code", [(409, "review_stale"),
                                         (409, "has_behavioural_model"),
                                         (402, "insufficient_credits")])
async def test_extract_refusals_come_back_as_data(
        mock_env: None, status: int, code: str) -> None:
    respx.post(BASE + "/extract").mock(return_value=httpx.Response(
        status, json={"detail": {"code": code, "message": "m"}}))
    out = await MipitiClient().extract_behavioural_model("tm-1", confirm_estimate=True)
    assert out["confirmed"] is False and out["http_status"] == status
    assert out["code"] == code


@pytest.mark.asyncio
@respx.mock
async def test_extract_other_failures_raise(mock_env: None) -> None:
    respx.post(BASE + "/extract").mock(
        return_value=httpx.Response(404, json={"detail": "Threat model not found."}))
    with pytest.raises(httpx.HTTPStatusError):
        await MipitiClient().extract_behavioural_model("tm-1")


@pytest.mark.asyncio
@respx.mock
async def test_writes_use_the_verbs_and_bodies_the_api_takes(mock_env: None) -> None:
    client = MipitiClient()
    ok = httpx.Response(200, json={"changed": True})

    answers = respx.post(BASE + "/answers").mock(return_value=ok)
    await client.answer_behavioural_questions(
        "tm-1", [{"question_id": "q1", "text": "Only the owner."}], extract_now=True)
    assert _body(answers) == {
        "answers": [{"question_id": "q1", "text": "Only the owner."}],
        "extract_now": True}

    element = respx.put(BASE + "/elements").mock(return_value=ok)
    await client.edit_behavioural_element("tm-1", "actions", {"id": "a1"})
    assert _body(element) == {"collection": "actions", "element": {"id": "a1"}}

    confirm = respx.post(BASE + "/confirm").mock(return_value=ok)
    await client.confirm_behavioural_model("tm-1", "abc", note="reviewed")
    assert _body(confirm) == {"ir_hash": "abc", "note": "reviewed"}

    link = respx.put(BASE + "/links/n1").mock(return_value=ok)
    await client.declare_behavioural_link("tm-1", "n1", "A1", component_id="C1")
    assert _body(link) == {"entity_id": "A1", "component_id": "C1"}

    accept = respx.post(BASE + "/links/accept").mock(return_value=ok)
    await client.accept_behavioural_link_proposals("tm-1", "h1")
    assert _body(accept) == {"proposals_hash": "h1"}

    delta = respx.put(BASE + "/controls/CTRL-1/delta").mock(return_value=ok)
    await client.declare_control_delta("tm-1", "CTRL-1", [{"op": "x"}])
    assert _body(delta) == {"edits": [{"op": "x"}], "unexpressed": []}


@pytest.mark.asyncio
@respx.mock
async def test_check_estimate_sends_only_the_flag(mock_env: None) -> None:
    route = respx.post(BASE + "/check").mock(return_value=httpx.Response(
        200, json={"confirmed": False, "model_version": 4, "set_revision": 2,
                   "estimate": {"credits": 30.0}}))
    out = await MipitiClient().request_model_check("tm-1")
    assert out["estimate"]["credits"] == 30.0
    assert _body(route) == {"confirm_estimate": False}


@pytest.mark.asyncio
@respx.mock
async def test_check_confirmation_names_the_reviewed_values(mock_env: None) -> None:
    route = respx.post(BASE + "/check").mock(return_value=httpx.Response(
        200, json={"confirmed": True, "job_id": "j1", "status": "queued"}))
    out = await MipitiClient().request_model_check(
        "tm-1", confirm_estimate=True, model_version=4, set_revision=2,
        obligations=["ob1"], scope={"domain": 1})
    assert out["job_id"] == "j1"
    assert _body(route) == {"confirm_estimate": True, "model_version": 4,
                            "set_revision": 2, "obligations": ["ob1"],
                            "scope": {"domain": 1}}


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("status,code", [(409, "not_confirmed"),
                                         (409, "review_stale"),
                                         (409, "no_runner_size"),
                                         (503, "not_priced"),
                                         (402, "insufficient_credits")])
async def test_check_refusals_come_back_as_data(
        mock_env: None, status: int, code: str) -> None:
    respx.post(BASE + "/check").mock(return_value=httpx.Response(
        status, json={"detail": {"code": code, "message": "m"}}))
    out = await MipitiClient().request_model_check("tm-1", confirm_estimate=True)
    assert out["confirmed"] is False and out["http_status"] == status
    assert out["code"] == code


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("status", [400, 403, 404])
async def test_check_other_failures_raise(mock_env: None, status: int) -> None:
    respx.post(BASE + "/check").mock(
        return_value=httpx.Response(status, json={"detail": {"code": "x"}}))
    with pytest.raises(httpx.HTTPStatusError):
        await MipitiClient().request_model_check("tm-1")


@pytest.mark.asyncio
@respx.mock
async def test_check_status_and_its_controls(mock_env: None) -> None:
    client = MipitiClient()
    read = respx.get(BASE + "/check").mock(return_value=httpx.Response(
        200, json={"model_id": "tm-1", "status": "running", "terminal": False}))
    assert (await client.get_model_check("tm-1"))["status"] == "running"
    assert read.called
    for tail, call, key in (
        ("/check/pause", client.pause_model_check, "paused"),
        ("/check/resume", client.resume_model_check, "resumed"),
        ("/check/discard", client.discard_model_check, "discarded"),
    ):
        respx.post(BASE + tail).mock(return_value=httpx.Response(
            200, json={"model_id": "tm-1", "job_id": "j1", "status": "x"}))
        out = await call("tm-1")
        assert out[key] is True and out["job_id"] == "j1", tail
        respx.post(BASE + tail).mock(return_value=httpx.Response(
            409, json={"detail": {"code": "not_running", "message": "m"}}))
        out = await call("tm-1")
        assert out[key] is False and out["http_status"] == 409, tail
        assert out["code"] == "not_running", tail


@pytest.mark.asyncio
async def test_generation_names_the_model_it_resumes(mock_env: None) -> None:
    client = MipitiClient()
    stream = AsyncMock(return_value={"type": "chat_response", "content": "c"})
    with patch.object(client, "_stream_model", stream):
        await client.generate_threat_model("desc", model_id="tm-1")
        await client.generate_threat_model("desc")
    assert stream.await_args_list[0].kwargs["model_id"] == "tm-1"
    assert stream.await_args_list[1].kwargs["model_id"] is None


@pytest.mark.asyncio
@respx.mock
async def test_a_refused_judgment_raises_with_its_escalation(mock_env: None) -> None:
    respx.post(BASE + "/confirm").mock(return_value=httpx.Response(
        403, json={"detail": {"code": "delegation_required",
                              "escalation_id": "E-1"}}))
    with pytest.raises(httpx.HTTPStatusError) as err:
        await MipitiClient().confirm_behavioural_model("tm-1", "abc")
    assert "E-1" in err.value.response.text


# ------------------------------------------------------------------
# Tools
# ------------------------------------------------------------------


def _client(**methods: object) -> AsyncMock:
    client = AsyncMock()
    for name, value in methods.items():
        setattr(client, name, AsyncMock(return_value=value))
    return client


@pytest.mark.asyncio
async def test_extract_tool_forwards_the_pin_and_returns_the_answer() -> None:
    client = _client(extract_behavioural_model={"confirmed": False, "estimate": {}})
    with patch("mipiti_mcp.server._get_client", return_value=client):
        out = await server.extract_behavioural_model(
            server_version="0", model_id="tm-1", confirm_estimate=True,
            model_version=4, set_revision=2)
    client.extract_behavioural_model.assert_awaited_once_with(
        "tm-1", confirm_estimate=True, model_version=4, set_revision=2)
    assert out["confirmed"] is False


@pytest.mark.asyncio
async def test_answers_are_parsed_and_forwarded() -> None:
    client = _client(answer_behavioural_questions={"extracted": False})
    answers = json.dumps([{"question_id": "q1", "text": "Only the owner."}])
    with patch("mipiti_mcp.server._get_client", return_value=client):
        await server.answer_behavioural_questions(
            server_version="0", model_id="tm-1", answers=answers)
    client.answer_behavioural_questions.assert_awaited_once_with(
        "tm-1", [{"question_id": "q1", "text": "Only the owner."}],
        extract_now=False)


@pytest.mark.asyncio
@pytest.mark.parametrize("answers,extract_now", [
    ("not json", False),
    ('{"question_id": "q1"}', False),
    ('[{"question_id": "q1"}]', False),
    ('[{"question_id": "", "text": "x"}]', False),
    ('[{"question_id": "q1", "disposition": "fact"}]', False),
    ('[{"question_id": "q1", "disposition": "skip"}]', False),
    ("[]", False),
])
async def test_malformed_answers_are_refused_before_the_call(
        answers: str, extract_now: bool) -> None:
    client = _client()
    with patch("mipiti_mcp.server._get_client", return_value=client):
        with pytest.raises(ToolError):
            await server.answer_behavioural_questions(
                server_version="0", model_id="tm-1", answers=answers,
                extract_now=extract_now)
    client.answer_behavioural_questions.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_disposition_answers_without_text() -> None:
    client = _client(answer_behavioural_questions={"extracted": False})
    answers = [{"question_id": "q1", "disposition": "unknown"},
               {"question_id": "q2", "disposition": "as_stated", "text": "note"}]
    with patch("mipiti_mcp.server._get_client", return_value=client):
        await server.answer_behavioural_questions(
            server_version="0", model_id="tm-1", answers=json.dumps(answers))
    client.answer_behavioural_questions.assert_awaited_once_with(
        "tm-1", answers, extract_now=False)


def test_the_answer_tool_names_every_disposition() -> None:
    text = _descriptions()["answer_behavioural_questions"]
    for disposition in server._ANSWER_DISPOSITIONS[1:]:
        assert f"``{disposition}``" in text, disposition


@pytest.mark.asyncio
async def test_extract_now_with_no_answers_is_allowed() -> None:
    client = _client(answer_behavioural_questions={"extracted": True})
    with patch("mipiti_mcp.server._get_client", return_value=client):
        await server.answer_behavioural_questions(
            server_version="0", model_id="tm-1", extract_now=True)
    client.answer_behavioural_questions.assert_awaited_once_with(
        "tm-1", [], extract_now=True)


@pytest.mark.asyncio
async def test_element_edit_needs_an_object_with_an_id() -> None:
    client = _client(edit_behavioural_element={"changed": True})
    with patch("mipiti_mcp.server._get_client", return_value=client):
        with pytest.raises(ToolError, match="id"):
            await server.edit_behavioural_element(
                server_version="0", model_id="tm-1", collection="actions",
                element='{"name": "x"}')
        with pytest.raises(ToolError, match="object"):
            await server.edit_behavioural_element(
                server_version="0", model_id="tm-1", collection="actions",
                element="[1]")
        await server.edit_behavioural_element(
            server_version="0", model_id="tm-1", collection="actions",
            element='{"id": "a1"}')
    client.edit_behavioural_element.assert_awaited_once_with(
        "tm-1", "actions", {"id": "a1"})


@pytest.mark.asyncio
async def test_blank_required_values_are_refused_before_the_call() -> None:
    client = _client()
    with patch("mipiti_mcp.server._get_client", return_value=client):
        with pytest.raises(ToolError, match="ir_hash"):
            await server.confirm_behavioural_model(
                server_version="0", model_id="tm-1", ir_hash=" ")
        with pytest.raises(ToolError, match="node_id"):
            await server.declare_behavioural_link(
                server_version="0", model_id="tm-1", node_id="", entity_id="A1")
        with pytest.raises(ToolError, match="proposals_hash"):
            await server.accept_behavioural_link_proposals(
                server_version="0", model_id="tm-1", proposals_hash="")
    client.confirm_behavioural_model.assert_not_awaited()
    client.declare_behavioural_link.assert_not_awaited()
    client.accept_behavioural_link_proposals.assert_not_awaited()


@pytest.mark.asyncio
async def test_delta_tool_parses_edits_and_unexpressed() -> None:
    client = _client(declare_control_delta={"status": "pending", "check_ran": True})
    with patch("mipiti_mcp.server._get_client", return_value=client):
        out = await server.declare_control_delta(
            server_version="0", model_id="tm-1", control_id="CTRL-1",
            edits='[{"op": "x"}]', unexpressed='[{"kind": "k", "quote": "q"}]')
        with pytest.raises(ToolError):
            await server.declare_control_delta(
                server_version="0", model_id="tm-1", control_id="CTRL-1",
                edits="nope")
    client.declare_control_delta.assert_awaited_once_with(
        "tm-1", "CTRL-1", [{"op": "x"}], [{"kind": "k", "quote": "q"}])
    assert out["check_ran"] is True


@pytest.mark.asyncio
async def test_a_refusal_is_a_tool_error_naming_the_escalation() -> None:
    request = httpx.Request("POST", "http://x/confirm")
    refusal = httpx.HTTPStatusError(
        "refused", request=request,
        response=httpx.Response(
            403, json={"detail": {"escalation_id": "E-1"}}, request=request))
    client = AsyncMock()
    client.confirm_behavioural_model = AsyncMock(side_effect=refusal)
    with patch("mipiti_mcp.server._get_client", return_value=client):
        with pytest.raises(ToolError, match="403.*E-1"):
            await server.confirm_behavioural_model(
                server_version="0", model_id="tm-1", ir_hash="abc")


@pytest.mark.asyncio
async def test_the_reads_forward_their_ids() -> None:
    client = _client(get_behavioural_model={"status": "none"},
                     get_behavioural_links={"links": []},
                     get_behavioural_threats={"objectives": []},
                     get_control_delta={"status": "absent"})
    with patch("mipiti_mcp.server._get_client", return_value=client):
        await server.get_behavioural_model(server_version="0", model_id="tm-1")
        await server.get_behavioural_links(server_version="0", model_id="tm-1")
        await server.get_behavioural_threats(server_version="0", model_id="tm-1")
        await server.get_control_delta(
            server_version="0", model_id="tm-1", control_id="CTRL-1")
    client.get_behavioural_model.assert_awaited_once_with("tm-1")
    client.get_behavioural_links.assert_awaited_once_with("tm-1")
    client.get_behavioural_threats.assert_awaited_once_with("tm-1")
    client.get_control_delta.assert_awaited_once_with("tm-1", "CTRL-1")


@pytest.mark.asyncio
async def test_check_tool_parses_obligations_and_scope() -> None:
    client = _client(request_model_check={"confirmed": True, "job_id": "j1"})
    with patch("mipiti_mcp.server._get_client", return_value=client):
        out = await server.request_model_check(
            server_version="0", model_id="tm-1", confirm_estimate=True,
            model_version=4, set_revision=2, obligations=" ob1, ,ob2 ",
            scope='{"domain": 1}')
    client.request_model_check.assert_awaited_once_with(
        "tm-1", confirm_estimate=True, model_version=4, set_revision=2,
        obligations=["ob1", "ob2"], scope={"domain": 1})
    assert out["job_id"] == "j1"


@pytest.mark.asyncio
async def test_check_tool_estimates_by_default() -> None:
    client = _client(request_model_check={"confirmed": False})
    with patch("mipiti_mcp.server._get_client", return_value=client):
        await server.request_model_check(server_version="0", model_id="tm-1")
    client.request_model_check.assert_awaited_once_with(
        "tm-1", confirm_estimate=False, model_version=None, set_revision=None,
        obligations=[], scope=None)


@pytest.mark.asyncio
@pytest.mark.parametrize("scope", ["nope", "[1]"])
async def test_a_malformed_scope_is_refused_before_the_call(scope: str) -> None:
    client = _client()
    with patch("mipiti_mcp.server._get_client", return_value=client):
        with pytest.raises(ToolError, match="scope"):
            await server.request_model_check(
                server_version="0", model_id="tm-1", scope=scope)
    client.request_model_check.assert_not_awaited()


@pytest.mark.asyncio
async def test_manage_model_check_dispatches_each_action() -> None:
    client = _client(pause_model_check={"paused": True},
                     resume_model_check={"resumed": True},
                     discard_model_check={"discarded": True})
    with patch("mipiti_mcp.server._get_client", return_value=client):
        for action, key in (("pause", "paused"), ("resume", "resumed"),
                            ("discard", "discarded")):
            out = await server.manage_model_check(
                server_version="0", model_id="tm-1", action=action)
            assert out[key] is True, action
        with pytest.raises(ToolError, match="action"):
            await server.manage_model_check(
                server_version="0", model_id="tm-1", action="restart")
        await server.get_model_check(server_version="0", model_id="tm-1")
    for name in ("pause_model_check", "resume_model_check", "discard_model_check",
                 "get_model_check"):
        getattr(client, name).assert_awaited_once_with("tm-1")


@pytest.mark.asyncio
async def test_a_generation_stopped_on_questions_returns_them() -> None:
    from mipiti_mcp.types import ChatResponse

    questions = [{"question_id": "q1", "text": "Who may delete a record?"}]
    stopped = ChatResponse.model_validate({
        "type": "chat_response", "content": "answer these",
        "needs_answers": {"model_id": "tm-9", "version": 1, "questions": questions}})
    client = _client(generate_threat_model=stopped)
    with patch("mipiti_mcp.server._get_client", return_value=client):
        out = await server.generate_threat_model(
            server_version="0", feature_description="desc", ctx=AsyncMock())
    assert out == {"generated": False, "needs_answers": True, "model_id": "tm-9",
                   "version": 1, "questions": questions, "message": "answer these"}


@pytest.mark.asyncio
async def test_a_generation_names_the_model_it_resumes_only_when_given() -> None:
    from mipiti_mcp.types import ChatResponse

    prose = ChatResponse.model_validate({"type": "chat_response", "content": "c"})
    client = _client(generate_threat_model=prose)
    with patch("mipiti_mcp.server._get_client", return_value=client):
        out = await server.generate_threat_model(
            server_version="0", feature_description="desc", ctx=AsyncMock(),
            model_id=" tm-9 ")
        await server.generate_threat_model(
            server_version="0", feature_description="desc", ctx=AsyncMock())
    calls = client.generate_threat_model.await_args_list
    assert calls[0].kwargs["model_id"] == "tm-9"
    assert calls[1].kwargs["model_id"] is None
    assert out == {"generated": False, "message": "c"}


# ------------------------------------------------------------------
# Published text
# ------------------------------------------------------------------

_TOOLS = (
    "get_behavioural_model", "extract_behavioural_model",
    "answer_behavioural_questions", "edit_behavioural_element",
    "confirm_behavioural_model", "get_behavioural_links",
    "declare_behavioural_link", "accept_behavioural_link_proposals",
    "get_control_delta", "declare_control_delta", "get_behavioural_threats",
    "request_model_check", "get_model_check", "manage_model_check",
)


def _descriptions() -> dict[str, str]:
    tools = asyncio.run(server.mcp.list_tools())
    return {t.name: t.description or "" for t in tools}


def test_every_tool_is_registered_with_the_version_pin() -> None:
    tools = {t.name: t for t in asyncio.run(server.mcp.list_tools())}
    for name in _TOOLS:
        assert name in tools, name
        assert "server_version" in tools[name].parameters["properties"], name


def test_published_text_has_no_em_dash_and_no_internal_state() -> None:
    text = "\n".join(_descriptions()[n] for n in _TOOLS)
    assert chr(0x2014) not in text
    for banned in ("dark", "feature flag", "enabled"):
        assert banned not in text.lower(), banned


def test_the_extraction_is_estimated_and_relayed_first() -> None:
    text = _descriptions()["extract_behavioural_model"]
    assert "confirm_estimate" in text and "RELAYED TO THE PERSON" in text
    assert "Never confirm on your own" in text


def test_the_check_is_estimated_and_relayed_first() -> None:
    text = _descriptions()["request_model_check"]
    assert "confirm_estimate" in text and "RELAYED TO THE PERSON" in text
    assert "Never confirm on your own" in text
    instructions = build_instructions("pro", "user")
    assert "RELAY THE ESTIMATE AND ITS NOTICES TO THE PERSON" in instructions
    assert "`manage_model_check`" in instructions


def test_a_stopped_generation_says_how_it_resumes() -> None:
    text = _descriptions()["generate_threat_model"]
    assert "needs_answers" in text and "RELAY THE QUESTIONS TO THE PERSON" in text
    assert "generation_ready" in text
    assert "needs_answers" in build_instructions("developer", "user")


def test_judgments_name_the_refusal_and_the_no_retry_rule() -> None:
    for name in ("answer_behavioural_questions", "edit_behavioural_element",
                 "confirm_behavioural_model", "declare_behavioural_link",
                 "accept_behavioural_link_proposals"):
        text = _descriptions()[name]
        assert "403" in text and "escalation_id" in text, name
        assert "Do not retry" in text, name


def test_a_programs_delta_is_never_a_persons_declaration() -> None:
    text = _descriptions()["declare_control_delta"]
    assert "never replaces a delta a person declared" in text


def test_threats_are_relayed_with_their_default_questions() -> None:
    assert "default questions" in _descriptions()["get_behavioural_threats"]
    text = build_instructions("pro", "user")
    assert "relay a possible threat to the person together with its default questions" in text


def test_instructions_route_open_questions_to_the_review_queue() -> None:
    text = build_instructions("developer", "user")
    assert "Open behavioural questions appear on `get_review_queue`" in text
    assert "never confirm on your own" in text


def test_review_queue_names_the_new_item_types() -> None:
    text = _descriptions()["get_review_queue"]
    for item in ("behavioural_question", "behavioural_link",
                 "not_applicable_refuted"):
        assert item in text, item


def test_decision_filter_accepts_the_behavioural_kinds() -> None:
    assert "behavioural_model_answered" in server._DECISION_KINDS
    assert "behavioural_model_confirmed" in server._DECISION_KINDS
