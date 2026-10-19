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
    await client.submit_control_delta("tm-1", "CTRL-1", [{"op": "x"}])
    assert _body(delta) == {"edits": [{"op": "x"}], "unexpressed": []}

    declare = respx.post(BASE + "/controls/CTRL-1/delta/declare").mock(return_value=ok)
    await client.declare_control_delta(
        "tm-1", "CTRL-1", nothing_spans=[{"start": 0, "end": 4}],
        declaration_hash="d1", confirm=True)
    assert _body(declare) == {"nothing_spans": [{"start": 0, "end": 4}],
                              "resolutions": [], "placements": [], "confirm": True,
                              "declaration_hash": "d1"}
    await client.declare_control_delta("tm-1", "CTRL-1")
    assert _body(declare) == {"nothing_spans": [], "resolutions": [], "placements": [],
                              "confirm": False}

    reading = respx.post(BASE + "/deltas/second-reading").mock(return_value=ok)
    await client.request_delta_second_reading("tm-1", ["CTRL-1", "CTRL-2"])
    assert _body(reading) == {"control_ids": ["CTRL-1", "CTRL-2"],
                              "confirm_estimate": False}


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


STREAM = "https://test.api.mipiti.io/api/model/stream"


def _sse(*events: tuple[str, dict]) -> httpx.Response:
    payload = "".join(f"event: {e}\ndata: {json.dumps(d)}\n\n" for e, d in events)
    return httpx.Response(200, content=payload.encode(),
                          headers={"content-type": "text/event-stream"})


_RESULT = {"type": "result", "markdown": "", "csv": "", "model_id": "tm-1", "version": 2,
           "threat_model": {"id": "tm-1", "title": "T", "version": 2}}


@pytest.mark.asyncio
@respx.mock
async def test_a_new_generation_names_no_model_and_asks_no_resume(mock_env: None) -> None:
    route = respx.post(STREAM).mock(return_value=_sse(("result", _RESULT)))
    await MipitiClient().generate_threat_model("desc")
    body = _body(route)
    assert body["intent"] == "generate"
    assert "model_id" not in body and "resume" not in body


@pytest.mark.asyncio
@respx.mock
async def test_generating_from_the_behavioural_model_asks_a_resume_of_it(
        mock_env: None) -> None:
    route = respx.post(STREAM).mock(return_value=_sse(("result", _RESULT)))
    out = await MipitiClient().generate_from_behavioural_model("tm-1")
    assert out.model_id == "tm-1"
    body = _body(route)
    assert (body["intent"], body["model_id"], body["resume"]) == ("generate", "tm-1", True)
    # The message names the model: the API's replay of a stream is keyed by
    # its message, so two models' resumes never replay each other.
    assert "tm-1" in body["messages"][-1]["content"]


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("code", ["not_awaiting_generation", "generation_in_progress"])
async def test_a_refused_resume_comes_back_as_data(mock_env: None, code: str) -> None:
    respx.post(STREAM).mock(return_value=httpx.Response(
        409, json={"detail": {"code": code, "message": "m", "model_id": "tm-1"}}))
    out = await MipitiClient().generate_from_behavioural_model("tm-1")
    assert out == {"generated": False, "http_status": 409, "code": code,
                   "message": "m", "model_id": "tm-1"}


@pytest.mark.asyncio
@respx.mock
async def test_a_resume_of_a_model_that_is_not_there_raises(mock_env: None) -> None:
    respx.post(STREAM).mock(return_value=httpx.Response(
        404, json={"detail": "Threat model not found."}))
    with pytest.raises(httpx.HTTPStatusError) as err:
        await MipitiClient().generate_from_behavioural_model("tm-1")
    assert err.value.response.status_code == 404


@pytest.mark.asyncio
@respx.mock
async def test_the_reads_send_their_view_wait_and_page(mock_env: None) -> None:
    client = MipitiClient()
    read = respx.get(BASE).mock(return_value=httpx.Response(200, json={"view": "x"}))
    await client.get_behavioural_model("tm-1")
    assert dict(read.calls.last.request.url.params) == {}
    await client.get_behavioural_model("tm-1", view="status", wait_seconds=10)
    assert dict(read.calls.last.request.url.params) == {"view": "status",
                                                        "wait_seconds": "10"}
    await client.get_behavioural_model("tm-1", view="questions", offset=50, limit=20)
    assert dict(read.calls.last.request.url.params) == {"view": "questions",
                                                        "offset": "50", "limit": "20"}
    threats = respx.get(BASE + "/threats").mock(
        return_value=httpx.Response(200, json={"total": 0}))
    await client.get_behavioural_threats("tm-1")
    assert dict(threats.calls.last.request.url.params) == {}
    await client.get_behavioural_threats("tm-1", co_id="CO5", offset=25, limit=10,
                                         standing="possible_threat")
    assert dict(threats.calls.last.request.url.params) == {
        "co_id": "CO5", "standing": "possible_threat", "offset": "25", "limit": "10"}


@pytest.mark.asyncio
@respx.mock
async def test_a_dry_run_is_sent_only_when_asked(mock_env: None) -> None:
    route = respx.post(BASE + "/answers").mock(return_value=httpx.Response(
        200, json={"dry_run": True, "outcome": {"extracts": False}}))
    client = MipitiClient()
    await client.answer_behavioural_questions("tm-1", [{"question_id": "q1", "text": "x"}],
                                              dry_run=True)
    assert _body(route)["dry_run"] is True
    await client.answer_behavioural_questions("tm-1", [{"question_id": "q1", "text": "x"}])
    assert "dry_run" not in _body(route)


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


@pytest.mark.asyncio
async def test_a_structured_answer_and_a_contradiction_are_forwarded() -> None:
    client = _client(answer_behavioural_questions={"extracted": False})
    answers = [{"question_id": "q1", "structured": {"classes": ["org_admin"]}},
               {"question_id": "q2", "text": "It also resets.",
                "contradicts": {"direction": "code_does_more"}}]
    with patch("mipiti_mcp.server._get_client", return_value=client):
        await server.answer_behavioural_questions(
            server_version="0", model_id="tm-1", answers=json.dumps(answers))
    client.answer_behavioural_questions.assert_awaited_once_with(
        "tm-1", answers, extract_now=False)


@pytest.mark.asyncio
async def test_a_zone_or_receiver_the_offer_does_not_list_is_forwarded_unchanged() -> None:
    # Which ids are new is the API's to decide from the offer: the tool keeps
    # no list of its own that would refuse them.
    client = _client(answer_behavioural_questions={"extracted": False})
    answers = [{"question_id": "q1", "structured": {"zones": {"feed": "vendor_zone"}}},
               {"question_id": "q2", "structured": {"zone": "partner_net"}},
               {"question_id": "q3", "structured": {"receivers": ["partner_api"]}}]
    with patch("mipiti_mcp.server._get_client", return_value=client):
        await server.answer_behavioural_questions(
            server_version="0", model_id="tm-1", answers=json.dumps(answers))
    client.answer_behavioural_questions.assert_awaited_once_with(
        "tm-1", answers, extract_now=False)


@pytest.mark.asyncio
@respx.mock
async def test_an_idle_reextraction_refusal_names_its_code(mock_env: None) -> None:
    respx.post(BASE + "/answers").mock(return_value=httpx.Response(
        409, json={"detail": {"code": "extraction_running",
                              "message": "An extraction is running."}}))
    with patch("mipiti_mcp.server._get_client", return_value=MipitiClient()):
        with pytest.raises(ToolError, match="extraction_running"):
            await server.answer_behavioural_questions(
                server_version="0", model_id="tm-1", extract_now=True)


def test_the_published_text_names_the_new_forms_and_the_refusal() -> None:
    text = _descriptions()["answer_behavioural_questions"]
    for term in ("new_zones", "new_actors", "id_in_use", "extraction_running"):
        assert f"``{term}``" in text, term
    assert "dropped_elements" in _descriptions()["get_behavioural_model"]
    instructions = build_instructions("pro", "owner")
    for term in ("new_zones", "new_actors", "extraction.dropped_elements",
                 "extraction_running"):
        assert f"`{term}`" in instructions, term


@pytest.mark.asyncio
@pytest.mark.parametrize("answer", [
    {"question_id": "q1", "structured": ["org_admin"]},
    {"question_id": "q1", "text": "x", "contradicts": {"direction": "sideways"}},
    {"question_id": "q1", "text": "x", "contradicts": "code_does_more"},
])
async def test_a_malformed_structured_answer_or_contradiction_is_refused(answer) -> None:
    client = _client()
    with patch("mipiti_mcp.server._get_client", return_value=client):
        with pytest.raises(ToolError):
            await server.answer_behavioural_questions(
                server_version="0", model_id="tm-1", answers=json.dumps([answer]))
    client.answer_behavioural_questions.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_generation_saved_first_returns_the_model_and_its_job() -> None:
    from mipiti_mcp.types import ChatResponse

    extracting = {"model_id": "tm-9", "version": 1, "title": "Keys",
                  "job": {"state": "queued"}, "estimate": {"credits": 40}}
    client = _client(generate_threat_model=ChatResponse.model_validate(
        {"type": "chat_response", "content": "Saved.", "extracting": extracting}))
    ctx = AsyncMock()
    with patch("mipiti_mcp.server._get_client", return_value=client):
        out = await server.generate_threat_model(
            server_version="0", feature_description="desc", ctx=ctx)
    assert out["extracting"] is True and out["generated"] is False
    assert (out["model_id"], out["job"]["state"]) == ("tm-9", "queued")


@pytest.mark.asyncio
@respx.mock
async def test_drift_intent_and_record_only_reach_their_routes(mock_env: None) -> None:
    client = MipitiClient()
    intent = respx.post("https://test.api.mipiti.io/api/models/tm-1/findings/f-1/drift-intent"
                        ).mock(return_value=httpx.Response(200, json={"intent": "defect"}))
    await client.decide_drift_intent("tm-1", "f-1", "defect", control_id="C1",
                                     head_commit="abc")
    assert _body(intent) == {"intent": "defect", "control_id": "C1", "head_commit": "abc",
                             "note": ""}
    decide = respx.post("https://test.api.mipiti.io/api/models/tm-1/proposals/p-1/decide"
                        ).mock(return_value=httpx.Response(200, json={"proposal": {}}))
    await client.decide_proposal("tm-1", "p-1", "accept", record_only=True)
    assert _body(decide)["record_only"] is True
    await client.decide_proposal("tm-1", "p-1", "accept")
    assert "record_only" not in _body(decide)


@pytest.mark.asyncio
@pytest.mark.parametrize("intent,control", [("maybe", ""), ("defect", "")])
async def test_a_drift_intent_the_api_would_refuse_is_refused_before_the_call(
        intent: str, control: str) -> None:
    client = _client()
    with patch("mipiti_mcp.server._get_client", return_value=client):
        with pytest.raises(ToolError):
            await server.decide_drift_intent(server_version="0", model_id="tm-1",
                                             finding_id="f-1", intent=intent,
                                             control_id=control)
    client.decide_drift_intent.assert_not_awaited()


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
async def test_submit_tool_parses_edits_and_unexpressed() -> None:
    client = _client(submit_control_delta={"status": "checked", "check_ran": True})
    with patch("mipiti_mcp.server._get_client", return_value=client):
        out = await server.submit_control_delta(
            server_version="0", model_id="tm-1", control_id="CTRL-1",
            edits='[{"op": "x"}]', unexpressed='[{"kind": "k", "quote": "q"}]')
        with pytest.raises(ToolError):
            await server.submit_control_delta(
                server_version="0", model_id="tm-1", control_id="CTRL-1",
                edits="nope")
    client.submit_control_delta.assert_awaited_once_with(
        "tm-1", "CTRL-1", [{"op": "x"}], [{"kind": "k", "quote": "q"}])
    assert out["check_ran"] is True


@pytest.mark.asyncio
async def test_declare_tool_previews_and_needs_the_hash_to_confirm() -> None:
    client = _client(declare_control_delta={"declaration_hash": "d1", "declarable": True})
    with patch("mipiti_mcp.server._get_client", return_value=client):
        out = await server.declare_control_delta(
            server_version="0", model_id="tm-1", control_id="CTRL-1",
            resolutions='[{"start": 0, "end": 4, "choice": "second"}]')
        with pytest.raises(ToolError, match="declaration_hash"):
            await server.declare_control_delta(
                server_version="0", model_id="tm-1", control_id="CTRL-1", confirm=True)
        with pytest.raises(ToolError, match="nothing_spans"):
            await server.declare_control_delta(
                server_version="0", model_id="tm-1", control_id="CTRL-1",
                nothing_spans="{}")
    client.declare_control_delta.assert_awaited_once_with(
        "tm-1", "CTRL-1", nothing_spans=[],
        resolutions=[{"start": 0, "end": 4, "choice": "second"}], placements=[],
        declaration_hash="", confirm=False)
    assert out["declaration_hash"] == "d1"


@pytest.mark.asyncio
async def test_second_reading_tool_splits_the_ids_and_estimates_by_default() -> None:
    client = _client(request_delta_second_reading={"confirmed": False})
    with patch("mipiti_mcp.server._get_client", return_value=client):
        await server.request_delta_second_reading(
            server_version="0", model_id="tm-1", control_ids=" CTRL-1, ,CTRL-2 ")
        with pytest.raises(ToolError, match="control_ids"):
            await server.request_delta_second_reading(
                server_version="0", model_id="tm-1", control_ids=" , ")
    client.request_delta_second_reading.assert_awaited_once_with(
        "tm-1", ["CTRL-1", "CTRL-2"], confirm_estimate=False)


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
        await server.get_behavioural_model(server_version="0", model_id="tm-1",
                                           ctx=AsyncMock())
        await server.get_behavioural_links(server_version="0", model_id="tm-1")
        await server.get_behavioural_threats(server_version="0", model_id="tm-1")
        await server.get_control_delta(
            server_version="0", model_id="tm-1", control_id="CTRL-1")
    client.get_behavioural_model.assert_awaited_once_with("tm-1", view="full")
    client.get_behavioural_links.assert_awaited_once_with("tm-1")
    client.get_behavioural_threats.assert_awaited_once_with(
        "tm-1", co_id="", offset=0, limit=25, standing="")
    client.get_control_delta.assert_awaited_once_with("tm-1", "CTRL-1")


@pytest.mark.asyncio
async def test_the_questions_view_is_read_a_page_at_a_time() -> None:
    client = _client(get_behavioural_model={"view": "questions", "total": 120,
                                            "next_offset": 70})
    with patch("mipiti_mcp.server._get_client", return_value=client):
        out = await server.get_behavioural_model(
            server_version="0", model_id="tm-1", ctx=AsyncMock(), view="questions",
            offset=20, limit=50)
    client.get_behavioural_model.assert_awaited_once_with(
        "tm-1", view="questions", offset=20, limit=50)
    assert out["next_offset"] == 70


@pytest.mark.asyncio
@pytest.mark.parametrize("kwargs", [
    {"view": "everything"}, {"wait_seconds": 51}, {"wait_seconds": -1},
    {"view": "questions", "limit": 0}, {"view": "questions", "limit": 201},
    {"view": "questions", "offset": -1},
])
async def test_a_behavioural_read_outside_the_api_bounds_is_refused(kwargs) -> None:
    client = _client()
    with patch("mipiti_mcp.server._get_client", return_value=client):
        with pytest.raises(ToolError):
            await server.get_behavioural_model(
                server_version="0", model_id="tm-1", ctx=AsyncMock(), **kwargs)
    client.get_behavioural_model.assert_not_awaited()


def _status(job) -> dict:
    return {"view": "status", "status": "extracting", "extraction": {"job": job}}


def _running(pass_name: str, completed: int, started: bool = True) -> dict:
    return {"state": "running", "progress": {
        "pass": pass_name, "calls_completed": completed, "calls_expected": 5,
        "call_started_at": "2026-10-19T10:00:00+00:00" if started else "",
        "estimated_finish": None}}


@pytest.mark.asyncio
async def test_a_waiting_read_reports_the_job_until_it_moves() -> None:
    reads = [_status(_running("actions", 2)), _status(_running("actions", 2)),
             _status(_running("links", 3)), {"view": "full", "status": "extracting"}]
    client = AsyncMock()
    client.get_behavioural_model = AsyncMock(side_effect=reads)
    ctx = AsyncMock()
    with patch("mipiti_mcp.server._get_client", return_value=client):
        out = await server.get_behavioural_model(
            server_version="0", model_id="tm-1", ctx=ctx, wait_seconds=50)
    assert out == {"view": "full", "status": "extracting"}
    calls = client.get_behavioural_model.await_args_list
    assert calls[0].kwargs == {"view": "status"}
    assert calls[1].kwargs == {"view": "status", "wait_seconds": 10}
    assert calls[-1].kwargs == {"view": "full"}
    notes = ctx.report_progress.await_args_list
    assert [n.args for n in notes] == [(1, None), (2, None), (3, None)]
    assert notes[0].kwargs["message"] == "call 3 of 5: actions"
    assert notes[-1].kwargs["message"] == "call 4 of 5: links"


@pytest.mark.asyncio
@pytest.mark.parametrize("job", [None, {"state": "failed", "error": "ask again"}])
async def test_a_waiting_read_with_no_job_running_answers_at_once(job) -> None:
    client = AsyncMock()
    client.get_behavioural_model = AsyncMock(side_effect=[
        _status(job), {"view": "status", "status": "extracted"}])
    ctx = AsyncMock()
    with patch("mipiti_mcp.server._get_client", return_value=client):
        out = await server.get_behavioural_model(
            server_version="0", model_id="tm-1", ctx=ctx, view="status", wait_seconds=50)
    assert out["status"] == "extracted"
    assert client.get_behavioural_model.await_count == 2
    ctx.report_progress.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_waiting_read_stops_at_its_bound() -> None:
    job = _status(_running("state", 1, started=False))
    client = AsyncMock()
    client.get_behavioural_model = AsyncMock(return_value=job)
    clock = iter([0, 0, 40, 51])
    with patch("mipiti_mcp.server._get_client", return_value=client), \
            patch("mipiti_mcp.server.time") as fake_time:
        fake_time.monotonic = lambda: next(clock)
        await server.get_behavioural_model(
            server_version="0", model_id="tm-1", ctx=AsyncMock(), wait_seconds=50)
    waits = [c.kwargs.get("wait_seconds") for c in client.get_behavioural_model.await_args_list]
    assert waits == [None, 10, 10, None]


def test_the_job_is_named_in_words() -> None:
    assert server._job_message(None) == "extraction finished"
    assert server._job_message({"state": "queued"}) == "extraction queued"
    assert server._job_message({"state": "running", "progress": {}}) == "extraction running"
    assert server._job_message(_running("actions", 2, started=False)) == \
        "call 2 of 5: actions"
    finishing = _running("links", 3)
    finishing["progress"]["estimated_finish"] = "2026-10-19T10:20:00+00:00"
    assert server._job_message(finishing) == \
        "call 4 of 5: links, estimated finish 2026-10-19T10:20:00+00:00"
    assert server._job_message({"state": "failed", "error": "ask again"}) == \
        "extraction failed: ask again"


@pytest.mark.asyncio
async def test_the_threats_page_is_forwarded_and_bounded() -> None:
    client = _client(get_behavioural_threats={"total": 300, "next_offset": 50,
                                              "truncated": True})
    with patch("mipiti_mcp.server._get_client", return_value=client):
        out = await server.get_behavioural_threats(
            server_version="0", model_id="tm-1", co_id=" CO5 ", offset=25, limit=25,
            standing="possible_threat")
        for bad in ({"limit": 0}, {"limit": 201}, {"offset": -1}, {"co_id": "x" * 129},
                    {"standing": "x" * 65}):
            with pytest.raises(ToolError):
                await server.get_behavioural_threats(
                    server_version="0", model_id="tm-1", **bad)
    client.get_behavioural_threats.assert_awaited_once_with(
        "tm-1", co_id="CO5", offset=25, limit=25, standing="possible_threat")
    assert (out["total"], out["next_offset"], out["truncated"]) == (300, 50, True)


@pytest.mark.asyncio
async def test_a_dry_run_is_forwarded() -> None:
    client = _client(answer_behavioural_questions={"dry_run": True, "outcome": {}})
    answers = [{"question_id": "q1", "structured": {"actions": ["a1"]}}]
    with patch("mipiti_mcp.server._get_client", return_value=client):
        out = await server.answer_behavioural_questions(
            server_version="0", model_id="tm-1", answers=json.dumps(answers),
            dry_run=True)
    client.answer_behavioural_questions.assert_awaited_once_with(
        "tm-1", answers, extract_now=False, dry_run=True)
    assert out["dry_run"] is True


@pytest.mark.asyncio
async def test_generating_from_the_behavioural_model_returns_the_generation() -> None:
    from mipiti_mcp.types import GenerateResult

    result = GenerateResult.model_validate({**_RESULT, "controls_status": "proposed"})
    client = _client(generate_from_behavioural_model=result)
    with patch("mipiti_mcp.server._get_client", return_value=client):
        out = await server.generate_from_behavioural_model(
            server_version="0", model_id=" tm-1 ", ctx=AsyncMock())
    assert client.generate_from_behavioural_model.await_args.args == ("tm-1",)
    assert (out["model_id"], out["version"], out["controls_status"]) == \
        ("tm-1", 2, "proposed")


@pytest.mark.asyncio
async def test_a_refused_generation_from_the_behavioural_model_is_data() -> None:
    refusal = {"generated": False, "http_status": 409, "code": "not_awaiting_generation",
               "message": "m"}
    client = _client(generate_from_behavioural_model=refusal)
    with patch("mipiti_mcp.server._get_client", return_value=client):
        out = await server.generate_from_behavioural_model(
            server_version="0", model_id="tm-1", ctx=AsyncMock())
        with pytest.raises(ToolError, match="model_id"):
            await server.generate_from_behavioural_model(
                server_version="0", model_id=" ", ctx=AsyncMock())
    assert out == refusal


@pytest.mark.asyncio
async def test_an_entity_job_reports_progress_while_it_waits() -> None:
    client = AsyncMock()
    client.start_add_attacker = AsyncMock(return_value={"job_id": "j1"})
    client.get_operation = AsyncMock(side_effect=[
        {"status": "running", "poll_after_seconds": 0},
        {"status": "running", "poll_after_seconds": 0},
        {"status": "completed", "result": {"model": {"id": "tm-1"}}}])
    ctx = AsyncMock()
    with patch("mipiti_mcp.server._get_client", return_value=client):
        out = await server.add_attacker(
            server_version="0", model_id="tm-1", capability="From the network, the "
            "attacker can read requests.", ctx=ctx)
    assert out == {"model": {"id": "tm-1"}}
    notes = ctx.report_progress.await_args_list
    assert [n.args for n in notes] == [(1, None), (2, None)]
    assert notes[0].kwargs["message"] == "job j1: running"


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
    next_step = out.pop("next")
    assert out == {"generated": False, "needs_answers": True, "model_id": "tm-9",
                   "version": 1, "questions": questions, "message": "answer these"}
    assert "generate_from_behavioural_model(model_id='tm-9')" in next_step
    assert "answer_behavioural_questions" in next_step


@pytest.mark.asyncio
async def test_a_model_saved_extracting_names_the_tool_that_generates_it() -> None:
    from mipiti_mcp.types import ChatResponse

    saved = ChatResponse.model_validate({
        "type": "chat_response", "content": "Saved.",
        "extracting": {"model_id": "tm-9", "version": 1, "job": {"state": "queued"}}})
    client = _client(generate_threat_model=saved)
    with patch("mipiti_mcp.server._get_client", return_value=client):
        out = await server.generate_threat_model(
            server_version="0", feature_description="desc", ctx=AsyncMock())
    assert "view='status', wait_seconds=50" in out["next"]
    assert "generate_from_behavioural_model(model_id='tm-9')" in out["next"]


@pytest.mark.asyncio
async def test_a_model_id_with_a_description_is_refused_before_the_call() -> None:
    client = _client()
    with patch("mipiti_mcp.server._get_client", return_value=client):
        with pytest.raises(ToolError, match="resume_takes_no_description"):
            await server.generate_threat_model(
                server_version="0", feature_description="desc", ctx=AsyncMock(),
                model_id="tm-9")
        with pytest.raises(ToolError, match="feature_description"):
            await server.generate_threat_model(
                server_version="0", feature_description=" ", ctx=AsyncMock())
    client.generate_threat_model.assert_not_awaited()
    client.generate_from_behavioural_model.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_model_id_alone_generates_from_the_behavioural_model() -> None:
    from mipiti_mcp.types import ChatResponse

    prose = ChatResponse.model_validate({"type": "chat_response", "content": "c"})
    client = _client(generate_from_behavioural_model=prose, generate_threat_model=prose)
    with patch("mipiti_mcp.server._get_client", return_value=client):
        out = await server.generate_threat_model(
            server_version="0", feature_description="", ctx=AsyncMock(),
            model_id=" tm-9 ")
        await server.generate_threat_model(
            server_version="0", feature_description="desc", ctx=AsyncMock())
    assert client.generate_from_behavioural_model.await_args.args == ("tm-9",)
    assert "model_id" not in client.generate_threat_model.await_args.kwargs
    assert out == {"generated": False, "message": "c"}


# ------------------------------------------------------------------
# Published text
# ------------------------------------------------------------------

_TOOLS = (
    "get_behavioural_model", "extract_behavioural_model",
    "generate_from_behavioural_model",
    "answer_behavioural_questions", "edit_behavioural_element",
    "confirm_behavioural_model", "get_behavioural_links",
    "declare_behavioural_link", "accept_behavioural_link_proposals",
    "get_control_delta", "submit_control_delta", "request_delta_second_reading",
    "declare_control_delta", "get_behavioural_threats",
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
    assert "``generate_from_behavioural_model``" in text
    assert "Deprecated" in text and "``resume_takes_no_description``" in text
    instructions = build_instructions("developer", "user")
    assert "needs_answers" in instructions
    for term in ("generate_from_behavioural_model", "resume_takes_no_description",
                 "dry_run=true", 'view="status", wait_seconds=50', "next_offset"):
        assert term in instructions, term
    assert "call `generate_threat_model` again" not in instructions


def test_the_resume_tool_says_what_it_takes_and_how_it_is_refused() -> None:
    text = _descriptions()["generate_from_behavioural_model"]
    assert "takes no description" in text
    for code in ("not_awaiting_generation", "generation_in_progress"):
        assert f"``{code}``" in text, code


def test_the_new_reads_publish_their_bounds() -> None:
    model = _descriptions()["get_behavioural_model"]
    for term in ('``view="status"``', "``wait_seconds`` (0 to 50)", "``waiting_on``",
                 "``poll_after_seconds``", "at most 200"):
        assert term in model, term
    threats = _descriptions()["get_behavioural_threats"]
    for term in ("``total``", "``next_offset``", "``truncated``", "default 25"):
        assert term in threats, term
    assert "``dry_run=True`` records nothing" in _descriptions()[
        "answer_behavioural_questions"]


def test_judgments_name_the_refusal_and_the_no_retry_rule() -> None:
    for name in ("answer_behavioural_questions", "edit_behavioural_element",
                 "confirm_behavioural_model", "declare_behavioural_link",
                 "accept_behavioural_link_proposals"):
        text = _descriptions()[name]
        assert "403" in text and "escalation_id" in text, name
        assert "Do not retry" in text, name


def test_a_programs_delta_is_never_a_persons_declaration() -> None:
    assert "never replaces a delta a person declared" in _descriptions()[
        "submit_control_delta"]
    text = " ".join(_descriptions()["declare_control_delta"].split())
    assert "403" in text and "escalation_id" in text and "Do not retry" in text
    assert "whatever the workspace delegates" in text


def test_the_second_reading_is_estimated_and_relayed_first() -> None:
    text = _descriptions()["request_delta_second_reading"]
    assert "confirm_estimate" in text and "RELAYED TO THE PERSON" in text
    assert "Never confirm on your own" in text


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
    assert "behavioural_delta_declared" in server._DECISION_KINDS
    assert "behavioural_cross_check_dismissed" in server._DECISION_KINDS


def test_a_cross_check_finding_is_relayed_and_dismissed_by_a_person() -> None:
    """A declared control's cross-check findings are relayed to the person,
    and no tool dismisses one: dismissing is a person's act."""
    delta = " ".join(_descriptions()["get_control_delta"].split())
    assert "RELAY OPEN FINDINGS TO THE PERSON" in delta
    assert "never a program's" in delta
    assert not any("dismiss" in name for name in _descriptions())
    sufficiency = " ".join(_descriptions()["get_sufficiency"].split())
    assert "``commitments``" in sufficiency and "declaration" in sufficiency
