"""The review playbook and run tools, the evidence a judgment carries, the run
header every write to a model carries, and the installable skill."""

import asyncio
import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx
from fastmcp.exceptions import ToolError

from mipiti_mcp import client as client_mod
from mipiti_mcp import server
from mipiti_mcp.client import MipitiClient, evidence_bound
from mipiti_mcp.skill_install import MARKER, InstallRefused, install

API = "https://test.api.mipiti.io"

#: The tools whose calls carry a judgment, so take the evidence it rests on.
JUDGMENT_TOOLS = {
    "decide_proposal", "decide_proposals", "decide_drift_intent", "decide_inventory_pair",
    "declare_inventory_tags", "apply_entity_proposals", "settle_entity_rating",
    "create_co_disposition", "revoke_co_disposition", "edit_assumption", "edit_attacker",
    "edit_trust_boundary", "submit_attestation", "answer_behavioural_questions",
    "accept_behavioural_link_proposals", "declare_behavioural_link", "add_proposed_attacker",
    "dismiss_proposed_attacker", "keep_attacker_whole", "split_grouped_attacker",
    "answer_attacker_credentials", "update_finding", "remediate_finding",
    "create_risk_acceptance", "confirm_behavioural_model", "answer_entity_question",
    "edit_asset", "add_assumption", "edit_behavioural_element", "remove_behavioural_element",
    "release_behavioural_element", "release_behavioural_elements",
    "accept_behavioural_proposal",
}

#: Tools whose description names a judgment without being one: they read, and
#: say what the judgments they list are.
_NAMES_JUDGMENTS_ONLY = {"get_threat_model", "get_review_queue", "list_co_dispositions",
                         "list_proposals", "list_decisions"}


def _tools() -> dict:
    return {t.name: t for t in asyncio.run(server.mcp.list_tools())}


def test_the_playbook_and_run_tools_are_registered():
    tools = _tools()
    assert {"get_review_playbook", "close_review_run", "get_review_run"} <= set(tools)


def test_every_judgment_tool_takes_evidence_and_says_so():
    tools = _tools()
    for name in JUDGMENT_TOOLS:
        prop = tools[name].parameters["properties"].get("evidence")
        assert prop is not None, name
        assert "citations this judgment rests on" in prop.get("description", ""), name


def test_every_tool_that_says_it_is_a_judgment_takes_evidence():
    """The list above is checked against the tools' own words, so a judgment
    tool added without ``evidence`` fails here rather than being parked for a
    person every time a rule requires evidence: any tool whose description
    says it is a judgment takes it, unless it only reads and names them."""
    import re

    tools = _tools()
    saying = {name for name, t in tools.items()
              if re.search(r"\bis a judgment\b|\ba judgment \(|\bare judgments\b",
                           t.description or "")}
    missing = sorted(n for n in saying - _NAMES_JUDGMENTS_ONLY
                     if "evidence" not in tools[n].parameters["properties"])
    assert not missing, f"judgment tools without evidence: {missing}"


def test_the_instructions_send_an_agent_to_the_playbook():
    text = server.build_instructions("pro")
    assert "get_review_playbook" in text and "close_review_run" in text


@pytest.mark.asyncio
async def test_a_judgment_tool_binds_its_evidence_for_the_call():
    cited = [{"kind": "code", "path": "src/auth.py", "lines": "40-52"}]
    seen = {}

    async def decide(*a, **k):
        seen["bound"] = client_mod._evidence.get()
        return {"proposal": {}, "effect": {}}

    fake = AsyncMock()
    fake.decide_proposal = decide
    with patch("mipiti_mcp.server._get_client", return_value=fake):
        await server.decide_proposal(server_version="0", model_id="m1", proposal_id="p1",
                                     decision="accept", evidence=json.dumps(cited))
    assert seen["bound"] == cited
    assert client_mod._evidence.get() is None


@pytest.mark.asyncio
async def test_malformed_evidence_is_refused_before_any_call():
    fake = AsyncMock()
    with patch("mipiti_mcp.server._get_client", return_value=fake):
        with pytest.raises(ToolError):
            await server.decide_proposal(server_version="0", model_id="m1", proposal_id="p1",
                                         decision="accept", evidence="not json")
    fake.decide_proposal.assert_not_called()


@respx.mock
@pytest.mark.asyncio
async def test_writes_carry_the_held_run_and_the_evidence_in_their_body():
    c = MipitiClient(api_key="k", api_url=API)
    c.hold_run("m1", "run-12345678")
    route = respx.post(f"{API}/api/models/m1/proposals/p1/decide").mock(
        return_value=httpx.Response(200, json={"proposal": {}, "effect": {}}))
    long = [{"kind": "quote", "source": "description", "text": "x" * 1900}] * 10
    with evidence_bound(long):
        await c.decide_proposal("m1", "p1", "accept")
    req = route.calls.last.request
    assert req.headers["Mipiti-Review-Run"] == "run-12345678"
    body = json.loads(req.content)
    assert body["decision"] == "accept" and body["citations"] == long
    assert not any(h.lower() == "mipiti-evidence" for h in req.headers)


@respx.mock
@pytest.mark.asyncio
async def test_a_write_that_would_drop_bound_evidence_is_refused():
    c = MipitiClient(api_key="k", api_url=API)
    respx.post(f"{API}/api/models/m1/anything").mock(return_value=httpx.Response(200, json={}))
    with evidence_bound([{"kind": "url", "url": "https://example.com/doc"}]):
        with pytest.raises(RuntimeError, match="drop the judgment's evidence"):
            await c._get_client().post(f"{API}/api/models/m1/anything", json={"a": 1})


@respx.mock
@pytest.mark.asyncio
@pytest.mark.usefixtures("real_run_lookup")
async def test_a_write_with_no_held_run_finds_the_open_one_once():
    c = MipitiClient(api_key="k", api_url=API)
    current = respx.get(f"{API}/api/models/m1/review-runs/current").mock(
        return_value=httpx.Response(200, json={"id": "run-abcdefgh", "open": True}))
    route = respx.post(f"{API}/api/models/m1/proposals/p1/decide").mock(
        return_value=httpx.Response(200, json={"proposal": {}, "effect": {}}))
    await c.decide_proposal("m1", "p1", "accept")
    await c.decide_proposal("m1", "p1", "accept")
    assert current.call_count == 1
    assert all(call.request.headers["Mipiti-Review-Run"] == "run-abcdefgh"
               for call in route.calls)
    # Held across clients of the same credential (a hosted server makes one
    # per request), and not across credentials.
    assert MipitiClient(api_key="k", api_url=API).held_run("m1") == "run-abcdefgh"
    assert MipitiClient(api_key="other", api_url=API).held_run("m1") == ""


@respx.mock
@pytest.mark.asyncio
@pytest.mark.usefixtures("real_run_lookup")
async def test_no_open_run_sends_no_header_and_is_not_asked_again_at_once():
    c = MipitiClient(api_key="k", api_url=API)
    current = respx.get(f"{API}/api/models/m1/review-runs/current").mock(
        return_value=httpx.Response(404, json={"detail": "none"}))
    route = respx.post(f"{API}/api/models/m1/proposals/p1/decide").mock(
        return_value=httpx.Response(200, json={"proposal": {}, "effect": {}}))
    await c.decide_proposal("m1", "p1", "accept")
    await c.decide_proposal("m1", "p1", "accept")
    assert current.call_count == 1
    assert all("Mipiti-Review-Run" not in call.request.headers for call in route.calls)


@respx.mock
@pytest.mark.asyncio
async def test_opening_a_run_holds_it_and_reads_carry_no_run():
    c = MipitiClient(api_key="k", api_url=API)
    opened = respx.post(f"{API}/api/models/m1/review-runs").mock(
        return_value=httpx.Response(201, json={"id": "run-opened1", "open": True}))
    read = respx.get(f"{API}/api/models/m1/proposals").mock(
        return_value=httpx.Response(200, json={"items": []}))
    await c.open_review_run("m1")
    await c.list_proposals("m1")
    assert "Mipiti-Review-Run" not in opened.calls.last.request.headers
    assert "Mipiti-Review-Run" not in read.calls.last.request.headers
    assert c.held_run("m1") == "run-opened1"


@respx.mock
@pytest.mark.asyncio
async def test_closing_a_run_stops_holding_it():
    c = MipitiClient(api_key="k", api_url=API)
    c.hold_run("m1", "run-12345678")
    respx.post(f"{API}/api/models/m1/review-runs/run-12345678/close").mock(
        return_value=httpx.Response(200, json={"run": {"id": "run-12345678"}}))
    await c.close_review_run("m1", "run-12345678", "done")
    assert c.held_run("m1") == ""


@pytest.mark.asyncio
async def test_the_playbook_tool_reuses_an_open_run_or_opens_one():
    fake = AsyncMock()
    fake.get_review_playbook = AsyncMock(return_value={"revision": 1, "open": []})
    fake.current_review_run = AsyncMock(return_value=None)
    fake.open_review_run = AsyncMock(return_value={"id": "run-new00001"})
    fake.hold_run = lambda *a: None
    with patch("mipiti_mcp.server._get_client", return_value=fake):
        got = await server.get_review_playbook(server_version="0", model_id="m1")
    assert got["review_run"]["id"] == "run-new00001" and got["revision"] == 1
    fake.current_review_run = AsyncMock(return_value={"id": "run-old00001"})
    fake.open_review_run = AsyncMock()
    with patch("mipiti_mcp.server._get_client", return_value=fake):
        got = await server.get_review_playbook(server_version="0", model_id="m1")
    assert got["review_run"]["id"] == "run-old00001"
    fake.open_review_run.assert_not_called()


@pytest.mark.asyncio
async def test_closing_with_no_run_says_how_to_open_one():
    fake = AsyncMock()
    fake.held_run = lambda m: ""
    fake.current_review_run = AsyncMock(return_value=None)
    with patch("mipiti_mcp.server._get_client", return_value=fake):
        with pytest.raises(ToolError, match="get_review_playbook"):
            await server.close_review_run(server_version="0", model_id="m1")


def test_install_writes_the_skill_and_replaces_only_its_own(tmp_path):
    dest = install(tmp_path)
    assert dest == tmp_path / ".agents/skills/mipiti-review/SKILL.md"
    assert MARKER in dest.read_text() and "get_review_playbook" in dest.read_text()
    assert install(tmp_path) == dest
    for agent, where in (("claude", ".claude"), ("gemini", ".gemini"), ("copilot", ".github")):
        assert install(tmp_path, target=agent) == tmp_path / where / "skills/mipiti-review/SKILL.md"
    own = tmp_path / "mine"
    (own / "mipiti-review").mkdir(parents=True)
    (own / "mipiti-review" / "SKILL.md").write_text("my own skill")
    with pytest.raises(InstallRefused):
        install(tmp_path, directory=own)
    assert (own / "mipiti-review" / "SKILL.md").read_text() == "my own skill"


@pytest.mark.parametrize("link", ["skills_dir", "skill_dir", "file"])
def test_install_never_writes_through_a_planted_link(tmp_path, link):
    """A repository can carry symbolic links: the skill is never written
    through one, and the place a link points at is left untouched."""
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "SKILL.md").write_text(f"{MARKER} planted")
    repo = tmp_path / "repo"
    skills = repo / ".agents" / "skills"
    if link == "skills_dir":
        skills.parent.mkdir(parents=True)
        skills.symlink_to(outside, target_is_directory=True)
    elif link == "skill_dir":
        skills.mkdir(parents=True)
        (skills / "mipiti-review").symlink_to(outside, target_is_directory=True)
    else:
        (skills / "mipiti-review").mkdir(parents=True)
        (skills / "mipiti-review" / "SKILL.md").symlink_to(outside / "SKILL.md")
    with pytest.raises(InstallRefused, match="symbolic link"):
        install(repo)
    assert (outside / "SKILL.md").read_text() == f"{MARKER} planted"


def test_install_never_writes_through_a_planted_temporary_name(tmp_path):
    """A link planted under the name a temporary file might take is never
    written through: the temporary file's name is fresh and created
    exclusively."""
    outside = tmp_path / "outside.txt"
    outside.write_text("untouched")
    skill_dir = tmp_path / "repo" / ".agents" / "skills" / "mipiti-review"
    skill_dir.mkdir(parents=True)
    for name in (".SKILL.md.tmp", ".SKILL.md.x.tmp"):
        (skill_dir / name).symlink_to(outside)
    dest = install(tmp_path / "repo")
    assert outside.read_text() == "untouched"
    assert MARKER in dest.read_text() and not dest.is_symlink()


def test_install_refuses_a_folder_resolving_outside_the_project(tmp_path):
    """A relative --dir climbing out of the project resolves outside it and
    is refused; naming the same place absolutely is the person's choice."""
    from pathlib import Path

    repo = tmp_path / "repo"
    repo.mkdir()
    with pytest.raises(InstallRefused, match="outside"):
        install(repo, directory=Path("../elsewhere"))
    assert not (tmp_path / "elsewhere").exists()  # refused before anything was created
    assert install(repo, directory=tmp_path / "elsewhere") == (
        (tmp_path / "elsewhere").resolve() / "mipiti-review" / "SKILL.md")


@pytest.mark.parametrize("bad", [".", "..", "%2e%2e"])
@pytest.mark.asyncio
async def test_an_id_that_is_a_dot_segment_is_refused(bad):
    from mipiti_mcp.client import UnsafePath

    c = MipitiClient(api_key="k", api_url=API)
    with pytest.raises(UnsafePath):
        await c.get_review_run(bad, "run-1")
    with pytest.raises(UnsafePath):
        await c.close_review_run("m1", bad, "notes")


@pytest.mark.parametrize("bad,sent", [
    ("../admin", "/api/models/..%2Fadmin/review-runs/run-1"),
    ("m1/../../admin", "/api/models/m1%2F..%2F..%2Fadmin/review-runs/run-1"),
    ("m1?x=1", "/api/models/m1%3Fx%3D1/review-runs/run-1"),
])
@respx.mock
@pytest.mark.asyncio
async def test_an_id_holding_structure_stays_one_segment_of_its_endpoint(bad, sent):
    """An id with a slash, a query or a climb is sent as one encoded segment
    of the endpoint its tool calls: the API reads it as an id it does not
    have, never as another path."""
    route = respx.get(url__regex=r".*").mock(return_value=httpx.Response(200, json={}))
    c = MipitiClient(api_key="k", api_url=API)
    await c.get_review_run(bad, "run-1")
    assert route.calls.last.request.url.raw_path.decode() == sent


def test_install_says_a_system_refusal_in_one_line(tmp_path, monkeypatch, capsys):
    """A folder the system will not write (here read-only) is said in one
    line, with a failing exit code, not a traceback."""
    import os
    import stat

    from mipiti_mcp.skill_install import main

    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(stat.S_IRUSR | stat.S_IXUSR)
    monkeypatch.chdir(tmp_path)
    try:
        if os.access(locked, os.W_OK):
            pytest.skip("running as a user the permission bits do not bind")
        assert main(["--dir", str(locked)]) == 1
    finally:
        locked.chmod(stat.S_IRWXU)
    err = capsys.readouterr().err
    assert err.startswith("Could not install the skill at ") and "Traceback" not in err


def test_the_skill_ships_in_the_agent_skills_format():
    from mipiti_mcp.skill_install import SOURCE

    text = SOURCE.read_text()
    assert text.startswith("---\nname: mipiti-review\ndescription: ")
