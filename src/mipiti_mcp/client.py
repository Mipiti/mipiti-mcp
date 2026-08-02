"""Async HTTP client for the Mipiti API."""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from typing import Any, Awaitable, Callable, Optional

import httpx
from httpx_sse import aconnect_sse

# Transient error retry policy for mutating requests. Each retry reuses the
# same Idempotency-Key so the server's idempotency cache deduplicates them
# safely (Stripe-style pattern).
_RETRY_BACKOFFS = (0.5, 1.0, 2.0)
_TRANSIENT_STATUS_CODES = frozenset({502, 503, 504})
_TRANSIENT_EXCEPTIONS = (
    httpx.ConnectError,
    httpx.ReadError,
    httpx.RemoteProtocolError,
    httpx.WriteError,
    httpx.PoolTimeout,
)

from .types import (
    ChatResponse,
    ComplianceFramework,
    ComplianceReport,
    Control,
    ControlEvidence,
    ControlObjectivesResponse,
    ControlsResponse,
    DeleteControlResult,
    EvidenceActionResult,
    Finding,
    FindingsRisksReport,
    GenerateResult,
    ImportConfirmResult,
    ModelRiskView,
    ModelSummary,
    OkResult,
    RemediationApplyResult,
    RenameResult,
    ReviewQueueResponse,
    ScanPromptResult,
    SelectFrameworksResult,
    SubmitAssertionsResult,
    System,
    SystemRiskView,
    SystemSelectFrameworksResult,
    ThreatModel,
    VerificationReport,
    Workspace,
    _Base,
)

DEFAULT_API_URL = "https://api.mipiti.io"

ProgressCallback = Callable[[float, float, str], Awaitable[None]]
"""Signature: (progress, total, message) -> None.

progress/total represent completed work (0/6 = starting, 5.6/6 = 93%).
step_start: progress = step - 1 (previous step completed).
step_progress: progress = step - 1 + (sub_step - 1)/sub_total (fractional, sub_step is 1-indexed).
"""


class MipitiClient:
    """Thin async client that wraps the Mipiti REST + SSE API."""

    def __init__(
        self,
        api_key: str | None = None,
        api_url: str | None = None,
        auth_headers: dict[str, str] | None = None,
    ) -> None:
        self.api_key = api_key or os.environ.get("MIPITI_API_KEY", "")
        self.api_url = (
            api_url or os.environ.get("MIPITI_API_URL", DEFAULT_API_URL)
        ).rstrip("/")
        self._auth_headers = auth_headers
        if not self.api_key and not self._auth_headers:
            raise ValueError(
                "MIPITI_API_KEY is required. Set it as an environment variable "
                "or pass api_key to MipitiClient."
            )
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            headers = dict(self._auth_headers) if self._auth_headers else {"X-API-Key": self.api_key}
            # Tag every request as MCP-originated. The API reads this on the
            # create/generate path to attribute new models to the MCP surface
            # (source_system="mcp") instead of defaulting to "web". Uses
            # setdefault so an explicit caller-supplied value is preserved.
            headers.setdefault("X-Mipiti-Source-System", "mcp")
            self._client = httpx.AsyncClient(
                base_url=self.api_url,
                headers=headers,
                timeout=httpx.Timeout(
                    connect=10.0, read=120.0, write=10.0, pool=10.0
                ),
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    # ------------------------------------------------------------------
    # Internal helpers (return raw data)
    # ------------------------------------------------------------------

    async def _get(self, path: str, **kwargs: Any) -> Any:
        resp = await self._get_client().get(path, **kwargs)
        resp.raise_for_status()
        return resp.json()

    async def _request_with_idempotency(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: Any = None,
    ) -> httpx.Response:
        """Send a mutating HTTP request with an Idempotency-Key header and
        automatic retry on transient errors.

        A fresh UUID is generated once per logical call. All retry attempts
        within this call reuse the same key so the server-side idempotency
        cache safely deduplicates them. Retries fire on connect errors, read
        errors, write errors, pool timeouts, and 502/503/504 status codes,
        with backoff intervals 0.5s / 1s / 2s.

        The `json` keyword matches httpx's own API so this helper feels like
        the thin wrapper that it is.
        """
        idem_key = str(uuid.uuid4())
        headers = {"Idempotency-Key": idem_key}
        client = self._get_client()
        last_exc: Exception | None = None
        for attempt in range(len(_RETRY_BACKOFFS) + 1):
            try:
                if method == "POST":
                    resp = await client.post(path, json=json, params=params, headers=headers)
                elif method == "PATCH":
                    resp = await client.patch(path, json=json, params=params, headers=headers)
                elif method == "PUT":
                    resp = await client.put(path, json=json, params=params, headers=headers)
                elif method == "DELETE":
                    resp = await client.delete(path, params=params, headers=headers)
                else:
                    raise ValueError(f"Unsupported method for idempotent retry: {method}")
            except _TRANSIENT_EXCEPTIONS as exc:
                last_exc = exc
                if attempt >= len(_RETRY_BACKOFFS):
                    raise
                await asyncio.sleep(_RETRY_BACKOFFS[attempt])
                continue
            # Retry transient server errors
            if resp.status_code in _TRANSIENT_STATUS_CODES and attempt < len(_RETRY_BACKOFFS):
                await asyncio.sleep(_RETRY_BACKOFFS[attempt])
                continue
            return resp
        # Unreachable: either we returned, raised, or exhausted retries above
        if last_exc is not None:
            raise last_exc
        raise RuntimeError("Idempotent request retry exhausted without resolution")

    async def _post(self, path: str, body: dict | None = None, **kwargs: Any) -> Any:
        params = kwargs.pop("params", None)
        if kwargs:
            raise TypeError(f"Unexpected kwargs for _post: {list(kwargs)}")
        resp = await self._request_with_idempotency("POST", path, json=body, params=params)
        resp.raise_for_status()
        return resp.json()

    async def _patch(self, path: str, body: dict | None = None, **kwargs: Any) -> Any:
        params = kwargs.pop("params", None)
        if kwargs:
            raise TypeError(f"Unexpected kwargs for _patch: {list(kwargs)}")
        resp = await self._request_with_idempotency("PATCH", path, json=body, params=params)
        resp.raise_for_status()
        return resp.json()

    async def _put(self, path: str, body: dict, **kwargs: Any) -> Any:
        params = kwargs.pop("params", None)
        if kwargs:
            raise TypeError(f"Unexpected kwargs for _put: {list(kwargs)}")
        resp = await self._request_with_idempotency("PUT", path, json=body, params=params)
        resp.raise_for_status()
        return resp.json()

    async def _delete(self, path: str, **kwargs: Any) -> Any:
        params = kwargs.pop("params", None)
        if kwargs:
            raise TypeError(f"Unexpected kwargs for _delete: {list(kwargs)}")
        resp = await self._request_with_idempotency("DELETE", path, params=params)
        resp.raise_for_status()
        if resp.status_code == 204:
            return None
        return resp.json()

    # ------------------------------------------------------------------
    # SSE stream consumer (generate / refine / query)
    # ------------------------------------------------------------------

    async def _stream_model(
        self,
        messages: list[dict[str, str]],
        model_id: str | None = None,
        force_generate: bool = False,
        parent_id: str | None = None,
        on_progress: ProgressCallback | None = None,
    ) -> dict[str, Any]:
        """POST /api/model/stream, consume SSE events, return final payload.

        Return shape is one of:
        - ``{"result": ...}``-shaped dict (normal generate/refine path)
        - ``{"chat_response": ...}``-shaped dict (query/general path)
        - ``{"similar_models": [...]}`` when the backend short-circuits
          generation because the feature description matches existing
          models in the workspace. Caller can retry with
          ``force_generate=True`` or pick a candidate to refine
          instead.
        """
        body: dict[str, Any] = {"messages": messages}
        if model_id:
            body["model_id"] = model_id
        if force_generate:
            body["force_generate"] = True
        if parent_id:
            body["parent_id"] = parent_id

        # Generate a fresh Idempotency-Key for this stream request. The
        # streaming endpoint handles caching directly (the global middleware
        # excludes /api/model/stream). On retry within the cache TTL, the
        # server replays the captured SSE bytes verbatim.
        idem_key = str(uuid.uuid4())

        client = self._get_client()
        result_data: dict[str, Any] | None = None
        chat_data: dict[str, Any] | None = None
        similar_data: dict[str, Any] | None = None

        async with aconnect_sse(
            client, "POST", "/api/model/stream", json=body,
            headers={"Idempotency-Key": idem_key},
        ) as event_source:
            async for sse in event_source.aiter_sse():
                event_type = sse.event
                if event_type == "step_start":
                    if on_progress:
                        data = json.loads(sse.data)
                        step = data.get("step", 0)
                        total = data.get("total_steps", 5)
                        title = data.get("title", "")
                        await on_progress(step - 1, total, title)
                elif event_type == "step_progress":
                    if on_progress:
                        data = json.loads(sse.data)
                        step = data.get("step", 0)
                        total = data.get("total_steps", 5)
                        sub = data.get("sub_step", 0)
                        sub_total = data.get("sub_total", 1)
                        detail = data.get("detail", "")
                        await on_progress(
                            step - 1 + (sub - 1) / sub_total, total, detail,
                        )
                elif event_type == "result":
                    result_data = json.loads(sse.data)
                elif event_type == "chat_response":
                    chat_data = json.loads(sse.data)
                elif event_type == "similar_models":
                    # Backend short-circuited: the feature description
                    # overlaps existing model(s) in the workspace.
                    # Caller retries with force_generate=True or
                    # refines a candidate. Stream closes after this
                    # event — there is no subsequent `result`.
                    similar_data = json.loads(sse.data)
                elif event_type == "error":
                    data = json.loads(sse.data)
                    raise RuntimeError(data.get("message", "Unknown error"))

        if chat_data:
            return chat_data
        if similar_data:
            # Normalize: tool callers look for this key.
            models = similar_data.get("models") or []
            return {"similar_models": list(models)}
        if result_data:
            return result_data
        raise RuntimeError("Stream ended without a result or response event")

    # ------------------------------------------------------------------
    # Threat Model CRUD
    # ------------------------------------------------------------------

    async def generate_threat_model(
        self,
        feature_description: str,
        force_generate: bool = False,
        parent_id: str | None = None,
        on_progress: ProgressCallback | None = None,
    ) -> GenerateResult | dict:
        """Returns a ``GenerateResult`` on normal generation, OR a raw
        ``{"similar_models": [{id, title, reason}, ...]}`` dict when
        the backend short-circuited because similar models already
        exist in the workspace. Pass ``force_generate=True`` to skip
        the similarity check and force a new generation.

        When ``parent_id`` is provided, the backend wires the new model
        under that parent on the recursive composition tree, so it
        inherits topology and participates in delta / inherited-credit
        composition.
        """
        data = await self._stream_model(
            [{"role": "user", "content": feature_description}],
            force_generate=force_generate,
            parent_id=parent_id,
            on_progress=on_progress,
        )
        if isinstance(data, dict) and "similar_models" in data:
            return data
        return GenerateResult.model_validate(data)

    async def refine_threat_model(
        self,
        model_id: str,
        instruction: str,
        on_progress: ProgressCallback | None = None,
    ) -> GenerateResult:
        data = await self._stream_model(
            [{"role": "user", "content": instruction}],
            model_id=model_id,
            on_progress=on_progress,
        )
        return GenerateResult.model_validate(data)

    async def query_threat_model(self, model_id: str, question: str) -> ChatResponse:
        data = await self._stream_model(
            [{"role": "user", "content": question}],
            model_id=model_id,
        )
        return ChatResponse.model_validate(data)

    async def list_models(
        self, source: str = "", include: str = "",
    ) -> list[ModelSummary]:
        params: dict[str, Any] = {}
        if source:
            params["source"] = source
        if include:
            params["include"] = include
        data = await self._get("/api/models", params=params)
        return [ModelSummary.model_validate(m) for m in data]

    async def get_model(self, model_id: str, version: int | None = None) -> ThreatModel:
        if version is not None:
            data = await self._get(f"/api/models/{model_id}/versions/{version}")
        else:
            data = await self._get(f"/api/models/{model_id}")
        return ThreatModel.model_validate(data)

    async def rename_model(self, model_id: str, name: str) -> RenameResult:
        data = await self._patch(f"/api/models/{model_id}", {"title": name})
        return RenameResult.model_validate(data)

    async def set_parent(
        self, model_id: str, parent_id: str | None,
    ) -> ThreatModel:
        """Set (or clear) a model's parent on the recursive composition tree.

        Calls ``PUT /api/models/{model_id}/parent``. ``parent_id=None``
        clears the parent. The backend rejects cycles and over-deep chains
        with 400. Bumps the model version on success.
        """
        data = await self._put(
            f"/api/models/{model_id}/parent",
            {"parent_id": parent_id},
        )
        return ThreatModel.model_validate(data)

    async def delete_model(self, model_id: str) -> None:
        await self._delete(f"/api/models/{model_id}")

    # --- Reliance / delegation (Foundation primitive) ---

    async def declare_foundation(
        self,
        model_id: str,
        provides: list[dict],
        visibility: str = "workspace",
    ) -> dict:
        """Mark a model as a shared foundation advertising providable controls.

        Calls ``PUT /api/models/{model_id}/foundation``.
        """
        return await self._put(
            f"/api/models/{model_id}/foundation",
            {"provides": provides, "visibility": visibility},
        )

    async def list_reliance(self, model_id: str) -> dict:
        """List cross-model dependency edges for a model (as consumer + provider)."""
        return await self._get(f"/api/models/{model_id}/reliance")

    async def create_reliance(
        self,
        model_id: str,
        provider_model_id: str,
        provider_control_id: str,
        mode: str,
        source_objective_id: str = "",
        source_control_id: str = "",
    ) -> dict:
        """Declare a cross-model dependency on a provider control.

        Calls ``POST /api/models/{model_id}/reliance``.
        """
        return await self._post(
            f"/api/models/{model_id}/reliance",
            {
                "provider_model_id": provider_model_id,
                "provider_control_id": provider_control_id,
                "mode": mode,
                "source_objective_id": source_objective_id,
                "source_control_id": source_control_id,
            },
        )

    async def confirm_reliance(
        self, edge_id: str, accept_partial_as_relied_upon: bool = False,
    ) -> dict:
        """Promote a draft reliance edge to active (post-validation gate)."""
        return await self._post(
            f"/api/reliance/{edge_id}/confirm",
            {"accept_partial_as_relied_upon": accept_partial_as_relied_upon},
        )

    async def delete_reliance(self, edge_id: str) -> None:
        await self._delete(f"/api/reliance/{edge_id}")

    async def propose_attach_foundation(
        self, model_id: str, foundation_model_id: str,
    ) -> dict:
        """Propose delegations from a consumer to a foundation (read-only)."""
        return await self._get(
            f"/api/models/{model_id}/attach-foundation/{foundation_model_id}/proposals",
        )

    async def attach_foundation(
        self, model_id: str, foundation_model_id: str, selections: list[dict],
    ) -> dict:
        """Create draft delegation edges for the selected (objective, control) pairs."""
        return await self._post(
            f"/api/models/{model_id}/attach-foundation",
            {"foundation_model_id": foundation_model_id, "selections": selections},
        )

    # --- Tags (Affiliation primitive — overlapping model grouping) ---

    async def list_tags(self) -> dict:
        """List the workspace's tags."""
        return await self._get("/api/tags")

    async def create_tag(
        self, name: str, description: str = "", model_ids: list[str] | None = None,
    ) -> dict:
        """Create a tag, optionally seeding it with member models."""
        return await self._post(
            "/api/tags",
            {"name": name, "description": description, "model_ids": model_ids or []},
        )

    async def delete_tag(self, tag_id: str) -> None:
        await self._delete(f"/api/tags/{tag_id}")

    async def add_model_to_tag(self, tag_id: str, model_id: str) -> dict:
        return await self._post(
            f"/api/tags/{tag_id}/models", {"model_id": model_id},
        )

    async def remove_model_from_tag(self, tag_id: str, model_id: str) -> None:
        await self._delete(f"/api/tags/{tag_id}/models/{model_id}")

    async def list_model_tags(self, model_id: str) -> dict:
        """List every tag a model belongs to (overlapping)."""
        return await self._get(f"/api/models/{model_id}/tags")

    async def get_tag_risk_view(self, tag_id: str) -> dict:
        """Aggregate per-CO risk rows across a tag's member models."""
        return await self._get(f"/api/tags/{tag_id}/risk-view")

    async def select_tag_compliance_frameworks(
        self, tag_id: str, framework_ids: list[str],
    ) -> dict:
        """Select compliance frameworks for a tag (scope-level), propagating to members."""
        return await self._post(
            f"/api/tags/{tag_id}/compliance/frameworks",
            {"framework_ids": framework_ids},
        )

    async def get_tag_compliance_report(
        self, tag_id: str, framework_id: str, level: int = 0,
    ) -> dict:
        """Cross-model compliance report scoped to a tag's members."""
        return await self._get(
            f"/api/tags/{tag_id}/compliance/{framework_id}/report",
            params={"level": level},
        )

    async def export_tag(self, tag_id: str, fmt: str = "html") -> str:
        """Fetch the signed auditor report (HTML) for a tag. Returns the body text."""
        resp = await self._get_client().get(
            f"/api/tags/{tag_id}/export", params={"format": fmt},
        )
        resp.raise_for_status()
        return resp.text

    async def start_export_model(self, model_id: str, fmt: str = "csv") -> str:
        """Kick off an async export job and return its job_id.

        The backend returns ``{"job_id": ...}`` immediately; callers poll
        ``get_operation(job_id)`` and fetch bytes via
        ``fetch_operation_result(job_id)`` once status is "completed".
        """
        data = await self._get(
            f"/api/models/{model_id}/export", params={"format": fmt},
        )
        return str(data["job_id"])

    async def start_export_model_full(self, model_id: str) -> str:
        """Kick off an async full-archive export job; return job_id."""
        data = await self._get(f"/api/models/{model_id}/export/full")
        return str(data["job_id"])

    async def fetch_operation_result(self, job_id: str) -> bytes:
        """Fetch the file bytes of a completed background job.

        The server's ``/api/operations/{job_id}/result`` endpoint decodes
        the base64-encoded payload from ``job.result`` and streams it
        with the original Content-Type. Callers are expected to have
        already polled ``get_operation`` until status="completed".
        """
        resp = await self._get_client().get(f"/api/operations/{job_id}/result")
        resp.raise_for_status()
        return resp.content

    async def import_model_full(self, envelope: dict, workspace_id: str) -> dict:
        """Import an audit archive envelope into the target workspace.

        Returns {"model_id": "<new id>"}. The caller must have write access
        to the target workspace; title collisions auto-suffix on the server.
        """
        return await self._post(
            "/api/models/import",
            {"envelope": envelope, "workspace_id": workspace_id},
        )

    # ------------------------------------------------------------------
    # Controls
    # ------------------------------------------------------------------

    async def get_controls(
        self, model_id: str, include_deleted: bool = False,
        include_orphaned: bool = False,
        control_id: str = "", status: str = "", co_id: str = "",
        component_id: str = "",
        offset: int = 0, limit: int = 0, summary_only: bool = False,
    ) -> ControlsResponse:
        params: dict[str, Any] = {}
        if include_deleted:
            params["include_deleted"] = "true"
        if include_orphaned:
            params["include_orphaned"] = "true"
        if summary_only:
            params["summary_only"] = "true"
        if control_id:
            params["control_id"] = control_id
        if status:
            params["status"] = status
        if co_id:
            params["co_id"] = co_id
        if component_id:
            params["component_id"] = component_id
        if offset:
            params["offset"] = offset
        if limit:
            params["limit"] = limit
        data = await self._get(f"/api/models/{model_id}/controls", params=params)
        return ControlsResponse.model_validate(data)

    async def get_control_generation_status(self, model_id: str) -> dict:
        """Async control-generation status for a model — the poll target after
        generate/refine returns ``controls_status`` other than complete."""
        return await self._get(f"/api/models/{model_id}/controls/status")

    async def regenerate_controls(
        self,
        model_id: str,
        mode: str = "batch",
        batch_size: int = 0,
        co_ids: list[str] | None = None,
    ) -> dict:
        body: dict = {"mode": mode}
        if batch_size > 0:
            body["batch_size"] = batch_size
        if co_ids is not None:
            body["co_ids"] = co_ids
        return await self._post(f"/api/models/{model_id}/controls/regenerate", body)

    async def update_control_status(
        self,
        model_id: str,
        control_id: str,
        status: str,
        implementation_notes: str = "",
    ) -> ThreatModel:
        body: dict[str, Any] = {
            "status": status,
            "implementation_notes": implementation_notes,
        }
        data = await self._patch(
            f"/api/controls/{control_id}",
            body,
            params={"model_id": model_id},
        )
        return ThreatModel.model_validate(data)

    async def start_refine_control(
        self,
        model_id: str,
        control_id: str,
        description: str,
        justification: str,
        codebase_findings: str = "",
    ) -> dict:
        """Kick off the AI-gated control refinement as a background job.

        The refinement re-evaluates whether every mapped control objective is
        still satisfied (a strong-LLM call that scales with the control's CO
        fan-out), so it runs as a job — POSTs the ``-job`` endpoint and returns
        ``{"job_id": ...}`` to poll rather than holding a synchronous request the
        MCP transport would drop. The job result is the response envelope
        (accepted refinement, or ``{accepted: false, reason, per_co}`` on
        semantic rejection).
        """
        body: dict[str, str] = {"justification": justification}
        if description:
            body["description"] = description
        if codebase_findings:
            body["codebase_findings"] = codebase_findings
        return await self._post(
            f"/api/models/{model_id}/controls/{control_id}/refine-job", body,
        )

    async def remap_control(
        self,
        model_id: str,
        control_id: str,
        co_ids: list[str],
        change_reason: str,
    ) -> dict:
        """Mechanical (non-AI-gated) remap of a control's CO mappings.

        Distinct from refine_control (AI-gated description edit).
        Rejects target co_ids that are tombstoned (removed=True) or
        do not exist on the model.
        """
        body: dict[str, Any] = {
            "co_ids": list(co_ids),
            "change_reason": change_reason,
        }
        resp = await self._request_with_idempotency(
            "PATCH",
            f"/api/models/{model_id}/controls/{control_id}/co-mapping",
            json=body,
        )
        resp.raise_for_status()
        return resp.json()

    async def apply_control_changeset(
        self,
        model_id: str,
        ops: list[dict],
        change_reason: str,
    ) -> dict:
        """Apply a batch of control operations atomically as one transaction.

        Ops (remap / delete / add / set_groups) all commit together or not at
        all. Mapping-only — never re-authors a control's description, so kept or
        reused controls keep their status, evidence, and assertions. The orphan
        guard is evaluated on the final post-changeset state, so a delete paired
        with a covering remap/add in the same batch is allowed.
        """
        body: dict[str, Any] = {
            "ops": list(ops),
            "change_reason": change_reason,
        }
        resp = await self._request_with_idempotency(
            "POST",
            f"/api/models/{model_id}/controls/changeset",
            json=body,
        )
        resp.raise_for_status()
        return resp.json()

    async def assign_control_to_components(
        self,
        model_id: str,
        control_id: str,
        component_ids: list[str],
        change_reason: str,
    ) -> dict:
        """Replace the control's component scope with the supplied list.

        Empty list → unscoped (visible to every coding agent regardless
        of repo). Single-element list → standard per-component scope.
        Multi-element list → cross-cutting control spanning multiple
        components.

        Validates that every supplied component_id exists on the model.
        """
        body: dict[str, Any] = {
            "component_ids": list(component_ids),
            "change_reason": change_reason,
        }
        resp = await self._request_with_idempotency(
            "PATCH",
            f"/api/models/{model_id}/controls/{control_id}/components",
            json=body,
        )
        resp.raise_for_status()
        return resp.json()

    async def assign_asset_to_components(
        self,
        model_id: str,
        asset_id: str,
        component_ids: list[str],
        change_reason: str,
    ) -> dict:
        """Replace an asset's component scope with the supplied list.

        Mirror of ``assign_control_to_components`` for assets. Empty
        list → unscoped (no explicit code-ownership binding); single
        element → standard case; multi-element → multi-instance asset
        flowing through several components (e.g., a session token on
        client + cache + DB).

        Validates that every supplied component_id exists on the
        model. Mechanical, non-AI-gated.
        """
        body: dict[str, Any] = {
            "component_ids": list(component_ids),
            "change_reason": change_reason,
        }
        resp = await self._request_with_idempotency(
            "PATCH",
            f"/api/models/{model_id}/assets/{asset_id}/components",
            json=body,
        )
        resp.raise_for_status()
        return resp.json()

    async def model_coherence_report(
        self, model_id: str, co_id: str = "",
    ) -> dict:
        """Static-analysis report on coherence between the model's
        component declarations and the code-binding strings on its
        controls and assertions.

        Returns ``{model_id, model_version, components_count, findings,
        summary}``. ``findings`` is a list of warning records, each with
        ``type``, ``severity``, and a human-readable ``message``.

        When ``co_id`` is set, the server filters findings to those
        carrying that CO id and returns 404 if the CO doesn't exist.
        """
        params = {"co_id": co_id} if co_id else None
        resp = await self._get_client().get(
            f"/api/models/{model_id}/coherence", params=params,
        )
        resp.raise_for_status()
        return resp.json()

    async def model_reachability_verdicts(
        self, model_id: str, co_id: str = "",
    ) -> dict:
        """Composer verdicts for every live CO on the model.

        Pure derivation from the model's structural primitives; not
        persisted on the CO. Returns ``{model_id, model_version,
        verdicts}`` where each verdict carries ``co_id``, ``kind``
        ("reachable" | "unreachable" | "indeterminate"), ``reason``
        (structural label), ``narration``, and (when applicable)
        ``boundary_id`` / ``assumption_id``.

        When ``co_id`` is set, the server returns a single verdict
        (the composer is per-CO; the cross-CO loop is skipped). 404
        if the CO doesn't exist or is tombstoned.
        """
        params = {"co_id": co_id} if co_id else None
        resp = await self._get_client().get(
            f"/api/models/{model_id}/reachability", params=params,
        )
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Composition (recursive-tree effective model) — read-only.
    # Gated by ``TREE_COMPOSITION_ENABLED`` on the backend. When the flag
    # is off, each endpoint returns a stable empty body with
    # ``flag_enabled: false`` so callers can render a disabled state
    # without a separate code path.
    # ------------------------------------------------------------------

    async def composition_index(self, model_id: str) -> dict:
        """Composition index — counts + tree metadata + structural warnings.

        Cheapest fetch (~1-2KB). Returns ``{model_id, model_version,
        flag_enabled, tree: {parent_id, ancestor_chain, depth, child_ids},
        counts: {entities, control_objectives, reconciliation_candidates},
        warnings}``.
        """
        resp = await self._get_client().get(
            f"/api/models/{model_id}/composition",
        )
        resp.raise_for_status()
        return resp.json()

    async def composition_entities(
        self,
        model_id: str,
        page: int = 1,
        page_size: int = 100,
        kind: str | None = None,
    ) -> dict:
        """Effective entity set (own ⊕ inherited) keyed by kind.

        Returns ``{model_id, flag_enabled, kinds: {trust_boundaries: [...],
        components: [...], assets: [...], attackers: [...], ...}, total,
        page, page_size}``. Each entry carries ``{kind, qualified_id,
        owner_model_id, owner_title, origin, entity}``.

        ``page`` / ``page_size`` paginate the entries (defaults
        ``page=1, page_size=100``). ``kind`` restricts to a single entity
        kind (e.g. ``"attackers"``).
        """
        params: dict[str, Any] = {"page": page, "page_size": page_size}
        if kind:
            params["kind"] = kind
        resp = await self._get_client().get(
            f"/api/models/{model_id}/composition/entities",
            params=params,
        )
        resp.raise_for_status()
        return resp.json()

    async def composition_control_objectives(self, model_id: str) -> dict:
        """Effective control objectives with origin classification.

        Returns ``{model_id, flag_enabled, control_objectives: [{co_qid,
        asset_qid, attacker_qid, security_properties, origin}, ...]}``.
        """
        resp = await self._get_client().get(
            f"/api/models/{model_id}/composition/control-objectives",
        )
        resp.raise_for_status()
        return resp.json()

    async def composition_coverage(
        self,
        model_id: str,
        page: int = 1,
        page_size: int = 100,
        origin: str | None = None,
    ) -> dict:
        """Effective coverage rollup with credited inheritance.

        Per CO: ``{co_qid, is_covered, own_credit, inherited_credit,
        contributing_controls: [{control_id, owner_model_id, origin,
        is_verified, mitigation_group}, ...]}``.

        ``page`` / ``page_size`` paginate the coverage rows (defaults
        ``page=1, page_size=100``). ``origin`` filters by contributing-
        control origin — one of ``"own" | "cross" | "inherited"``.
        """
        params: dict[str, Any] = {"page": page, "page_size": page_size}
        if origin:
            params["origin"] = origin
        resp = await self._get_client().get(
            f"/api/models/{model_id}/composition/coverage",
            params=params,
        )
        resp.raise_for_status()
        return resp.json()

    async def composition_reachability(
        self,
        model_id: str,
        page: int = 1,
        page_size: int = 100,
        kind_filter: str | None = None,
    ) -> dict:
        """Per-CO reachability verdicts over the composed effective topology.

        Returns ``{model_id, flag_enabled, verdicts: [{co_qid, asset_qid,
        attacker_qid, kind, reason}, ...]}``.

        ``page`` / ``page_size`` paginate the verdicts (defaults
        ``page=1, page_size=100``). ``kind_filter`` restricts the result
        to one verdict kind — one of
        ``"reachable" | "unreachable" | "indeterminate"``. Named
        ``kind_filter`` (not ``kind``) to disambiguate from the verdict's
        own ``kind`` field.
        """
        params: dict[str, Any] = {"page": page, "page_size": page_size}
        if kind_filter:
            params["kind_filter"] = kind_filter
        resp = await self._get_client().get(
            f"/api/models/{model_id}/composition/reachability",
            params=params,
        )
        resp.raise_for_status()
        return resp.json()

    async def composition_attack_paths(self, model_id: str) -> dict:
        """Effective AttackPath set + lifted suggestion compute.

        Returns ``{model_id, flag_enabled, effective_paths, lattice_positions,
        authored_paths, suggestions: {missing_path, dangling_path}}``.
        """
        resp = await self._get_client().get(
            f"/api/models/{model_id}/composition/attack-paths",
        )
        resp.raise_for_status()
        return resp.json()

    async def composition_reconciliation(
        self, model_id: str, page: int = 1, page_size: int = 50,
    ) -> dict:
        """Reconciliation candidates with origin/heuristic tiers.

        Paginated. Returns ``{model_id, flag_enabled, total, tiers:
        {certain, heuristic}, page, page_size, candidates: [{kind, own_qid,
        inherited_qid, tier, reasons}, ...]}``.
        """
        params = {"page": page, "page_size": page_size}
        resp = await self._get_client().get(
            f"/api/models/{model_id}/composition/reconciliation",
            params=params,
        )
        resp.raise_for_status()
        return resp.json()

    async def apply_certain_reconciliation_match(
        self,
        model_id: str,
        kind: str,
        own_qid: str,
        inherited_qid: str,
        confirm_heuristic: bool = False,
    ) -> dict:
        """POST /api/models/{model_id}/composition/reconciliation/apply-match.

        Mutating. Soft-deletes the descendant's own duplicate entity so
        the inherited entity becomes the canonical surface for the
        effective-model resolver. The server re-validates the candidate
        against current live state.

        By default heuristic-tier matches are refused; pass
        ``confirm_heuristic=True`` to acknowledge the structural
        divergence and apply a heuristic-tier candidate anyway.

        Returns the post-mutation model envelope:
        ``{"model": <ThreatModel>, "controls_carried": int,
        "controls_orphaned": int, "orphaned_control_ids": [str, ...]}``.

        Errors: 400 if the candidate is stale, or heuristic-tier
        without ``confirm_heuristic``; 404 if the model is missing;
        503 if composition is disabled.
        """
        body: dict[str, Any] = {
            "kind": kind,
            "own_qid": own_qid,
            "inherited_qid": inherited_qid,
        }
        if confirm_heuristic:
            body["confirm_heuristic"] = True
        return await self._post(
            f"/api/models/{model_id}/composition/reconciliation/apply-match",
            body,
        )

    async def reject_reconciliation_candidate(
        self,
        model_id: str,
        kind: str,
        own_qid: str,
        inherited_qid: str,
    ) -> dict:
        """POST /api/models/{model_id}/composition/reconciliation/reject.

        Records the operator's "these are NOT duplicates" decision at
        org scope. Idempotent on the natural key ``(model_id, kind,
        own_qid, inherited_qid)`` — re-rejecting an existing pair
        returns the same row. The candidate detector consults this
        store on subsequent reads, so the decision is durable across
        sessions and teammates.

        Does NOT bump model version (rejection is org state, not model
        state).

        Returns the persisted record::

            {"id": str, "model_id": str, "kind": str, "own_qid": str,
             "inherited_qid": str, "rejected_by": str,
             "rejected_at": <ISO-8601>}

        Errors: 400 if the body is missing fields; 404 if the model is
        missing; 503 if composition is disabled or the rejection store
        is not configured.
        """
        return await self._post(
            f"/api/models/{model_id}/composition/reconciliation/reject",
            {
                "kind": kind,
                "own_qid": own_qid,
                "inherited_qid": inherited_qid,
            },
        )

    async def unreject_reconciliation_candidate(
        self,
        model_id: str,
        rejection_id: str,
    ) -> dict:
        """DELETE /api/models/{model_id}/composition/reconciliation/reject/{rejection_id}.

        Removes a previously-persisted rejection by its surrogate id.
        The pair becomes eligible to surface in the active candidate
        queue again on the next read. Does NOT bump model version.

        Returns ``{"ok": True}`` on success.

        Errors: 404 if no rejection with that id exists on the model;
        503 if composition is disabled or the rejection store is not
        configured.
        """
        return await self._delete(
            f"/api/models/{model_id}/composition/reconciliation/reject/{rejection_id}",
        )

    async def list_reconciliation_rejections(self, model_id: str) -> dict:
        """GET /api/models/{model_id}/composition/reconciliation/rejections.

        Lists persisted rejections for a model in ``rejected_at``
        ascending order. Used to render the "Rejected" section of the
        triage view and to surface unreject affordances.

        Returns ``{"model_id": str, "flag_enabled": bool, "rejections":
        [<rejection>, ...]}``. ``flag_enabled: false`` (with an empty
        list) when ``TREE_COMPOSITION_ENABLED`` is off; the same empty
        shape is returned with ``flag_enabled: true`` when the
        rejection store is not configured.
        """
        resp = await self._get_client().get(
            f"/api/models/{model_id}/composition/reconciliation/rejections",
        )
        resp.raise_for_status()
        return resp.json()

    async def lift_composition_entity(
        self,
        model_id: str,
        kind: str,
        local_id_a: str,
        local_id_b: str,
        descendant_a_id: str,
        descendant_b_id: str,
        lca_model_id: str,
        *,
        lca_descendant_ids: list[str] | None = None,
        acknowledged_third_party_subtrees: list[str] | None = None,
        field_resolutions: dict[str, str] | None = None,
        attached_state_resolutions: dict[str, str] | None = None,
        skip_overapplication_gate: bool = False,
    ) -> dict:
        """POST /api/models/{model_id}/composition/lift.

        Promote a shared-anchor entity from two sibling descendants to
        their lowest common ancestor. The route's ``model_id`` is the
        operator's context model (the model whose composition view
        surfaced the candidate) — it doesn't have to be the LCA.

        The server re-detects conflicts against current live state and
        refuses if new conflicts surfaced that aren't covered by the
        operator's ``field_resolutions`` / ``attached_state_resolutions``.
        It also re-runs the over-application gate against the LCA's
        descendant set; pass ``skip_overapplication_gate=True`` after
        explicit operator acknowledgement.

        Returns ``{"lift_id": str, "lca_model": <ThreatModel>,
        "descendant_a_model": <ThreatModel>,
        "descendant_b_model": <ThreatModel>,
        "applied_migrations": [...], "lift_event": {...}}``. The
        ``lift_event`` block matches the structured activity payload the
        audit pack surfaces under ``lift_history``.

        Errors: 400 if required fields are missing, the kind isn't in
        ``{assets, attackers, components}``, no LCA exists, conflict
        resolutions are stale, or the lift itself is structurally
        refused; 404 if the route model or either source descendant is
        missing; 503 if ``TREE_COMPOSITION_ENABLED`` is off.
        """
        body: dict = {
            "kind": kind,
            "local_id_a": local_id_a,
            "local_id_b": local_id_b,
            "descendant_a_id": descendant_a_id,
            "descendant_b_id": descendant_b_id,
            "lca_model_id": lca_model_id,
        }
        if lca_descendant_ids is not None:
            body["lca_descendant_ids"] = list(lca_descendant_ids)
        if acknowledged_third_party_subtrees is not None:
            body["acknowledged_third_party_subtrees"] = list(
                acknowledged_third_party_subtrees,
            )
        if field_resolutions is not None:
            body["field_resolutions"] = dict(field_resolutions)
        if attached_state_resolutions is not None:
            body["attached_state_resolutions"] = dict(attached_state_resolutions)
        if skip_overapplication_gate:
            body["skip_overapplication_gate"] = True
        return await self._post(
            f"/api/models/{model_id}/composition/lift",
            body,
        )

    async def split_composition_entity(
        self,
        model_id: str,
        kind: str,
        ancestor_local_id: str,
        target_descendants: list[str],
    ) -> dict:
        """POST /api/models/{model_id}/composition/split.

        Push an ancestor-owned entity to one or more descendants,
        soft-deleting the ancestor's copy. The route's ``model_id`` IS
        the ancestor (the entity being split lives on it).

        Each affected model (ancestor + every target descendant) bumps
        version and emits a generic ``model_refined`` activity event;
        the structured ``split_event`` block is emitted on the ancestor
        only.

        Returns ``{"split_id": str, "ancestor_model": <ThreatModel>,
        "descendant_models": [<ThreatModel>, ...],
        "applied_duplications": [...], "split_event": {...}}``. The
        ``split_event`` block matches the structured activity payload
        the audit pack surfaces under ``split_history``.

        Errors: 400 if required fields are missing, the kind isn't in
        ``{assets, attackers, components}``, or the split itself is
        structurally refused; 404 if the ancestor or any target
        descendant is missing; 503 if ``TREE_COMPOSITION_ENABLED`` is
        off.
        """
        return await self._post(
            f"/api/models/{model_id}/composition/split",
            {
                "kind": kind,
                "ancestor_local_id": ancestor_local_id,
                "target_descendants": list(target_descendants),
            },
        )

    async def preview_lift_undo(self, model_id: str, lift_id: str) -> dict:
        """GET /api/models/{model_id}/composition/lift/{lift_id}/undo/preview.

        Compute + return the inverse-plan summary OR the divergence
        refusal for a prior ``lift_applied`` event WITHOUT applying.
        Used by the confirmation flow so the operator sees what an
        undo would do before committing.

        Body shape: ``{"plan": <UndoPlan> | null, "refusal":
        <UndoRefusal> | null}`` — exactly one is non-null. The plan
        block carries the inverse state operations (tombstone /
        restore / CO rewrites) the apply step would commit; the
        refusal block carries the enumerated divergence reasons when
        state has materially evolved.

        Errors: 404 if the cited event doesn't exist or belongs to a
        different model; 503 if ``TREE_COMPOSITION_ENABLED`` is off.
        """
        resp = await self._get_client().get(
            f"/api/models/{model_id}/composition/lift/{lift_id}/undo/preview",
        )
        resp.raise_for_status()
        return resp.json()

    async def undo_lift(self, model_id: str, lift_id: str) -> dict:
        """POST /api/models/{model_id}/composition/lift/{lift_id}/undo.

        Apply the inverse of a previous ``lift_applied`` event. Runs
        the divergence detector immediately before applying; refuses
        loudly when state has materially evolved.

        Returns ``{"undone_event_id": str, "original_event_id": str,
        "applied_state_ops": [...], "models": {"lca_model":
        <ThreatModel>, "source_descendant_models": [<ThreatModel>,
        ...]}}`` on success. The ``undone_event_id`` matches the
        ``lift_undone`` structured activity event the audit pack
        chains back to the original lift via ``original_event_id``.

        Errors: 409 with ``detail = {message, refusal: {reasons:
        [...]}}`` when the divergence detector refuses; 404 if the
        cited event doesn't exist or belongs to a different model;
        400 on payload / event-type mismatch; 503 if
        ``TREE_COMPOSITION_ENABLED`` is off.
        """
        return await self._post(
            f"/api/models/{model_id}/composition/lift/{lift_id}/undo",
        )

    async def preview_split_undo(self, model_id: str, split_id: str) -> dict:
        """GET /api/models/{model_id}/composition/split/{split_id}/undo/preview.

        Preview counterpart for split undo. Same ``{plan, refusal}``
        shape as ``preview_lift_undo``; the plan block carries the
        split-specific inverse operations (restore at ancestor,
        tombstone target copies) instead of the lift mirrors.
        """
        resp = await self._get_client().get(
            f"/api/models/{model_id}/composition/split/{split_id}/undo/preview",
        )
        resp.raise_for_status()
        return resp.json()

    async def undo_split(self, model_id: str, split_id: str) -> dict:
        """POST /api/models/{model_id}/composition/split/{split_id}/undo.

        Apply the inverse of a previous ``split_applied`` event.

        Returns ``{"undone_event_id": str, "original_event_id": str,
        "applied_state_ops": [...], "models": {"ancestor_model":
        <ThreatModel>, "descendant_models": [<ThreatModel>, ...]}}``
        on success.

        Errors: same shape as ``undo_lift`` — 409 on divergence
        refusal, 404 on missing event, 400 on type mismatch, 503 on
        flag off.
        """
        return await self._post(
            f"/api/models/{model_id}/composition/split/{split_id}/undo",
        )

    async def get_control_objective(self, model_id: str, co_id: str) -> dict:
        """Get a single control objective with its composer verdict."""
        resp = await self._get_client().get(
            f"/api/models/{model_id}/control-objectives/{co_id}",
        )
        resp.raise_for_status()
        return resp.json()

    async def get_asset(self, model_id: str, asset_id: str) -> dict:
        resp = await self._get_client().get(
            f"/api/models/{model_id}/assets/{asset_id}",
        )
        resp.raise_for_status()
        return resp.json()

    async def get_attacker(self, model_id: str, attacker_id: str) -> dict:
        resp = await self._get_client().get(
            f"/api/models/{model_id}/attackers/{attacker_id}",
        )
        resp.raise_for_status()
        return resp.json()

    async def get_component(self, model_id: str, component_id: str) -> dict:
        resp = await self._get_client().get(
            f"/api/models/{model_id}/components/{component_id}",
        )
        resp.raise_for_status()
        return resp.json()

    async def get_trust_boundary(self, model_id: str, tb_id: str) -> dict:
        resp = await self._get_client().get(
            f"/api/models/{model_id}/trust-boundaries/{tb_id}",
        )
        resp.raise_for_status()
        return resp.json()

    async def get_assumption(self, model_id: str, assumption_id: str) -> dict:
        resp = await self._get_client().get(
            f"/api/models/{model_id}/assumptions/{assumption_id}",
        )
        resp.raise_for_status()
        return resp.json()

    async def get_control(
        self, model_id: str, control_id: str, version: int = 0,
    ) -> dict:
        params = {"version": version} if version else None
        resp = await self._get_client().get(
            f"/api/models/{model_id}/controls/{control_id}", params=params,
        )
        resp.raise_for_status()
        return resp.json()

    async def restore_asset(self, model_id: str, asset_id: str) -> ThreatModel:
        """Un-soft-delete an asset. Tombstoned COs for that asset's
        pairs are revived at save-time with their original IDs."""
        data = await self._post(
            f"/api/models/{model_id}/assets/{asset_id}/restore", {},
        )
        return ThreatModel.model_validate(data)

    async def restore_attacker(self, model_id: str, attacker_id: str) -> ThreatModel:
        """Un-soft-delete an attacker. Tombstoned COs for that
        attacker's pairs are revived with their original IDs."""
        data = await self._post(
            f"/api/models/{model_id}/attackers/{attacker_id}/restore", {},
        )
        return ThreatModel.model_validate(data)

    async def get_mitigation_groups(
        self, model_id: str, co_id: str,
    ) -> dict:
        resp = await self._get_client().get(
            f"/api/models/{model_id}/control-objectives/{co_id}/mitigation-groups",
        )
        resp.raise_for_status()
        return resp.json()

    async def start_set_mitigation_groups(
        self,
        model_id: str,
        co_id: str,
        groups: dict,
        defense_in_depth: list[str],
        justification: str,
    ) -> dict:
        """Kick off the AI-gated mitigation-group authoring as a background job.

        The platform evaluates whether the proposed group structure satisfies
        the CO (a strong-LLM call), so it runs as a job — POSTs the ``-job``
        endpoint and returns ``{"job_id": ...}`` to poll rather than holding a
        synchronous request the MCP transport would drop. The job result is the
        response envelope.
        """
        body = {
            "groups": groups,
            "defense_in_depth": defense_in_depth,
            "justification": justification,
        }
        return await self._post(
            f"/api/models/{model_id}/control-objectives/{co_id}/mitigation-groups-job",
            body,
        )

    async def get_control_assumption_groups(
        self, model_id: str, control_id: str,
    ) -> dict:
        resp = await self._get_client().get(
            f"/api/models/{model_id}/controls/{control_id}/assumption-groups",
        )
        resp.raise_for_status()
        return resp.json()

    async def start_set_control_assumption_groups(
        self,
        model_id: str,
        control_id: str,
        groups: dict,
        justification: str,
    ) -> dict:
        """Kick off the AI-gated assumption-group authoring as a background job.

        Each non-empty proposed group is evaluated for relevance to the control
        (a strong-LLM call per group), so it runs as a job — POSTs the ``-job``
        endpoint and returns ``{"job_id": ...}`` to poll rather than holding a
        synchronous request the MCP transport would drop. The job result is the
        response envelope.
        """
        body = {
            "groups": groups,
            "justification": justification,
        }
        return await self._post(
            f"/api/models/{model_id}/controls/{control_id}/assumption-groups-job",
            body,
        )

    async def link_assumption(
        self, model_id: str, assumption_id: str, target_model_id: str,
    ) -> dict:
        resp = await self._request_with_idempotency(
            "POST",
            f"/api/models/{model_id}/assumptions/{assumption_id}/link",
            json={"target_model_id": target_model_id},
        )
        resp.raise_for_status()
        return resp.json()

    async def get_system_dependencies(self, system_id: str) -> dict:
        resp = await self._get_client().get(
            f"/api/systems/{system_id}/dependencies",
        )
        resp.raise_for_status()
        return resp.json()

    async def add_evidence(
        self,
        model_id: str,
        control_id: str,
        type: str = "code",
        label: str = "",
        url: str = "",
    ) -> EvidenceActionResult:
        data = await self._post(
            f"/api/models/{model_id}/controls/{control_id}/evidence",
            {"type": type, "label": label, "url": url},
        )
        return EvidenceActionResult.model_validate(data)

    async def remove_evidence(
        self, model_id: str, control_id: str, evidence_index: int,
    ) -> EvidenceActionResult:
        data = await self._delete(
            f"/api/models/{model_id}/controls/{control_id}/evidence/{evidence_index}"
        )
        return EvidenceActionResult.model_validate(data)

    async def start_import_preview(
        self,
        model_id: str,
        controls_json: str = "",
        free_text: str = "",
        source_label: str = "",
        auto_map: bool = True,
    ) -> dict:
        """Kick off the import preview (parse / auto-map / dedup) as a background
        job. Returns ``{"job_id": ...}`` to poll. The LLM work runs off the
        backend event loop, and polling keeps the transport warm instead of a
        10-30s silent request the MCP transport would time out."""
        body: dict[str, Any] = {"auto_map": auto_map}
        if controls_json:
            body["controls"] = json.loads(controls_json)
        if free_text:
            body["free_text"] = free_text
        if source_label:
            body["source_label"] = source_label
        return await self._post(
            f"/api/models/{model_id}/controls/import/preview-job", body
        )

    @staticmethod
    def build_import_controls(preview: dict) -> list[dict[str, Any]]:
        """Turn a preview result into the confirm payload: the parsed +
        auto-mapped controls, dropping any the preview flagged as duplicates of
        existing controls."""
        parsed = preview.get("parsed") or []
        duplicate_idxs = {d["import_idx"] for d in (preview.get("duplicates") or [])}
        mitigation_group_by_idx = {
            m["control_idx"]: m.get("mitigation_group")
            for m in (preview.get("mappings") or [])
        }
        return [
            {
                "description": item["description"],
                "co_ids": item.get("co_ids", []),
                "mitigation_group": mitigation_group_by_idx.get(idx),
                "status": item.get("status", "not_implemented"),
                "implementation_notes": item.get("implementation_notes", ""),
                "framework_refs": item.get("framework_refs", []),
            }
            for idx, item in enumerate(parsed)
            if idx not in duplicate_idxs
        ]

    async def import_confirm(
        self,
        model_id: str,
        controls: list[dict[str, Any]],
        source_label: str = "",
    ) -> ImportConfirmResult:
        """Persist the reviewed controls — the fast, stateless confirm step."""
        data = await self._post(
            f"/api/models/{model_id}/controls/import/confirm",
            {"controls": controls, "source_label": source_label},
        )
        return ImportConfirmResult.model_validate(data)

    async def delete_control(
        self, model_id: str, control_id: str, reason: str = "",
    ) -> DeleteControlResult:
        data = await self._delete(
            f"/api/models/{model_id}/controls/{control_id}",
            params={"reason": reason} if reason else {},
        )
        return DeleteControlResult.model_validate(data)

    async def check_control_gaps(self, model_id: str) -> dict:
        return await self._post(f"/api/models/{model_id}/controls/check-gaps")

    async def get_scan_prompt(
        self, model_id: str, control_id: str = "",
    ) -> ScanPromptResult:
        params = {}
        if control_id:
            params["control_id"] = control_id
        data = await self._get(
            f"/api/models/{model_id}/controls/scan-prompt", params=params,
        )
        return ScanPromptResult.model_validate(data)

    # ------------------------------------------------------------------
    # Control Objectives
    # ------------------------------------------------------------------

    async def get_control_objectives(
        self, model_id: str, offset: int = 0, limit: int = 0,
    ) -> ControlObjectivesResponse:
        params: dict[str, Any] = {}
        if offset:
            params["offset"] = offset
        if limit:
            params["limit"] = limit
        data = await self._get(f"/api/models/{model_id}/control-objectives", params=params)
        return ControlObjectivesResponse.model_validate(data)

    # ------------------------------------------------------------------
    # Assets & Attackers
    # ------------------------------------------------------------------

    async def start_add_asset(self, model_id: str, **kwargs: Any) -> dict:
        """Kick off an asset add as a background job; returns ``{"job_id": ...}``.

        The add is LLM-gated (restore-candidate + factor reasoning), so it runs
        as a job to keep the work off the backend event loop and the MCP
        transport warm. The job result is the same envelope the synchronous add
        returned — one of three shapes:

        1. Normal create:
           ``{"model": ThreatModel, "controls_carried": N, ...}``
        2. Auto-restore (LLM classified as ``same``):
           ``{"model": ThreatModel, "auto_restored": True,
              "restored_asset_id": "A-N", "reason": "...",
              "discarded_fields": [{"field", "proposed_value",
              "preserved_value", "reason", "identity_bearing"}, ...]}``
        3. Similar-verdict rejection:
           ``{"accepted": False, "classification": "similar",
              "candidate_restore_id": "A-N", "reason": "...",
              "suggestion": "..."}``

        HTTP 503 (evaluator unreachable) and 502 (evaluator returned
        malformed output) surface as a failed job; 503 means
        retry-with-backoff, 502 means retry-now.
        """
        return await self._post(f"/api/models/{model_id}/assets/add-job", kwargs)

    async def start_edit_asset(self, model_id: str, asset_id: str, **kwargs: Any) -> dict:
        """Kick off an asset edit as a background job; returns ``{"job_id": ...}``.

        Runs the LLM-gated edit as a job; the job result is the same envelope
        the synchronous edit returned — one of two shapes:

        1. Accepted edit (or non-identity edit skipped the AI gate):
           ``{"model": ThreatModel, "controls_carried": N, ...}``
        2. Semantic-preservation rejection:
           ``{"accepted": False, "classification": "replace"|"ambiguous",
              "reason": "...", "per_field": {...}, "suggestion": "..."}``

        HTTP 503 (evaluator unreachable) or 502 (evaluator returned
        malformed output) surface as a failed job with distinct signals.
        """
        return await self._post(
            f"/api/models/{model_id}/assets/{asset_id}/edit-job", kwargs,
        )

    async def remove_asset(self, model_id: str, asset_id: str) -> dict:
        """DELETE /assets/{id} soft-deletes. Returns the
        ``{"model": ThreatModel, ...}`` envelope; the asset stays in
        ``model.assets`` with ``deleted=True``.
        """
        return await self._delete(f"/api/models/{model_id}/assets/{asset_id}")

    async def start_add_attacker(self, model_id: str, **kwargs: Any) -> dict:
        """Kick off an attacker add as a background job; returns
        ``{"job_id": ...}``. Same three-shape job result as
        ``start_add_asset`` (normal create / auto-restore /
        similar-rejection) plus 503 on LLM outage."""
        return await self._post(f"/api/models/{model_id}/attackers/add-job", kwargs)

    async def start_edit_attacker(self, model_id: str, attacker_id: str, **kwargs: Any) -> dict:
        """Kick off an attacker edit as a background job; returns
        ``{"job_id": ...}``. Same two-shape job result as
        ``start_edit_asset`` (accepted edit / semantic rejection) plus 503
        on LLM outage."""
        return await self._post(
            f"/api/models/{model_id}/attackers/{attacker_id}/edit-job", kwargs,
        )

    async def remove_attacker(self, model_id: str, attacker_id: str) -> dict:
        """DELETE /attackers/{id} soft-deletes. Returns the envelope
        with the attacker now marked ``deleted=True`` in the model."""
        return await self._delete(f"/api/models/{model_id}/attackers/{attacker_id}")

    async def start_reevaluate_factors(
        self, model_id: str, change_reason: Optional[str] = None,
    ) -> dict:
        """Kick off the bulk factor re-evaluation as a background job.

        Bulk re-runs the LLM factor judgment on every live asset and attacker.
        It scales with entity count, so it runs as a job (returns
        ``{"job_id": ...}`` to poll) rather than a long synchronous request the
        MCP transport would time out. The job result is the response envelope:
        ``{"model_id", "assets_reevaluated", "attackers_reevaluated", "deltas":
        {"assets": [...], "attackers": [...]}, "failed_entities": [...]}`` —
        per-entity soft-fail (a single LLM error surfaces in ``failed_entities``
        and successful revisions still persist); the job fails only when every
        live entity failed. Body optional; an omitted ``change_reason`` defaults
        to ``"LLM factor re-evaluation"``. Soft-deleted entities are skipped.
        """
        body: dict[str, Any] = {}
        if change_reason is not None:
            body["change_reason"] = change_reason
        return await self._post(
            f"/api/models/{model_id}/factors/reevaluate-job", body,
        )

    async def revalidate_entities(self, model_id: str) -> dict:
        """POST /api/models/{model_id}/revalidate-entities.

        Re-runs quality validation over the model's live assets and attackers
        as if they were freshly generated: a fast first-pass check on every
        entity, with a deeper review of only the ones it flags (which confirms
        them, sharpens their wording, or flags them for review). Stale quality
        warnings are cleared first so previously-flagged entities are re-judged.

        Non-destructive: an entity that should be removed is left in place with
        a quality warning rather than deleted, so no control objective loses its
        asset/attacker anchor. The result is saved as a new model version
        (controls and control objectives carry forward). May consume credits for
        the entities that need the deeper review.

        Returns the entity-CRUD envelope: ``{"accepted": true, "model": {...}}``.
        """
        return await self._post(
            f"/api/models/{model_id}/revalidate-entities", {},
        )

    async def recompute_verdicts(self, model_id: str) -> dict:
        """POST /api/models/{model_id}/verdict-divergence/recompute.

        Force-enqueue a fresh evaluation of every control's coverage verdict
        and every live CO's group-sufficiency verdict, bypassing the normal
        quiet-period batching. Evaluation runs in the background.

        Returns ``{"model_id", "model_version", "enqueued_coverage",
        "enqueued_group_sufficiency", "total_enqueued", "estimated_credits",
        "quote", "governor"}``. Raises the backend's 503 when verdict
        observability is unavailable on the deployment.
        """
        return await self._post(
            f"/api/models/{model_id}/verdict-divergence/recompute", {},
        )

    async def get_recompute_quote(self, model_id: str) -> dict:
        """GET /api/models/{model_id}/verdict-divergence/recompute/quote.

        Informational pre-flight cost estimate for ``recompute_verdicts``.
        Nothing is charged from the estimate — actual usage is metered as the
        evaluation runs. Returns ``{"estimated_credits", "computed_at",
        "rate_version", "informational", "total_enqueueable",
        "already_evaluated", "governor"}``.
        """
        return await self._get(
            f"/api/models/{model_id}/verdict-divergence/recompute/quote",
        )

    async def retry_verdicts(self, model_id: str) -> dict:
        """POST /api/models/{model_id}/verdicts/retry.

        Re-trigger the model's parked/errored verdict re-evals — every kind —
        by clearing the failure budget on only the failed/backing-off slots so
        the worker re-runs them on the next tick. Non-destructive: no
        assertions, controls, or verdict content change.

        Returns ``{"model_id", "model_version", "retried_slots", "governor"}``.
        """
        return await self._post(
            f"/api/models/{model_id}/verdicts/retry", {},
        )

    # ------------------------------------------------------------------
    # Assurance
    # ------------------------------------------------------------------

    async def assess_model(
        self, model_id: str, summary_only: bool = False,
        status: str = "", offset: int = 0, limit: int = 0,
    ) -> _Base:
        params: dict[str, Any] = {}
        if summary_only:
            params["summary_only"] = "true"
        if status:
            params["status"] = status
        if offset:
            params["offset"] = offset
        if limit:
            params["limit"] = limit
        data = await self._post(f"/api/models/{model_id}/assess", params=params)
        return _Base.model_validate(data)

    async def get_review_queue(self) -> ReviewQueueResponse:
        data = await self._get("/api/review-queue")
        # API returns a raw list; wrap it
        if isinstance(data, list):
            return ReviewQueueResponse(items=data)
        return ReviewQueueResponse.model_validate(data)

    # ------------------------------------------------------------------
    # Compliance
    # ------------------------------------------------------------------

    async def list_compliance_frameworks(self) -> list[ComplianceFramework]:
        data = await self._get("/api/compliance/frameworks")
        return [ComplianceFramework.model_validate(f) for f in data]

    async def import_compliance_framework(self, framework: dict) -> dict:
        """Import a custom compliance framework (JSON body).

        The backend accepts ``application/json`` directly — no multipart
        needed for agent-driven imports. The dict must follow the schema:
        ``{"name": str, "version": str?, "description": str?,
        "level_definitions": {int: {name, description, source}}?,
        "requirements": [{"id", "description", "level"?,
        "level_specific_text"?, "chapter_id"?, ...}]}``.
        """
        return await self._post(
            "/api/compliance/frameworks/import", framework,
        )

    async def select_compliance_frameworks(
        self, model_id: str, framework_ids: list[str],
    ) -> SelectFrameworksResult:
        data = await self._post(
            f"/api/models/{model_id}/compliance/frameworks",
            {"framework_ids": framework_ids},
        )
        return SelectFrameworksResult.model_validate(data)

    async def get_compliance_report(
        self,
        model_id: str,
        framework_id: str,
        level: int | None = None,
        status: str = "",
        offset: int = 0,
        limit: int = 0,
    ) -> ComplianceReport:
        params: dict[str, Any] = {}
        if level is not None:
            params["level"] = level
        if status:
            params["status"] = status
        if offset:
            params["offset"] = offset
        if limit:
            params["limit"] = limit
        data = await self._get(
            f"/api/models/{model_id}/compliance/{framework_id}/report",
            params=params,
        )
        return ComplianceReport.model_validate(data)

    async def map_control_to_requirement(
        self,
        model_id: str,
        framework_id: str,
        requirement_id: str,
        control_id: str,
        confidence: str = "manual",
        notes: str = "",
    ) -> _Base:
        data = await self._post(
            f"/api/models/{model_id}/compliance/{framework_id}/mappings",
            {
                "requirement_id": requirement_id,
                "control_id": control_id,
                "confidence": confidence,
                "notes": notes,
            },
        )
        return _Base.model_validate(data)

    async def auto_map_controls(
        self,
        model_id: str,
        framework_id: str,
        control_id: str = "",
    ) -> dict:
        body: dict[str, Any] = {}
        if control_id:
            body["control_id"] = control_id
        return await self._post(
            f"/api/models/{model_id}/compliance/{framework_id}/auto-map", body,
        )

    async def suggest_compliance_remediation(
        self, model_id: str, framework_id: str,
    ) -> dict:
        return await self._post(
            f"/api/models/{model_id}/compliance/{framework_id}/remediate",
        )

    async def apply_compliance_remediation(
        self,
        model_id: str,
        framework_id: str,
        suggestions: list[dict] | None = None,
    ) -> RemediationApplyResult:
        body: dict[str, Any] = {}
        if suggestions:
            body["suggestions"] = suggestions
        data = await self._post(
            f"/api/models/{model_id}/compliance/{framework_id}/remediate/apply",
            body,
        )
        return RemediationApplyResult.model_validate(data)

    async def auto_remediate(
        self,
        model_id: str,
        framework_id: str,
    ) -> dict:
        """Trigger auto-remediation for a compliance framework."""
        data = await self._post(
            f"/api/models/{model_id}/compliance/{framework_id}/auto-remediate",
            {},
        )
        return data

    # ------------------------------------------------------------------
    # Operations (job polling)
    # ------------------------------------------------------------------

    async def get_operation(self, job_id: str) -> dict:
        return await self._get(f"/api/operations/{job_id}")

    # ------------------------------------------------------------------
    # Components
    # ------------------------------------------------------------------

    async def add_component(self, model_id: str, name: str, repo_url: str = "", path: str = "", trust_boundary_ids: list[str] | None = None) -> dict:
        body: dict = {"name": name, "repo_url": repo_url, "path": path}
        if trust_boundary_ids:
            body["trust_boundary_ids"] = trust_boundary_ids
        return await self._post(f"/api/models/{model_id}/components", body)

    async def edit_component(self, model_id: str, component_id: str, **fields) -> dict:
        return await self._put(f"/api/models/{model_id}/components/{component_id}", fields)

    async def remove_component(self, model_id: str, component_id: str) -> dict:
        return await self._delete(f"/api/models/{model_id}/components/{component_id}")

    async def discover_components(self, repo_url: str) -> dict:
        return await self._get("/api/components/discover", params={"repo_url": repo_url})

    # ------------------------------------------------------------------
    # Per-CO ISO/SAE 21434 Cybersecurity Assurance Level
    # ------------------------------------------------------------------

    async def set_co_cal(
        self, model_id: str, co_id: str, cal: Optional[int],
    ) -> dict:
        """PATCH the per-CO ISO/SAE 21434 CAL on the identity side-table.

        ``cal=None`` clears the value. No new model version is created.
        """
        return await self._patch(
            f"/api/models/{model_id}/control-objectives/{co_id}",
            {"cal": cal},
        )

    # ------------------------------------------------------------------
    # Organization level grades (IEC 62443-4-1 ML / NIST CSF Tier)
    # ------------------------------------------------------------------

    async def update_organization(
        self,
        org_id: str,
        *,
        target_ml: Optional[int] = None,
        csf_tier: Optional[int] = None,
        clear_target_ml: bool = False,
        clear_csf_tier: bool = False,
    ) -> dict:
        """PUT per-organization level grades.

        ``target_ml`` is the IEC 62443-4-1 Maturity Level (1-5).
        ``csf_tier`` is the NIST CSF Tier (1-4).

        ``None`` on the wire is indistinguishable from "field omitted",
        so callers must pass ``clear_target_ml=True`` /
        ``clear_csf_tier=True`` to explicitly reset to NULL.
        """
        body: dict = {}
        if target_ml is not None:
            body["target_ml"] = target_ml
        if csf_tier is not None:
            body["csf_tier"] = csf_tier
        if clear_target_ml:
            body["clear_target_ml"] = True
        if clear_csf_tier:
            body["clear_csf_tier"] = True
        return await self._put(f"/api/organizations/{org_id}", body)

    # ------------------------------------------------------------------
    # System Compliance
    # ------------------------------------------------------------------

    async def select_system_compliance_frameworks(
        self, system_id: str, framework_ids: list[str],
    ) -> SystemSelectFrameworksResult:
        data = await self._post(
            f"/api/systems/{system_id}/compliance/frameworks",
            {"framework_ids": framework_ids},
        )
        return SystemSelectFrameworksResult.model_validate(data)

    async def get_system_compliance_report(
        self,
        system_id: str,
        framework_id: str,
        level: int | None = None,
        status: str = "",
        offset: int = 0,
        limit: int = 0,
    ) -> ComplianceReport:
        params: dict[str, Any] = {}
        if level is not None:
            params["level"] = level
        if status:
            params["status"] = status
        if offset:
            params["offset"] = offset
        if limit:
            params["limit"] = limit
        data = await self._get(
            f"/api/systems/{system_id}/compliance/{framework_id}/report",
            params=params,
        )
        return ComplianceReport.model_validate(data)

    # ------------------------------------------------------------------
    # Assertions & Verification
    # ------------------------------------------------------------------

    async def submit_assertions(
        self, model_id: str, assertions: list[dict],
        control_id: str = "", assumption_id: str = "",
    ) -> SubmitAssertionsResult:
        if control_id and assumption_id:
            raise ValueError("Provide control_id or assumption_id, not both")
        if not control_id and not assumption_id:
            raise ValueError("One of control_id or assumption_id is required")
        if assumption_id:
            url = f"/api/models/{model_id}/assumptions/{assumption_id}/assertions"
        else:
            url = f"/api/models/{model_id}/controls/{control_id}/assertions"
        data = await self._post(url, {"assertions": assertions})
        if isinstance(data, list):
            return SubmitAssertionsResult(assertions=data)
        return SubmitAssertionsResult.model_validate(data)

    async def list_assertions(
        self, model_id: str, control_id: str = "", assumption_id: str = "",
    ) -> list[_Base]:
        if assumption_id:
            url = f"/api/models/{model_id}/assumptions/{assumption_id}/assertions"
        else:
            url = f"/api/models/{model_id}/controls/{control_id}/assertions"
        data = await self._get(url)
        # The assertion listing endpoints return either a flat list or an
        # ``{"own": [...], "inherited": [...]}`` wrapper, depending on whether
        # the model participates in cross-model inheritance. Flatten both arms
        # into this method's flat-list contract, tagging every assertion with
        # an additive ``origin`` field ("own" | "inherited"); a flat list is
        # entirely "own".
        if isinstance(data, dict) and ("own" in data or "inherited" in data):
            tagged = [
                *(("own", a) for a in data.get("own") or []),
                *(("inherited", a) for a in data.get("inherited") or []),
            ]
        elif isinstance(data, list):
            tagged = [("own", a) for a in data]
        else:
            raise ValueError(
                "Unexpected assertion listing response: expected a list of "
                "assertions or an own/inherited grouping, got "
                f"{type(data).__name__}"
            )
        out: list[_Base] = []
        for origin, item in tagged:
            if not isinstance(item, dict):
                raise ValueError(
                    "Unexpected assertion listing response: expected assertion "
                    f"objects, got {type(item).__name__}"
                )
            out.append(_Base.model_validate({**item, "origin": origin}))
        return out

    async def delete_assertion(
        self, model_id: str, assertion_id: str,
        control_id: str = "", assumption_id: str = "",
    ) -> None:
        # Backend delete endpoint uses assertion_id only (control_id in path is
        # cosmetic). Route assumption assertions through the control path with
        # the assumption_id as placeholder — backend ignores the path segment.
        path_id = control_id or assumption_id or "_"
        await self._delete(
            f"/api/models/{model_id}/controls/{path_id}/assertions/{assertion_id}",
        )

    async def get_verification_report(
        self,
        model_id: str,
        status: str = "",
        summary_only: bool = False,
        offset: int = 0,
        limit: int = 0,
    ) -> VerificationReport:
        params: dict[str, str] = {}
        if status:
            params["status"] = status
        if summary_only:
            params["summary_only"] = "true"
        if offset:
            params["offset"] = str(offset)
        if limit:
            params["limit"] = str(limit)
        qs = "&".join(f"{k}={v}" for k, v in params.items())
        url = f"/api/models/{model_id}/verification/report"
        if qs:
            url += f"?{qs}"
        data = await self._get(url)
        return VerificationReport.model_validate(data)

    async def get_sufficiency(self, model_id: str, control_id: str) -> dict:
        return await self._get(f"/api/models/{model_id}/controls/{control_id}/sufficiency")

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    async def submit_findings(self, model_id: str, findings: list[dict]) -> list[Finding]:
        data = await self._post(
            f"/api/models/{model_id}/findings",
            {"findings": findings},
        )
        return [Finding.model_validate(f) for f in data]

    async def list_findings(
        self, model_id: str, control_id: str = "", status: str = "",
    ) -> list[Finding]:
        params: dict[str, Any] = {}
        if control_id:
            params["control_id"] = control_id
        if status:
            params["status"] = status
        data = await self._get(f"/api/models/{model_id}/findings", params=params)
        # The findings endpoint returns either a flat list or a
        # ``{"own": [...], "inherited": [...]}`` wrapper, depending on whether
        # the model participates in cross-model inheritance. Flatten both arms
        # into this tool's flat-list contract; inherited rows are full Finding
        # payloads with additive ``origin`` / ``inherited_from_*`` keys handled
        # by ``extra="allow"``.
        if isinstance(data, dict):
            data = list(data.get("own", [])) + list(data.get("inherited", []))
        return [Finding.model_validate(f) for f in data]

    async def update_finding(
        self,
        model_id: str,
        finding_id: str,
        status: str,
        notes: str = "",
        reason: str = "",
        remediation_assertion_ids: str = "",
    ) -> Finding:
        body: dict[str, Any] = {"status": status}
        if notes:
            body["notes"] = notes
        if reason:
            body["reason"] = reason
        if remediation_assertion_ids:
            body["remediation_assertion_ids"] = remediation_assertion_ids
        data = await self._patch(f"/api/models/{model_id}/findings/{finding_id}", body)
        return Finding.model_validate(data)

    async def preview_finding_remediation(self, finding_id: str) -> dict:
        """GET /api/findings/{finding_id}/remediation/preview.

        Read-only. Returns a structured diff describing what an
        ``apply_finding_remediation`` call would do. The exact shape of
        the diff depends on the finding's ``kind``; the server returns
        the envelope verbatim so newly added remediation handlers
        surface automatically without a client change.

        404 if the finding doesn't exist; 422 if the finding's kind has
        no automatic remediation handler — both surface as
        ``HTTPStatusError`` and are wrapped by the tool layer's
        ``_api_error`` helper.
        """
        return await self._get(f"/api/findings/{finding_id}/remediation/preview")

    async def start_apply_finding_remediation(
        self, finding_id: str, justification: str,
    ) -> dict:
        """POST /api/findings/{finding_id}/remediation/apply-job.

        Mutating. Commits the remediation that
        ``preview_finding_remediation`` showed as a background job — the
        remediation handler runs a strong-LLM step that scales with the
        finding's blast radius, so it returns ``{"job_id": ...}`` to poll
        rather than holding a synchronous request the MCP transport would
        drop. ``justification`` is recorded on the audit trail so future
        reviewers can see why the cleanup was run; the server enforces
        non-empty.

        The job result is the server envelope verbatim. 404 if the finding
        doesn't exist; 409 if it is already remediated or dismissed; 400 if
        justification is empty; 422 if the finding's kind has no automatic
        remediation handler.
        """
        return await self._post(
            f"/api/findings/{finding_id}/remediation/apply-job",
            {"justification": justification},
        )

    # ------------------------------------------------------------------
    # Findings / Risk aggregates
    # ------------------------------------------------------------------

    async def get_findings_risks(self) -> FindingsRisksReport:
        """Workspace-scoped triage dashboard combining open findings,
        active risk acceptances, and at-risk Control Objectives across
        every model in the caller's workspace.

        One round-trip returns all three categories with per-model
        context and risk dimensions. The endpoint is workspace-scoped
        — no filters are supplied; the server selects every model the
        caller can access.
        """
        data = await self._get("/api/findings-risks")
        return FindingsRisksReport.model_validate(data)

    async def get_model_risk_view(self, model_id: str) -> ModelRiskView:
        """Per-model Prioritized Risk View: one row per live Control
        Objective with derived risk tier, asset impact, attacker
        likelihood, control coverage counts, and open-finding count.
        """
        data = await self._get(f"/api/models/{model_id}/risk-view")
        return ModelRiskView.model_validate(data)

    async def get_remediation_leverage(self, model_id: str) -> dict:
        """GET /api/models/{model_id}/remediation.

        Read-only remediation-leverage plan for a model: how the model's
        many control objectives collapse onto far fewer not-yet-satisfied
        controls, each control ranked by how many objectives it closes,
        plus a greedy minimal fix order. Returns the server envelope
        verbatim (``summary``, ``ranked``, ``greedy_plan``) so newly
        added fields surface automatically.
        """
        return await self._get(f"/api/models/{model_id}/remediation")

    async def get_system_risk_view(self, system_id: str) -> SystemRiskView:
        """System-level cross-model Prioritized Risk View: one row per
        live Control Objective across every model in the system, with
        model context attached to each row.
        """
        data = await self._get(f"/api/systems/{system_id}/risk-view")
        return SystemRiskView.model_validate(data)

    async def list_risk_acceptances(self, model_id: str) -> list[dict[str, Any]]:
        """List all risk acceptances on a specific threat model.

        Returns a bare list of risk-acceptance dicts (id, model_id,
        control_objective_id, owner, justification, status,
        accepted_at, review_by). Server-side shape; passed through
        unchanged so newly added fields surface automatically.
        """
        data = await self._get(f"/api/models/{model_id}/risk-acceptances")
        return list(data) if isinstance(data, list) else data

    # ------------------------------------------------------------------
    # Workspaces & Systems
    # ------------------------------------------------------------------

    async def list_workspaces(self) -> list[Workspace]:
        data = await self._get("/api/workspaces")
        if isinstance(data, dict):
            data = data.get("workspaces", [])
        return [Workspace.model_validate(w) for w in data]

    async def list_systems(self) -> list[System]:
        data = await self._get("/api/systems")
        return [System.model_validate(s) for s in data]

    async def get_system(self, system_id: str) -> System:
        data = await self._get(f"/api/systems/{system_id}")
        return System.model_validate(data)

    async def create_system(
        self, name: str, description: str = "",
    ) -> System:
        body: dict[str, Any] = {"name": name}
        if description:
            body["description"] = description
        data = await self._post("/api/systems", body)
        return System.model_validate(data)

    async def add_model_to_system(self, system_id: str, model_id: str) -> OkResult:
        data = await self._post(
            f"/api/systems/{system_id}/models", {"model_id": model_id},
        )
        return OkResult.model_validate(data)

    async def complete_setup_step(self, step_id: str) -> dict:
        return await self._patch("/api/onboarding", {"check": step_id})

    async def get_setup_status(self) -> dict:
        return await self._get("/api/onboarding")

    # --- Trust boundary CRUD ---

    async def add_trust_boundary(
        self,
        model_id: str,
        description: str,
        crosses: list[str] | None = None,
        passes: list[str] | None = None,
        sealed: bool | None = None,
    ) -> dict:
        body: dict = {"description": description}
        if crosses:
            body["crosses"] = crosses
        if passes is not None:
            body["passes"] = passes
        if sealed is not None:
            body["sealed"] = sealed
        return await self._post(f"/api/models/{model_id}/trust-boundaries", body)

    async def edit_trust_boundary(self, model_id: str, tb_id: str, **kwargs) -> dict:
        return await self._put(f"/api/models/{model_id}/trust-boundaries/{tb_id}", kwargs)

    async def remove_trust_boundary(self, model_id: str, tb_id: str) -> dict:
        return await self._delete(f"/api/models/{model_id}/trust-boundaries/{tb_id}")

    # --- Assumption CRUD ---

    async def add_assumption(
        self,
        model_id: str,
        description: str,
        linked_co_ids: list[str] | None = None,
        *,
        assumption_type: str = "external",
        exclusion: dict | None = None,
    ) -> dict:
        body: dict = {"description": description}
        if linked_co_ids:
            body["linked_co_ids"] = linked_co_ids
        if assumption_type != "external":
            body["assumption_type"] = assumption_type
        if exclusion is not None:
            body["exclusion"] = exclusion
        return await self._post(f"/api/models/{model_id}/assumptions", body)

    async def edit_assumption(self, model_id: str, as_id: str, **kwargs) -> dict:
        return await self._put(f"/api/models/{model_id}/assumptions/{as_id}", kwargs)

    async def remove_assumption(self, model_id: str, as_id: str) -> dict:
        return await self._delete(f"/api/models/{model_id}/assumptions/{as_id}")

    # --- Attestation ---

    async def submit_attestation(
        self, model_id: str, assumption_id: str,
        attested_by: str = "", statement: str = "",
        expires_at: str = "", evidence_url: str = "",
    ) -> dict:
        body: dict = {}
        if attested_by:
            body["attested_by"] = attested_by
        if statement:
            body["statement"] = statement
        if expires_at:
            body["expires_at"] = expires_at
        if evidence_url:
            body["evidence_url"] = evidence_url
        return await self._post(f"/api/models/{model_id}/assumptions/{assumption_id}/attest", body)

    async def list_attestations(self, model_id: str, assumption_id: str) -> dict:
        return await self._get(f"/api/models/{model_id}/assumptions/{assumption_id}/attestations")

    async def convert_assumption_to_controls(self, model_id: str, assumption_id: str) -> dict:
        return await self._post(f"/api/models/{model_id}/assumptions/{assumption_id}/convert-to-controls", {})

    # ------------------------------------------------------------------
    # Functional conformance (Capability × Condition)
    # ------------------------------------------------------------------

    async def generate_functional(self, model_id: str, refresh: bool = False) -> dict:
        params = {"refresh": "true"} if refresh else None
        return await self._post(
            f"/api/models/{model_id}/functional/generate", {}, params=params,
        )

    async def list_capabilities(self, model_id: str) -> dict:
        return await self._get(f"/api/models/{model_id}/capabilities")

    async def get_capability(self, model_id: str, cap_id: str) -> dict:
        return await self._get(f"/api/models/{model_id}/capabilities/{cap_id}")

    async def list_functional_objectives(self, model_id: str) -> dict:
        return await self._get(f"/api/models/{model_id}/functional-objectives")

    async def get_functional_objective(self, model_id: str, fo_id: str) -> dict:
        return await self._get(f"/api/models/{model_id}/functional-objectives/{fo_id}")

    async def get_functional_coverage(self, model_id: str) -> dict:
        return await self._get(f"/api/models/{model_id}/functional/coverage")

    async def get_functional_gaps(self, model_id: str) -> dict:
        return await self._get(f"/api/models/{model_id}/functional/gaps")

    async def get_functional_scan_prompt(self, model_id: str) -> dict:
        return await self._get(f"/api/models/{model_id}/functional/scan-prompt")

    async def add_functional_test(
        self, model_id: str, description: str,
        functional_objective_ids: list[str], status: str = "not_implemented",
        component_ids: list[str] | None = None,
    ) -> dict:
        return await self._post(
            f"/api/models/{model_id}/functional-tests",
            {
                "description": description,
                "functional_objective_ids": functional_objective_ids,
                "status": status,
                "component_ids": component_ids or [],
            },
        )

    async def import_functional_tests(
        self, model_id: str, tests: list[dict],
    ) -> dict:
        return await self._post(
            f"/api/models/{model_id}/functional/import-tests",
            {"tests": tests},
        )

    async def submit_functional_tests(
        self, model_id: str, functional_test_id: str, assertions: list[dict],
    ) -> dict:
        return await self._post(
            f"/api/models/{model_id}/functional-tests/{functional_test_id}/assertions",
            {"assertions": assertions},
        )

    async def suggest_functional_test_mappings(
        self, model_id: str, test_ids: list[str],
    ) -> dict:
        return await self._post(
            f"/api/models/{model_id}/functional/suggest-test-mappings",
            {"test_ids": test_ids},
        )

    async def associate_functional_test(
        self, model_id: str, functional_test_id: str,
        functional_objective_ids: list[str],
    ) -> dict:
        return await self._post(
            f"/api/models/{model_id}/functional-tests/{functional_test_id}/associate",
            {"functional_objective_ids": functional_objective_ids},
        )

    async def get_functional_satisfaction_groups(
        self, model_id: str, functional_objective_id: str,
    ) -> dict:
        return await self._get(
            f"/api/models/{model_id}/functional-objectives/{functional_objective_id}"
            "/satisfaction-groups"
        )

    async def set_functional_satisfaction_groups(
        self, model_id: str, functional_objective_id: str,
        groups: dict, ungrouped: list[str],
    ) -> dict:
        return await self._put(
            f"/api/models/{model_id}/functional-objectives/{functional_objective_id}"
            "/satisfaction-groups",
            {"groups": groups, "ungrouped": ungrouped},
        )

    async def get_functional_test_sufficiency(
        self, model_id: str, functional_test_id: str,
    ) -> dict:
        return await self._get(
            f"/api/models/{model_id}/functional-tests/{functional_test_id}/sufficiency"
        )

    async def get_cwe_catalog(self) -> dict:
        """Platform CWE reference catalog status: current MITRE version +
        entry count. Reports ``enabled: false`` when the instance doesn't
        have CWE classification turned on."""
        return await self._get("/api/cwe/catalog")

    async def get_model_cwe_tags(self, model_id: str) -> dict:
        """CWE tags for a model's live control objectives, with a staleness
        marker for tags whose catalog entry has since been deprecated,
        redefined, or removed."""
        return await self._get(f"/api/models/{model_id}/cwe")

    async def classify_model_cwe(self, model_id: str, force: bool = False) -> dict:
        """Trigger grounded CO->CWE classification for a model's live COs.

        Calls ``POST /api/models/{model_id}/cwe/classify``.
        """
        return await self._post(
            f"/api/models/{model_id}/cwe/classify", params={"force": force},
        )
