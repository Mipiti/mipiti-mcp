"""Async HTTP client for the Mipiti API."""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from typing import Any, Awaitable, Callable

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
    GenerateResult,
    ImportConfirmResult,
    ModelSummary,
    OkResult,
    RemediationApplyResult,
    RenameResult,
    ReviewQueueResponse,
    ScanPromptResult,
    SelectFrameworksResult,
    SubmitAssertionsResult,
    System,
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
        on_progress: ProgressCallback | None = None,
    ) -> GenerateResult | dict:
        """Returns a ``GenerateResult`` on normal generation, OR a raw
        ``{"similar_models": [{id, title, reason}, ...]}`` dict when
        the backend short-circuited because similar models already
        exist in the workspace. Pass ``force_generate=True`` to skip
        the similarity check and force a new generation.
        """
        data = await self._stream_model(
            [{"role": "user", "content": feature_description}],
            force_generate=force_generate,
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

    async def delete_model(self, model_id: str) -> None:
        await self._delete(f"/api/models/{model_id}")

    async def export_model(self, model_id: str, fmt: str = "csv") -> bytes:
        resp = await self._get_client().get(
            f"/api/models/{model_id}/export", params={"format": fmt}
        )
        resp.raise_for_status()
        return resp.content

    async def export_model_full(self, model_id: str) -> dict:
        """Return the self-contained JSON audit archive envelope for a model."""
        return await self._get(f"/api/models/{model_id}/export/full")

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

    async def refine_control(
        self,
        model_id: str,
        control_id: str,
        description: str,
        justification: str,
        codebase_findings: str = "",
    ) -> dict:
        body: dict[str, str] = {"justification": justification}
        if description:
            body["description"] = description
        if codebase_findings:
            body["codebase_findings"] = codebase_findings
        resp = await self._request_with_idempotency(
            "PATCH",
            f"/api/models/{model_id}/controls/{control_id}/refine",
            json=body,
        )
        if resp.status_code == 422:
            # AI evaluator rejected — return body with accepted=false
            return resp.json()
        resp.raise_for_status()
        return resp.json()

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

    async def set_mitigation_groups(
        self,
        model_id: str,
        co_id: str,
        groups: dict,
        defense_in_depth: list[str],
        justification: str,
    ) -> dict:
        body = {
            "groups": groups,
            "defense_in_depth": defense_in_depth,
            "justification": justification,
        }
        resp = await self._request_with_idempotency(
            "PUT",
            f"/api/models/{model_id}/control-objectives/{co_id}/mitigation-groups",
            json=body,
        )
        resp.raise_for_status()
        return resp.json()

    async def get_control_assumption_groups(
        self, model_id: str, control_id: str,
    ) -> dict:
        resp = await self._get_client().get(
            f"/api/models/{model_id}/controls/{control_id}/assumption-groups",
        )
        resp.raise_for_status()
        return resp.json()

    async def set_control_assumption_groups(
        self,
        model_id: str,
        control_id: str,
        groups: dict,
        justification: str,
    ) -> dict:
        body = {
            "groups": groups,
            "justification": justification,
        }
        resp = await self._request_with_idempotency(
            "PUT",
            f"/api/models/{model_id}/controls/{control_id}/assumption-groups",
            json=body,
        )
        resp.raise_for_status()
        return resp.json()

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

    async def import_controls(
        self,
        model_id: str,
        controls_json: str = "",
        free_text: str = "",
        source_label: str = "",
        auto_map: bool = True,
    ) -> ImportConfirmResult:
        body: dict[str, Any] = {"auto_map": auto_map}
        if controls_json:
            body["controls_json"] = controls_json
        if free_text:
            body["free_text"] = free_text
        if source_label:
            body["source_label"] = source_label
        preview = await self._post(f"/api/models/{model_id}/controls/import", body)
        data = await self._post(
            f"/api/models/{model_id}/controls/import/confirm",
            {"import_id": preview.get("import_id", "")},
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

    async def add_asset(self, model_id: str, **kwargs: Any) -> dict:
        """POST /assets returns one of three response shapes:

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
        malformed output) both raise via httpx and are caught by the
        tool wrapper as tool errors. The two are semantically
        distinct: 503 means retry-with-backoff; 502 means retry-now.
        """
        return await self._post(f"/api/models/{model_id}/assets", kwargs)

    async def edit_asset(self, model_id: str, asset_id: str, **kwargs: Any) -> dict:
        """PUT /assets/{id} returns one of two response shapes:

        1. Accepted edit (or non-identity edit skipped the AI gate):
           ``{"model": ThreatModel, "controls_carried": N, ...}``
        2. Semantic-preservation rejection:
           ``{"accepted": False, "classification": "replace"|"ambiguous",
              "reason": "...", "per_field": {...}, "suggestion": "..."}``

        HTTP 503 (evaluator unreachable) or 502 (evaluator returned
        malformed output) raise via httpx as distinct signals.
        """
        return await self._put(f"/api/models/{model_id}/assets/{asset_id}", kwargs)

    async def remove_asset(self, model_id: str, asset_id: str) -> dict:
        """DELETE /assets/{id} soft-deletes. Returns the
        ``{"model": ThreatModel, ...}`` envelope; the asset stays in
        ``model.assets`` with ``deleted=True``.
        """
        return await self._delete(f"/api/models/{model_id}/assets/{asset_id}")

    async def add_attacker(self, model_id: str, **kwargs: Any) -> dict:
        """POST /attackers — same three-shape response as add_asset
        (normal create / auto-restore / similar-rejection) plus 503 on
        LLM outage."""
        return await self._post(f"/api/models/{model_id}/attackers", kwargs)

    async def edit_attacker(self, model_id: str, attacker_id: str, **kwargs: Any) -> dict:
        """PUT /attackers/{id} — same two-shape response as edit_asset
        (accepted edit / semantic rejection) plus 503 on LLM outage."""
        return await self._put(f"/api/models/{model_id}/attackers/{attacker_id}", kwargs)

    async def remove_attacker(self, model_id: str, attacker_id: str) -> dict:
        """DELETE /attackers/{id} soft-deletes. Returns the envelope
        with the attacker now marked ``deleted=True`` in the model."""
        return await self._delete(f"/api/models/{model_id}/attackers/{attacker_id}")

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
        return [_Base.model_validate(a) for a in data]

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

    async def add_trust_boundary(self, model_id: str, description: str, crosses: list[str] | None = None) -> dict:
        body: dict = {"description": description}
        if crosses:
            body["crosses"] = crosses
        return await self._post(f"/api/models/{model_id}/trust-boundaries", body)

    async def edit_trust_boundary(self, model_id: str, tb_id: str, **kwargs) -> dict:
        return await self._put(f"/api/models/{model_id}/trust-boundaries/{tb_id}", kwargs)

    async def remove_trust_boundary(self, model_id: str, tb_id: str) -> dict:
        return await self._delete(f"/api/models/{model_id}/trust-boundaries/{tb_id}")

    # --- Assumption CRUD ---

    async def add_assumption(self, model_id: str, description: str, linked_co_ids: list[str] | None = None, *, assumption_type: str = "external") -> dict:
        body: dict = {"description": description}
        if linked_co_ids:
            body["linked_co_ids"] = linked_co_ids
        if assumption_type != "external":
            body["assumption_type"] = assumption_type
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
