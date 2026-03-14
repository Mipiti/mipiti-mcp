"""Async HTTP client for the Mipiti API."""

from __future__ import annotations

import json
import os
from typing import Any, Awaitable, Callable

import httpx
from httpx_sse import aconnect_sse

from .types import (
    AutoMapResult,
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
    GapAnalysisResult,
    GenerateResult,
    ImportConfirmResult,
    MarkEvidenceCompleteResult,
    ModelSummary,
    OkResult,
    RemediationApplyResult,
    RemediationSuggestions,
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

ProgressCallback = Callable[[int, int, str], Awaitable[None]]
"""Signature: (step, total_steps, title) -> None"""


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

    async def _post(self, path: str, body: dict | None = None, **kwargs: Any) -> Any:
        resp = await self._get_client().post(path, json=body, **kwargs)
        resp.raise_for_status()
        return resp.json()

    async def _patch(self, path: str, body: dict | None = None, **kwargs: Any) -> Any:
        resp = await self._get_client().patch(path, json=body, **kwargs)
        resp.raise_for_status()
        return resp.json()

    async def _put(self, path: str, body: dict, **kwargs: Any) -> Any:
        resp = await self._get_client().put(path, json=body, **kwargs)
        resp.raise_for_status()
        return resp.json()

    async def _delete(self, path: str, **kwargs: Any) -> Any:
        resp = await self._get_client().delete(path, **kwargs)
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
        on_progress: ProgressCallback | None = None,
    ) -> dict[str, Any]:
        """POST /api/model/stream, consume SSE events, return final payload."""
        body: dict[str, Any] = {"messages": messages}
        if model_id:
            body["model_id"] = model_id

        client = self._get_client()
        result_data: dict[str, Any] | None = None
        chat_data: dict[str, Any] | None = None

        async with aconnect_sse(
            client, "POST", "/api/model/stream", json=body,
        ) as event_source:
            async for sse in event_source.aiter_sse():
                event_type = sse.event
                if event_type == "step_start":
                    if on_progress:
                        data = json.loads(sse.data)
                        await on_progress(
                            data.get("step", 0),
                            data.get("total_steps", 5),
                            data.get("title", ""),
                        )
                elif event_type == "result":
                    result_data = json.loads(sse.data)
                elif event_type == "chat_response":
                    chat_data = json.loads(sse.data)
                elif event_type == "error":
                    data = json.loads(sse.data)
                    raise RuntimeError(data.get("message", "Unknown error"))

        if chat_data:
            return chat_data
        if result_data:
            return result_data
        raise RuntimeError("Stream ended without a result or response event")

    # ------------------------------------------------------------------
    # Threat Model CRUD
    # ------------------------------------------------------------------

    async def generate_threat_model(
        self,
        feature_description: str,
        on_progress: ProgressCallback | None = None,
    ) -> GenerateResult:
        data = await self._stream_model(
            [{"role": "user", "content": feature_description}],
            on_progress=on_progress,
        )
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

    async def list_models(self, source: str = "") -> list[ModelSummary]:
        params = {}
        if source:
            params["source"] = source
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

    # ------------------------------------------------------------------
    # Controls
    # ------------------------------------------------------------------

    async def get_controls(
        self, model_id: str, include_deleted: bool = False,
    ) -> ControlsResponse:
        params: dict[str, Any] = {}
        if include_deleted:
            params["include_deleted"] = "true"
        data = await self._get(f"/api/models/{model_id}/controls", params=params)
        return ControlsResponse.model_validate(data)

    async def regenerate_controls(self, model_id: str) -> ControlsResponse:
        data = await self._post(f"/api/models/{model_id}/controls/regenerate")
        return ControlsResponse.model_validate(data)

    async def update_control_status(
        self,
        model_id: str,
        control_id: str,
        status: str,
        implementation_notes: str = "",
        evidence: list[dict] | None = None,
    ) -> ThreatModel:
        body: dict[str, Any] = {
            "status": status,
            "implementation_notes": implementation_notes,
        }
        if evidence is not None:
            body["evidence"] = evidence
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
    ) -> dict:
        resp = await self._get_client().patch(
            f"/api/models/{model_id}/controls/{control_id}/refine",
            json={"description": description, "justification": justification},
        )
        if resp.status_code == 422:
            # AI evaluator rejected — return body with accepted=false
            return resp.json()
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

    async def check_control_gaps(self, model_id: str) -> GapAnalysisResult:
        data = await self._post(f"/api/models/{model_id}/controls/check-gaps")
        return GapAnalysisResult.model_validate(data)

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

    async def add_asset(self, model_id: str, **kwargs: Any) -> ThreatModel:
        data = await self._post(f"/api/models/{model_id}/assets", kwargs)
        return ThreatModel.model_validate(data)

    async def edit_asset(self, model_id: str, asset_id: str, **kwargs: Any) -> ThreatModel:
        data = await self._put(f"/api/models/{model_id}/assets/{asset_id}", kwargs)
        return ThreatModel.model_validate(data)

    async def remove_asset(self, model_id: str, asset_id: str) -> ThreatModel:
        data = await self._delete(f"/api/models/{model_id}/assets/{asset_id}")
        return ThreatModel.model_validate(data)

    async def add_attacker(self, model_id: str, **kwargs: Any) -> ThreatModel:
        data = await self._post(f"/api/models/{model_id}/attackers", kwargs)
        return ThreatModel.model_validate(data)

    async def edit_attacker(self, model_id: str, attacker_id: str, **kwargs: Any) -> ThreatModel:
        data = await self._put(f"/api/models/{model_id}/attackers/{attacker_id}", kwargs)
        return ThreatModel.model_validate(data)

    async def remove_attacker(self, model_id: str, attacker_id: str) -> ThreatModel:
        data = await self._delete(f"/api/models/{model_id}/attackers/{attacker_id}")
        return ThreatModel.model_validate(data)

    # ------------------------------------------------------------------
    # Assurance
    # ------------------------------------------------------------------

    async def assess_model(self, model_id: str) -> _Base:
        data = await self._post(f"/api/models/{model_id}/assess")
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
    ) -> AutoMapResult:
        body: dict[str, Any] = {}
        if control_id:
            body["control_id"] = control_id
        data = await self._post(
            f"/api/models/{model_id}/compliance/{framework_id}/auto-map", body,
        )
        return AutoMapResult.model_validate(data)

    async def suggest_compliance_remediation(
        self, model_id: str, framework_id: str,
    ) -> RemediationSuggestions:
        data = await self._post(
            f"/api/models/{model_id}/compliance/{framework_id}/remediate",
        )
        return RemediationSuggestions.model_validate(data)

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
        self, model_id: str, control_id: str, assertions: list[dict],
    ) -> SubmitAssertionsResult:
        data = await self._post(
            f"/api/models/{model_id}/controls/{control_id}/assertions",
            {"assertions": assertions},
        )
        # API may return a bare list or a wrapped dict
        if isinstance(data, list):
            return SubmitAssertionsResult(assertions=data)
        return SubmitAssertionsResult.model_validate(data)

    async def list_assertions(
        self, model_id: str, control_id: str,
    ) -> list[_Base]:
        data = await self._get(
            f"/api/models/{model_id}/controls/{control_id}/assertions",
        )
        return [_Base.model_validate(a) for a in data]

    async def delete_assertion(
        self, model_id: str, control_id: str, assertion_id: str,
    ) -> None:
        await self._delete(
            f"/api/models/{model_id}/controls/{control_id}/assertions/{assertion_id}",
        )

    async def get_verification_report(self, model_id: str) -> VerificationReport:
        data = await self._get(f"/api/models/{model_id}/verification/report")
        return VerificationReport.model_validate(data)

    async def mark_evidence_complete(
        self, model_id: str, control_id: str,
    ) -> MarkEvidenceCompleteResult:
        data = await self._post(
            f"/api/models/{model_id}/controls/{control_id}/evidence-complete",
        )
        return MarkEvidenceCompleteResult.model_validate(data)

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

    async def list_systems(self, workspace_id: str = "") -> list[System]:
        params = {}
        if workspace_id:
            params["workspace_id"] = workspace_id
        data = await self._get("/api/systems", params=params)
        return [System.model_validate(s) for s in data]

    async def get_system(self, system_id: str) -> System:
        data = await self._get(f"/api/systems/{system_id}")
        return System.model_validate(data)

    async def create_system(
        self, name: str, description: str = "", workspace_id: str = "",
    ) -> System:
        body: dict[str, Any] = {"name": name}
        if description:
            body["description"] = description
        if workspace_id:
            body["workspace_id"] = workspace_id
        data = await self._post("/api/systems", body)
        return System.model_validate(data)

    async def add_model_to_system(self, system_id: str, model_id: str) -> OkResult:
        data = await self._post(
            f"/api/systems/{system_id}/models", {"model_id": model_id},
        )
        return OkResult.model_validate(data)
