"""Async HTTP client for the Mipiti API."""

from __future__ import annotations

import json
import os
from typing import Any, Awaitable, Callable

import httpx
from httpx_sse import aconnect_sse

from .types import Control, ModelSummary, ThreatModel

DEFAULT_API_URL = "https://api.mipiti.io"

ProgressCallback = Callable[[int, int, str], Awaitable[None]]
"""Signature: (step, total_steps, title) -> None"""


class MipitiClient:
    """Thin async client that wraps the Mipiti REST + SSE API."""

    def __init__(
        self,
        api_key: str | None = None,
        api_url: str | None = None,
    ) -> None:
        self.api_key = api_key or os.environ.get("MIPITI_API_KEY", "")
        self.api_url = (
            api_url or os.environ.get("MIPITI_API_URL", DEFAULT_API_URL)
        ).rstrip("/")
        if not self.api_key:
            raise ValueError(
                "MIPITI_API_KEY is required. Set it as an environment variable "
                "or pass api_key to MipitiClient."
            )
        self._client: httpx.AsyncClient | None = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.api_url,
                headers={"X-API-Key": self.api_key},
                timeout=httpx.Timeout(
                    connect=10.0, read=120.0, write=10.0, pool=10.0
                ),
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    # ------------------------------------------------------------------
    # SSE stream consumer (core of generate / refine / query / general)
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
            client,
            "POST",
            "/api/model/stream",
            json=body,
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
                # intent, step_complete, keepalive — ignored

        if chat_data:
            return chat_data
        if result_data:
            return result_data
        raise RuntimeError("Stream ended without a result or response event")

    # ------------------------------------------------------------------
    # High-level methods
    # ------------------------------------------------------------------

    async def generate_threat_model(
        self,
        feature_description: str,
        on_progress: ProgressCallback | None = None,
    ) -> ThreatModel:
        result = await self._stream_model(
            [{"role": "user", "content": feature_description}],
            on_progress=on_progress,
        )
        return ThreatModel.model_validate(result["threat_model"])

    async def refine_threat_model(
        self,
        model_id: str,
        instruction: str,
        on_progress: ProgressCallback | None = None,
    ) -> ThreatModel:
        result = await self._stream_model(
            [{"role": "user", "content": instruction}],
            model_id=model_id,
            on_progress=on_progress,
        )
        return ThreatModel.model_validate(result["threat_model"])

    async def query_threat_model(self, model_id: str, question: str) -> str:
        result = await self._stream_model(
            [{"role": "user", "content": question}],
            model_id=model_id,
        )
        return result.get("content", "")

    async def list_models(self) -> list[ModelSummary]:
        client = self._get_client()
        resp = await client.get("/api/models")
        resp.raise_for_status()
        return [ModelSummary.model_validate(m) for m in resp.json()]

    async def get_model(
        self, model_id: str, version: int | None = None
    ) -> ThreatModel:
        client = self._get_client()
        if version is not None:
            resp = await client.get(
                f"/api/models/{model_id}/versions/{version}"
            )
        else:
            resp = await client.get(f"/api/models/{model_id}")
        resp.raise_for_status()
        return ThreatModel.model_validate(resp.json())

    async def get_controls(self, model_id: str) -> list[Control]:
        client = self._get_client()
        resp = await client.get(f"/api/models/{model_id}/controls")
        resp.raise_for_status()
        data = resp.json()
        controls = [Control.model_validate(c) for c in data.get("controls", [])]
        if not controls:
            gen_resp = await client.post(
                f"/api/models/{model_id}/controls/generate"
            )
            gen_resp.raise_for_status()
            gen_data = gen_resp.json()
            controls = [
                Control.model_validate(c)
                for c in gen_data.get("controls", [])
            ]
        return controls

    async def update_control_status(
        self,
        model_id: str,
        control_id: str,
        status: str,
        implementation_notes: str = "",
    ) -> Control:
        client = self._get_client()
        resp = await client.patch(
            f"/api/controls/{control_id}",
            params={"model_id": model_id},
            json={"status": status, "implementation_notes": implementation_notes},
        )
        resp.raise_for_status()
        return Control.model_validate(resp.json())

    async def assess_model(self, model_id: str) -> dict:
        client = self._get_client()
        resp = await client.post(f"/api/models/{model_id}/assess")
        resp.raise_for_status()
        return resp.json()

    async def export_model(self, model_id: str, fmt: str = "csv") -> bytes:
        client = self._get_client()
        resp = await client.get(
            f"/api/models/{model_id}/export", params={"format": fmt}
        )
        resp.raise_for_status()
        return resp.content
