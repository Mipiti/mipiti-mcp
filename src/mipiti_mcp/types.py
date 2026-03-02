"""Pydantic response models mirroring the Mipiti API domain types."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel


class SecurityProperty(str, Enum):
    C = "C"
    I = "I"  # noqa: E741
    A = "A"
    U = "U"


class Asset(BaseModel):
    id: str
    name: str
    description: str = ""
    security_properties: list[SecurityProperty] = []
    impact: str = "M"
    notes: str = ""


class Attacker(BaseModel):
    id: str
    capability: str
    position: str = ""
    archetype: str = ""
    likelihood: str = "M"


class TrustBoundary(BaseModel):
    id: str
    description: str
    crosses: list[str] = []


class ControlObjective(BaseModel):
    id: str
    asset_id: str
    security_property: SecurityProperty
    attacker_id: str
    statement: str
    risk_tier: str = "medium"


class Assumption(BaseModel):
    id: str
    description: str
    status: str = "active"


class Control(BaseModel):
    id: str
    control_objective_ids: list[str] = []
    description: str
    status: str = "not_implemented"
    implementation_notes: str = ""


class ThreatModel(BaseModel):
    id: str = ""
    feature_description: str = ""
    title: str = ""
    version: int = 1
    created_at: str = ""
    trust_boundaries: list[TrustBoundary] = []
    assets: list[Asset] = []
    attackers: list[Attacker] = []
    control_objectives: list[ControlObjective] = []
    assumptions: list[Assumption] = []


class ModelSummary(BaseModel):
    id: str
    title: str = ""
    feature_description: str = ""
    created_at: str = ""
    version: int = 1
