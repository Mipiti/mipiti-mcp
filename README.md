# Mipiti MCP Server

MCP (Model Context Protocol) server for [Mipiti](https://mipiti.io) — security posture platform.

Lets AI coding agents (Claude Code, Claude Desktop, Cursor, etc.) generate and manage threat models, controls, assumptions, compliance mapping, and evidence programmatically.

## Hosted Endpoint (Recommended)

The Mipiti backend hosts an MCP server at `https://api.mipiti.io/mcp/`. No installation needed — just configure your MCP client to connect.

### Claude Code (quickstart)

```bash
claude mcp add --transport http Mipiti https://api.mipiti.io/mcp/
```

You'll be prompted to log in via your browser (OAuth). That's it.

### OAuth (manual config)

MCP clients with OAuth support (Claude Code, Claude Desktop, Cursor) automatically prompt you to log in via your browser. Add to your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "mipiti": {
      "type": "http",
      "url": "https://api.mipiti.io/mcp/"
    }
  }
}
```

On first connection, your MCP client opens a browser window where you approve access with your Mipiti account. Tokens refresh automatically.

### API Key

For clients without OAuth support, or headless/CI environments, create an API key in Settings:

```json
{
  "mcpServers": {
    "mipiti": {
      "type": "http",
      "url": "https://api.mipiti.io/mcp/",
      "headers": {
        "X-API-Key": "your-api-key"
      }
    }
  }
}
```

## Standalone Package (Alternative)

If you prefer running the MCP server locally (e.g., for development or self-hosted instances), install the `mipiti-mcp` package. This is a thin HTTP client that calls the Mipiti API.

```bash
pip install mipiti-mcp
# Or run directly with uvx
uvx mipiti-mcp
```

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MIPITI_API_KEY` | Yes | — | Your Mipiti API key |
| `MIPITI_API_URL` | No | `https://api.mipiti.io` | API base URL |

### Claude Code (standalone)

```json
{
  "mcpServers": {
    "mipiti": {
      "command": "uvx",
      "args": ["mipiti-mcp"],
      "env": {
        "MIPITI_API_KEY": "your-api-key"
      }
    }
  }
}
```

## Tools (63)

### Threat Modeling

| Tool | Description |
|------|-------------|
| `generate_threat_model` | Generate a complete threat model from a feature description. Runs a multi-step AI pipeline producing trust boundaries, assets, attackers, control objectives, and assumptions. Returns a `job_id` — poll with `get_operation_status`. |
| `refine_threat_model` | Refine an existing threat model based on an instruction. Creates a new version. Only affected entity types are modified — unaffected entities are preserved server-side. |
| `query_threat_model` | Ask a question about an existing threat model. |
| `get_threat_model` | Get the full details of a specific threat model (trust boundaries, assets, attackers, assumptions). Use `include_cos=True` to include control objectives. |
| `list_threat_models` | List all saved threat models with IDs, titles, versions, and creation dates. |
| `rename_threat_model` | Rename a model (metadata only, no new version). |
| `delete_threat_model` | Permanently delete a model and all its data. |
| `export_threat_model` | Export as PDF, HTML, or CSV. |

### Entity CRUD

| Tool | Description |
|------|-------------|
| `add_asset` / `edit_asset` / `remove_asset` | Targeted single-entity changes for assets. Creates a new version. |
| `add_attacker` / `edit_attacker` / `remove_attacker` | Same for attackers. |

### Trust Boundaries

| Tool | Description |
|------|-------------|
| `get_threat_model` | Returns existing trust boundaries (along with assets, attackers, assumptions). Review current boundaries before adding or modifying. |
| `add_trust_boundary` / `edit_trust_boundary` / `remove_trust_boundary` | CRUD for trust boundaries. Defines where trust transitions occur in the system architecture. Attackers are positioned at boundaries; COs are annotated with boundary reachability. Changes auto-generate boundary assumptions for newly unreachable COs. |

### Controls

| Tool | Description |
|------|-------------|
| `get_controls` | List controls with current status. Use `summary_only=True` for compact response. |
| `get_control_objectives` | List COs with which controls cover each one. Includes `boundary_reachable` per CO. |
| `update_control_status` | Mark implemented or not_implemented. Requires at least one assertion first. |
| `refine_control` | Modify a control's description with justification. Platform evaluates whether the mitigation group still covers the COs. |
| `regenerate_controls` | Regenerate controls. Supports `mode="per_co"` and `co_ids` to target specific COs. |
| `import_controls` | Import controls from JSON or free text, auto-mapped to COs and deduplicated. |
| `delete_control` | Soft-delete with justification. Blocked if it's the only control covering a CO. |
| `check_control_gaps` | AI-powered gap analysis across all controls. |

### Assumptions and Attestation

| Tool | Description |
|------|-------------|
| `get_threat_model` | Returns existing assumptions (along with assets, attackers, trust boundaries). Review current assumptions before adding or modifying. |
| `add_assumption` | Add an assumption, optionally linking it to COs via `linked_co_ids`. |
| `edit_assumption` | Update description and/or linked COs. |
| `remove_assumption` | Soft-delete (preserved for audit). Linked COs are no longer mitigated by it. |
| `restore_assumption` | Restore a soft-deleted assumption. Re-attestation required. |
| `submit_attestation` | Record that a responsible party affirmed an assumption holds. Provide `attested_by`, `statement`, `expires_at`. |
| `list_attestations` | Attestation history for an assumption. |
| `assume_control` | Mark a control as externally handled by an assumption. Counts as active for mitigation group completeness when attested. |
| `unassume_control` | Clear externally-handled status; control reverts to not_implemented. |
| `convert_assumption_to_controls` | Generate controls for assumption-covered COs and retire the assumption linkage. |

### Assertions and Evidence

| Tool | Description |
|------|-------------|
| `submit_assertions` | Submit typed, machine-verifiable claims about system properties (21 assertion types). |
| `list_assertions` / `delete_assertion` | List or delete assertions for a control. |
| `add_evidence` / `remove_evidence` | Attach auxiliary metadata (docs, links). Evidence is contextual — only assertions prove implementation. |
| `get_verification_report` | Shows verified, partially verified, and unverified controls with sufficiency details. |
| `get_sufficiency` | Quick check: do assertions for a single control collectively cover all aspects? |
| `get_scan_prompt` | Returns targeted prompts for scanning the codebase against not_implemented controls. |
| `get_review_queue` | Controls not reviewed in 90+ days. Start here for periodic maintenance. |
| `submit_findings` / `list_findings` / `update_finding` | Report and track negative findings (gap discovery). |

### Assurance

| Tool | Description |
|------|-------------|
| `assess_model` | Deterministic assessment of all COs. Returns mitigated/at_risk/unassessed with `risk_reason` (missing_controls, pending_attestation, expired_attestation) and `boundary_reachable` per CO. |

### Compliance

| Tool | Description |
|------|-------------|
| `list_compliance_frameworks` | Available frameworks (OWASP ASVS, ISO 27001, SOC 2, NIST CSF, GDPR, FedRAMP, PCI DSS, EU CRA). |
| `select_compliance_frameworks` | Select frameworks for a model. |
| `get_compliance_report` | Coverage report for a selected framework. |
| `auto_map_controls` | AI-powered semantic mapping of controls to framework requirements. |
| `map_control_to_requirement` | Manual control-to-requirement mapping. |
| `suggest_compliance_remediation` / `apply_compliance_remediation` | AI-suggested controls for uncovered requirements. |

### Systems and Workspaces

| Tool | Description |
|------|-------------|
| `list_workspaces` | List available workspaces. |
| `list_systems` / `get_system` / `create_system` | Manage systems (groups of related models). |
| `add_model_to_system` | Add a model to a system. |
| `select_system_compliance_frameworks` / `get_system_compliance_report` | System-level compliance aggregation. |

### Setup and Operations

| Tool | Description |
|------|-------------|
| `get_setup_status` | Check which onboarding steps are done. |
| `complete_setup_step` | Mark an onboarding step as done (mcp_configured, mipiti_verify_installed, ci_secret_added, ci_pipeline_added). |
| `get_operation_status` | Poll background operations. Response includes adaptive `poll_after_seconds`. |

## Development

```bash
git clone https://github.com/Mipiti/mipiti-mcp.git
cd mipiti-mcp
pip install -e ".[dev]"
python -m pytest -v
```

## Local Testing with Claude Desktop

```json
{
  "mcpServers": {
    "mipiti": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/mipiti-mcp", "mipiti-mcp"],
      "env": {
        "MIPITI_API_KEY": "your-key"
      }
    }
  }
}
```

## License

Proprietary. Copyright (c) 2026 Mipiti, LLC. All rights reserved. See [LICENSE](LICENSE) for details.
