# Mipiti MCP Server

MCP (Model Context Protocol) server for [Mipiti](https://mipiti.io) — security posture platform.

Lets AI coding agents (Claude Code, Claude Desktop, Cursor, etc.) generate and manage security models, controls, compliance mapping, and evidence programmatically.

## Hosted Endpoint (Recommended)

The Mipiti backend hosts an MCP server at `https://api.mipiti.io/mcp/`. No installation needed — just configure your MCP client to connect.

### OAuth (Recommended)

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

## Tools

### `generate_threat_model`

Generate a complete threat model from a feature description. Runs a 5-step AI pipeline (30-60 seconds) producing trust boundaries, assets, attackers, control objectives, and assumptions.

**Example prompt**: "Generate a threat model for our new OAuth login feature that supports Google and GitHub providers"

### `refine_threat_model`

Refine an existing threat model based on an instruction. Creates a new version.

**Example prompt**: "Add CSRF attack vectors to model tm-001"

### `query_threat_model`

Ask a question about an existing threat model.

**Example prompt**: "Does model tm-001 cover SQL injection attacks?"

### `list_threat_models`

List all saved threat models with IDs, titles, versions, and creation dates.

### `get_threat_model`

Get the full details of a specific threat model by ID, optionally at a specific version.

### `get_controls`

Get implementation controls for a threat model's control objectives. Auto-generates controls if none exist yet.

### `export_threat_model`

Export a threat model as CSV (returned as text), PDF, or DOCX (download URL).

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
