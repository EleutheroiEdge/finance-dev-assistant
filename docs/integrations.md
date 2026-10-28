# Coding-agent integration

The CLI works independently of a coding-agent product. Optional adapters are
provided for supported hosts:

The installed wheel includes all three templates and the workflow/provider/readiness guides.
Export them to a new directory:

```sh
finassist export-kit --output assistant-integration
```

This writes a standalone kit for inspection, not host configuration. Existing
destination directories are refused. Repository copies are listed below.

- Portable procedure: `skills/evidence-review/SKILL.md`.
- Claude role: `.claude/agents/finance-reviewer.md`.
- Codex role: `.codex/agents/finance-reviewer.toml`.

Copy only the desired reviewed role or skill into the host's documented project
location. Do not replace existing AGENTS.md, tool permissions, personal profiles
or model routes. Keep the target project's specification authoritative. Resolve
the installed skill location when moving role files across projects.

These role files provide behavioral instructions, not an independent sandbox.
The Codex role requests read-only mode; execution evidence needs a separately
approved runner with scratch access. A host may not support every metadata field;
verify its current role/skill documentation and fail clearly rather than
silently broadening permissions.

Users of other model hosts can use the CLI directly or adapt the portable skill.
No native-agent SDK, MCP server, browser extension, background service or personal
login is installed by this package. Direct model adapters and native coding-agent
roles are distinct integration modes. Both remain subject to project policy.
