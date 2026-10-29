# Research input lineage

Track normalized observations and their approval history in the optional finledgerpoli evidence store. Its command is `finassist`; records remain in the private local state directory.

An observation contains entity, metric, exact value, unit, period start/end,
period kind, publication/retrieval times and source. Content cannot include an
approval status: every new entry is a draft. Revisions append and explicitly
supersede the previous entry for the same entity, metric, unit and period.
Changing period or units is a separate fact, not a silent revision.

```sh
finassist evidence add --input YOUR_REDUCED_OBSERVATION_FILE
finassist evidence approve --id ENTRY_ID --approve-hash INSPECTED_CONTENT_HASH
finassist evidence latest --entity ENTITY --metric METRIC --period-end TIMESTAMP --unit UNIT
```

`reject` uses the same id/hash contract. An approval or rejection is final for
that revision; a correction creates a new revision. Drafts never replace an
approved result in `latest`. An ambiguous period or unit selection blocks until resolved.
Use `--period-start` and `--period-kind` to distinguish a quarter and annual
observation sharing the same end date.
Evaluate an approved observation against the intended decision time with
`finance-check --kind observation` before using it in point-in-time analysis.

## Limits

SQLite triggers prevent ordinary content updates/deletion and decision-history
edits. A user who controls the database file can bypass local integrity checks;
this is not enterprise authentication, a signature or proof the filing is true.
Restrict approval actions to your approval process and use a project adapter for
SSO, separation of duties, retention, or regulated recordkeeping requirements.

Keep licensed/private observations local. Metadata validation does not establish
that a payload is safe for a public repository or another model provider.

The store does not fetch filings, create investment opinions or automatically send observations to a provider. See the [threat model](threat-model.md).
