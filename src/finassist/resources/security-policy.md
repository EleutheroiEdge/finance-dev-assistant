# Security policy

Use this finledgerpoli policy to handle sensitive source, approve actions and report vulnerabilities privately. The command is `finassist`; detailed boundaries are in the [threat model](docs/threat-model.md).

## Safe use

Treat source, diffs, test output and model responses as untrusted. Never copy
live personal profiles, account data, licensed datasets, environment files or
credentials into a repository or outgoing request.

The default path is offline. A remote review needs a reviewed configuration,
network permission and approval of the exact screened outgoing-request hash. Source paths,
both file versions, content patterns, size, encoding and Git object modes are
checked. A short denylist cannot prove confidentiality; inspect the payload.
There is no guard-bypass switch or automatic provider escalation.

Code under review can be hostile. Use a dedicated, patched container runtime,
prebuilt digest-pinned images, read-only mounts, network isolation and no secrets.
Do not mount a container socket, host home, credentials or production state.
Direct model HTTP requests receive no shell tools. Tool descriptions and role
instructions do not enforce operating-system boundaries.

## Limits

The components you rely on include this package, its dependencies, reviewed
configuration, your team, Git/Python and the chosen runtime/provider. Prompt
injection resistance is layered, not guaranteed. A syntactically valid report
does not establish that its findings are true. Private local audit hashes are
not signatures and cannot defeat a malicious same-user rewrite of all state.

Spend controls reserve a conservative estimate before a call; prices and actual
provider accounting may differ. Failed or unknown attempts stay held. Reconcile
them from real billing rather than deleting state or retrying blindly.

No merge, deployment, security-policy change, trade or credential operation is
authorized by the assistant's report. Follow the target project's human gates.

Private artifacts use owner-only file modes on POSIX. Windows inherits directory
ACLs: chmod does not establish a POSIX-equivalent restriction on Windows. Choose
a private user-owned state/output directory and review its Windows access list;
do not use a shared folder for private audit/evidence data. `doctor` reports this
limitation explicitly. No security policy or ACL is changed automatically.
Native CI exercises Windows, macOS and Linux. Local recipes remain trusted-code
execution: POSIX process groups and Windows job objects are cleanup mechanisms,
not sandboxes. Windows launches the primary thread suspended, assigns its Job,
then resumes execution. Container daemon
cleanup is verified separately. `doctor` checks binary presence, not daemon access.

## Reporting vulnerabilities

For a suspected vulnerability, do not post credentials, client records or a
working private-data payload to a public issue. Use a minimal synthetic
reproducer and the repository's available private security-reporting channel.
If private reporting is unavailable, request contact without posting the payload.
