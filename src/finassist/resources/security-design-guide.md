# Security design

finledgerpoli screens outgoing source, constrains execution and binds approvals to exact evidence so you can review changes with explicit control over disclosure and mutation. Its command is `finassist`; the [threat model](threat-model.md) describes the boundaries and assumptions.

## Source and request controls

| Area | Protection |
| --- | --- |
| Sensitive content | Screen both committed source versions for credential assignments, quoted JSON/dict keys, YAML/scalar values and configured sensitive patterns; apply the same patterns to reports and evidence. |
| Source identity | Read immutable Git blobs without checkout filters, hooks, fsmonitor or ambient Git overrides; bind base/head, source hashes and executable modes. |
| Coverage | Account for public binary assets as omissions without reading bytes; reject private paths even outside the allowlist. Require complete coverage unless partial model review is explicitly selected; readiness always requires complete coverage. |
| Generated files | Bind configured exclusions to outgoing requests and snapshots; retain publication screening, source rebuild comparisons and startup asset integrity checks. |
| Model responses | Validate structured findings, source references and line bounds. Keep source and provider text separate from fixed authority instructions. |
| Network | Require reviewed provider configuration, explicit network approval and approval of the exact outgoing-request hash. Existing keys do not enable a provider. |

## Execution and patch controls

Container images must be prebuilt and digest-pinned. Image values reject option-shaped arguments, and option termination precedes the image. Approved argument arrays run on screened committed snapshots with read-only source, no network, non-root execution, dropped capabilities, bounded scratch storage and resource limits. Cleanup is checked separately from the test result.

Patch proposals protect policy, build, dependency and script paths by default. Application requires inspection and approval of the exact patch hash, the original head and a clean feature branch. Parsing counts both sides of hunks, rejects undeclared sections and checks Git's complete path list before backups or mutation. Special files, binary/rename patches, stale heads and default/protected branches are rejected. Backups and guarded rollback preserve original bytes and supported modes; later changes prevent automatic restoration.

## Audit, spend and readiness controls

Operational commands record correlated lifecycle events with reduced metadata. Verification checks event envelopes, start/completion correspondence, reservation balances and incomplete runs. Readiness, export and incomplete-run queries verify and read in one SQLite transaction. Corrupt or unavailable audit state blocks operations before work begins. Unknown paid usage stays reserved until explicitly reconciled; zero-rate self-hosted usage is treated separately.

A saved record binds an action to hashes. Readiness requires matching configuration, base/head, source hashes and modes, complete coverage, fresh audited model review, passing required recipe records and cleanup, and no unknown spend or incomplete commands. Source must be clean before and after the CLI check. Stale or invalid evidence returns a blocked result. Observation checks receive derived approval status; malformed reconciliation values produce a bounded error.

## Repository and release controls

A local patch guard and a live server policy protect different boundaries. The read-only GitHub inspector reports classic PR, CI, administrator, force-push and deletion controls. A zero formal-approval count is an explicit policy observation. Your team must independently verify actual reviews, discussions and current server rules.

Adapt the [branch-protection template](maintainers/branch-protection-proposal.json) to your check identities, including native platform and isolation checks. Require up-to-date successful CI, PRs, resolved conversations, administrator enforcement and linear history; prevent force pushes and deletion. Require an independent formal approval when an eligible reviewer exists. With a sole author, select a workable approval policy explicitly; model comments are not GitHub approvals. See the [settings checklist](maintainers/repository-settings.md).

## Limits

- Pattern screening cannot establish confidentiality. Inspect the outgoing request yourself; prompt delimiters cannot make untrusted text safe.
- Local hash chains detect corruption but do not defeat a malicious same-user rewrite. Independent identities, retention and external integrity anchors require a separate integration.
- `check` tests committed source, not an uncommitted applied proposal. Commit a candidate in an isolated feature branch or use a separately reviewed adapter.
- Native tests cover Windows, macOS and Linux; real OCI isolation is exercised on Linux. Runtime sharing, contexts and host/kernel safety remain your responsibility. Local recipes require trusted-code approval and have no OS sandbox.
- Synthetic tests and mocked transports exercise contracts, not live protocol compatibility, model quality or the truth of findings. Version pins and release provenance do not replace complete dependency artifact-hash locking or security review.
- Configuration and local evidence do not authorize merges, deployment, settings changes or financial actions. No settings-write command or hosted production target is provided.

Secret and confidential-figure screening is a backstop, not the control that keeps
data private. The primary controls are the path allowlist, keeping secrets in
gitignored files or a secret manager, and a policy that keeps client data out of
reviewed source. A pass means only that no rule matched.

In parseable `.py`/`.pyi` source, credential screening reads code with Python's own
parser. A credential-named target given a literal value is refused: an assignment,
typed assignment, walrus target, keyword argument, function default, dictionary
key, attribute or subscript, including a literal fallback in `os.getenv(NAME, ...)`
or `os.environ.get(NAME, ...)` and a literal `default=` argument. Credential names
use the label vocabulary below: a name matches when it ends with a credential word,
at any length and whatever characters come first. A string or numeric value must
have at least 12 characters, counted in its source spelling; account and routing
numbers need at least six digits, and integers count by magnitude. Type
annotations are never inspected, so a `signing_key` field annotated
`Ed25519PrivateKey | None` passes. Unquoted names and call results are not literals and pass. Comments,
docstrings and other string text are screened with the text rules, and known
secret formats are screened across the whole file. Python that does not tokenize
and parse keeps the strict text rules.

In TypeScript and JavaScript (`.ts`, `.mts`, `.cts`, `.js`, `.mjs`, `.cjs`), Go, Java,
Kotlin and SQL files, the screen first finds the file's strings and comments. In these
languages a string literal needs quotes, so a credential-named field followed by an
unquoted value in code is being given an expression: a variable, a member, a call or an
environment lookup. That is a reference, and it is not refused. The same words inside a
string or a comment are text and keep the strict rules, and a number is a literal
everywhere.

A reference is still refused when its expression holds a quoted literal of 12 or more
characters that the field would receive. That is every string in the expression except
three kinds:

- **The name a lookup is given.** When the name of a call or of an indexed object is made
  of lookup words, its first string is the name of the value:
  `config.get("auth.signing")`, `process.env["NAME"]`, `requireEnv("NAME")`,
  `getSecretValue("name")`. One word must say that it looks something up, or where: `get`,
  `getenv`, `read`, `load`, `fetch`, `require`, `lookup`, `resolve`, `find`, `must`, `env`,
  `config`, `setting`, `param`, `header`, `query`, `option`, `property` and a few like
  them. Every other word may only say what comes back, from where, or what happens when it
  is missing: `secret`, `password`, `key`, `token`, `value`, `string`, `or`, `throw`,
  `vault`, `from` and the like. Any other word means the call may use what it is given, so
  `getPasswordHash("...")` and `builder.withConfig("...")` hold values. A later argument
  is what the field gets when the lookup finds nothing, and it counts.
- **The text of an error.** A call whose name has `error`, `fail`, `panic`, `throw`,
  `exception` or a word like them, and `requireNonNull` and its relatives, stop the
  program, so their strings are messages.
- **A field of an object passed as an argument,** as in `createClient({ url: "..." })`.

So a literal handed to a call that hashes, encodes or wraps it is still the literal:
a field named `password` given `argon2.hashSync("...")` or `encoder.encode("...")` is
refused, and so is an operand after `||`, `??`, `?:` or `+`, and the argument of a call
that supplies a default (`orElse`, `getOrElse`, `unwrapOr`, `default`, `defaultValue`,
`withDefault`, `fallback`). The expression ends at a comma, a semicolon or a closing
bracket it did not open. It ends at the end of a line only when the line ends with an
operand and the next line of code begins something new: a name, or a closing bracket. Any
operator at either place carries it on, written as a sign or as a word such as `in` or
`instanceof`, and so does anything the reader cannot place, because reading on can only
refuse more. In SQL it also ends at the next keyword.
A comma between type arguments, as in `derive<A, B>("...")`, is not an end.

This reading is narrow on purpose. A file, or one match in it, keeps the strict text rules
whenever it is not clear that the words are code:

- The file does not read cleanly: a string or a comment is never closed, a quoted string
  runs past the end of its line, or a SQL file holds a backslash before a quote, which
  dialects read differently. In SQL and Kotlin a block comment can hold another one, and
  is read to the end of the outer one.
- A script holds a closing or self-closing tag. The text between two tags is not quoted,
  so `.jsx` and `.tsx` files are not read this way at all.
- In a SQL file, the words are in the rows after `COPY ... FROM stdin`, in a client command
  such as `\connect`, or in a dollar-quoted string, whatever its tag (`$$`, `$body$`,
  `$q1$`). A dollar-quoted body after `AS` or `DO` is a function or a block, and is read as
  code.
- The words are inside a regular expression. A slash starts one after an operator, an
  opening bracket or a word such as `return`; after a name, a number, a string or a closing
  bracket it is a division sign. Where one starts and does not end on its line within
  1,000 characters, the whole file keeps the strict rules. As a second check, an odd
  number of slashes in code before the label on its line keeps them for that match.
- The label and a bare value are alone on their line outside every bracket. A settings
  file saved under a code suffix reads the same. Code in front of the label on its line,
  such as a keyword or the object the field belongs to, shows a program, and in SQL so
  does a keyword earlier in the statement.
- The expression has no end within 4,000 characters, or the file needs more work than the
  screen allows one file.

In any file read with its path, a quoted value that is exactly one expansion names a value
kept elsewhere and is not refused: `${NAME}`, `${{ secrets.NAME }}`, `{{ name }}`,
`$(NAME)` and `${provider:path}`. An expansion with a default written into it, such as
`${NAME:-word}`, and an expansion with anything beside it are literals; an empty default,
`${NAME:-}`, holds nothing and is a reference. A dollar and a name without braces, and
`$(...)` around anything but a name, are references only inside double quotes in a shell
script (`.sh`, `.bash`, `.zsh`, `.ksh`), where the shell always expands them. Anywhere
else a password can be spelled that way. A substitution that holds `echo`, `printf` or a
here-string prints its own words, and one that holds an expansion with a default carries
that default: both are literals.

In a YAML file, a key on the line after a credential-named key starts a mapping and is not
a value, as in `github_token:` followed by `description:`. Inside a block scalar the same
lines are text, and keep the strict rules, with or without a tag or an anchor before the
`|` or `>`.

Text read without a path keeps the strict rules: a file name, a setting, policy text and
everything a model returns.

Under a path the operator lists in `placeholder_credential_paths`, the credential label
rules are not applied. That is the operator's statement that the credential-named values
there are made up, and the files are sent as they are. The format rules, the account
rules and the project's own patterns are applied there as everywhere, and a model may
repeat a labelled value from such a file only exactly.

Credential key screening requires a credential word in the label: secret,
private, signing, encryption, access, client, master, auth or api, optionally
followed by access and then key (underscore/hyphen separators are supported).
Bare key, primary/foreign/partition/sort/cache/idempotency keys are not secrets
by name alone. In text, the matcher screens quoted literals of at least 12
characters and unquoted values; it excludes unquoted calls,
dotted references and digit-free uppercase-leading whole identifiers. Whitespace,
end of input and annotation punctuation (`[`, `]`, `)`, `,`, `;`) can end such an
identifier; `/`, `+`, `=`, `-`, `:` and `@` continue a candidate literal.
Uppercase-leading unquoted literals containing digits are screened too.
Source/request bytes are never rewritten.

Review output may quote an exact credential-label match from a screened Python
annotation in its hash-bound request; a value merely occurring elsewhere in source
is insufficient. The screening view retains the label and hides the complete
recorded annotation, including a union, so a new value appended after `=` remains
subject to the assignment patterns. Shorter `label: Type` quotes also pass; an
unrecorded union/subscript continuation is refused conservatively. This does not
prove output confidentiality. Original output strings
are screened before JSON escaping as well as in the serialized envelope. Proposed
and approved patches are parsed and applied only to private disposable copies for
screening each complete post-image with its path, before any target worktree
mutation. Rollback screens the original and current file with their Python paths
when an active policy is supplied. Approval, head, scope and recovery checks remain.

Review output may also repeat a reference from the screened source: the label, the
separator and the complete value exactly as they stand there, and after them what follows
on the same source line, such as the brackets of a call. The quote must be a whole
operand, so one that ends with an operator is refused, and it must end its expression, in
one of two shapes:

- **In prose, a code span:** a backtick just before the label and one just after the
  quote. No operator that could join a literal to it may follow: `||`, `??`, `&&` or `+`,
  or a `?` or `:` before another code span.
- **In code, the end of its line:** nothing after the quote but a comma or a semicolon.
  Without one, the next line that holds code must begin something new: a name that is no
  operator, a closing bracket, a quoted key, or the end of a fenced block.

Nothing after the quote on its line may hold a quote mark or an equals sign. The same
label with any other value, or with a literal added after it in quote marks, in backticks
or as a number, on the same line or the next, is refused as before. So is a quote outside
a code span with prose after it on its line: what follows cannot be told from code.

A refusal names its rule, and for a file's content the version (`base` or `head`) and up
to 20 line numbers, in local output only: under `local` in the error that `plan` prints,
and in the path rows of both `doctor` reports. It never holds the value. The rules are
`credential_label`, `account_label`, `private_key_block`, `github_token`,
`aws_access_key_id`, `sk_prefixed_key` and `nine_digit_identifier`.

Known limits of the text rules, which are no longer extended:

- A typed assignment in non-Python text, such as `password: str = "..."` in a
  Markdown code block, is not detected.
- A credential-named label followed by a digit-bearing type name, such as
  `signing_key` annotated `Ed25519PrivateKey`, is refused in Markdown and YAML.
- Digit-free all-caps unquoted values resemble constants and are not detected.
- Labels outside the vocabulary (for example `auth_token` or `pwd`) and values
  shorter than the threshold are not detected.
- Values split across lines, encoded or built at runtime are not detected.

Known limits of reading a file as its language, each listed with its reason in
`tests/credential_cases.py` and tested as it behaves today:

- A string argument counts as a value unless the call's name says it looks something up
  or raises an error. So a usage text, or a name given to a lookup the words above do not
  cover, is refused: `flags.String("name", "", "the credential used for the database")`,
  `loadTenantSecret("billing/jwt-signing-key")`.
- Outside a shell script, a quoted `$NAME` without braces is refused. Inside one, a
  command substitution that holds an expansion with a default is refused.
- A comparison written with `<` after a name, before a comma, reads on past the comma, so
  a literal in the next field can refuse the line.
- SQL comments are read as nesting, which PostgreSQL does and MySQL does not.
- A reply that repeats a reference whose expression goes on over the next line is refused.
  So is one that quotes a reference outside a code span with more text on its line, or
  with a bullet, a number or an opening bracket at the start of the next.
- A statement that ends its line with something other than an operand is read on into the
  next line, so a literal there can refuse it.
- A reference in a `.jsx` or `.tsx` file, or in a script that holds markup, is refused.
- The name of a stored secret written as a plain YAML scalar is refused when its key ends
  in a credential word, as Helm's `existingSecret` does: a password is a plain scalar too.
- A quoted value with an expansion and other text, such as `"prefix-${NAME}"`, is refused.
- A literal in backticks is not detected, and neither is a literal after a short
  expression: the label rules need 12 value characters after the separator, so
  `env.DB || "..."` is not read. A literal that follows a label without a separator, as
  in SQL's `PASSWORD '...'`, is not detected.
- Inside a block of a script an unquoted value is an expression whatever it spells. A
  settings line with a dotted name saved under a code suffix reads as code, and so does
  a regular expression that directly follows a closing bracket when an even number of
  slashes stands before it on its line.
- A literal passes when it is the first string of a call whose name is made of lookup
  words, or stands in brackets after such a name; when it is a field of an object passed
  as an argument; and in a shell script when a command substitution other than `echo`,
  `printf` or a here-string prints it.

Known limits of the Python check: values computed at runtime (concatenation,
variables and calls other than the two fallback forms above) are not literals and
pass, and a credential written as a type annotation is not inspected.

Quote literal credentials. Filename and syntax are not proof of privacy. This
supplements inspection, not a confidentiality proof.

Confidential numeric screening in the policy-approved model gate and history
compares listed magnitudes in source, allowed fixtures, profiles and provider
free text before exposing findings. Every file is screened as text; in Python files
each numeric literal, including one inside an f-string field, is also read with Python's
own tokenizer and parser and compared by exact value, zero padding included, and a
`.py` file that cannot be read is refused. It fails closed on grouped
short figures;
legacy `review` and `propose` remain outside this opt-in guard. See the
[pre-merge gate](pre-merge-gate.md#confidential-numeric-tokens-policy-approved-model-gate)
for exact exemptions, encoding limits and private token-file rules.
