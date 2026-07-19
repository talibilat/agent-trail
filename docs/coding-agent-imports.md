# Coding-Agent Session Imports

AgentTrail converts explicitly supplied local Claude Code, Codex, and OpenCode session exports into canonical AgentTrail JSONL without a source SDK or network service.
The importer reads only `INPUT` and writes only `OUTPUT`.
It never searches home directories, global session directories, repository state, or other session files.

## Usage

Import a session with automatic source detection:

```bash
agent-tail import session session.jsonl --source auto --output run.jsonl
```

Select a source explicitly when detection reports ambiguity:

```bash
agent-tail import session session.jsonl --source claude-code --output run.jsonl
```

The accepted source values are `auto`, `claude-code`, `codex`, and `opencode`.
`INPUT` or `OUTPUT` may be `-`, but both cannot be standard streams in the same invocation.
Importing identical bytes twice produces byte-identical sorted compact JSONL.

Inspect the generated artifact through the existing sanitizer boundary:

```bash
agent-tail run.jsonl
agent-tail run.jsonl --export report.md
agent-tail serve run.jsonl
```

## Supported Formats

The support boundary is intentionally fixture-pinned rather than inferred from undocumented historical variants.

| Source | Tested producer version | Required format declaration | Container | Status |
| --- | --- | --- | --- | --- |
| Claude Code | `1.0.58` | `system` and `init` record with `session_format_version: "1"` | Transcript JSONL | Current pinned format |
| Codex CLI | `0.98.0` | Initial `session_meta.payload.format_version: "1"` | Rollout JSONL | Current pinned format |
| OpenCode | `1.0.153` | Top-level `schema_version: "1"` | Session export JSON | Current pinned format |

Claude Code records are identified by `sessionId` and `uuid`, with optional `parentUuid` and `agentId` identities.
Codex records use an initial `session_meta` followed by `response_item` and `event_msg` records whose normalized payload type determines the mapping.
Codex payload `id` is preferred, and the source record ordinal is the documented fallback when an ID is absent.
OpenCode exports contain `info` and `messages`, and each message contains `info` plus ordered `parts`.
OpenCode part `id` is preferred, and the message ID plus part ordinal is the documented fallback when a part ID is absent.
Declared format versions other than `1` fail as unsupported instead of being interpreted as malformed current records.
Producer versions in the table identify the exact fixtures under test and do not promise compatibility with every release in the same product series.

## Mapping

Mappings are best effort and use only fields directly reported by the source.
Message roles, session identity, producer metadata, source schema version, and complete accepted source records remain under `attributes.claude_code`, `attributes.codex`, or `attributes.opencode`.
Messages become `message.sent`, and explicit agent start and stop records become agent lifecycle events.
Directly reported model token counts become `model.request.finished` with canonical `input_tokens`, `output_tokens`, and `total_tokens` fields when available.
Explicit tool starts and outcomes become tool lifecycle events with directly reported arguments, command, result, and exit code.
An explicit repository path can become `context.read`, while valid positive line and symbol locators are retained only when supplied.
An edit becomes `change.applied` only when the source supplies a non-blank path and all four valid Git hunk range values.
Whole-file writes, prose edit claims, and patches without complete valid ranges remain ordinary tool events and never create an evidence-map hunk.
Explicit verification start and finish records become verification lifecycle events only when command and result boundaries are present.
A verification finish references its explicit start with `completes`.
Test origin remains unknown because these pinned source formats do not prove whether a test was pre-existing or written by the same agent.
The importer does not infer requirements from user prose.
A task can become `requirement.observed` only in a future pinned format that directly supplies both a stable non-blank requirement ID and non-blank text.
Only explicit source event references create `motivated_by`, `informed_by`, `preceded_by`, `applies`, `verified_by`, or `corrects` relationships.
No relationship, edit, verification, requirement, repository locator, or test provenance is reconstructed from prose or repository state.

Trace IDs are SHA-256-derived from the source name and session ID.
Event and span IDs are SHA-256-derived from the source name, session ID, and stable source record ID or documented ordinal fallback.
Actor and emitter identities retain the source tool prefix and directly reported agent identity.
Sequences are contiguous independently for each emitter in source order.
Explicit parent source IDs become canonical parent spans only when the referenced source record was accepted.
Records from different emitters retain source order within each emitter without inventing a total order between concurrent agents.

## Detection And Diagnostics

Automatic detection checks only structural signatures in the supplied bytes.
It fails when no source matches or when multiple source signatures match, and an ambiguous result instructs the user to pass `--source`.
Explicit source selection still validates that source's required header and version.
Malformed JSONL siblings and malformed semantic records produce path-based diagnostics while independent valid records continue.
Malformed OpenCode top-level JSON cannot expose independent message boundaries and therefore fails as an unsupported document.
Diagnostics identify paths and expected shapes without printing rejected source values.
Diagnostics are redacted and bounded to 100 individual errors plus an omitted-count summary.

Exit code `0` means at least one canonical event was written, including partial success with diagnostics.
Exit code `1` means a supported document was read but no canonical event was accepted.
Exit code `2` means command validation, decoding, file access, output, source detection, document shape, or source version failed.

## Artifact Safety

Generated canonical JSONL is a sensitive local source artifact and intentionally retains prompts, commands, results, paths, IDs, errors, and unknown source fields.
Protect it exactly like the original coding-agent session.
Direct inspection, Markdown export, and serve mode pass canonical events through the existing sanitizer before indexing.
The sanitizer redacts common secret shapes and neutralizes browser and Markdown rendering paths, but no finite ruleset can guarantee removal of every private value.
Review any output before sharing it.
