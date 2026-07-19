# Context Provenance

AgentTrail accepts producer-recorded context provenance and never opens a repository or recomputes a fingerprint while ingesting, serving, reviewing, or exporting a run.
The contract records identifiers and digests rather than file contents, search result contents, prompts, private reasoning, or compaction summary text.

## Canonical Events

A `context.read` event may set `attributes.context.content_sha256` to a lowercase 64-character SHA-256 digest and may set `attributes.repository` as described below.
The digest is computed over the exact sequence of bytes returned to the actor for the complete observed file, before text decoding, newline conversion, Unicode normalization, truncation, or display formatting.
An observation of a byte range or generated representation must not be labeled with the complete-file digest unless those complete file bytes were actually observed.

A `context.search` event sets `attributes.search.query` to a non-blank string and `attributes.search.matches` to an array of distinct non-blank repository-relative path strings in producer result order.
An empty `matches` array is canonical and reports only that the producer emitted no matches.
The event may set the same repository snapshot fields as a read or change.

A `change.applied` event may set `attributes.change.preimage_sha256` to the SHA-256 digest of the complete file immediately before the edit.
The digest uses the exact pre-edit file bytes with no decoding, newline conversion, Unicode normalization, or hunk extraction.
The event may set the same repository snapshot fields as a read or search.

`attributes.repository.commit` is an optional non-blank Git object ID string identifying the producer's resolved repository commit.
`attributes.repository.worktree_sha256` is an optional lowercase 64-character SHA-256 digest of the manifest defined below.
The two fields are independent, so a producer may report either or both.

## Path Safety

Provenance matching converts backslashes to forward slashes, collapses `.` and repeated separators, and otherwise preserves case.
Matching rejects blank paths, paths beginning with `/`, Windows drive-absolute paths, and any path containing a `..` segment.
Rejected paths remain visible as sanitized `raw_path` values with `invalid_repository_path`, `absolute_repository_path`, or `parent_traversal_repository_path` diagnostics.
Rejected paths never participate in freshness matching.

Search projection preserves every sanitized producer match for inspection while exposing only safe, normalized, first-occurrence paths in `canonical_matches`.
A repeated raw match produces `duplicate_search_match` and does not add another canonical match.
Malformed query, matches, digest, and snapshot fields remain in the sanitized event attributes but are omitted from validated calculations and receive typed diagnostics.

## Dirty-Worktree Manifest

The worktree digest is SHA-256 over a binary manifest and is the SHA-256 of zero bytes when the manifest has no records.
The candidate path set is the union of every tracked path whose index or worktree state differs from `HEAD` and every untracked non-ignored file path.
Producers must include staged-only changes, unstaged changes, deletions, type changes, executable-bit changes, unmerged paths, intent-to-add paths, and files below untracked directories.
Ignored paths and paths inside Git's administrative directory are excluded.
Renames are represented by the old path deletion and the new path file record, so rename detection settings cannot change the fingerprint.

Each repository-relative path is represented by the exact raw path bytes used by Git and records are sorted by unsigned lexicographic comparison of those path bytes.
Each record is appended to the hash stream as `kind NUL mode NUL path_length NUL path content_length NUL content`, with no trailing separator after `content`.
`kind`, `mode`, `path_length`, and `content_length` are ASCII bytes, `NUL` is one zero byte, and both lengths are unsigned base-10 byte counts without signs or leading zeroes except the value `0`.
The `path` and `content` fields contain exactly the declared number of bytes, so embedded newlines and other delimiters cannot make two manifests ambiguous.

An existing regular file uses kind `F`, mode `100755` when its Git executable bit is set and mode `100644` otherwise, and exact file bytes as content.
An existing symbolic link uses kind `L`, mode `120000`, and the link target's raw bytes as content without dereferencing the link.
A deleted tracked path uses kind `D`, its `HEAD` Git mode, and zero content bytes.
A gitlink uses kind `G`, mode `160000`, and the lowercase hexadecimal object ID currently selected by the submodule worktree as ASCII content.
An unmerged non-gitlink path uses the kind, mode, and bytes currently present in the worktree, or the deletion record when no path is present.
Directories themselves do not produce records.

The manifest describes the producer-visible working tree, not the index as an alternate file tree.
For a staged file that also has unstaged edits, content therefore comes from the working tree.
For a staged-only file, the working-tree bytes equal the staged bytes and are hashed once.
For a tracked path deleted only in the index but still present in the working tree, the existing worktree object is hashed because that is the current producer-visible path.

## Deterministic Diagnostics

A read is `stale` for a change only when both events have the same safe normalized path, both relevant SHA-256 fields are valid, and their digest values differ.
A read is `fresh` only as shorthand for byte equality of that recorded file and does not prove that all relevant context was loaded.
Missing or malformed hashes produce `unknown`, and unsafe paths cannot produce `fresh` or `stale`.
`stale_context_read` identifies the read event, change event, and normalized path without claiming why the bytes differ.

Chronology remains independent from byte comparison.
Distinct sequence values from one emitter establish order even when timestamps are equal or clock-skewed, while equal sequence values remain undetermined.
Across emitters, a later timestamp establishes order and equal timestamps remain undetermined.
Reads after a decision or change and undetermined ordering retain the existing chronology diagnostics rather than being rewritten as a hash conclusion.

Two actor snapshots produce `divergent_repository_snapshot` only when their events are causally concurrent or their ordering is undetermined and at least one comparable valid field differs.
The diagnostic lists exactly the differing comparable fields from `commit` and `worktree_sha256` and does not infer which snapshot is correct.
Missing or malformed snapshot fields are not comparable and therefore cannot establish divergence.

A compaction boundary lists only distinct explicit `summarizes` event references and their known chronology.
AgentTrail does not infer what the compaction retained, omitted, or changed.

## Shared Projection

Run detail exposes `context_provenance.actors` as actor-specific timelines of reads, searches, compactions, and changes in canonical run order.
Each entry exposes snapshot and hash availability explicitly as `available`, `absent`, or `malformed`.
Run detail also exposes deterministic diagnostics and an event lookup under `context_provenance.by_event_id`.
Each valid Change Evidence Map change links to its shared projected timeline entry through the same event ID.
The packaged browser, live review, and offline HTML report all render this shared run-detail projection.
