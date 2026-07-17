import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.request import urlopen

from playwright.sync_api import expect, sync_playwright

def event_data(**changes):
    data = {
        "schema_version": "1.0",
        "event_id": "evt-1",
        "trace_id": "trace-1",
        "span_id": "span-1",
        "emitter_id": "worker-1",
        "sequence": 1,
        "timestamp": "2026-07-13T11:02:44.912Z",
        "kind": "tool.call.started",
        "actor": {"id": "reviewer-1", "role": "planner"},
        "operation": {"status": "running", "name": "read_file"},
    }
    data.update(changes)
    return data


class ServeEndToEndTests(unittest.TestCase):
    def test_change_inspector_shows_evidence_and_human_corrections_safely(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "change-evidence.jsonl")
            source.write_text("".join((
                json.dumps(event_data(
                    event_id="requirement-1",
                    kind="requirement.observed",
                    actor={"id": "user"},
                    attributes={"requirement": {
                        "id": "R3",
                        "text": "Expired sessions must be rejected. <img id=evidence-injected src=x>",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="context-1",
                    span_id="span-2",
                    sequence=2,
                    kind="context.read",
                    actor={"id": "researcher-1"},
                    attributes={"context": {
                        "path": "docs/session-lifecycle.md<img id=context-injected>",
                        "line_start": 42,
                        "line_end": 47,
                        "symbol": "Session expiry<img id=context-symbol-injected>",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="context-end-only",
                    span_id="span-context-end-only",
                    sequence=2,
                    kind="context.read",
                    actor={"id": "researcher-2"},
                    attributes={"context": {
                        "path": "docs/session-retention.md",
                        "line_end": 51,
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="context-unknown-actor",
                    span_id="span-context-unknown-actor",
                    sequence=2,
                    kind="context.read",
                    actor={"id": " \t"},
                    attributes={"context": {
                        "path": "docs/anonymous-research.md",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="verification-started-1",
                    span_id="span-3",
                    sequence=3,
                    kind="verification.started",
                    actor={"id": "test-runner-1<img id=verification-starter-injected>"},
                    attributes={"verification": {}},
                )) + "\n",
                json.dumps(event_data(
                    event_id="verification-started-conflict",
                    span_id="span-verification-started-conflict",
                    sequence=3,
                    kind="verification.started",
                    actor={"id": "conflicting-test-runner"},
                    attributes={"verification": {
                        "command": "pytest tests/test_other_session.py<img id=verification-conflict-injected>",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="verification-1",
                    span_id="span-verification-finished",
                    sequence=4,
                    kind="verification.finished",
                    actor={"id": "result-reporter-1"},
                    attributes={"verification": {
                        "command": "pytest tests/test_session.py<img id=verification-injected>",
                        "passed": True,
                        "exit_code": 0,
                        "test_origin": "same_agent",
                    }},
                    relationships=[
                        {
                            "type": "completes",
                            "event_id": "verification-started-1",
                        },
                        {
                            "type": "completes",
                            "event_id": "verification-started-conflict",
                        },
                    ],
                )) + "\n",
                json.dumps(event_data(
                    event_id="verification-2",
                    span_id="span-verification-missing",
                    sequence=5,
                    kind="verification.finished",
                    actor={"id": "result-reporter-2"},
                    attributes={"verification": {"passed": False}},
                    relationships=[
                        {
                            "type": "completes",
                            "event_id": "missing-start<img id=verification-missing-injected>",
                        },
                        {
                            "type": "completes",
                            "event_id": "context-1",
                        },
                    ],
                )) + "\n",
                json.dumps(event_data(
                    event_id="compaction-1",
                    span_id="span-compaction",
                    sequence=6,
                    kind="context.compacted",
                    actor={"id": "summarizer-1"},
                    relationships=[
                        {"type": "summarizes", "event_id": "context-1"},
                        {"type": "summarizes", "event_id": "context-end-only"},
                        {"type": "summarizes", "event_id": "context-invalid-detail<img id=invalid-context-injected>"},
                        {"type": "summarizes", "event_id": "missing-context<img id=compaction-missing-injected>"},
                        {"type": "summarizes", "event_id": "tool-1"},
                        {"type": "references", "event_id": "unrelated-context"},
                        {"type": "references", "event_id": "irrelevant-missing-context"},
                    ],
                )) + "\n",
                json.dumps(event_data(
                    event_id="compaction-unknown-actor",
                    span_id="span-compaction-unknown-actor",
                    emitter_id="unknown-compaction-worker",
                    sequence=1,
                    kind="context.compacted",
                    actor={"id": " \t"},
                    relationships=[
                        {"type": "summarizes", "event_id": "context-unknown-actor"},
                    ],
                )) + "\n",
                json.dumps(event_data(
                    event_id="empty-compaction<img id=invalid-compaction-injected>",
                    span_id="span-empty-compaction",
                    sequence=6,
                    kind="context.compacted",
                    actor={"id": "empty-summarizer"},
                )) + "\n",
                json.dumps(event_data(
                    event_id="tool-1",
                    span_id="span-4",
                    sequence=7,
                    kind="tool.call.completed",
                    actor={"id": "shell-1"},
                    operation={"status": " \t", "name": "shell"},
                    attributes={"tool": {
                        "command": "git diff -- src/auth/session.py<img id=tool-command-injected>",
                        "result": "1 file changed<img id=tool-result-injected>",
                        "exit_code": 0,
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="tool-unknown-actor",
                    span_id="span-tool-unknown-actor",
                    emitter_id="unknown-tool-worker",
                    sequence=1,
                    kind="tool.call.completed",
                    actor={"id": " \t"},
                    operation={"status": "ok", "name": "shell"},
                    attributes={"tool": {
                        "command": "git status --short",
                        "result": "clean",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="tool-invalid-detail<img id=invalid-tool-injected>",
                    span_id="span-tool-invalid-detail",
                    sequence=2,
                    kind="tool.call.completed",
                    operation={"status": "ok", "name": "shell"},
                    attributes={"tool": {"command": " \t", "result": 42}},
                )) + "\n",
                json.dumps(event_data(
                    event_id="tool-invalid-exit-code",
                    span_id="span-tool-invalid-exit-code",
                    sequence=2,
                    kind="tool.call.completed",
                    operation={"status": "ok", "name": "shell"},
                    attributes={"tool": {
                        "command": "git diff --check",
                        "exit_code": "<img id=invalid-tool-exit-code-injected>",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="tool-invalid-operation-name",
                    span_id="span-tool-invalid-operation-name",
                    sequence=2,
                    kind="tool.call.completed",
                    operation={
                        "status": "ok",
                        "name": ["<img id=invalid-tool-operation-name-injected>"],
                    },
                    attributes={"tool": {"command": "git status --porcelain"}},
                )) + "\n",
                json.dumps(event_data(
                    event_id="proposal-1",
                    span_id="span-proposal",
                    sequence=8,
                    kind="change.proposed",
                    actor={"id": "planner-1<img id=proposal-injected>"},
                )) + "\n",
                json.dumps(event_data(
                    event_id="anonymous-proposal",
                    span_id="span-anonymous-proposal",
                    sequence=8,
                    kind="change.proposed",
                    actor={"id": " \t"},
                )) + "\n",
                json.dumps(event_data(
                    event_id="change-1",
                    span_id="span-5",
                    sequence=9,
                    kind="change.applied",
                    actor={"id": "implementer-1"},
                    attributes={"change": {
                        "path": "src/auth/session.py",
                        "old_start": 84,
                        "old_count": 18,
                        "new_start": 84,
                        "new_count": 19,
                        "symbol": "reject_expired_session<img id=hunk-symbol-injected>",
                    }},
                    relationships=[
                        {"type": "applies", "event_id": "proposal-1"},
                        {"type": "applies", "event_id": "anonymous-proposal"},
                        {"type": "references", "event_id": "unrelated-proposal"},
                        {"type": "motivated_by", "event_id": "requirement-1"},
                        {"type": "motivated_by", "event_id": "requirement-invalid-detail"},
                        {"type": "references", "event_id": "unrelated-requirement"},
                        {"type": "informed_by", "event_id": "context-1"},
                        {"type": "informed_by", "event_id": "context-end-only"},
                        {"type": "informed_by", "event_id": "context-unknown-actor"},
                        {"type": "informed_by", "event_id": "context-invalid-detail<img id=invalid-context-injected>"},
                        {"type": "references", "event_id": "unrelated-context"},
                        {"type": "informed_by", "event_id": "compaction-1"},
                        {"type": "informed_by", "event_id": "compaction-unknown-actor"},
                        {"type": "informed_by", "event_id": "empty-compaction<img id=invalid-compaction-injected>"},
                        {"type": "preceded_by", "event_id": "tool-1"},
                        {"type": "preceded_by", "event_id": "tool-unknown-actor"},
                        {"type": "preceded_by", "event_id": "tool-invalid-detail<img id=invalid-tool-injected>"},
                        {"type": "preceded_by", "event_id": "tool-invalid-exit-code"},
                        {"type": "preceded_by", "event_id": "tool-invalid-operation-name"},
                        {"type": "references", "event_id": "unrelated-tool"},
                        {"type": "verified_by", "event_id": "verification-1"},
                        {"type": "verified_by", "event_id": "verification-1"},
                        {"type": "verified_by", "event_id": "verification-2"},
                        {"type": "verified_by", "event_id": "verification-outcome-only"},
                        {"type": "verified_by", "event_id": "verification-unknown-actors"},
                        {"type": "verified_by", "event_id": "verification-invalid-result"},
                        {"type": "verified_by", "event_id": "verification-conflicting-outcome"},
                        {"type": "verified_by", "event_id": "verification-invalid-exit-code"},
                        {"type": "verified_by", "event_id": "context-1"},
                        {"type": "references", "event_id": "unrelated-verification"},
                        {"type": "reviewed_by", "event_id": "missing-review<img id=evidence-missing-injected>"},
                    ],
                )) + "\n",
                json.dumps(event_data(
                    event_id="correction-1",
                    span_id="span-6",
                    sequence=10,
                    kind="human.corrected",
                    actor={"id": "maintainer-1<img id=correction-injected>"},
                    attributes={"correction": {"action": "modified"}},
                    relationships=[{"type": "corrects", "event_id": "change-1"}],
                )) + "\n",
                json.dumps(event_data(
                    event_id="correction-2",
                    span_id="span-7",
                    sequence=11,
                    kind="human.corrected",
                    actor={"id": "maintainer-2"},
                    attributes={"correction": {"action": "reverted"}},
                    relationships=[{"type": "corrects", "event_id": "change-1"}],
                )) + "\n",
                json.dumps(event_data(
                    event_id="correction-unknown-actor",
                    span_id="span-correction-unknown-actor",
                    emitter_id="unknown-correction-worker",
                    sequence=1,
                    kind="human.corrected",
                    actor={"id": " \t"},
                    attributes={"correction": {"action": "modified"}},
                    relationships=[{"type": "corrects", "event_id": "change-1"}],
                )) + "\n",
                json.dumps(event_data(
                    event_id="correction-invalid-detail",
                    span_id="span-correction-invalid-detail",
                    emitter_id="invalid-correction-detail-worker",
                    sequence=1,
                    kind="human.corrected",
                    actor={"id": "maintainer-invalid-detail"},
                    attributes={"correction": {"action": "edited"}},
                    relationships=[{"type": "corrects", "event_id": "change-1"}],
                )) + "\n",
                json.dumps(event_data(
                    event_id="unrelated-proposal",
                    span_id="span-unrelated-proposal",
                    sequence=12,
                    kind="change.proposed",
                    actor={"id": "unrelated-planner<img id=unrelated-proposal-injected>"},
                )) + "\n",
                json.dumps(event_data(
                    event_id="unrelated-requirement",
                    span_id="span-unrelated-requirement",
                    sequence=13,
                    kind="requirement.observed",
                    actor={"id": "unrelated-user"},
                    attributes={"requirement": {
                        "id": "R-unrelated",
                        "text": "Unrelated requirement <img id=unrelated-requirement-injected>",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="unrelated-context",
                    span_id="span-unrelated-context",
                    sequence=14,
                    kind="context.read",
                    actor={"id": "unrelated-researcher"},
                    attributes={"context": {
                        "path": "docs/unrelated.md<img id=unrelated-context-injected>",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="unrelated-tool",
                    span_id="span-unrelated-tool",
                    sequence=15,
                    kind="tool.call.completed",
                    actor={"id": "unrelated-shell"},
                    operation={"status": "ok", "name": "shell"},
                    attributes={"tool": {
                        "command": "rm unrelated.tmp<img id=unrelated-tool-injected>",
                        "result": "unrelated result",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="unrelated-verification",
                    span_id="span-unrelated-verification",
                    sequence=16,
                    kind="verification.finished",
                    actor={"id": "unrelated-reporter<img id=unrelated-verification-reporter-injected>"},
                    attributes={"verification": {
                        "command": "pytest unrelated_test.py<img id=unrelated-verification-injected>",
                        "passed": False,
                    }},
                    relationships=[{
                        "type": "completes",
                        "event_id": "unrelated-missing-start",
                    }],
                )) + "\n",
                json.dumps(event_data(
                    event_id="unrelated-correction",
                    span_id="span-unrelated-correction",
                    sequence=17,
                    kind="human.corrected",
                    actor={"id": "unrelated-maintainer<img id=unrelated-correction-injected>"},
                    attributes={"correction": {"action": "reverted"}},
                    relationships=[{"type": "references", "event_id": "change-1"}],
                )) + "\n",
                json.dumps(event_data(
                    event_id="verification-outcome-only",
                    span_id="span-verification-outcome-only",
                    sequence=18,
                    kind="verification.finished",
                    actor={"id": "outcome-only-reporter"},
                    attributes={"verification": {
                        "passed": False,
                        "exit_code": 2,
                        "test_origin": "pre_existing",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="invalid-correction",
                    span_id="span-invalid-correction",
                    sequence=19,
                    kind="human.corrected",
                    actor={"id": "invalid-maintainer"},
                    relationships=[{
                        "type": "corrects",
                        "event_id": "context-1<img id=invalid-correction-target-injected>",
                    }],
                )) + "\n",
                json.dumps(event_data(
                    event_id="context-1<img id=invalid-correction-target-injected>",
                    span_id="span-invalid-correction-target",
                    sequence=20,
                    kind="context.read",
                    actor={"id": "invalid-correction-target"},
                    attributes={"context": {"path": "docs/not-a-change.md"}},
                )) + "\n",
                json.dumps(event_data(
                    event_id="verification-started-unknown-actor",
                    span_id="span-verification-started-unknown-actor",
                    sequence=21,
                    kind="verification.started",
                    actor={"id": " \t"},
                    attributes={"verification": {
                        "command": "pytest tests/test_anonymous_verifier.py",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="verification-unknown-actors",
                    span_id="span-verification-unknown-actors",
                    sequence=22,
                    kind="verification.finished",
                    actor={"id": " \t"},
                    attributes={"verification": {
                        "passed": True,
                        "test_origin": "pre_existing",
                    }},
                    relationships=[{
                        "type": "completes",
                        "event_id": "verification-started-unknown-actor",
                    }],
                )) + "\n",
                json.dumps(event_data(
                    event_id="anonymous-change",
                    span_id="span-anonymous-change",
                    emitter_id="anonymous-change-worker",
                    sequence=1,
                    kind="change.applied",
                    actor={"id": " \t"},
                    attributes={"change": {
                        "path": "src/anonymous.py",
                        "old_start": 1,
                        "old_count": 1,
                        "new_start": 1,
                        "new_count": 1,
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="verification-invalid-result",
                    span_id="span-verification-invalid-result",
                    sequence=23,
                    kind="verification.finished",
                    actor={"id": "invalid-result-reporter"},
                    attributes={"verification": {
                        "command": "pytest tests/test_invalid_result.py",
                        "passed": "yes",
                        "test_origin": "pre_existing",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="requirement-invalid-detail",
                    span_id="span-requirement-invalid-detail",
                    sequence=24,
                    kind="requirement.observed",
                    attributes={"requirement": {
                        "id": "R-BAD<img id=invalid-requirement-injected>",
                        "text": " \t",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="context-invalid-detail<img id=invalid-context-injected>",
                    span_id="span-context-invalid-detail",
                    sequence=25,
                    kind="context.read",
                    attributes={"context": {"path": " \t"}},
                )) + "\n",
                json.dumps(event_data(
                    event_id="verification-conflicting-outcome",
                    span_id="span-verification-conflicting-outcome",
                    sequence=26,
                    kind="verification.finished",
                    actor={"id": "conflicting-outcome-reporter"},
                    attributes={"verification": {
                        "command": "pytest tests/test_conflicting_outcome.py",
                        "passed": True,
                        "exit_code": 7,
                        "test_origin": "pre_existing",
                    }},
                )) + "\n",
                json.dumps(event_data(
                    event_id="verification-invalid-exit-code",
                    span_id="span-verification-invalid-exit-code",
                    sequence=27,
                    kind="verification.finished",
                    actor={"id": "invalid-exit-code-reporter"},
                    attributes={"verification": {
                        "command": "pytest tests/test_invalid_exit_code.py",
                        "passed": True,
                        "exit_code": "<img id=invalid-exit-code-injected>",
                        "test_origin": "pre_existing",
                    }},
                )) + "\n",
            )), encoding="utf-8")
            port = _free_port()
            process = subprocess.Popen(
                [sys.executable, "-m", "agent_tail", "serve", str(source), "--port", str(port)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            self.addCleanup(_stop_process, process)
            _wait_for_server_line(process)

            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(channel="chrome", headless=True)
                page = browser.new_page()
                page.goto(f"http://127.0.0.1:{port}", wait_until="domcontentloaded")
                expect(page.locator(".node-wrap").filter(has_text="implementer-1")).to_be_visible()
                page.evaluate("""() => {
                  [...document.querySelectorAll('.node-wrap')]
                    .find((node) => node.textContent.includes('implementer-1')).click();
                  [...document.querySelectorAll('.event-row')]
                    .find((row) => row.textContent.includes('change.applied')).click();
                }""")

                evidence = page.locator(".change-evidence")
                expect(evidence).to_contain_text("CHANGE EVIDENCE")
                expect(evidence).to_contain_text("src/auth/session.py:84-102")
                expect(evidence).to_contain_text("@@ -84,18 +84,19 @@")
                expect(evidence).to_contain_text("symbol reject_expired_session")
                expect(evidence).to_contain_text("implementer-1")
                expect(evidence).to_contain_text("Change proposed")
                expect(evidence).to_contain_text("proposed by planner-1")
                expect(evidence.locator(".proposal-card")).to_have_count(2)
                anonymous_proposal = evidence.locator(".proposal-card").filter(
                    has_text="proposing actor unknown"
                )
                expect(anonymous_proposal).to_have_count(1)
                expect(anonymous_proposal).not_to_contain_text("proposed by")
                invalid_decision = evidence.locator(".unresolved-evidence").filter(
                    has_text="anonymous-proposal"
                )
                expect(invalid_decision).to_contain_text("Invalid decision actor · applies")
                expect(invalid_decision).to_contain_text("change.proposed")
                expect(evidence).not_to_contain_text("unrelated-planner")
                expect(evidence).to_contain_text("R3")
                expect(evidence).to_contain_text("Expired sessions must be rejected.")
                expect(evidence).not_to_contain_text("R-unrelated")
                expect(evidence).not_to_contain_text("Unrelated requirement")
                expect(evidence).to_contain_text("docs/session-lifecycle.md")
                expect(evidence).to_contain_text(":42-47")
                expect(evidence).to_contain_text("researcher-1")
                expect(evidence).to_contain_text("Session expiry")
                end_only_context = evidence.locator(".context-card").filter(has_text="docs/session-retention.md")
                expect(end_only_context.locator(".path")).to_have_text("docs/session-retention.md:?-51")
                expect(end_only_context).to_contain_text("researcher-2")
                unknown_context_actor = evidence.locator(".context-card").filter(has_text="docs/anonymous-research.md")
                expect(unknown_context_actor).to_contain_text("reading actor unknown")
                expect(unknown_context_actor).not_to_contain_text("read by")
                expect(evidence).not_to_contain_text("docs/unrelated.md")
                expect(evidence).not_to_contain_text("unrelated-researcher")
                expect(evidence).to_contain_text("Context compacted before change")
                expect(evidence).to_contain_text("compacted by summarizer-1")
                compaction = evidence.locator(".compaction-card").filter(has_text="summarizer-1")
                expect(compaction).to_contain_text("source from researcher-1")
                expect(compaction).to_contain_text("Session expiry")
                expect(compaction.locator(".source").filter(has_text="docs/session-retention.md")).to_have_text("docs/session-retention.md:?-51")
                expect(compaction).to_contain_text("source from researcher-2")
                expect(evidence).to_contain_text("Missing summarizes source")
                expect(evidence).to_contain_text("missing-context")
                expect(compaction).to_contain_text("Invalid summarizes source target · tool-1 · tool.call.completed")
                expect(compaction).not_to_contain_text("source from shell-1")
                expect(evidence).not_to_contain_text("irrelevant-missing-context")
                expect(evidence).to_contain_text("3 compacted sources unresolved")
                unknown_compaction_actor = evidence.locator(".compaction-card").filter(has_text="docs/anonymous-research.md")
                expect(unknown_compaction_actor).to_contain_text("compacting actor unknown")
                expect(unknown_compaction_actor).not_to_contain_text("compacted by")
                expect(unknown_compaction_actor).to_contain_text("source actor unknown")
                expect(unknown_compaction_actor).not_to_contain_text("source from")
                expect(evidence).to_contain_text("Tool · shell")
                expect(evidence).to_contain_text("git diff -- src/auth/session.py")
                expect(evidence).to_contain_text("1 file changed")
                expect(evidence).to_contain_text("run by shell-1 · exit 0")
                unknown_tool_actor = evidence.locator(".tool-card").filter(has_text="git status --short")
                expect(unknown_tool_actor).to_contain_text("running actor unknown · ok")
                expect(unknown_tool_actor).not_to_contain_text("run by")
                expect(evidence).not_to_contain_text("undefined")
                expect(evidence).not_to_contain_text("rm unrelated.tmp")
                expect(evidence).not_to_contain_text("unrelated result")
                expect(evidence).not_to_contain_text("unrelated-shell")
                expect(evidence).to_contain_text("PASS")
                expect(evidence).to_contain_text("pytest tests/test_session.py")
                expect(evidence).to_contain_text("started by test-runner-1")
                expect(evidence).to_contain_text("result reported by result-reporter-1")
                expect(evidence).to_contain_text("Invalid completes start command · verification-started-1 · verification.started")
                expect(evidence).to_contain_text("Conflicting completes start command · verification-started-conflict · verification.started")
                expect(evidence).to_contain_text("Verification command · pytest tests/test_session.py")
                expect(evidence.locator(".verification-card").filter(has_text="result-reporter-1")).to_have_count(1)
                expect(evidence).to_contain_text("exit 0")
                expect(evidence).to_contain_text("implementation and test written by the same agent")
                expect(evidence).to_contain_text("FAIL")
                expect(evidence).to_contain_text("result reported by result-reporter-2")
                expect(evidence).to_contain_text("Missing completes start")
                expect(evidence).to_contain_text("missing-start")
                expect(evidence).to_contain_text("Invalid completes start target · context-1 · context.read")
                expect(evidence).to_contain_text("Test provenance unknown")
                outcome_only = evidence.locator(".verification-card").filter(has_text="outcome-only-reporter")
                expect(outcome_only).to_contain_text("FAIL")
                expect(outcome_only).to_contain_text("exit 2")
                expect(outcome_only).to_contain_text("Test existed before this change")
                unknown_verification_actors = evidence.locator(".verification-card").filter(has_text="test_anonymous_verifier.py")
                expect(unknown_verification_actors).to_contain_text("starting actor unknown")
                expect(unknown_verification_actors).to_contain_text("reporting actor unknown")
                expect(unknown_verification_actors).not_to_contain_text("started by")
                expect(unknown_verification_actors).not_to_contain_text("result reported by")
                expect(evidence).not_to_contain_text("undefined")
                expect(evidence).not_to_contain_text("pytest unrelated_test.py")
                expect(evidence).not_to_contain_text("unrelated-reporter")
                expect(evidence).not_to_contain_text("unrelated-missing-start")
                expect(evidence).to_contain_text("Human modified this change")
                expect(evidence).to_contain_text("corrected by maintainer-1")
                expect(evidence).to_contain_text("Human reverted this change")
                expect(evidence).to_contain_text("corrected by maintainer-2")
                unknown_correction = evidence.locator(".correction-card").filter(has_text="correcting actor unknown")
                expect(unknown_correction).to_contain_text("Human modified this change")
                expect(unknown_correction).not_to_contain_text("corrected by")
                invalid_correction = evidence.locator(".correction-card").filter(has_text="maintainer-invalid-detail")
                expect(invalid_correction).to_contain_text("Human correction action invalid")
                expect(invalid_correction).not_to_contain_text("Human modified this change")
                expect(invalid_correction).not_to_contain_text("Human reverted this change")
                expect(evidence).not_to_contain_text("unrelated-maintainer")
                generic_diagnostic = evidence.locator(".unresolved-evidence").filter(has_text="reviewed_by")
                expect(generic_diagnostic).to_contain_text("Missing relationship target · reviewed_by")
                expect(generic_diagnostic).not_to_contain_text("Missing evidence")
                expect(generic_diagnostic).to_contain_text("missing-review")
                invalid_evidence = evidence.locator(".unresolved-evidence").filter(
                    has_text="context-1 · context.read"
                )
                expect(invalid_evidence).to_contain_text("Invalid evidence target · verified_by")
                expect(invalid_evidence).to_contain_text("context-1 · context.read")
                malformed_result = evidence.locator(".unresolved-evidence").filter(
                    has_text="verification-invalid-result"
                )
                expect(malformed_result).to_contain_text("Invalid verification result · verified_by")
                expect(malformed_result).to_contain_text("verification.finished")
                expect(evidence).not_to_contain_text("invalid-result-reporter")
                commandless_result = evidence.locator(".unresolved-evidence").filter(
                    has_text="verification-outcome-only"
                )
                expect(commandless_result).to_contain_text("Invalid verification command · verified_by")
                expect(commandless_result).to_contain_text("verification.finished")
                conflicting_outcome = evidence.locator(".verification-card").filter(
                    has_text="conflicting-outcome-reporter"
                )
                expect(conflicting_outcome).to_contain_text("PASS")
                expect(conflicting_outcome).to_contain_text("exit 7")
                conflicting_outcome_diagnostic = evidence.locator(".unresolved-evidence").filter(
                    has_text="verification-conflicting-outcome"
                )
                expect(conflicting_outcome_diagnostic).to_contain_text(
                    "Conflicting verification outcome · verified_by"
                )
                expect(conflicting_outcome_diagnostic).to_contain_text("verification.finished")
                invalid_exit_code = evidence.locator(".verification-card").filter(
                    has_text="invalid-exit-code-reporter"
                )
                expect(invalid_exit_code).to_contain_text("pytest tests/test_invalid_exit_code.py")
                expect(invalid_exit_code).to_contain_text("PASS")
                invalid_exit_code_diagnostic = evidence.locator(".unresolved-evidence").filter(
                    has_text="verification-invalid-exit-code"
                )
                expect(invalid_exit_code_diagnostic).to_contain_text(
                    "Invalid verification exit code · verified_by"
                )
                expect(invalid_exit_code_diagnostic).to_contain_text("verification.finished")
                expect(page.locator("#invalid-exit-code-injected")).to_have_count(0)
                malformed_requirement = evidence.locator(".unresolved-evidence").filter(
                    has_text="requirement-invalid-detail"
                )
                expect(malformed_requirement).to_contain_text("Invalid requirement details · motivated_by")
                expect(malformed_requirement).to_contain_text("requirement.observed")
                expect(evidence).not_to_contain_text("Requirement R-BAD")
                malformed_context = evidence.locator(".unresolved-evidence").filter(
                    has_text="context-invalid-detail"
                )
                expect(malformed_context).to_contain_text("Invalid context details · informed_by")
                expect(malformed_context).to_contain_text("context.read")
                malformed_compacted_context = evidence.locator(".compaction-card").filter(
                    has_text="Context compacted before change"
                ).locator(".incomplete").filter(has_text="context-invalid-detail")
                expect(malformed_compacted_context).to_contain_text("Invalid summarizes source details")
                expect(malformed_compacted_context).to_contain_text("context.read")
                empty_compaction = evidence.locator(".unresolved-evidence").filter(
                    has_text="empty-compaction"
                )
                expect(empty_compaction).to_contain_text("Invalid compaction details · informed_by")
                expect(empty_compaction).to_contain_text("context.compacted")
                malformed_tool = evidence.locator(".unresolved-evidence").filter(
                    has_text="tool-invalid-detail"
                )
                expect(malformed_tool).to_contain_text("Invalid tool details · preceded_by")
                expect(malformed_tool).to_contain_text("tool.call.completed")
                malformed_tool_status = evidence.locator(".unresolved-evidence").filter(
                    has_text="tool-1"
                )
                expect(malformed_tool_status).to_contain_text(
                    "Invalid tool operation status · preceded_by"
                )
                expect(malformed_tool_status).to_contain_text("tool.call.completed")
                malformed_tool_exit_code = evidence.locator(".unresolved-evidence").filter(
                    has_text="tool-invalid-exit-code"
                )
                expect(malformed_tool_exit_code).to_contain_text("Invalid tool exit code · preceded_by")
                expect(malformed_tool_exit_code).to_contain_text("tool.call.completed")
                expect(evidence).to_contain_text("git diff --check")
                expect(page.locator("#invalid-tool-exit-code-injected")).to_have_count(0)
                malformed_tool_operation_name = evidence.locator(".unresolved-evidence").filter(
                    has_text="tool-invalid-operation-name"
                )
                expect(malformed_tool_operation_name).to_contain_text(
                    "Invalid tool operation name · preceded_by"
                )
                expect(malformed_tool_operation_name).to_contain_text("tool.call.completed")
                expect(evidence).to_contain_text("git status --porcelain")
                expect(page.locator("#invalid-tool-operation-name-injected")).to_have_count(0)
                expect(evidence).to_contain_text("Evidence incomplete · 0 missing categories · 20 unresolved references · 1 test with unknown provenance · 1 same-agent test · 2 failed verifications")
                expect(page.locator("#evidence-injected")).to_have_count(0)
                expect(page.locator("#hunk-symbol-injected")).to_have_count(0)
                expect(page.locator("#context-injected")).to_have_count(0)
                expect(page.locator("#context-symbol-injected")).to_have_count(0)
                expect(page.locator("#unrelated-context-injected")).to_have_count(0)
                expect(page.locator("#tool-command-injected")).to_have_count(0)
                expect(page.locator("#tool-result-injected")).to_have_count(0)
                expect(page.locator("#unrelated-tool-injected")).to_have_count(0)
                expect(page.locator("#verification-injected")).to_have_count(0)
                expect(page.locator("#verification-starter-injected")).to_have_count(0)
                expect(page.locator("#verification-conflict-injected")).to_have_count(0)
                expect(page.locator("#verification-missing-injected")).to_have_count(0)
                expect(page.locator("#invalid-requirement-injected")).to_have_count(0)
                expect(page.locator("#invalid-context-injected")).to_have_count(0)
                expect(page.locator("#invalid-compaction-injected")).to_have_count(0)
                expect(page.locator("#invalid-tool-injected")).to_have_count(0)
                expect(page.locator("#unrelated-verification-injected")).to_have_count(0)
                expect(page.locator("#unrelated-verification-reporter-injected")).to_have_count(0)
                expect(page.locator("#correction-injected")).to_have_count(0)
                expect(page.locator("#unrelated-correction-injected")).to_have_count(0)
                expect(page.locator("#proposal-injected")).to_have_count(0)
                expect(page.locator("#unrelated-proposal-injected")).to_have_count(0)
                expect(page.locator("#compaction-missing-injected")).to_have_count(0)
                expect(page.locator("#evidence-missing-injected")).to_have_count(0)
                page.evaluate("""() => {
                  [...document.querySelectorAll('.node-wrap')]
                    .find((node) => !node.querySelector('.node-label .id').textContent.trim()).click();
                  [...document.querySelectorAll('.event-row')]
                    .find((row) => row.textContent.includes('change.applied')).click();
                }""")
                anonymous_evidence = page.locator(".change-evidence")
                expect(anonymous_evidence).to_contain_text("src/anonymous.py:1-1")
                expect(anonymous_evidence).to_contain_text("applying actor unknown")
                expect(anonymous_evidence).not_to_contain_text("applied by")
                page.locator(".back-btn").click()
                page.evaluate("""() => {
                  [...document.querySelectorAll('.node-wrap')]
                    .find((node) => node.textContent.includes('invalid-maintainer')).click();
                  [...document.querySelectorAll('.event-row')]
                    .find((row) => row.textContent.includes('human.corrected')).click();
                }""")
                diagnostics = page.locator(".relationship-diagnostics")
                expect(diagnostics).to_contain_text("RELATIONSHIP DIAGNOSTICS")
                expect(diagnostics).to_contain_text("Invalid relationship target · corrects")
                expect(diagnostics).to_contain_text("context-1")
                expect(diagnostics).to_contain_text("context.read")
                expect(page.locator("#invalid-correction-target-injected")).to_have_count(0)
                browser.close()

    def test_multi_trace_run_picker_stays_within_top_bar(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "multi-trace.jsonl")
            source.write_text("".join((
                json.dumps(event_data()) + "\n",
                json.dumps(event_data(
                    event_id="trace-2-event",
                    trace_id="trace-2",
                    span_id="trace-2-span",
                )) + "\n",
            )), encoding="utf-8")
            port = _free_port()
            process = subprocess.Popen(
                [sys.executable, "-m", "agent_tail", "serve", str(source), "--port", str(port)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            self.addCleanup(_stop_process, process)
            _wait_for_server_line(process)

            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(channel="chrome", headless=True)
                page = browser.new_page(viewport={"width": 1440, "height": 900})
                page.goto(f"http://127.0.0.1:{port}", wait_until="domcontentloaded")
                expect(page.locator("#run-picker-btn")).to_have_count(1)
                self.assertEqual(round(page.locator("header.topbar").bounding_box()["height"]), 52)
                page.locator("#run-picker-btn").click()
                expect(page.locator(".run-menu")).to_be_visible()
                expect(page.locator(".run-menu button.run-row")).to_have_count(2)
                page.locator(".run-menu button.run-row").filter(has_text="trace-2").click()
                expect(page.locator("#run-picker-btn")).to_contain_text("trace-2")
                page.set_viewport_size({"width": 390, "height": 844})
                expect(page.locator("#run-picker-btn")).to_be_visible()
                expect(page.locator(".top-search")).to_be_hidden()
                page.locator("#scrubber").evaluate(
                    "element => { element.value = '0'; element.dispatchEvent(new Event('input', { bubbles: true })); }"
                )
                expect(page.get_by_role("button", name="Jump to live")).to_be_visible()
                page.get_by_role("button", name="Jump to live").click()
                browser.close()

    def test_primary_journey_in_chrome_firefox_and_webkit(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "cross-browser.jsonl")
            source.write_text(json.dumps(event_data()) + "\n", encoding="utf-8")
            port = _free_port()
            process = subprocess.Popen(
                [sys.executable, "-m", "agent_tail", "serve", str(source), "--port", str(port)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            self.addCleanup(_stop_process, process)
            _wait_for_server_line(process)
            base_url = f"http://127.0.0.1:{port}"

            with sync_playwright() as playwright:
                browsers = (
                    ("chrome", playwright.chromium, {"channel": "chrome"}),
                    ("firefox", playwright.firefox, {}),
                    ("webkit", playwright.webkit, {}),
                )
                for index, (browser_name, browser_type, options) in enumerate(browsers, 2):
                    with self.subTest(browser=browser_name):
                        browser = browser_type.launch(headless=True, **options)
                        page = browser.new_page()
                        page.goto(base_url, wait_until="domcontentloaded")
                        expect(page.locator(".brand-name")).to_contain_text("AGENT")
                        expect(page.locator(".node-wrap")).to_have_count(1)
                        for view in ("Tree", "Swimlane", "Sequence", "Graph"):
                            page.get_by_role("button", name=view, exact=True).click()
                            expect(page.locator(".stage-content")).to_be_visible()
                        page.locator(".node-wrap").first.click()
                        expect(page.locator("#inspector")).to_contain_text("Focus subtree")
                        page.get_by_role("button", name="Warnings", exact=True).click()
                        expect(page.locator("#warnings-drawer")).to_be_visible()
                        page.get_by_role("button", name="Close warnings").click()
                        page.get_by_role("button", name="Swimlane", exact=True).click()
                        page.locator("#search").fill("reviewer")
                        expect(page.locator(".lane-row")).to_have_count(1)
                        page.locator("#search").fill("")
                        page.locator("#scrubber").evaluate(
                            "element => { element.value = '0'; element.dispatchEvent(new Event('input', { bubbles: true })); }"
                        )
                        expect(page.get_by_role("button", name="Jump to live")).to_be_visible()
                        page.get_by_role("button", name="Jump to live").click()
                        requests_metric = page.locator(".metric").filter(has_text="REQUESTS")
                        requests_before = int(requests_metric.locator(".value").inner_text())
                        live_event_id = f"{browser_name}-live"
                        with source.open("a", encoding="utf-8") as handle:
                            handle.write(json.dumps(event_data(
                                event_id=live_event_id,
                                span_id=f"span-{browser_name}",
                                sequence=index,
                            )) + "\n")
                        expect(requests_metric).to_contain_text(str(requests_before + 1))
                        browser.close()

            final = _wait_for_event(base_url, "webkit-live")

        self.assertIn("chrome-live", [event["event_id"] for event in final["events"]])
        self.assertIn("firefox-live", [event["event_id"] for event in final["events"]])
        self.assertIn("webkit-live", [event["event_id"] for event in final["events"]])

    def test_real_serve_command_ui_api_sse_reconnect_and_sanitization(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "run.jsonl")
            source.write_text(json.dumps(event_data(
                payload={"token": "Bearer hidden-secret", "text": "visible"},
                operation={
                    "status": "running",
                    "name": "read_file",
                    "duration_ms": '<img id="injected" src=x onerror=alert(1)>',
                },
                usage={"input_tokens": 12},
            )) + "\n", encoding="utf-8")
            port = _free_port()
            process = subprocess.Popen(
                [sys.executable, "-m", "agent_tail", "serve", str(source), "--port", str(port)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            self.addCleanup(_stop_process, process)
            _wait_for_server_line(process)
            base_url = f"http://127.0.0.1:{port}"

            runs = json.loads(urlopen(base_url + "/api/v1/runs", timeout=3).read())
            detail = json.loads(urlopen(base_url + "/api/v1/runs/trace-1", timeout=3).read())

            self.assertEqual(runs["runs"][0]["state"], "live")
            self.assertEqual(detail["events"][0]["event_id"], "evt-1")
            self.assertNotIn("hidden-secret", json.dumps(detail))
            self.assertEqual(detail["source"]["state"], "caught_up")

            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                context = browser.new_context()
                page = context.new_page()
                page.goto(base_url, wait_until="domcontentloaded")
                expect(page.locator(".brand-name")).to_contain_text("AGENT")
                expect(page.locator(".node-wrap")).to_have_count(1)
                self.assertNotIn("hidden-secret", page.content())

                for view in ("Tree", "Swimlane", "Sequence", "Graph"):
                    page.get_by_role("button", name=view, exact=True).click()
                    expect(page.locator(".stage-content")).to_be_visible()

                page.locator(".node-wrap").first.click()
                expect(page.locator("#inspector")).to_contain_text("EVENT TIMELINE")
                page.locator(".event-row").first.click()
                expect(page.locator("#inspector")).to_contain_text("Event Inspector")
                expect(page.locator("#inspector")).to_contain_text("read_file")
                expect(page.locator("#injected")).to_have_count(0)
                page.get_by_role("button", name="Load retained payload").click()
                expect(page.locator("#inspector pre")).to_contain_text("visible")
                self.assertNotIn("hidden-secret", page.locator("#inspector").inner_text())

                page.get_by_role("button", name="Warnings", exact=True).click()
                expect(page.locator("#warnings-drawer")).to_be_visible()
                page.get_by_role("button", name="Close warnings").click()
                page.get_by_role("button", name="Swimlane", exact=True).click()
                page.locator("#search").fill("evt-1")
                expect(page.locator(".lane-row")).to_have_count(1)
                page.locator("#search").fill("")
                expect(page.locator(".lane-row")).to_have_count(1)

                with source.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(event_data(
                        event_id="evt-2",
                        span_id="span-2",
                        sequence=2,
                        actor={"id": "worker-1", "role": "executor"},
                        parent_span_id="span-1",
                        kind="message.sent",
                        attributes={"to": "reviewer-1"},
                    )) + "\n")
                expect(page.locator(".lane-row")).to_have_count(2)
                page.get_by_role("button", name="Sequence", exact=True).click()
                expect(page.locator("#sequence")).to_contain_text("worker-1")
                expect(page.locator("#sequence")).to_contain_text("delegate")

                page.locator("#scrubber").evaluate("element => { element.value = '0'; element.dispatchEvent(new Event('input', { bubbles: true })); }")
                expect(page.get_by_role("button", name="Jump to live")).to_be_visible()
                context.set_offline(True)
                with source.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(event_data(
                        event_id="buffered",
                        span_id="span-3",
                        sequence=3,
                        actor={"id": "worker-2"},
                    )) + "\n")
                context.set_offline(False)
                page.wait_for_timeout(1500)
                page.get_by_role("button", name="Jump to live").click()
                page.get_by_role("button", name="Graph", exact=True).click()
                expect(page.locator(".node-wrap")).to_have_count(3)

                with source.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(event_data(
                        event_id="done",
                        span_id="span-1",
                        sequence=4,
                        kind="trace.completed",
                        operation={"status": "completed"},
                    )) + "\n")
                expect(page.locator("#run-picker-btn")).to_contain_text("completed")
                browser.close()

            final = json.loads(urlopen(base_url + "/api/v1/runs/trace-1", timeout=3).read())

        self.assertEqual(
            [event["event_id"] for event in final["events"]],
            ["evt-1", "evt-2", "buffered", "done"],
        )
        self.assertEqual(final["run"]["state"], "completed")

    def test_non_serve_invocation_still_renders_terminal_snapshot(self):
        line = json.dumps(event_data()) + "\n"
        result = subprocess.run(
            [sys.executable, "-m", "agent_tail", "-"],
            input=line,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("AGENT LANES", result.stdout)
        self.assertIn("event evt-1", result.stdout)

    def test_large_projection_performance_envelope(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "large.jsonl")
            lines = []
            for sequence in range(500):
                actor_id = f"agent-{sequence % 300:03d}"
                lines.append(json.dumps(event_data(
                    event_id=f"evt-{sequence}",
                    span_id=f"span-{sequence}",
                    actor={"id": actor_id},
                    sequence=sequence,
                    timestamp=f"2026-07-13T11:{sequence // 60 % 60:02d}:{sequence % 60:02d}Z",
                )) + "\n")
            source.write_text("".join(lines), encoding="utf-8")
            port = _free_port()
            process = subprocess.Popen(
                [sys.executable, "-m", "agent_tail", "serve", str(source), "--port", str(port)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
            self.addCleanup(_stop_process, process)
            _wait_for_server_line(process)

            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                page = browser.new_page()
                started = time.perf_counter()
                page.goto(f"http://127.0.0.1:{port}", wait_until="domcontentloaded")
                expect(page.locator(".node-wrap")).to_have_count(160, timeout=10_000)
                first_useful_paint = time.perf_counter() - started
                page.locator('[data-action="show-more"]').click()
                expect(page.locator(".node-wrap")).to_have_count(200)
                page.locator('[data-action="show-more"]').click()
                expect(page.locator(".node-wrap")).to_have_count(240)
                page.get_by_role("button", name="Tree", exact=True).click()
                expect(page.locator(".node-wrap")).to_have_count(240)
                browser.close()

        self.assertLess(first_useful_paint, 10.0)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
    if process.stdout:
        process.stdout.close()
    if process.stderr:
        process.stderr.close()


def _wait_for_server_line(process: subprocess.Popen[str]) -> None:
    deadline = time.time() + 5
    while time.time() < deadline:
        line = process.stdout.readline()
        if "Agent Tail serve mode listening" in line:
            return
        if process.poll() is not None:
            raise AssertionError(process.stderr.read())
    raise AssertionError("serve command did not start")


def _read_sse_data(response) -> dict[str, object]:
    for _ in range(50):
        line = response.readline().decode("utf-8")
        if line.startswith("data: "):
            return json.loads(line.removeprefix("data: "))
    raise AssertionError("SSE data frame was not received")


def _wait_for_event(base_url: str, event_id: str) -> dict[str, object]:
    deadline = time.time() + 3
    while time.time() < deadline:
        detail = json.loads(urlopen(base_url + "/api/v1/runs/trace-1", timeout=3).read())
        if any(event["event_id"] == event_id for event in detail["events"]):
            return detail
        time.sleep(0.05)
    raise AssertionError(f"event did not arrive: {event_id}")


if __name__ == "__main__":
    unittest.main()
