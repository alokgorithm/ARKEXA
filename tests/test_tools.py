"""The labelling tool must not be able to see what the scanner thinks.

A benchmark label is only worth publishing if a human wrote it without the
tool's output in front of them. `tools/label.py` promises that in its
docstring, and a docstring is not a guarantee. So the blindness is checked
twice: statically, because a lazy import inside a function would not show up
in the import graph until the branch runs, and again in a fresh interpreter,
because the source is only evidence about what the source says.

The rest exercises the helpers that decide what a labeller is shown. A bug in
those is discovered thirty workflows into a session, which is exactly when it
is most expensive.
"""

import ast
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from support import ROOT

LABEL_PY = ROOT / "tools" / "label.py"

# Importing anything from this set would put scanner output within reach of a
# labelling session, one way or another.
FORBIDDEN_IMPORTS = {"arkexa", "subprocess", "shutil"}

PROBE = """
import importlib.util
import sys

spec = importlib.util.spec_from_file_location("probe_label", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
print(",".join(sorted(
    name for name in sys.modules
    if name == "arkexa" or name.startswith("arkexa.")
)))
"""


def load_tool():
    spec = importlib.util.spec_from_file_location("arkexa_label_tool", LABEL_PY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


label = load_tool()


def imported_roots(tree: ast.AST) -> set[str]:
    """Every top-level package name the module imports, wherever it does it."""
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                roots.add(node.module.split(".")[0])
    return roots


class BlindnessTest(unittest.TestCase):
    """Nothing in the labelling path may consult a scanner."""

    def setUp(self):
        self.source = LABEL_PY.read_text(encoding="utf-8")
        self.tree = ast.parse(self.source)

    def test_it_imports_no_scanner_and_no_way_to_run_one(self):
        offenders = imported_roots(self.tree) & FORBIDDEN_IMPORTS
        self.assertEqual(
            offenders,
            set(),
            f"tools/label.py imports {sorted(offenders)}; a labeller must not "
            "be able to see a scanner's opinion before writing the label",
        )

    def test_it_never_shells_out(self):
        calls = {
            ast.unparse(node.func)
            for node in ast.walk(self.tree)
            if isinstance(node, ast.Call)
        }
        for escape in ("os.system", "os.popen", "os.execv", "os.spawnv"):
            self.assertNotIn(escape, calls)

    def test_importing_it_does_not_pull_in_arkexa(self):
        finished = subprocess.run(
            [sys.executable, "-c", PROBE, str(LABEL_PY)],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
            timeout=120,
        )
        self.assertEqual(finished.returncode, 0, finished.stderr)
        self.assertEqual(
            finished.stdout.strip(),
            "",
            "importing tools/label.py loaded arkexa into the interpreter",
        )

    def test_the_digest_offers_no_verdict(self):
        """The digest restates two keys. It must not hint at a rule or a label."""
        lines = "\n".join(label.digest(
            "on:\n"
            "  issue_comment:\n"
            "    types: [created]\n"
            "permissions:\n"
            "  contents: write\n"
            "jobs:\n"
            "  go:\n"
            "    steps:\n"
            "      - uses: anthropics/claude-code-action@v1\n"
        ))
        for leak in ("ARK", "vulnerable", "injection", "unsafe", "risk"):
            self.assertNotIn(leak, lines)


class TriggersTest(unittest.TestCase):
    """PyYAML reads a bare `on` as the boolean True. Every form must survive."""

    def test_bare_on_is_not_lost_to_the_boolean(self):
        events = label.triggers_of(
            label.yaml.safe_load("on:\n  issues:\n    types: [opened]\n")
        )
        self.assertEqual(list(events), ["issues"])

    def test_a_quoted_on_key_reads_the_same(self):
        events = label.triggers_of(
            label.yaml.safe_load('"on":\n  issues:\n    types: [opened]\n')
        )
        self.assertEqual(list(events), ["issues"])

    def test_a_list_of_events(self):
        events = label.triggers_of(label.yaml.safe_load("on: [push, pull_request]\n"))
        self.assertEqual(sorted(events), ["pull_request", "push"])

    def test_a_single_event_as_a_string(self):
        self.assertEqual(list(label.triggers_of({"on": "push"})), ["push"])

    def test_a_workflow_with_no_trigger(self):
        self.assertEqual(label.triggers_of({"jobs": {}}), {})

    def test_something_that_is_not_a_mapping(self):
        self.assertEqual(label.triggers_of(["on"]), {})


class DigestTest(unittest.TestCase):
    def test_an_undeclared_permission_block_says_it_inherits(self):
        lines = label.digest("on: push\njobs:\n  go:\n    steps: []\n")
        self.assertIn("    workflow: (not declared - inherits the repository default)", lines)

    def test_a_job_scope_shows_when_the_workflow_declares_none(self):
        lines = label.digest(
            "on: push\n"
            "jobs:\n"
            "  go:\n"
            "    permissions:\n"
            "      contents: write\n"
            "    steps: []\n"
        )
        self.assertIn("    job 'go': contents: write", lines)

    def test_a_job_that_only_inherits_is_not_repeated(self):
        lines = label.digest(
            "on: push\n"
            "permissions:\n"
            "  contents: read\n"
            "jobs:\n"
            "  go:\n"
            "    steps: []\n"
        )
        self.assertIn("    workflow: contents: read", lines)
        self.assertFalse([line for line in lines if line.startswith("    job 'go'")])

    def test_trigger_filters_are_shown(self):
        lines = label.digest("on:\n  issue_comment:\n    types: [created]\n")
        self.assertIn("    issue_comment  (types: ['created'])", lines)

    def test_a_file_that_is_not_yaml_says_so_instead_of_raising(self):
        lines = label.digest("on: [\n  unterminated\n")
        self.assertEqual(len(lines), 1)
        self.assertIn("could not parse", lines[0])

    def test_a_file_that_is_not_a_mapping_says_so(self):
        self.assertIn("does not parse into a mapping", label.digest("- just\n- a list\n")[0])


class RenderPermissionsTest(unittest.TestCase):
    def test_the_shorthand_string(self):
        self.assertEqual(label.render_permissions("read-all"), "read-all")

    def test_an_empty_mapping_is_the_locked_down_case(self):
        self.assertEqual(label.render_permissions({}), "(empty)")

    def test_a_mapping(self):
        self.assertEqual(
            label.render_permissions({"contents": "read", "issues": "write"}),
            "contents: read, issues: write",
        )


class CorpusTest(unittest.TestCase):
    def test_an_explicit_directory_without_workflows_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(SystemExit):
                label.corpus_dir(directory)

    def test_shas_read_the_private_source_list_first(self):
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory)
            (corpus / "sources.json").write_text(
                json.dumps([{"id": "wf-001", "sha": "public"}]), encoding="utf-8"
            )
            (corpus / "sources-private.json").write_text(
                json.dumps([{"id": "wf-001", "sha": "private"}]), encoding="utf-8"
            )
            self.assertEqual(label.shas(corpus), {"wf-001": "private"})

    def test_shas_accept_the_wrapped_shape_too(self):
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory)
            (corpus / "sources.json").write_text(
                json.dumps({"workflows": [{"id": "wf-002", "sha": "abc"}]}), encoding="utf-8"
            )
            self.assertEqual(label.shas(corpus), {"wf-002": "abc"})

    def test_a_corpus_with_no_source_list_still_labels(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(label.shas(Path(directory)), {})


class LabelsFileTest(unittest.TestCase):
    def test_a_missing_file_starts_from_the_documented_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            data = label.load_labels(Path(directory) / "labels.json")
        self.assertEqual(data["workflows"], [])
        self.assertIn("no scanner output visible", data["description"])

    def test_an_existing_file_keeps_the_keys_it_already_had(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "labels.json"
            path.write_text(
                json.dumps({"schema": 1, "note": "kept", "workflows": []}), encoding="utf-8"
            )
            data = label.load_labels(path)
            label.save(path, data)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["note"], "kept")

    def test_labels_are_written_with_unix_newlines_on_every_platform(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "labels.json"
            label.save(path, {"schema": 1, "workflows": []})
            self.assertNotIn(b"\r\n", path.read_bytes())


class EncodingTest(unittest.TestCase):
    """A workflow with an emoji in it must not end the session.

    Real workflows name jobs things like "deploy". A Windows console drops to
    cp1252 as soon as the session is piped or redirected, and printing the file
    then raises UnicodeEncodeError partway through a run. This is checked
    through a real subprocess, because the bug only exists when stdout is a
    pipe rather than the terminal the tool was written at.
    """

    WORKFLOW = (
        "# deploy \N{ROCKET} \N{EM DASH} caf\N{LATIN SMALL LETTER E WITH ACUTE}\n"
        "on: push\n"
        "jobs:\n"
        "  go:\n"
        "    name: \N{ROCKET} ship it\n"
        "    steps: []\n"
    )

    def test_a_workflow_the_console_cannot_encode_still_prints(self):
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory)
            (corpus / "workflows").mkdir()
            (corpus / "workflows" / "wf-001.yml").write_text(self.WORKFLOW, encoding="utf-8")
            finished = subprocess.run(
                [
                    sys.executable, str(ROOT / "tools" / "label.py"),
                    "--labeller", "TT", "--corpus", str(corpus),
                    "--out", str(corpus / "labels.json"),
                ],
                input="q\n",
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env={**os.environ, "PYTHONIOENCODING": "cp1252"},
                cwd=str(ROOT),
                timeout=120,
            )
        self.assertEqual(finished.returncode, 0, finished.stderr)
        self.assertNotIn("UnicodeEncodeError", finished.stderr)
        self.assertIn("ship it", finished.stdout)


class Answers:
    """A scripted labeller, so a session can be replayed without a terminal."""

    def __init__(self, *answers):
        self.remaining = list(answers)
        self.prompts: list[str] = []

    def __call__(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if not self.remaining:
            raise AssertionError(f"asked something the script has no answer for: {prompt!r}")
        return self.remaining.pop(0).strip()


def run_judge(*answers):
    scripted = Answers(*answers)
    captured = io.StringIO()
    with mock.patch.object(label, "ask", scripted), redirect_stdout(captured):
        verdict = label.judge("wf-001", "on: push\njobs: {}\n", "1 of 1")
    return verdict, scripted, captured.getvalue()


class JudgeTest(unittest.TestCase):
    def test_a_vulnerable_label_carries_its_exploit_path(self):
        verdict, _, _ = run_judge("v", "e", "the comment body reaches the prompt", "ark001")
        self.assertEqual(verdict["label"], "vulnerable")
        self.assertEqual(verdict["reachability"], "external")
        self.assertEqual(verdict["expected_rules"], ["ARK001"])
        self.assertEqual(verdict["rationale"], "the comment body reaches the prompt")

    def test_a_vulnerable_workflow_cannot_be_recorded_as_unreachable(self):
        """The prompt offers e, c and m. Anything else is a typo, not a fourth answer."""
        verdict, _, output = run_judge("v", "u", "e", "a fork PR reaches it", "")
        self.assertEqual(verdict["reachability"], "external")
        self.assertIn("Answer e, c or m.", output)

    def test_a_clean_label_needs_the_reason_it_is_safe(self):
        verdict, scripted, _ = run_judge("c", "every scope is read")
        self.assertEqual(verdict["label"], "clean")
        self.assertEqual(verdict["rationale"], "every scope is read")
        self.assertEqual(scripted.remaining, [])

    def test_a_blank_reason_twice_backs_out_to_the_verdict(self):
        """Silence is not a rationale. Refusing it is the whole point of the corpus."""
        verdict, _, output = run_judge("c", "", "", "c", "every scope is read")
        self.assertEqual(verdict["rationale"], "every scope is read")
        self.assertIn("Required.", output)
        self.assertIn(label.RULE, output)

    def test_an_excluded_entry_records_why_it_is_not_judgeable(self):
        verdict, _, _ = run_judge("x", "it calls a reusable workflow that cannot be read")
        self.assertEqual(verdict["label"], "excluded")

    def test_skip_and_quit_write_nothing(self):
        self.assertIsNone(run_judge("s")[0])
        self.assertEqual(run_judge("q")[0], {"__quit__": True})

    def test_an_unrecognised_verdict_is_asked_again(self):
        verdict, _, output = run_judge("y", "s")
        self.assertIsNone(verdict)
        self.assertIn("Answer v, c, x, s or q.", output)


class SessionTest(unittest.TestCase):
    """One run of main, end to end, over a corpus built for the occasion."""

    WORKFLOWS = {
        "wf-001": "on:\n  issue_comment:\n    types: [created]\njobs: {}\n",
        "wf-002": "on: schedule\njobs: {}\n",
    }

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.corpus = Path(self.directory.name)
        (self.corpus / "workflows").mkdir()
        for name, text in self.WORKFLOWS.items():
            (self.corpus / "workflows" / f"{name}.yml").write_text(text, encoding="utf-8")
        (self.corpus / "sources-private.json").write_text(
            json.dumps([
                {"id": "wf-001", "repo": "held back", "sha": "1111111"},
                {"id": "wf-002", "repo": "held back", "sha": "2222222"},
            ]),
            encoding="utf-8",
        )
        self.out = self.corpus / "labels.json"

    def session(self, *answers, extra=()):
        scripted = Answers(*answers)
        captured = io.StringIO()
        argv = ["--labeller", "TT", "--corpus", str(self.corpus), "--out", str(self.out), *extra]
        with mock.patch.object(label, "ask", scripted), redirect_stdout(captured):
            code = label.main(argv)
        self.assertEqual(code, 0)
        if not self.out.is_file():
            # A session that answered nothing writes nothing, by design.
            return {"workflows": [], "superseded": []}, captured.getvalue()
        return json.loads(self.out.read_text(encoding="utf-8")), captured.getvalue()

    def test_a_full_pass_records_both_workflows(self):
        data, output = self.session(
            "v", "e", "the comment body reaches the prompt", "ARK001",
            "c", "it only runs on a schedule",
        )
        first, second = data["workflows"]
        self.assertEqual(first["id"], "wf-001")
        self.assertEqual(first["label"], "vulnerable")
        self.assertEqual(first["sha"], "1111111")
        self.assertEqual(first["triggers"], ["issue_comment"])
        self.assertEqual(first["labeller"], "TT")
        self.assertEqual(second["label"], "clean")
        self.assertEqual(second["triggers"], ["schedule"])
        self.assertIn("Totals: clean 1, vulnerable 1", output)

    def test_the_totals_line_says_none_rather_than_trailing_off(self):
        _, output = self.session("q")
        self.assertIn("Totals: none", output)

    def test_quitting_halfway_keeps_what_was_already_answered(self):
        data, _ = self.session("c", "read-only scopes", "q")
        self.assertEqual([e["id"] for e in data["workflows"]], ["wf-001"])

    def test_relabelling_supersedes_rather_than_overwrites(self):
        self.session("c", "read-only scopes", "q")
        data, _ = self.session(
            "v", "e", "a second look: the body does reach the prompt", "",
            "q",
            extra=("--redo",),
        )
        self.assertEqual([e["id"] for e in data["workflows"]], ["wf-001"])
        self.assertEqual(data["workflows"][0]["label"], "vulnerable")
        self.assertEqual(data["superseded"][0]["rationale"], "read-only scopes")

    def test_start_skips_everything_before_the_given_id(self):
        data, _ = self.session("c", "it only runs on a schedule", extra=("--start", "wf-002"))
        self.assertEqual([e["id"] for e in data["workflows"]], ["wf-002"])

    def test_limit_stops_the_session_where_it_was_told_to(self):
        data, output = self.session(
            "v", "e", "the comment body reaches the prompt", "", extra=("--limit", "1")
        )
        self.assertEqual(len(data["workflows"]), 1)
        self.assertIn("Stopping at --limit 1.", output)


if __name__ == "__main__":
    unittest.main()
