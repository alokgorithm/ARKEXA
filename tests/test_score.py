"""The two corpora answer two questions, and must not answer each other's.

Prevalence is a claim about the world, so it may only be computed from a
corpus collected by query and never topped up. Precision and recall are claims
about a tool, so their corpus may be enriched with vulnerable-skewed
candidates to have enough positives to divide by.

Mixing them produces a number that looks fine and is wrong: an enriched corpus
reports whatever proportion was mixed into it. Nothing in the output would
show it, which is why it is checked here rather than trusted to care.
"""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

from support import ROOT

SCORE_PY = ROOT / "tools" / "score.py"


def load_tool():
    name = "arkexa_score_tool"
    spec = importlib.util.spec_from_file_location(name, SCORE_PY)
    module = importlib.util.module_from_spec(spec)
    # `@dataclass` resolves annotations through sys.modules, so the module has
    # to be registered before it executes, not after.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


score = load_tool()


def write_corpus(directory: Path, kind: str, enriched: bool, entries, **extra) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "workflows").mkdir(exist_ok=True)
    payload = {"schema": 1, "corpus": kind, "enriched": enriched, "workflows": entries}
    payload.update(extra)
    (directory / "labels.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8"
    )
    return directory


def entry(entry_id, label, reachability=""):
    return {
        "id": entry_id,
        "label": label,
        "reachability": reachability,
        "rationale": "structural",
    }


VULNERABLE = [entry(f"wf-{i:03d}", "vulnerable", "external") for i in range(1, 6)]
CLEAN = [entry(f"wf-{i:03d}", "clean") for i in range(6, 21)]
EXCLUDED = [entry("wf-021", "excluded")]


class EnrichedPrevalenceTest(unittest.TestCase):
    """The one that matters: a prevalence figure must never come from enrichment."""

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def test_an_enriched_corpus_refuses_to_yield_a_prevalence(self):
        corpus = score.load_corpus(
            write_corpus(self.root / "e", score.EVALUATION, True, VULNERABLE + CLEAN)
        )
        with self.assertRaises(score.CorpusError) as caught:
            score.prevalence(corpus)
        self.assertIn("enriched", str(caught.exception).lower())

    def test_an_evaluation_corpus_refuses_even_when_it_says_it_is_not_enriched(self):
        """The kind alone disqualifies it. Enrichment is the reason, not the test."""
        corpus = score.load_corpus(
            write_corpus(self.root / "u", score.EVALUATION, False, VULNERABLE + CLEAN)
        )
        with self.assertRaises(score.CorpusError):
            score.prevalence(corpus)

    def test_a_prevalence_corpus_marked_enriched_is_also_refused(self):
        """A contradiction resolves against publishing, not in favour of it."""
        corpus = score.load_corpus(
            write_corpus(self.root / "c", score.PREVALENCE, True, VULNERABLE + CLEAN)
        )
        with self.assertRaises(score.CorpusError):
            score.prevalence(corpus)

    def test_the_cli_refuses_too_and_says_so_on_stderr(self):
        write_corpus(self.root / "e", score.EVALUATION, True, VULNERABLE + CLEAN)
        self.assertEqual(
            score.main([score.PREVALENCE, "--corpus", str(self.root / "e")]), 2
        )

    def test_an_undeclared_corpus_is_refused_rather_than_assumed(self):
        directory = self.root / "bare"
        (directory / "workflows").mkdir(parents=True)
        (directory / "labels.json").write_text(
            json.dumps({"schema": 1, "workflows": []}), encoding="utf-8"
        )
        with self.assertRaises(score.CorpusError) as caught:
            score.load_corpus(directory)
        self.assertIn("does not declare", str(caught.exception))

    def test_a_corpus_that_will_not_say_whether_it_was_enriched_is_refused(self):
        directory = self.root / "quiet"
        (directory / "workflows").mkdir(parents=True)
        (directory / "labels.json").write_text(
            json.dumps({"schema": 1, "corpus": "prevalence", "workflows": []}),
            encoding="utf-8",
        )
        with self.assertRaises(score.CorpusError):
            score.load_corpus(directory)


class PrevalenceTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.corpus = score.load_corpus(write_corpus(
            Path(self.directory.name) / "p",
            score.PREVALENCE, False, VULNERABLE + CLEAN + EXCLUDED,
        ))

    def test_excluded_entries_are_not_in_the_denominator(self):
        result = score.prevalence(self.corpus)
        self.assertEqual(result.judgeable, 20)
        self.assertEqual(result.reachable, 5)
        self.assertEqual(result.excluded, 1)

    def test_only_externally_reachable_counts_as_reachable(self):
        entries = [entry("wf-001", "vulnerable", "maintainer"), entry("wf-002", "clean")]
        corpus = score.load_corpus(write_corpus(
            Path(self.directory.name) / "m", score.PREVALENCE, False, entries
        ))
        self.assertEqual(score.prevalence(corpus).reachable, 0)

    def test_the_figure_is_never_a_bare_percentage(self):
        described = score.prevalence(self.corpus).describe()
        self.assertIn("5 of 20", described)
        self.assertIn("Wilson 95% CI", described)
        self.assertIn("excluded", described)

    def test_an_unlabelled_corpus_produces_no_figure_at_all(self):
        corpus = score.load_corpus(write_corpus(
            Path(self.directory.name) / "empty", score.PREVALENCE, False, []
        ))
        result = score.prevalence(corpus)
        self.assertIsNone(result.proportion)
        self.assertIn("no prevalence figure", result.describe())

    def test_the_report_carries_the_interval_not_just_the_ratio(self):
        text = score.prevalence_report(
            self.corpus, score.prevalence(self.corpus), "2026-09-02", []
        )
        self.assertIn("Wilson 95% CI", text)
        self.assertIn("unenriched", text)
        self.assertIn("no agent step", text)


class WilsonTest(unittest.TestCase):
    """Checked against known values, because a wrong interval still prints."""

    def test_a_textbook_case(self):
        low, high = score.wilson(5, 20)
        self.assertAlmostEqual(low, 0.1119, places=3)
        self.assertAlmostEqual(high, 0.4687, places=3)

    def test_the_interval_brackets_the_point_estimate(self):
        for successes, total in ((0, 10), (1, 30), (17, 40), (93, 93)):
            low, high = score.wilson(successes, total)
            point = successes / total
            # A tolerance because the bound is computed in floating point:
            # at k == n the upper bound lands a rounding step below 1.0.
            self.assertLessEqual(low, point + 1e-12)
            self.assertGreaterEqual(high, point - 1e-12)

    def test_it_never_leaves_the_unit_interval(self):
        """Where the normal approximation goes negative, which is why not that one."""
        for successes, total in ((0, 5), (5, 5), (1, 100)):
            low, high = score.wilson(successes, total)
            self.assertGreaterEqual(low, 0.0)
            self.assertLessEqual(high, 1.0)

    def test_a_wider_interval_for_a_smaller_sample(self):
        narrow = score.wilson(50, 100)
        wide = score.wilson(5, 10)
        self.assertLess(narrow[1] - narrow[0], wide[1] - wide[0])

    def test_no_sample_has_no_interval(self):
        self.assertIsNone(score.wilson(0, 0))


class EvaluationTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.corpus = score.load_corpus(write_corpus(
            Path(self.directory.name) / "e",
            score.EVALUATION, True, VULNERABLE + CLEAN + EXCLUDED,
        ))

    def test_the_report_says_it_is_enriched_and_disclaims_prevalence(self):
        text = score.evaluation_report(self.corpus, [score.Score(tool="arkexa")], "2026-09-02")
        self.assertIn("enriched", text)
        self.assertIn("nothing about", text)

    def test_the_report_pins_the_tool_version(self):
        scored = score.Score(tool="zizmor", version="1.2.3", true_positives=1)
        self.assertIn("1.2.3", score.evaluation_report(self.corpus, [scored], "2026-09-02"))

    def test_precision_and_recall_are_none_rather_than_zero_when_undefined(self):
        blank = score.Score(tool="arkexa")
        self.assertIsNone(blank.precision)
        self.assertIsNone(blank.recall)
        self.assertIn("-", blank.row())

    def test_excluded_entries_are_not_scored(self):
        self.assertEqual(len(self.corpus.judgeable), 20)


class NormalisedDuplicateTest(unittest.TestCase):
    """The same template in two repositories: two exposures, one test input.

    Policy decision 2(b) in METHODOLOGY.md. Prevalence counts the deployment,
    because two repositories running the same reachable template really are two
    reachable repositories. Evaluation counts the distinct workflow, because a
    scanner should be neither rewarded nor punished twice for one input.
    """

    TEMPLATE = (
        "on:\n"
        "  issue_comment:\n"
        "    types: [created]\n"
        "jobs:\n"
        "  go:\n"
        "    permissions:\n"
        "      issues: write\n"
        "    steps:\n"
        "      - uses: actions/ai-inference@{pin}\n"
        "{comment}"
    )

    def build(self, kind, enriched):
        directory = Path(self.tmp.name) / kind
        (directory / "workflows").mkdir(parents=True, exist_ok=True)
        # Same workflow, different comment and a different pin: what a template
        # copied between two repositories actually looks like.
        (directory / "workflows" / "wf-001.yml").write_text(
            self.TEMPLATE.format(pin="a" * 40, comment="# our review bot\n"),
            encoding="utf-8",
        )
        (directory / "workflows" / "wf-002.yml").write_text(
            self.TEMPLATE.format(pin="b" * 40, comment="# triage helper\n"),
            encoding="utf-8",
        )
        (directory / "labels.json").write_text(json.dumps({
            "schema": 1, "corpus": kind, "enriched": enriched,
            "workflows": [
                entry("wf-001", "vulnerable", "external"),
                entry("wf-002", "vulnerable", "external"),
            ],
        }), encoding="utf-8")
        return score.load_corpus(directory)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_the_pair_is_recognised_despite_comments_and_pins(self):
        corpus = self.build(score.PREVALENCE, False)
        self.assertEqual(score.duplicate_clusters(corpus), [["wf-001", "wf-002"]])

    def test_prevalence_counts_both_deployments(self):
        result = score.prevalence(self.build(score.PREVALENCE, False))
        self.assertEqual(result.judgeable, 2)
        self.assertEqual(result.reachable, 2)

    def test_evaluation_collapses_them_to_one(self):
        corpus = self.build(score.EVALUATION, True)
        self.assertEqual(score.collapsed_ids(corpus), {"wf-002"})

    def test_the_lowest_id_is_the_one_that_survives(self):
        """Deterministic, so a rerun scores the same file."""
        self.assertNotIn("wf-001", score.collapsed_ids(self.build(score.EVALUATION, True)))

    def test_distinct_workflows_are_not_collapsed(self):
        corpus = self.build(score.EVALUATION, True)
        (corpus.root / "workflows" / "wf-002.yml").write_text(
            self.TEMPLATE.format(pin="b" * 40, comment="") + "      - run: echo hi\n",
            encoding="utf-8",
        )
        self.assertEqual(score.collapsed_ids(corpus), set())

    def test_a_declared_cluster_is_honoured_without_the_files(self):
        """A corpus shipped without its workflows still knows what it collapsed."""
        directory = Path(self.tmp.name) / "declared"
        (directory / "workflows").mkdir(parents=True)
        (directory / "labels.json").write_text(json.dumps({
            "schema": 1, "corpus": score.EVALUATION, "enriched": True,
            "normalised_duplicates": [["wf-056", "wf-076"]],
            "workflows": [entry("wf-056", "clean"), entry("wf-076", "clean")],
        }), encoding="utf-8")
        self.assertEqual(score.collapsed_ids(score.load_corpus(directory)), {"wf-076"})

    def test_normalisation_ignores_comments_and_pins_only(self):
        same = score.fingerprint("jobs:\n  a:\n    steps: []\n# note\n")
        also = score.fingerprint("# different note\njobs:\n  a:\n    steps: []\n")
        different = score.fingerprint("jobs:\n  b:\n    steps: []\n")
        self.assertEqual(same, also)
        self.assertNotEqual(same, different)


class ShippedCorporaTest(unittest.TestCase):
    """Whatever is committed must declare what it is allowed to claim."""

    def corpus_files(self):
        return sorted((ROOT / "benchmark").glob("*/labels.json"))

    def test_both_corpora_are_present(self):
        names = {p.parent.name for p in self.corpus_files()}
        self.assertEqual(names, {"prevalence", "evaluation"})

    def test_each_declares_its_kind_and_enrichment(self):
        for path in self.corpus_files():
            corpus = score.load_corpus(path.parent)
            self.assertIn(corpus.kind, score.KINDS, path)

    def test_the_prevalence_corpus_is_not_enriched(self):
        corpus = score.load_corpus(ROOT / "benchmark" / "prevalence")
        self.assertEqual(corpus.kind, score.PREVALENCE)
        self.assertFalse(corpus.enriched)

    def test_the_evaluation_corpus_declares_that_it_is(self):
        corpus = score.load_corpus(ROOT / "benchmark" / "evaluation")
        self.assertTrue(corpus.enriched)
        with self.assertRaises(score.CorpusError):
            score.prevalence(corpus)


if __name__ == "__main__":
    unittest.main()
