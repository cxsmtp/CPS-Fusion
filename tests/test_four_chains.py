"""Checks that the four example chains score the way the CPS writeup says.

Run with either:
    python -m unittest discover -s tests
    python -m pytest tests
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import demo  # noqa: E402
from cps_engine import AssemblyState, band  # noqa: E402

# Chain CPS published in the writeup's examples table.
EXPECTED = {
    "CH-101": 10.00,  # Account takeover
    "CH-104": 9.14,   # Token theft
    "CH-106": 9.15,   # Silent data exfiltration
    "CH-110": 8.01,   # API token forgery
}

CHAIN_DIRS = {
    "CH-101": "CH-101-account-takeover",
    "CH-104": "CH-104-token-theft",
    "CH-106": "CH-106-silent-exfiltration",
    "CH-110": "CH-110-token-forgery",
}


def run_fixture(scan: Path = demo.DEFAULT_SCAN):
    results, _ = demo.run(scan, demo.DEFAULT_CATALOG)
    return {r.chain_id: r for r in results}


class FourChainScores(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.results = run_fixture()

    def test_catalog_holds_exactly_the_four_examples(self):
        self.assertEqual(set(self.results), set(EXPECTED))

    def test_every_chain_fully_assembles(self):
        for cid, r in self.results.items():
            with self.subTest(chain=cid):
                self.assertIs(r.state, AssemblyState.FULLY_ASSEMBLED, r.missing)

    def test_chain_scores_match_the_writeup(self):
        for cid, want in EXPECTED.items():
            with self.subTest(chain=cid):
                self.assertAlmostEqual(self.results[cid].chain_cps, want, places=2)

    def test_every_chain_is_high_band(self):
        for cid, r in self.results.items():
            with self.subTest(chain=cid):
                self.assertEqual(r.chain_cps_band, "High")

    def test_no_constituent_is_rated_above_medium(self):
        medium = demo.severity_rank("Medium")
        for cid, r in self.results.items():
            for m in r.matches:
                for f in m.matched_findings:
                    with self.subTest(chain=cid, query=f.query_name):
                        self.assertLessEqual(
                            demo.severity_rank(f.default_severity), medium)

    def test_chain_scores_above_its_best_single_finding(self):
        # Individually every finding stays below the chain score: the High
        # result comes from composition, not from one standout finding.
        for cid, r in self.results.items():
            best = max(f.cps_score for m in r.matches for f in m.matched_findings)
            with self.subTest(chain=cid):
                self.assertLess(best, r.chain_cps)

    def test_ch106_is_built_only_from_informational_findings(self):
        sevs = {demo.severity_rank(f.default_severity)
                for m in self.results["CH-106"].matches
                for f in m.matched_findings}
        self.assertEqual(sevs, {demo.severity_rank("Informational")})

    def test_chain_score_follows_the_rubric_formula(self):
        # CPS_chain = max + 0.1 * sum(others), capped at 10.
        for cid, r in self.results.items():
            scores = [max(f.cps_score for f in m.matched_findings)
                      for m in r.matches]
            top = max(scores)
            want = min(10.0, top + 0.1 * (sum(scores) - top))
            with self.subTest(chain=cid):
                self.assertAlmostEqual(r.chain_cps, want, places=6)
                self.assertEqual(band(want), "High")


class BreakingOneLink(unittest.TestCase):
    """Fixing any single finding means the chain no longer fully assembles."""

    def test_removing_any_one_finding_breaks_its_chain(self):
        fixture = json.loads(demo.DEFAULT_SCAN.read_text(encoding="utf-8"))
        queries = fixture["scanResults"]["resultsList"]
        with tempfile.TemporaryDirectory() as tmpdir:
            scan = Path(tmpdir) / "scan.json"
            for i, q in enumerate(queries):
                doc = copy.deepcopy(fixture)
                del doc["scanResults"]["resultsList"][i]
                scan.write_text(json.dumps(doc), encoding="utf-8")
                path = q["vulnerabilities"][0]["destinationFileName"]
                cid = next(c for c, d in CHAIN_DIRS.items() if f"/{d}/" in path)
                with self.subTest(fixed=q["queryName"], chain=cid):
                    r = run_fixture(scan)[cid]
                    self.assertIsNot(r.state, AssemblyState.FULLY_ASSEMBLED)
                    self.assertLess(r.chain_cps, EXPECTED[cid])


class FixturePointsAtRealCode(unittest.TestCase):

    def test_each_finding_points_at_an_existing_file_and_line(self):
        fixture = json.loads(demo.DEFAULT_SCAN.read_text(encoding="utf-8"))
        for q in fixture["scanResults"]["resultsList"]:
            for v in q["vulnerabilities"]:
                path = ROOT / v["destinationFileName"].lstrip("/")
                with self.subTest(query=q["queryName"]):
                    self.assertTrue(path.is_file(), path)
                    lines = path.read_text(encoding="utf-8").splitlines()
                    self.assertTrue(1 <= v["destinationLine"] <= len(lines))

    def test_catalog_scoping_points_into_each_chain_folder(self):
        catalog = json.loads(demo.DEFAULT_CATALOG.read_text(encoding="utf-8"))
        for chain in catalog["chains"]:
            folder = ROOT / "chains" / CHAIN_DIRS[chain["id"]]
            for req in chain["required_findings"]:
                with self.subTest(chain=chain["id"], query=req["query_name"]):
                    self.assertTrue((folder / req["match_file_contains"]).is_dir())
                    self.assertTrue((ROOT / req["expected_file_glob"]).is_file())


class DemoCli(unittest.TestCase):

    def _main(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = demo.main(list(argv))
        return code, out.getvalue()

    def test_demo_exits_zero_and_prints_each_chain(self):
        code, out = self._main()
        self.assertEqual(code, 0)
        for cid, score in EXPECTED.items():
            self.assertIn(cid, out)
            self.assertIn(f"{score:.2f}", out)

    def test_single_chain_filter(self):
        code, out = self._main("--chain", "CH-104")
        self.assertEqual(code, 0)
        self.assertIn("CH-104", out)
        self.assertNotIn("CH-101", out)

    def test_unknown_chain_is_an_error(self):
        code, _ = self._main("--chain", "CH-999")
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
