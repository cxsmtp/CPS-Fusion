"""Checks the ten scan-proven chains.

Every finding in fixtures/scan_findings.json came from Checkmarx One scan
a71e672d-dd27-4bfb-a26a-c7fa4d15e5bb of this repository. These tests pin
what that scan proved: every chain fully assembles, no link is rated above
Low, and the chain scores follow the rubric.

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

SCAN_ID = "a71e672d-dd27-4bfb-a26a-c7fa4d15e5bb"

# Chain CPS composed from the scan's own findings.
EXPECTED = {
    "CH-201": 10.00,  # Session prediction
    "CH-202": 7.62,   # Silent bulk export
    "CH-203": 7.25,   # Report substitution
    "CH-204": 9.61,   # Support-desk impersonation
    "CH-205": 7.81,   # Error oracle
    "CH-206": 8.70,   # Remember-me hijack
    "CH-207": 9.94,   # Token leak
    "CH-208": 6.71,   # Upload to script
    "CH-209": 7.89,   # Operator console blind spot
    "CH-210": 6.09,   # Silent order loss
}

CHAIN_DIRS = {
    "CH-201": "CH-201-session-prediction",
    "CH-202": "CH-202-silent-export",
    "CH-203": "CH-203-report-swap",
    "CH-204": "CH-204-session-trust",
    "CH-205": "CH-205-error-oracle",
    "CH-206": "CH-206-cookie-scope-phish",
    "CH-207": "CH-207-token-leak",
    "CH-208": "CH-208-content-sniffing",
    "CH-209": "CH-209-operator-console",
    "CH-210": "CH-210-silent-order-loss",
}


def run_fixture(scan: Path = demo.DEFAULT_SCAN):
    results, _ = demo.run(scan, demo.DEFAULT_CATALOG)
    return {r.chain_id: r for r in results}


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


class TenChainScores(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.results = run_fixture()

    def test_catalog_holds_exactly_the_ten_chains(self):
        self.assertEqual(set(self.results), set(EXPECTED))

    def test_every_chain_fully_assembles(self):
        for cid, r in self.results.items():
            with self.subTest(chain=cid):
                self.assertIs(r.state, AssemblyState.FULLY_ASSEMBLED, r.missing)

    def test_chain_scores(self):
        for cid, want in EXPECTED.items():
            with self.subTest(chain=cid):
                self.assertAlmostEqual(self.results[cid].chain_cps, want, places=2)

    def test_no_constituent_is_rated_above_low(self):
        low = demo.severity_rank("Low")
        for cid, r in self.results.items():
            for m in r.matches:
                for f in m.matched_findings:
                    with self.subTest(chain=cid, query=f.query_name):
                        self.assertLessEqual(
                            demo.severity_rank(f.default_severity), low)

    def test_ch202_is_built_only_from_informational_findings(self):
        sevs = {demo.severity_rank(f.default_severity)
                for m in self.results["CH-202"].matches
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
                self.assertEqual(band(want), r.chain_cps_band)


class BreakingOneLink(unittest.TestCase):
    """Fixing every instance of one link means its chain no longer assembles."""

    def test_removing_any_one_link_breaks_its_chain(self):
        fixture = load(demo.DEFAULT_SCAN)
        catalog = load(demo.DEFAULT_CATALOG)
        with tempfile.TemporaryDirectory() as tmpdir:
            scan = Path(tmpdir) / "scan.json"
            for chain in catalog["chains"]:
                cid = chain["id"]
                for req in chain["required_findings"]:
                    gone = set(req["observed"]["finding_ids"])
                    doc = copy.deepcopy(fixture)
                    for q in doc["scanResults"]["resultsList"]:
                        q["vulnerabilities"] = [v for v in q["vulnerabilities"]
                                                if v["similarityId"] not in gone]
                    scan.write_text(json.dumps(doc), encoding="utf-8")
                    with self.subTest(fixed=req["query_name"], chain=cid):
                        r = run_fixture(scan)[cid]
                        self.assertIsNot(r.state, AssemblyState.FULLY_ASSEMBLED)


class FixtureIsTheRealScan(unittest.TestCase):

    def test_fixture_and_catalog_name_the_same_scan(self):
        self.assertEqual(load(demo.DEFAULT_SCAN)["scanInformation"]["scanId"], SCAN_ID)
        for chain in load(demo.DEFAULT_CATALOG)["chains"]:
            with self.subTest(chain=chain["id"]):
                self.assertEqual(chain["validation"]["scan_id"], SCAN_ID)
                for req in chain["required_findings"]:
                    self.assertEqual(req["observed"]["scan_id"], SCAN_ID)

    def test_every_catalog_finding_id_is_in_the_fixture(self):
        ids = {v["similarityId"]
               for q in load(demo.DEFAULT_SCAN)["scanResults"]["resultsList"]
               for v in q["vulnerabilities"]}
        for chain in load(demo.DEFAULT_CATALOG)["chains"]:
            for req in chain["required_findings"]:
                with self.subTest(chain=chain["id"], query=req["query_name"]):
                    self.assertTrue(req["observed"]["finding_ids"])
                    self.assertLessEqual(set(req["observed"]["finding_ids"]), ids)

    def test_each_finding_points_at_an_existing_file_and_line(self):
        for q in load(demo.DEFAULT_SCAN)["scanResults"]["resultsList"]:
            for v in q["vulnerabilities"]:
                path = ROOT / v["destinationFileName"].lstrip("/")
                with self.subTest(query=q["queryName"], file=str(path)):
                    self.assertTrue(path.is_file(), path)
                    lines = path.read_text(encoding="utf-8").splitlines()
                    self.assertTrue(1 <= v["destinationLine"] <= len(lines))

    def test_catalog_scoping_points_into_each_chain_folder(self):
        for chain in load(demo.DEFAULT_CATALOG)["chains"]:
            folder = CHAIN_DIRS[chain["id"]]
            for req in chain["required_findings"]:
                with self.subTest(chain=chain["id"], query=req["query_name"]):
                    self.assertTrue(req["match_file_contains"].startswith(folder + "/"))
                    self.assertTrue((ROOT / "chains" / req["match_file_contains"]).is_dir())
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
        self.assertIn(SCAN_ID, out)
        for cid, score in EXPECTED.items():
            self.assertIn(cid, out)
            self.assertIn(f"{score:.2f}", out)

    def test_single_chain_filter(self):
        code, out = self._main("--chain", "CH-204")
        self.assertEqual(code, 0)
        self.assertIn("CH-204", out)
        self.assertNotIn("CH-201", out)

    def test_unknown_chain_is_an_error(self):
        code, _ = self._main("--chain", "CH-999")
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
