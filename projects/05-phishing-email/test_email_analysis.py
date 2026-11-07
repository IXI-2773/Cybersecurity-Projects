from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
MODULE_PATH = HERE / "analyze_email.py"


def load_module():
    spec = importlib.util.spec_from_file_location("email_lab", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load analyzer")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class EmailAnalysisTests(unittest.TestCase):
    def test_fixture_hash_and_complete_analysis_match_oracle(self) -> None:
        module = load_module()
        fixture = HERE / "sample_message.eml"
        expected = json.loads((HERE / "expected_analysis.json").read_text())
        result = module.analyze_message(fixture)
        self.assertEqual(result, expected)
        self.assertEqual(result["sha256"], hashlib.sha256(fixture.read_bytes()).hexdigest())

    def test_detects_sender_mismatch_authentication_failures_and_defanged_url(self) -> None:
        result = load_module().analyze_message(HERE / "sample_message.eml")
        self.assertTrue(result["sender_reply_to_mismatch"])
        self.assertEqual(result["authentication"], {"spf": "fail", "dkim": "none", "dmarc": "fail"})
        self.assertEqual(len(result["urls"]), 1)
        self.assertEqual(
            result["urls"][0]["defanged"],
            "hxxps://contoso-login[.]example/verify?account=analyst",
        )
        self.assertEqual(result["message_id"], "<lab-mail-001@contoso.example>")

    def test_rejects_incomplete_message(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broken.eml"
            path.write_text("Subject: incomplete\n\nbody", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "required header"):
                load_module().analyze_message(path)

    def test_analyzer_has_no_network_client(self) -> None:
        source = MODULE_PATH.read_text(encoding="utf-8")
        for forbidden in ("urllib.request", "socket", "requests", "http.client"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
