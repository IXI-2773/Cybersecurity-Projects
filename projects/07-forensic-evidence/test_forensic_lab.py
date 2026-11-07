from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load_module(name: str):
    path = HERE / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"forensic_{name}", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ForensicLabTests(unittest.TestCase):
    def test_package_is_deterministic_and_manifest_matches(self) -> None:
        builder = load_module("build_evidence")
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.zip"
            second = Path(directory) / "second.zip"
            first_manifest = builder.build_package(HERE / "evidence-source", first)
            second_manifest = builder.build_package(HERE / "evidence-source", second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(first_manifest, second_manifest)
            committed = json.loads((HERE / "manifest.json").read_text())
            self.assertEqual(first_manifest, committed)

    def test_examination_matches_oracle_and_preserves_original(self) -> None:
        examiner = load_module("examine_evidence")
        package = HERE / "evidence-package.zip"
        before = package.read_bytes()
        manifest = json.loads((HERE / "manifest.json").read_text())
        result = examiner.examine_package(package, manifest["package_sha256"])
        self.assertEqual(before, package.read_bytes())
        self.assertEqual(result["original_sha256"], result["working_copy_sha256"])
        self.assertEqual(result, json.loads((HERE / "examination.json").read_text()))
        self.assertEqual(
            [item["artifact"] for item in result["inventory"]],
            sorted(item["artifact"] for item in result["inventory"]),
        )
        self.assertEqual(
            [item["timestamp_utc"] for item in result["timeline"]],
            sorted(item["timestamp_utc"] for item in result["timeline"]),
        )

    def test_tamper_is_rejected_before_examination(self) -> None:
        examiner = load_module("examine_evidence")
        manifest = json.loads((HERE / "manifest.json").read_text())
        with tempfile.TemporaryDirectory() as directory:
            tampered = Path(directory) / "tampered.zip"
            shutil.copy2(HERE / "evidence-package.zip", tampered)
            tampered.write_bytes(tampered.read_bytes() + b"tamper")
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                examiner.examine_package(tampered, manifest["package_sha256"])

    def test_path_traversal_member_is_rejected(self) -> None:
        examiner = load_module("examine_evidence")
        with tempfile.TemporaryDirectory() as directory:
            hostile = Path(directory) / "hostile.zip"
            with zipfile.ZipFile(hostile, "w") as archive:
                archive.writestr("../escape.txt", "blocked")
            digest = examiner.sha256_file(hostile)
            with self.assertRaisesRegex(ValueError, "unsafe archive path"):
                examiner.examine_package(hostile, digest)

    def test_findings_cite_artifacts_and_stable_summary(self) -> None:
        examiner = load_module("examine_evidence")
        result = json.loads((HERE / "examination.json").read_text())
        artifacts = {item["artifact"] for item in result["inventory"]}
        for finding in result["findings"]:
            self.assertIn(finding["artifact"], artifacts)
            self.assertIn("timestamp_utc", finding)
        self.assertEqual(
            examiner.evidence_summary(result),
            json.loads((HERE / "evidence-summary.json").read_text()),
        )


if __name__ == "__main__":
    unittest.main()
