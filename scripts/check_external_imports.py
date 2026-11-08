"""Verify exact independent upstream source snapshots without running their software."""
import ast
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMPORT_ROOT = (ROOT / "third_party/external").resolve()
MANIFEST = IMPORT_ROOT / "imports.json"
EXPECTED = {"dnstwist", "assetfinder", "httprobe"}


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(
        b"blob " + str(len(data)).encode("ascii") + b"\0" + data
    ).hexdigest()


def main() -> None:
    records = json.loads(MANIFEST.read_text(encoding="utf-8"))["imports"]
    if len(records) != len(EXPECTED) or {r["name"] for r in records} != EXPECTED:
        raise ValueError("Unexpected independent import set")
    total = 0
    for entry in records:
        folder = (ROOT / entry["root"]).resolve()
        if not folder.is_relative_to(IMPORT_ROOT) or folder == IMPORT_ROOT:
            raise ValueError("Import escaped external source directory")
        if not any(file["path"] == "LICENSE" for file in entry["files"]):
            raise ValueError("Upstream license missing from manifest")
        expected_paths = set()
        for file in entry["files"]:
            target = (folder / file["path"]).resolve()
            if not target.is_relative_to(folder) or not target.is_file():
                raise ValueError(f"Unsafe or missing source file: {file['path']}")
            data = target.read_bytes()
            if git_blob_sha1(data) != file["git_blob_sha1"]:
                raise ValueError(f"Changed upstream content: {target.relative_to(ROOT)}")
            if target.suffix == ".py":
                ast.parse(data.decode("utf-8"), filename=str(target.relative_to(ROOT)))
            if target in expected_paths:
                raise ValueError(f"Duplicate upstream file: {target.relative_to(ROOT)}")
            expected_paths.add(target)
            total += 1
        found = {path.resolve() for path in folder.rglob("*") if path.is_file()
                 and "__pycache__" not in path.parts and path.suffix != ".pyc"}
        if found != expected_paths:
            raise ValueError(f"Unexpected or missing imported files: {entry['name']}")
    print(f"PASS: {total} exact third-party source files; licenses present; Python parses")
    print("Source-only verification; no builds, network probes or detection results claimed")


if __name__ == "__main__":
    main()
