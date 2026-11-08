"""Verify pinned, untouched community CLI copies; never execute upstream tools."""
import ast
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "third_party/community/imports.json"


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def main() -> None:
    records = json.loads(MANIFEST.read_text(encoding="utf-8"))["imports"]
    expected_names = {"http-headers-scanner", "hash-identifier"}
    if {item["name"] for item in records} != expected_names or len(records) != len(expected_names):
        raise ValueError("Unexpected community import set")
    total = 0
    for item in records:
        folder = (ROOT / item["root"]).resolve()
        if not folder.is_relative_to(ROOT / "third_party/community"):
            raise ValueError("Import escaped community source directory")
        expected = set()
        if not any(row["path"] == "LICENSE" for row in item["files"]):
            raise ValueError(f'Missing upstream license: {item["name"]}')
        for row in item["files"]:
            path = (folder / row["path"]).resolve()
            if not path.is_relative_to(folder) or not path.is_file():
                raise ValueError(f'Unsafe or missing upstream file: {row["path"]}')
            data = path.read_bytes()
            if git_blob_sha1(data) != row["git_blob_sha1"]:
                raise ValueError(f'Changed upstream file: {path.relative_to(ROOT)}')
            if path.suffix == ".py":
                ast.parse(data.decode("utf-8"), filename=str(path.relative_to(ROOT)))
            expected.add(path)
            total += 1
        found = {p.resolve() for p in folder.rglob("*") if p.is_file() and
                 "__pycache__" not in p.parts and p.suffix != ".pyc"}
        if expected != found:
            raise ValueError(f'Extra or missing files: {item["name"]}')
    print(f"PASS: {total} exact upstream files; licenses present; Python parses")
    print("Source-copy check only; no network scan or detection accuracy claimed")


if __name__ == "__main__":
    main()
