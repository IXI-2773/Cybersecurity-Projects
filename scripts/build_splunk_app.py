"""Build a deterministic, inspectable Splunk .spl (gzipped TAR) application.

Only files beneath splunk_app/don_lopez_soc are included. The package uses
no shell scripts, credentials, endpoints or auto-enabled scheduled alerts.
"""
from __future__ import annotations

import argparse
import gzip
import io
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "splunk_app" / "don_lopez_soc"
DEST_DEFAULT = ROOT / "don_lopez_soc.spl"
EXTENSIONS = {".xml", ".conf", ".csv", ".meta"}
EXPECTED = {
    "default/app.conf", "default/data/ui/nav/default.xml",
    "default/data/ui/views/auth_triage_demo.xml",
    "default/data/ui/views/auth_triage_indexed.xml",
    "default/savedsearches.conf", "lookups/portfolio_auth_validation.csv",
    "metadata/default.meta",
}


def build(output: Path) -> dict:
    files = sorted(x for x in APP.rglob("*") if x.is_file())
    names = {p.relative_to(APP).as_posix() for p in files}
    if names != EXPECTED:
        raise ValueError(f"Unexpected app files: missing={EXPECTED - names} extra={names - EXPECTED}")
    if any(p.is_symlink() or p.suffix not in EXTENSIONS for p in files):
        raise ValueError("Unsafe or unexpected packaged app content")
    if output.resolve().is_relative_to(APP):
        raise ValueError("Cannot write archive into app source directory")

    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb", filename="", mtime=0, compresslevel=9) as zipped:
        with tarfile.open(fileobj=zipped, mode="w", format=tarfile.USTAR_FORMAT) as package:
            for path in files:
                name = "don_lopez_soc/" + path.relative_to(APP).as_posix()
                data = path.read_bytes()
                info = tarfile.TarInfo(name=name)
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = 0
                info.mode = 0o644
                info.size = len(data)
                package.addfile(info, io.BytesIO(data))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(out.getvalue())
    with tarfile.open(output, mode="r:gz") as t:
        packed = [x for x in t.getmembers() if x.isfile()]
        if len(packed) != len(EXPECTED) or any(not x.name.startswith("don_lopez_soc/") for x in packed):
            raise ValueError("App package structure invalid")
        if any(x.issym() or x.islnk() for x in packed):
            raise ValueError("No links allowed in app package")
    return {"status": "PACKAGE_CREATED_NOT_INSTALLED", "bytes": output.stat().st_size,
            "files": len(EXPECTED), "path": str(output)}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", type=Path, default=DEST_DEFAULT)
    args = ap.parse_args()
    print(json.dumps(build(args.output), indent=2))


if __name__ == "__main__":
    main()
