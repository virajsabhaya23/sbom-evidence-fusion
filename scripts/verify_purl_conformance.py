#!/usr/bin/env python3
"""Run the official PURL validate vectors relevant to SBOMFuse inputs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sbom_fuse.identity import canonicalize_purl


SUPPORTED_TYPES = ("npm", "pypi", "maven", "nuget", "deb", "rpm", "generic")


def vector_files(root: Path) -> list[Path]:
    return [
        root / "tests" / "spec" / "specification-test.json",
        *(root / "tests" / "types" / f"{package_type}-test.json" for package_type in SUPPORTED_TYPES),
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("purl_spec", type=Path, help="pinned package-url/purl-spec checkout")
    args = parser.parse_args()

    passed = 0
    failures: list[str] = []
    for path in vector_files(args.purl_spec):
        if not path.is_file():
            raise FileNotFoundError(path)
        for vector in json.loads(path.read_text(encoding="utf-8"))["tests"]:
            if vector["test_type"] != "validate":
                continue
            try:
                actual = canonicalize_purl(vector["input"])
                error = None
            except Exception as exc:  # the vector decides whether failure is expected
                actual = None
                error = exc
            if vector["expected_failure"]:
                ok = error is not None
            else:
                ok = error is None and actual == vector["expected_output"]
            if ok:
                passed += 1
            else:
                failures.append(
                    f"{path.name}: {vector['description']}: "
                    f"expected={vector['expected_output']!r}, actual={actual!r}, error={error!r}"
                )

    if failures:
        print("\n".join(failures))
        print(f"PURL conformance: {passed} passed, {len(failures)} failed")
        return 1
    print(f"PURL conformance: {passed} passed, 0 failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
