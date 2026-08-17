from __future__ import annotations
import argparse
import json
import pathlib
import sys
from .exporters import dump_json, evidence_report, repaired_cyclonedx, repaired_spdx, source_diff
from .fusion import fuse, reachability
from .identity import canonical_reference
from .parsers import parse_input


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sbom-fuse", description="Evidence-backed SBOM graph repair")
    sub = p.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fuse", help="Fuse evidence and emit repaired CycloneDX + evidence ledger")
    f.add_argument("inputs", nargs="+", help="CycloneDX/SPDX/package-lock JSON files")
    f.add_argument("--out-dir", default="sbom-fuse-out")
    f.add_argument("--type", action="append", default=[], metavar="PATH=TYPE", help="Override input type for ambiguous files")
    r = sub.add_parser("reach", help="Compute uncertainty-aware reachability")
    r.add_argument("inputs", nargs="+")
    r.add_argument("--from", dest="source", required=True)
    r.add_argument("--to", dest="target", required=True)
    r.add_argument("--json", action="store_true")
    r.add_argument("--context", choices=("all", "compile", "runtime", "test"), default="all")
    r.add_argument("--type", action="append", default=[], metavar="PATH=TYPE")
    i = sub.add_parser("inspect", help="Inspect graph quality and evidence completeness")
    i.add_argument("inputs", nargs="+")
    i.add_argument("--type", action="append", default=[], metavar="PATH=TYPE")
    return p


def load_graphs(inputs: list[str], overrides: list[str] | None = None):
    typed = {}
    for item in overrides or []:
        if "=" not in item:
            raise ValueError("--type must use PATH=TYPE")
        k, v = item.split("=", 1); typed[k] = v
    graphs = []
    for idx, raw in enumerate(inputs, 1):
        path = pathlib.Path(raw)
        if not path.is_file():
            raise FileNotFoundError(path)
        graphs.append(parse_input(path, f"source-{idx}:{path.name}", typed.get(raw) or typed.get(path.name)))
    return graphs


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = fuse(load_graphs(args.inputs, getattr(args, "type", [])))
        if args.cmd == "fuse":
            out = pathlib.Path(args.out_dir)
            out.mkdir(parents=True, exist_ok=True)
            dump_json(out / "repaired.cdx.json", repaired_cyclonedx(result))
            dump_json(out / "repaired.spdx.json", repaired_spdx(result))
            dump_json(out / "evidence-ledger.json", evidence_report(result))
            dump_json(out / "graph-diff.json", source_diff(result))
            print(json.dumps({"status": "ok", "output": str(out), "sources": len(result.sources), "components": len(result.components), "edges": len(result.edges)}, indent=2))
        elif args.cmd == "inspect":
            print(json.dumps(evidence_report(result), indent=2))
        elif args.cmd == "reach":
            verdict = reachability(
                result,
                canonical_reference(args.source),
                canonical_reference(args.target),
                args.context,
            )
            print(json.dumps(verdict, indent=2) if args.json else f"{verdict['verdict']} completeness={verdict['completeness']} path={' -> '.join(verdict.get('path', []))}")
            return 0 if verdict["verdict"] == "reachable" else (2 if verdict["verdict"] == "unknown" else 1)
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 64

if __name__ == "__main__":
    raise SystemExit(main())
