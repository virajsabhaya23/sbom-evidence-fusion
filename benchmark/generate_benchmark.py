#!/usr/bin/env python3
"""Deterministic synthetic 100-case benchmark for graph repair methodology.
This is intentionally synthetic and must not be represented as the tracker's future real-world 100-project validation corpus.
"""
from __future__ import annotations
import json, random, pathlib, statistics, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]/"src"))
from sbom_fuse.model import SourceGraph
from sbom_fuse.fusion import fuse

SEED=20260814

def run_case(rng, idx):
    n=rng.randint(8,25)
    nodes=[f"pkg:generic/p{idx}-{j}@1" for j in range(n)]
    truth=set()
    for j in range(1,n): truth.add((nodes[rng.randrange(0,j)],nodes[j]))
    for _ in range(rng.randint(0,n//3)): truth.add((nodes[rng.randrange(n)],nodes[rng.randrange(n)]))
    truth={(a,b) for a,b in truth if a!=b}
    sbom1={e for e in truth if rng.random()>0.35}
    sbom2={e for e in truth if rng.random()>0.45}
    lock={e for e in truth if rng.random()>0.08}
    comps={n:{} for n in nodes}
    r=fuse([SourceGraph("sbom-a","cyclonedx",comps,sbom1),SourceGraph("sbom-b","spdx",comps,sbom2),SourceGraph("lock","npm-lock",comps,lock)])
    pred={e for e,d in r.edges.items() if d.state in {"confirmed","probable"}}
    tp=len(pred&truth); fp=len(pred-truth); fn=len(truth-pred)
    precision=tp/(tp+fp) if tp+fp else 1.0; recall=tp/(tp+fn) if tp+fn else 1.0
    best_single=max(len(sbom1&truth)/len(truth),len(sbom2&truth)/len(truth),len(lock&truth)/len(truth)) if truth else 1.0
    return {"case":idx,"truth_edges":len(truth),"fused_edges":len(pred),"precision":precision,"recall":recall,"best_single_recall":best_single}

def main():
    rng=random.Random(SEED); rows=[run_case(rng,i) for i in range(100)]
    summary={"seed":SEED,"cases":100,"mean_precision":statistics.mean(r["precision"] for r in rows),"mean_recall":statistics.mean(r["recall"] for r in rows),"mean_best_single_recall":statistics.mean(r["best_single_recall"] for r in rows),"note":"Synthetic methodology benchmark only; not a substitute for the planned real 100-project multi-tool corpus."}
    out=pathlib.Path(__file__).with_name("results.json"); out.write_text(json.dumps({"summary":summary,"cases":rows},indent=2)+"\n")
    print(json.dumps(summary,indent=2))
if __name__=="__main__": main()
