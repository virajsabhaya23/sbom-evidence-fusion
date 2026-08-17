import unittest
from sbom_fuse.fusion import combine_confidence, fuse, graph_quality, reachability
from sbom_fuse.model import SourceGraph
from sbom_fuse.exporters import repaired_cyclonedx, repaired_spdx

class FusionTests(unittest.TestCase):
    def test_confidence_combines_independent_sources(self):
        self.assertAlmostEqual(combine_confidence([0.8, 0.8]), 0.96)

    def test_degenerate_graph_detected(self):
        g = SourceGraph("x", "cyclonedx", components={str(i): {} for i in range(10)}, edges={("0", "1")})
        self.assertTrue(graph_quality(g)["degenerate"])

    def test_two_sboms_confirm_edge(self):
        a = SourceGraph("a", "cyclonedx", components={"p": {}, "c": {}}, edges={("p", "c")})
        b = SourceGraph("b", "spdx", components={"p": {}, "c": {}}, edges={("p", "c")})
        r = fuse([a,b])
        self.assertEqual(r.edges[("p","c")].state, "confirmed")

    def test_low_evidence_refuses_unreachable(self):
        g = SourceGraph("a", "cyclonedx", components={"p": {}, "c": {}}, edges=set(), roots={"p"})
        self.assertEqual(reachability(fuse([g]), "p", "c")["verdict"], "unknown")

    def test_reachable_path(self):
        g = SourceGraph("lock", "npm-lock", components={"a": {}, "b": {}, "c": {}}, edges={("a","b"),("b","c")}, roots={"a"})
        v = reachability(fuse([g]), "a", "c")
        self.assertEqual(v["verdict"], "reachable")
        self.assertEqual(v["path"], ["a","b","c"])

    def test_maven_reachability_respects_context(self):
        edge=("pkg:maven/a/app@1","pkg:maven/a/helper@1")
        graph=SourceGraph("maven","maven-resolution",components={edge[0]:{},edge[1]:{}},edges={edge},roots={edge[0]},edge_metadata={edge:[{"scope":"test","optional":False}]})
        result=fuse([graph])
        self.assertEqual(reachability(result,*edge,context="runtime")["verdict"],"unreachable")
        self.assertEqual(reachability(result,*edge,context="test")["verdict"],"reachable")
        self.assertEqual(result.edges[edge].evidence[0].relationship["scope"],"test")

    def test_relationship_variants_do_not_inflate_source_confidence(self):
        edge=("a","b")
        graph=SourceGraph("maven","maven-resolution",components={"a":{},"b":{}},edges={edge},roots={"a"},
                          edge_metadata={edge:[{"scope":"compile"},{"scope":"test"}]})
        decision=fuse([graph]).edges[edge]
        self.assertEqual(len(decision.evidence),2)
        self.assertEqual(decision.confidence,0.99)

    def test_matching_strong_hashes_merge_with_provenance_and_round_trip(self):
        digest="a"*64; key="pkg:npm/a@1"
        a=SourceGraph("a","cyclonedx",components={key:{"name":"a","version":"1","artifact_hashes":[{"algorithm":"SHA-256","value":digest,"source_id":"a","source_type":"cyclonedx"}]}})
        b=SourceGraph("b","spdx",components={key:{"name":"a","version":"1","artifact_hashes":[{"algorithm":"SHA-256","value":digest,"source_id":"b","source_type":"spdx"}]}})
        result=fuse([a,b]); component=result.components[key]
        self.assertEqual(component["material_identity"],"confirmed")
        self.assertEqual({item["source_id"] for item in component["artifact_hashes"]},{"a","b"})
        self.assertEqual(repaired_cyclonedx(result)["components"][0]["hashes"][0]["content"],digest)
        self.assertEqual(repaired_spdx(result)["packages"][0]["checksums"][0]["checksumValue"],digest)

    def test_conflicting_strong_hashes_quarantine_cross_source_edges(self):
        key="pkg:npm/a@1"; child="pkg:npm/b@1"
        a=SourceGraph("a","cyclonedx",components={key:{"artifact_hashes":[{"algorithm":"SHA-256","value":"a"*64,"source_id":"a","source_type":"cyclonedx"}]},child:{}},edges={(key,child)})
        b=SourceGraph("b","spdx",components={key:{"artifact_hashes":[{"algorithm":"SHA-256","value":"b"*64,"source_id":"b","source_type":"spdx"}]},child:{}},edges={(key,child)})
        result=fuse([a,b])
        self.assertEqual(result.components[key]["material_identity"],"conflicted")
        self.assertEqual(result.edges[(key,child)].state,"quarantined")
        self.assertNotIn(child,result.adjacency.get(key,set()))
        self.assertNotIn("hashes",repaired_cyclonedx(result)["components"][0])

    def test_missing_or_weak_hashes_do_not_create_false_strong_conflict(self):
        key="pkg:npm/a@1"
        a=SourceGraph("a","cyclonedx",components={key:{"artifact_hashes":[{"algorithm":"SHA-256","value":"a"*64,"source_id":"a","source_type":"cyclonedx"}]}})
        b=SourceGraph("b","spdx",components={key:{"weak_artifact_hashes":[{"algorithm":"MD5","value":"different","source_id":"b","source_type":"spdx"}]}})
        result=fuse([a,b])
        self.assertEqual(result.components[key]["material_identity"],"confirmed")
        self.assertEqual(result.components[key]["artifact_hash_conflicts"],{})

if __name__ == "__main__": unittest.main()
