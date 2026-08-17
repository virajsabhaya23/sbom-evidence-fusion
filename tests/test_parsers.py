import json, pathlib, tempfile, unittest
from sbom_fuse.parsers import parse_cyclonedx, parse_spdx, parse_package_lock, parse_input

class ParserTests(unittest.TestCase):
    def _write(self, obj):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(obj, f); f.close(); return pathlib.Path(f.name)

    def test_cyclonedx(self):
        p=self._write({"bomFormat":"CycloneDX","components":[{"bom-ref":"a","name":"a","version":"1","purl":"pkg:npm/a@1"},{"bom-ref":"b","name":"b","version":"1","purl":"pkg:npm/b@1"}],"dependencies":[{"ref":"a","dependsOn":["b"]}]})
        g=parse_cyclonedx(p,"x"); self.assertIn(("pkg:npm/a@1","pkg:npm/b@1"),g.edges)

    def test_cyclonedx_canonicalizes_unlisted_purl_dependency_refs(self):
        p=self._write({"bomFormat":"CycloneDX","components":[],"dependencies":[{"ref":"pkg:generic/Acme/Widget@V1","dependsOn":["pkg:nuget/EnterpriseLibrary.Common@6.0.1304"]}]})
        g=parse_cyclonedx(p,"x")
        self.assertIn(("pkg:generic/Acme/Widget@V1","pkg:nuget/EnterpriseLibrary.Common@6.0.1304"),g.edges)

    def test_spdx(self):
        p=self._write({"spdxVersion":"SPDX-2.3","packages":[{"SPDXID":"SPDXRef-A","name":"a","versionInfo":"1"},{"SPDXID":"SPDXRef-B","name":"b","versionInfo":"1"}],"relationships":[{"spdxElementId":"SPDXRef-A","relationshipType":"DEPENDS_ON","relatedSpdxElement":"SPDXRef-B"}]})
        g=parse_spdx(p,"x"); self.assertEqual(len(g.edges),1)

    def test_package_lock(self):
        p=self._write({"name":"app","version":"1","lockfileVersion":3,"packages":{"":{"name":"app","version":"1","dependencies":{"left-pad":"1.3.0"}},"node_modules/left-pad":{"version":"1.3.0"}}})
        g=parse_package_lock(p,"x"); self.assertEqual(len(g.edges),1)

    def test_json_signatures_override_maven_looking_filenames(self):
        fixtures = [
            ("maven-tree-cyclonedx.json", {"bomFormat":"CycloneDX","components":[],"dependencies":[]}, "cyclonedx"),
            ("dependency-tree-spdx.json", {"spdxVersion":"SPDX-2.3","packages":[],"relationships":[]}, "spdx"),
            ("dependency-tree-package-lock.json", {"name":"app","version":"1","lockfileVersion":3,"packages":{}}, "npm-lock"),
        ]
        with tempfile.TemporaryDirectory() as td:
            for filename, payload, expected_type in fixtures:
                with self.subTest(filename=filename):
                    path=pathlib.Path(td)/filename
                    path.write_text(json.dumps(payload),encoding="utf-8")
                    self.assertEqual(parse_input(path,"x").source_type,expected_type)

class MultiEcosystemParserTests(unittest.TestCase):
    def _write(self, obj):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(obj, f); f.close(); return pathlib.Path(f.name)
    def test_pip_inspect(self):
        p=self._write({"pip_version":"26","installed":[{"metadata":{"name":"app","version":"1","requires_dist":["requests>=2"]}},{"metadata":{"name":"requests","version":"2.32","requires_dist":[]}}]})
        from sbom_fuse.parsers import parse_pip_inspect
        self.assertEqual(len(parse_pip_inspect(p,"x").edges),1)

    def test_node_tree(self):
        p=self._write({"name":"app","version":"1","dependencies":{"foo":{"version":"2","dependencies":{"bar":{"version":"3"}}}}})
        from sbom_fuse.parsers import parse_node_tree
        self.assertEqual(len(parse_node_tree(p,"x","pnpm-resolution").edges),2)

    def test_poetry_lock(self):
        import tempfile, pathlib
        f=tempfile.NamedTemporaryFile(mode="w", suffix="poetry.lock", delete=False)
        f.write('[[package]]\nname = "app"\nversion = "1"\n[package.dependencies]\nrequests = ">=2"\n\n[[package]]\nname = "requests"\nversion = "2"\n')
        f.close()
        from sbom_fuse.parsers import parse_poetry_lock
        self.assertEqual(len(parse_poetry_lock(pathlib.Path(f.name),"x").edges),1)

    def test_maven_tree(self):
        import tempfile, pathlib
        f=tempfile.NamedTemporaryFile(mode="w", suffix="maven-tree.txt", delete=False)
        f.write('[INFO] com.acme:app:jar:1.0\n[INFO] +- org.slf4j:slf4j-api:jar:2.0\n[INFO] |  \\- org.example:child:jar:3.0\n')
        f.close()
        from sbom_fuse.parsers import parse_maven_tree
        self.assertGreaterEqual(len(parse_maven_tree(pathlib.Path(f.name),"x").edges),1)

    def test_maven_text_preserves_classifier_scope_and_optional(self):
        f=tempfile.NamedTemporaryFile(mode="w", suffix="maven-tree.txt", delete=False)
        f.write("[INFO] com.acme:app:jar:1.0\n[INFO] +- org.example:native:jar:linux-x86_64:2.0:runtime\n[INFO] \\- org.example:test-helper:jar:3.0:test (optional)\n")
        f.close()
        from sbom_fuse.parsers import parse_maven_tree
        graph=parse_maven_tree(pathlib.Path(f.name),"x")
        classified="pkg:maven/org.example/native@2.0?classifier=linux-x86_64"
        root="pkg:maven/com.acme/app@1.0"
        self.assertIn(classified,graph.components)
        self.assertEqual(graph.components[classified]["version"],"2.0")
        self.assertEqual(graph.edge_metadata[(root,classified)][0]["scope"],"runtime")
        test_edge=next(edge for edge in graph.edges if edge[1].endswith("/test-helper@3.0"))
        self.assertEqual(graph.edge_metadata[test_edge][0]["scope"],"test")
        self.assertTrue(graph.edge_metadata[test_edge][0]["optional"])

    def test_maven_dependency_tree_json_is_preferred(self):
        path=self._write({"groupId":"com.acme","artifactId":"app","version":"1.0","type":"jar","children":[{"groupId":"org.example","artifactId":"api","version":"2.0","type":"jar","scope":"provided","optional":"false","children":[]}]})
        from sbom_fuse.parsers import parse_maven_tree
        graph=parse_maven_tree(path,"x")
        edge=("pkg:maven/com.acme/app@1.0","pkg:maven/org.example/api@2.0")
        self.assertIn(edge,graph.edges)
        self.assertEqual(graph.edge_metadata[edge][0]["scope"],"provided")
        self.assertEqual(graph.metadata["maven_format"],"dependency-tree-json")

class EvidenceParserTests(unittest.TestCase):
    def _write(self, obj):
        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump(obj, f); f.close(); return pathlib.Path(f.name)
    def test_runtime_evidence(self):
        p=self._write({"format":"sbom-fuse-evidence/v1","source_type":"runtime","components":[],"edges":[{"parent":"pkg:npm/a@1","child":"pkg:npm/b@1"}]})
        from sbom_fuse.parsers import parse_evidence_json
        g=parse_evidence_json(p,"x")
        self.assertEqual(g.source_type,"runtime")
        self.assertEqual(len(g.edges),1)

    def test_runtime_evidence_preserves_case_sensitive_purl_identity(self):
        p=self._write({"format":"sbom-fuse-evidence/v1","source_type":"runtime","components":[],"edges":[{"parent":"pkg:generic/Acme/Widget@V1","child":"pkg:nuget/EnterpriseLibrary.Common@6.0.1304"}]})
        from sbom_fuse.parsers import parse_evidence_json
        g=parse_evidence_json(p,"x")
        self.assertIn(("pkg:generic/Acme/Widget@V1","pkg:nuget/EnterpriseLibrary.Common@6.0.1304"),g.edges)
